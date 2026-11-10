"""End-to-end over HTTP: REST API, Slack callback, and the MCP endpoint."""

from __future__ import annotations

import hashlib
import hmac
import json
import socket
import threading
import time
from urllib.parse import urlencode

import pytest
import requests
import uvicorn

from actiongate.config import build
from actiongate.keys import SigningKey
from actiongate.server import create_app
from actiongate.store import Store
from actiongate.vault import MemoryVault

from .conftest import ADMIN_TOKEN, AGENT_KEY, ALICE_TOKEN, BOB_TOKEN, CONFIG, FakePayments, RecordingNotifier

SLACK_SECRET = "slack-signing-secret"


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


@pytest.fixture(scope="module")
def server():
    port = _free_port()
    cfg = {**CONFIG, "public_url": f"http://127.0.0.1:{port}",
           "slack": {"channel": "#x", "bot_token_secret": "bot", "signing_secret_name": "sig"}}
    vault = MemoryVault({"bot": "xoxb-test", "sig": SLACK_SECRET})
    notifier = RecordingNotifier()
    app = build(cfg, store=Store(":memory:"), key=SigningKey.generate(), vault=vault, notifier=notifier)
    pay = FakePayments()
    app.gateway.connectors["pay"] = pay
    srv = uvicorn.Server(uvicorn.Config(create_app(app), host="127.0.0.1", port=port, log_level="warning"))
    t = threading.Thread(target=srv.run, daemon=True)
    t.start()
    base = f"http://127.0.0.1:{port}"
    for _ in range(100):
        try:
            if requests.get(base + "/healthz", timeout=1).ok:
                break
        except requests.ConnectionError:
            time.sleep(0.05)
    yield {"base": base, "pay": pay, "app": app}
    srv.should_exit = True
    t.join(timeout=5)


def auth(token):
    return {"Authorization": f"Bearer {token}"}


def test_rest_flow(server):
    base, pay = server["base"], server["pay"]
    r = requests.post(base + "/v1/actions", json={"tool": "pay.refund", "params": {"charge": "ch_9", "amount": 20000}})
    assert r.status_code == 401

    r = requests.post(base + "/v1/actions", headers=auth(AGENT_KEY),
                      json={"tool": "pay.refund", "params": {"charge": "ch_9", "amount": 20000}})
    assert r.status_code == 202, r.text
    rid = r.json()["request_id"]

    # The agent key cannot approve; neither can an approver not on the rule.
    assert requests.post(f"{base}/v1/requests/{rid}/decision", headers=auth(AGENT_KEY),
                         json={"decision": "approve"}).status_code == 401
    assert requests.post(f"{base}/v1/requests/{rid}/decision", headers=auth(BOB_TOKEN),
                         json={"decision": "approve"}).status_code == 403

    r = requests.post(f"{base}/v1/requests/{rid}/decision", headers=auth(ALICE_TOKEN), json={"decision": "approve"})
    assert r.status_code == 200 and r.json()["status"] == "executed"
    assert requests.get(f"{base}/v1/requests/{rid}", headers=auth(AGENT_KEY)).json()["status"] == "executed"
    assert any(c[1]["charge"] == "ch_9" for c in pay.calls)

    v = requests.get(base + "/v1/audit/verify", headers=auth(ADMIN_TOKEN)).json()
    assert v["ok"] is True


def _slack_post(base, body: bytes, ts: str, secret: str = SLACK_SECRET):
    sig = "v0=" + hmac.new(secret.encode(), b"v0:" + ts.encode() + b":" + body, hashlib.sha256).hexdigest()
    return requests.post(base + "/slack/interactions", data=body,
                         headers={"X-Slack-Request-Timestamp": ts, "X-Slack-Signature": sig,
                                  "Content-Type": "application/x-www-form-urlencoded"})


def test_slack_approval(server):
    base = server["base"]
    rid = requests.post(base + "/v1/actions", headers=auth(AGENT_KEY),
                        json={"tool": "pay.refund", "params": {"charge": "ch_s", "amount": 30000}}).json()["request_id"]
    payload = {"user": {"id": "UALICE"}, "actions": [{"action_id": "approve", "value": rid}]}
    body = urlencode({"payload": json.dumps(payload)}).encode()
    ts = str(int(time.time()))

    assert _slack_post(base, body, ts, secret="wrong").status_code == 401
    assert _slack_post(base, body, str(int(time.time()) - 3600)).status_code == 401  # replayed/stale

    r = _slack_post(base, body, ts)
    assert r.status_code == 200 and "executed" in r.json()["text"]


def _mcp(base, method, params=None, session=None, rid=1, token=AGENT_KEY):
    headers = {**auth(token), "Accept": "application/json, text/event-stream", "Content-Type": "application/json"}
    if session:
        headers["mcp-session-id"] = session
        headers["mcp-protocol-version"] = "2025-06-18"
    msg = {"jsonrpc": "2.0", "method": method}
    if rid is not None:
        msg["id"] = rid
    if params is not None:
        msg["params"] = params
    r = requests.post(base + "/mcp/", json=msg, headers=headers, timeout=10)
    data = None
    if r.headers.get("content-type", "").startswith("text/event-stream"):
        for line in r.text.splitlines():
            if line.startswith("data:") and line[5:].strip():
                data = json.loads(line[5:])
    elif r.content:
        data = r.json()
    return r, data


def test_mcp_requires_agent_key(server):
    r, _ = _mcp(server["base"], "initialize", token="not-a-key",
                params={"protocolVersion": "2025-06-18", "capabilities": {},
                        "clientInfo": {"name": "t", "version": "0"}})
    assert r.status_code == 401


def test_mcp_tools_and_gated_call(server):
    base, pay = server["base"], server["pay"]
    r, data = _mcp(base, "initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                        "clientInfo": {"name": "t", "version": "0"}})
    assert r.status_code == 200, r.text
    session = r.headers.get("mcp-session-id")
    _mcp(base, "notifications/initialized", session=session, rid=None)

    _, data = _mcp(base, "tools/list", {}, session=session, rid=2)
    tools = {t["name"]: t for t in data["result"]["tools"]}
    assert {"pay_refund", "pay_get_charge", "check_request"} <= set(tools)
    schema = tools["pay_refund"]["inputSchema"]
    assert set(schema["required"]) == {"charge", "amount"}

    before = len(pay.calls)
    _, data = _mcp(base, "tools/call", {"name": "pay_refund", "arguments": {"charge": "ch_m", "amount": 25000}},
                   session=session, rid=3)
    out = json.loads(data["result"]["content"][0]["text"])
    assert out["status"] == "pending" and out["agent_id"] == "support-bot"
    assert len(pay.calls) == before  # nothing ran

    _, data = _mcp(base, "tools/call", {"name": "pay_refund", "arguments": {"charge": "ch_m", "amount": 900}},
                   session=session, rid=4)
    assert json.loads(data["result"]["content"][0]["text"])["status"] == "executed"

    _, data = _mcp(base, "tools/call", {"name": "check_request", "arguments": {"request_id": out["request_id"]}},
                   session=session, rid=5)
    assert json.loads(data["result"]["content"][0]["text"])["status"] == "pending"
