from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from actiongate.config import build, hash_key  # noqa: E402
from actiongate.connectors.base import Connector, Operation  # noqa: E402
from actiongate.keys import SigningKey  # noqa: E402
from actiongate.store import Store  # noqa: E402
from actiongate.vault import MemoryVault  # noqa: E402


class FakeClock:
    def __init__(self, t: float = 1_800_000_000.0):
        self.t = t

    def __call__(self) -> float:
        return self.t

    def advance(self, s: float) -> None:
        self.t += s


class RecordingNotifier:
    def __init__(self):
        self.requested: list[Any] = []
        self.decided: list[Any] = []

    def request_approval(self, request):
        self.requested.append(request)

    def decision_made(self, request):
        self.decided.append(request)


class FakePayments(Connector):
    """Stands in for Stripe: records every execution and its idempotency key."""

    name = "pay"

    def __init__(self, fail: bool = False):
        self.calls: list[tuple[str, dict, str]] = []
        self.fail = fail
        self.charge_total = 300_00     # what inspect() reports for any charge
        self.inspect_error: str | None = None

    def inspect(self, operation, params):
        from actiongate.connectors.base import ConnectorError

        if operation != "refund":
            return None
        if self.inspect_error:
            raise ConnectorError(self.inspect_error)
        refunded = sum(p["amount"] for op, p, _ in self.calls if op == "refund" and p["charge"] == params["charge"])
        if params["amount"] > self.charge_total - refunded:
            raise ConnectorError("refund exceeds the amount still refundable")
        return {"summary": f"Refund {params['amount']} of {self.charge_total}"}

    def operations(self):
        return {
            "get_charge": Operation("get_charge", "read", True,
                                    {"type": "object", "properties": {"charge": {"type": "string"}},
                                     "required": ["charge"]}),
            "refund": Operation("refund", "refund", False,
                                {"type": "object",
                                 "properties": {"charge": {"type": "string"}, "amount": {"type": "integer"}},
                                 "required": ["charge", "amount"]}),
        }

    def execute(self, operation, params, idempotency_key):
        from actiongate.connectors.base import ConnectorError

        if self.fail:
            raise ConnectorError("upstream 500")
        self.calls.append((operation, dict(params), idempotency_key))
        return {"ok": True, "op": operation}


AGENT_KEY = "agk_test_agent"
ALICE_TOKEN = "apt_alice"
BOB_TOKEN = "apt_bob"
ADMIN_TOKEN = "adm_ops"

CONFIG = {
    "public_url": "http://localhost:8080",
    "agents": [{"id": "support-bot", "key_sha256": hash_key(AGENT_KEY)}],
    "approvers": [
        {"id": "alice", "token_sha256": hash_key(ALICE_TOKEN), "slack_user": "UALICE"},
        {"id": "bob", "token_sha256": hash_key(BOB_TOKEN)},
    ],
    "admins": [{"id": "ops", "token_sha256": hash_key(ADMIN_TOKEN)}],
    "connectors": [],
    "rules": [
        {"name": "small-auto", "tool": "pay.refund", "when": {"amount": {"lte": 5000}}, "decision": "allow"},
        {"name": "large-approval", "tool": "pay.refund", "when": {"amount": {"lte": 100000}},
         "decision": "require_approval", "approvers": ["alice"], "timeout_seconds": 600},
        {"name": "huge-deny", "tool": "pay.refund", "decision": "deny"},
    ],
}


@pytest.fixture
def env():
    clock = FakeClock()
    store = Store(":memory:")
    key = SigningKey.generate()
    notifier = RecordingNotifier()
    app = build(CONFIG, store=store, key=key, vault=MemoryVault(), clock=clock, notifier=notifier)
    pay = FakePayments()
    app.gateway.connectors["pay"] = pay
    return {"app": app, "gw": app.gateway, "clock": clock, "pay": pay, "notifier": notifier, "store": store}
