"""HTTP server: REST API, Slack interactions, and the MCP endpoint at /mcp."""

from __future__ import annotations

import contextlib
import json
import logging
from typing import Any
from urllib.parse import parse_qs

from starlette.applications import Starlette
from starlette.requests import Request as HttpRequest
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from .config import App
from .gateway import GatewayError
from .mcp_server import build_mcp
from .models import Action
from .notify import verify_slack_signature

log = logging.getLogger("actiongate.server")

_HTTP_STATUS = {"bad_request": 400, "invalid_params": 400, "unknown_tool": 400, "unauthorized": 401,
                "forbidden": 403, "not_found": 404, "conflict": 409}


def _bearer(request: HttpRequest) -> str | None:
    auth = request.headers.get("authorization", "")
    return auth[7:].strip() if auth.lower().startswith("bearer ") else None


def _error(e: GatewayError) -> JSONResponse:
    return JSONResponse({"error": e.code, "message": str(e)}, status_code=_HTTP_STATUS.get(e.code, 400))


def create_app(app: App) -> Starlette:
    gw = app.gateway

    async def submit_action(request: HttpRequest) -> JSONResponse:
        agent_id = app.principals.agent(_bearer(request))
        if agent_id is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            body = await request.json()
        except ValueError:
            return JSONResponse({"error": "bad_request", "message": "body must be JSON"}, status_code=400)
        if not isinstance(body, dict) or not isinstance(body.get("tool"), str) or "." not in body["tool"]:
            return JSONResponse({"error": "bad_request", "message": "expected {tool: 'connector.operation', params: {}}"},
                                status_code=400)
        params = body.get("params") or {}
        if not isinstance(params, dict):
            return JSONResponse({"error": "bad_request", "message": "params must be an object"}, status_code=400)
        connector, operation = body["tool"].split(".", 1)
        # agent_id comes from the authenticated key, never from the body.
        action = Action(connector, operation, params, agent_id, on_behalf_of=body.get("on_behalf_of"))
        try:
            outcome = gw.submit(action)
        except GatewayError as e:
            return _error(e)
        code = 202 if outcome.status.value == "pending" else 200
        return JSONResponse(outcome.to_dict(), status_code=code)

    async def get_request(request: HttpRequest) -> JSONResponse:
        token = _bearer(request)
        agent_id = app.principals.agent(token)
        approver = app.principals.approver(token)
        if agent_id is None and approver is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            req = gw.get(request.path_params["request_id"], agent_id=agent_id)
            if approver is not None and approver not in req.approvers:
                raise GatewayError("unknown request", "not_found")
        except GatewayError as e:
            return _error(e)
        return JSONResponse(req.public_view())

    async def decide(request: HttpRequest) -> JSONResponse:
        approver = app.principals.approver(_bearer(request))
        if approver is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        try:
            body = await request.json()
        except ValueError:
            body = {}
        decision = body.get("decision")
        if decision not in ("approve", "deny"):
            return JSONResponse({"error": "bad_request", "message": "decision must be approve or deny"},
                                status_code=400)
        try:
            outcome = gw.decide(request.path_params["request_id"], approver, decision == "approve",
                                note=body.get("note"))
        except GatewayError as e:
            return _error(e)
        return JSONResponse(outcome.to_dict())

    async def slack_interactions(request: HttpRequest) -> JSONResponse:
        if not app.slack_signing_secret:
            return JSONResponse({"error": "slack not configured"}, status_code=404)
        raw = await request.body()
        if not verify_slack_signature(app.slack_signing_secret, request.headers.get("x-slack-request-timestamp", ""),
                                      raw, request.headers.get("x-slack-signature", "")):
            return JSONResponse({"error": "bad signature"}, status_code=401)
        try:
            payload = json.loads(parse_qs(raw.decode())["payload"][0])
            slack_user = payload["user"]["id"]
            action = payload["actions"][0]
            request_id, verb = action["value"], action["action_id"]
        except (KeyError, IndexError, ValueError):
            return JSONResponse({"error": "bad payload"}, status_code=400)
        approver = app.principals.slack_users.get(slack_user)
        if approver is None or verb not in ("approve", "deny"):
            return JSONResponse({"text": "You are not set up as an approver.", "response_type": "ephemeral"})
        try:
            outcome = gw.decide(request_id, approver, verb == "approve", note="via slack")
            text = f"Request `{request_id}` is *{outcome.status.value}*."
        except GatewayError as e:
            text = f"Could not record decision: {e}"
        return JSONResponse({"text": text, "replace_original": True})

    async def audit_verify(request: HttpRequest) -> JSONResponse:
        if app.principals.admin(_bearer(request)) is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        r = gw.audit.verify()
        return JSONResponse({"ok": r.ok, "records": r.records, "error": r.error, "bad_seq": r.bad_seq})

    async def public_key(request: HttpRequest) -> JSONResponse:
        # Lets customers verify grants and audit signatures themselves.
        return JSONResponse({"kid": gw.grants.key.kid, "alg": "EdDSA", "public_key_pem": gw.grants.key.public_pem()})

    async def health(request: HttpRequest) -> JSONResponse:
        return JSONResponse({"ok": True})

    mcp = build_mcp(app)
    mcp_app = mcp.streamable_http_app(streamable_http_path="/")

    @contextlib.asynccontextmanager
    async def lifespan(_: Any):
        async with mcp.session_manager.run():
            yield

    return Starlette(
        routes=[
            Route("/healthz", health),
            Route("/v1/actions", submit_action, methods=["POST"]),
            Route("/v1/requests/{request_id}", get_request, methods=["GET"]),
            Route("/v1/requests/{request_id}/decision", decide, methods=["POST"]),
            Route("/v1/audit/verify", audit_verify, methods=["GET"]),
            Route("/v1/public-key", public_key, methods=["GET"]),
            Route("/slack/interactions", slack_interactions, methods=["POST"]),
            Mount("/mcp", app=mcp_app),
        ],
        lifespan=lifespan,
    )
