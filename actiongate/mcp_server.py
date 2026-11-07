"""MCP server: one tool per connector operation, plus check_request.

Agents authenticate with a bearer agent key; the token verifier maps it
to an agent ID. The agent never sees connector credentials, and every
tool call goes through Gateway.submit.
"""

from __future__ import annotations

import inspect
import json
from typing import Any

from mcp.server.auth.middleware.auth_context import get_access_token
from mcp.server.auth.provider import AccessToken
from mcp.server.auth.settings import AuthSettings
from mcp.server.mcpserver import MCPServer
from mcp.types import ToolAnnotations

from .config import App
from .connectors.base import Operation
from .gateway import GatewayError
from .models import Action, Status

_PY = {"string": str, "integer": int, "boolean": bool, "object": dict, "array": list}


class AgentKeyVerifier:
    def __init__(self, app: App, resource_url: str):
        self.app = app
        self.resource_url = resource_url

    async def verify_token(self, token: str) -> AccessToken | None:
        agent_id = self.app.principals.agent(token)
        if agent_id is None:
            return None
        return AccessToken(token=token, client_id=agent_id, scopes=["actions"], subject=agent_id,
                           resource=self.resource_url)


def _current_agent() -> str:
    tok = get_access_token()
    if tok is None:
        raise GatewayError("not authenticated", "unauthorized")
    return tok.client_id


def _format(outcome_view: dict[str, Any]) -> str:
    status = outcome_view["status"]
    if status == Status.PENDING.value:
        outcome_view = {**outcome_view, "next_step": (
            "A human must approve this action. Tell the user it is awaiting approval and call "
            f"check_request with request_id={outcome_view['request_id']} later. Do not retry the action.")}
    return json.dumps(outcome_view, default=str)


def _make_tool_fn(app: App, connector: str, op: Operation):
    props: dict[str, Any] = op.input_schema.get("properties", {})
    required = set(op.input_schema.get("required", []))

    def tool(**kwargs: Any) -> str:
        params = {k: v for k, v in kwargs.items() if v is not None}
        action = Action(connector=connector, operation=op.name, params=params, agent_id=_current_agent())
        try:
            outcome = app.gateway.submit(action)
        except GatewayError as e:
            return json.dumps({"status": "error", "code": e.code, "message": str(e)})
        return _format(outcome.to_dict())

    # Give the function a real signature so the SDK builds the JSON schema
    # agents see from the connector's declared parameters.
    params = []
    annotations: dict[str, Any] = {"return": str}
    for name, schema in props.items():
        py = _PY.get(schema.get("type"), Any)
        if name in required:
            params.append(inspect.Parameter(name, inspect.Parameter.KEYWORD_ONLY, annotation=py))
            annotations[name] = py
        else:
            params.append(inspect.Parameter(name, inspect.Parameter.KEYWORD_ONLY, default=None,
                                            annotation=py | None))
            annotations[name] = py | None
    tool.__signature__ = inspect.Signature(params, return_annotation=str)  # type: ignore[attr-defined]
    tool.__annotations__ = annotations
    tool.__name__ = f"{connector}_{op.name}"
    return tool


def build_mcp(app: App) -> MCPServer:
    resource_url = app.public_url.rstrip("/") + "/mcp"
    server = MCPServer(
        name="actiongate",
        instructions=(
            "Tools here act on real systems. Some actions need human approval: when a tool returns "
            "status 'pending', tell the user and poll check_request later. Never retry a pending action."
        ),
        token_verifier=AgentKeyVerifier(app, resource_url),
        auth=AuthSettings(issuer_url=app.public_url, resource_server_url=resource_url,
                          validate_token_resource=True),
    )

    for cname, connector in app.gateway.connectors.items():
        for op in connector.operations().values():
            server.add_tool(
                _make_tool_fn(app, cname, op),
                name=f"{cname}_{op.name}",
                description=op.description + ("" if op.read_only else " (gated: may need human approval)"),
                annotations=ToolAnnotations(readOnlyHint=op.read_only, destructiveHint=not op.read_only),
            )

    def check_request(request_id: str) -> str:
        """Check the status and result of an earlier action that was pending approval."""
        try:
            req = app.gateway.get(request_id, agent_id=_current_agent())
        except GatewayError as e:
            return json.dumps({"status": "error", "code": e.code, "message": str(e)})
        return _format(req.public_view())

    server.add_tool(check_request, name="check_request",
                    annotations=ToolAnnotations(readOnlyHint=True))
    return server
