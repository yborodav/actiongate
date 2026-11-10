"""Approval notifications: Slack (production) and console (development)."""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from typing import Any, Callable, Protocol

import requests

from .models import Request

log = logging.getLogger("actiongate.notify")


class Notifier(Protocol):
    def request_approval(self, request: Request) -> None: ...
    def decision_made(self, request: Request) -> None: ...


class ConsoleNotifier:
    def __init__(self, out: Callable[[str], None] = print):
        self.out = out

    def request_approval(self, request: Request) -> None:
        summary = (request.context or {}).get("summary")
        self.out(
            f"[approval needed] {request.id} {request.action.tool_name} "
            + (f"\"{summary}\" " if summary else "")
            + f"params={json.dumps(request.action.params)} agent={request.action.agent_id} "
            + f"approvers={request.approvers}"
        )

    def decision_made(self, request: Request) -> None:
        self.out(f"[{request.status.value}] {request.id} by {request.decided_by}")


class SlackNotifier:
    """Posts approval requests with Approve/Deny buttons via chat.postMessage."""

    def __init__(self, bot_token_lookup: Callable[[], str], channel: str,
                 approver_slack_ids: dict[str, str], session: requests.Session | None = None):
        self._token = bot_token_lookup
        self.channel = channel
        self.approver_slack_ids = approver_slack_ids
        self._http = session or requests.Session()

    def request_approval(self, request: Request) -> None:
        mentions = " ".join(
            f"<@{self.approver_slack_ids[a]}>" for a in request.approvers if a in self.approver_slack_ids
        )
        # Parameters come from the agent: escape them so a crafted value can't
        # inject Slack mentions, links or formatting into the approval card.
        params = "\n".join(f"• `{_escape(k)}`: `{_escape(str(v)).replace('`', 'ˋ')}`"
                           for k, v in sorted(request.action.params.items()))
        ctx = request.context or {}
        headline = f"*{_escape(ctx['summary'])}*\n" if ctx.get("summary") else ""
        extra = "".join(f"{label}: `{_escape(str(ctx[key]))}`\n"
                        for key, label in (("customer_email", "Customer"), ("customer", "Customer ID"))
                        if ctx.get(key))
        blocks: list[dict[str, Any]] = [
            {"type": "section", "text": {"type": "mrkdwn", "text":
                f"*Approval needed:* `{request.action.tool_name}`\n{headline}"
                f"Agent: `{request.action.agent_id}`  Rule: `{request.rule_name}`\n{extra}"
                f"Exact parameters that will run:\n{params}\n{mentions}"}},
            {"type": "context", "elements": [{"type": "mrkdwn", "text":
                f"Request `{request.id}` · action hash `{request.action_hash[:16]}…` · "
                f"expires <!date^{int(request.expires_at or 0)}^{{time}}|soon>; no answer means deny"}]},
            {"type": "actions", "elements": [
                {"type": "button", "style": "primary", "text": {"type": "plain_text", "text": "Approve"},
                 "action_id": "approve", "value": request.id},
                {"type": "button", "style": "danger", "text": {"type": "plain_text", "text": "Deny"},
                 "action_id": "deny", "value": request.id},
            ]},
        ]
        self._post({"channel": self.channel, "text": f"Approval needed: {request.action.tool_name}",
                    "blocks": blocks})

    def decision_made(self, request: Request) -> None:
        self._post({"channel": self.channel,
                    "text": f"Request `{request.id}` is now *{request.status.value}* (by {request.decided_by})"})

    def _post(self, body: dict[str, Any]) -> None:
        try:
            resp = self._http.post(
                "https://slack.com/api/chat.postMessage",
                json=body,
                headers={"Authorization": f"Bearer {self._token()}"},
                timeout=10,
            )
            if not resp.json().get("ok"):
                log.error("slack post failed: %s", resp.json().get("error"))
        except (requests.RequestException, ValueError) as e:
            # A failed notification must not approve anything; the request
            # simply times out and is denied.
            log.error("slack post failed: %s", e.__class__.__name__)


def _escape(text: str) -> str:
    """Escape Slack mrkdwn control characters in values that came from upstream data."""
    return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def verify_slack_signature(signing_secret: str, timestamp: str, body: bytes, signature: str,
                           now: float | None = None, max_age: int = 300) -> bool:
    """Slack request signing (v0). Rejects stale timestamps to stop replays."""
    try:
        ts = int(timestamp)
    except (TypeError, ValueError):
        return False
    if abs((now if now is not None else time.time()) - ts) > max_age:
        return False
    base = b"v0:" + str(ts).encode() + b":" + body
    expected = "v0=" + hmac.new(signing_secret.encode(), base, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, signature or "")
