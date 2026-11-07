"""Core data types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Decision(str, Enum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class Status(str, Enum):
    PENDING = "pending"      # waiting for an approver
    APPROVED = "approved"    # approved, grant issued, not yet executed
    DENIED = "denied"        # denied by policy or approver
    EXPIRED = "expired"      # approval timed out (fail closed)
    EXECUTED = "executed"    # connector call succeeded
    FAILED = "failed"        # connector call failed

    @property
    def terminal(self) -> bool:
        return self in {Status.DENIED, Status.EXPIRED, Status.EXECUTED, Status.FAILED}


@dataclass(frozen=True)
class Action:
    """One tool call an agent wants to perform."""

    connector: str
    operation: str
    params: dict[str, Any]
    agent_id: str
    on_behalf_of: str | None = None

    @property
    def tool_name(self) -> str:
        return f"{self.connector}.{self.operation}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "connector": self.connector,
            "operation": self.operation,
            "params": self.params,
            "agent_id": self.agent_id,
            "on_behalf_of": self.on_behalf_of,
        }

    @classmethod
    def from_dict(cls, d: dict[str, Any]) -> "Action":
        return cls(
            connector=d["connector"],
            operation=d["operation"],
            params=dict(d.get("params") or {}),
            agent_id=d["agent_id"],
            on_behalf_of=d.get("on_behalf_of"),
        )


@dataclass
class PolicyResult:
    decision: Decision
    rule_name: str | None
    approvers: list[str] = field(default_factory=list)
    timeout_seconds: int = 900
    reason: str = ""


@dataclass
class Request:
    """A stored action and its lifecycle. The stored action is what executes."""

    id: str
    action: Action
    action_hash: str
    status: Status
    rule_name: str | None
    approvers: list[str]
    reason: str | None
    created_at: float
    expires_at: float | None
    decided_by: str | None = None
    decided_at: float | None = None
    result: Any = None
    error: str | None = None

    def public_view(self) -> dict[str, Any]:
        """What an agent or approver may see. Never includes credentials."""
        return {
            "request_id": self.id,
            "status": self.status.value,
            "tool": self.action.tool_name,
            "params": self.action.params,
            "agent_id": self.action.agent_id,
            "action_hash": self.action_hash,
            "rule": self.rule_name,
            "reason": self.reason,
            "decided_by": self.decided_by,
            "expires_at": self.expires_at,
            "result": self.result,
            "error": self.error,
        }
