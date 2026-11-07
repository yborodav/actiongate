"""Policy engine: first matching rule wins; no match means deny."""

from __future__ import annotations

from dataclasses import dataclass, field
from fnmatch import fnmatchcase
from typing import Any

from .models import Action, Decision, PolicyResult

_OPS = {"eq", "ne", "gt", "gte", "lt", "lte", "in", "not_in", "exists"}


@dataclass
class Rule:
    name: str
    tool: str                                 # glob, e.g. "stripe.create_refund" or "stripe.*"
    decision: Decision
    when: dict[str, dict[str, Any]] = field(default_factory=dict)
    agents: list[str] | None = None           # None = any agent
    approvers: list[str] = field(default_factory=list)
    timeout_seconds: int = 900

    def __post_init__(self) -> None:
        for param, conds in self.when.items():
            if not isinstance(conds, dict) or not conds:
                raise ValueError(f"rule {self.name}: condition for '{param}' must be a non-empty mapping")
            unknown = set(conds) - _OPS
            if unknown:
                raise ValueError(f"rule {self.name}: unknown operators {sorted(unknown)}")
        if self.decision == Decision.REQUIRE_APPROVAL and not self.approvers:
            raise ValueError(f"rule {self.name}: require_approval needs at least one approver")
        if self.timeout_seconds <= 0:
            raise ValueError(f"rule {self.name}: timeout_seconds must be positive")

    def matches(self, action: Action) -> bool:
        if not fnmatchcase(action.tool_name, self.tool):
            return False
        if self.agents is not None and action.agent_id not in self.agents:
            return False
        return all(_check(action.params, p, c) for p, c in self.when.items())


def _check(params: dict[str, Any], name: str, conds: dict[str, Any]) -> bool:
    present = name in params
    value = params.get(name)
    for op, expected in conds.items():
        if op == "exists":
            if present != bool(expected):
                return False
            continue
        if not present:
            # A condition on a missing parameter never matches, so an agent
            # cannot dodge an approval rule by omitting a field: the later
            # catch-all rules (or default deny) still apply.
            return False
        try:
            ok = {
                "eq": lambda: value == expected,
                "ne": lambda: value != expected,
                "gt": lambda: value > expected,
                "gte": lambda: value >= expected,
                "lt": lambda: value < expected,
                "lte": lambda: value <= expected,
                "in": lambda: value in expected,
                "not_in": lambda: value not in expected,
            }[op]()
        except TypeError:
            return False  # type mismatch (e.g. "100" > 50) never matches
        if not ok:
            return False
    return True


class PolicyEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    @classmethod
    def from_config(cls, items: list[dict[str, Any]]) -> "PolicyEngine":
        rules = []
        for i, item in enumerate(items or []):
            rules.append(
                Rule(
                    name=item.get("name") or f"rule-{i + 1}",
                    tool=item["tool"],
                    decision=Decision(item["decision"]),
                    when=item.get("when") or {},
                    agents=item.get("agents"),
                    approvers=list(item.get("approvers") or []),
                    timeout_seconds=int(item.get("timeout_seconds", 900)),
                )
            )
        return cls(rules)

    def evaluate(self, action: Action) -> PolicyResult:
        for rule in self.rules:
            if rule.matches(action):
                return PolicyResult(
                    decision=rule.decision,
                    rule_name=rule.name,
                    approvers=list(rule.approvers),
                    timeout_seconds=rule.timeout_seconds,
                    reason=f"matched rule '{rule.name}'",
                )
        return PolicyResult(decision=Decision.DENY, rule_name=None, reason="no rule matched (default deny)")
