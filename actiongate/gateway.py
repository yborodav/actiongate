"""The gateway: evaluate, approve, grant, execute, audit.

Invariants (see the spec's security section):
1. Fail closed: unknown tool, no matching rule, or approval timeout means nothing runs.
2. The stored action is what executes; nothing the agent sends later changes it.
3. Only approvers named on the matching rule can decide; an agent never approves.
4. Execution requires a single-use grant bound to the action hash, verified just before the call.
5. The request ID is the connector idempotency key.
6. Agents never receive third-party credentials.
"""

from __future__ import annotations

import logging
import time
import uuid
from dataclasses import dataclass
from typing import Any

from .audit import AuditLog
from .canonical import action_hash
from .connectors.base import Connector, ConnectorError
from .grants import GrantError, GrantIssuer
from .models import Action, Decision, Request, Status
from .notify import Notifier
from .policy import PolicyEngine
from .store import Store

log = logging.getLogger("actiongate.gateway")

AUTO_APPROVER = "policy:auto"


class GatewayError(Exception):
    """A caller error: bad input, unknown request, not authorised."""

    def __init__(self, message: str, code: str = "bad_request"):
        super().__init__(message)
        self.code = code


@dataclass
class Outcome:
    status: Status
    request: Request

    def to_dict(self) -> dict[str, Any]:
        return self.request.public_view()


class Gateway:
    def __init__(self, *, store: Store, policy: PolicyEngine, connectors: dict[str, Connector],
                 grants: GrantIssuer, audit: AuditLog, notifier: Notifier, clock=time.time):
        self.store = store
        self.policy = policy
        self.connectors = connectors
        self.grants = grants
        self.audit = audit
        self.notifier = notifier
        self.clock = clock

    # ------------------------------------------------------------------ submit

    def submit(self, action: Action) -> Outcome:
        connector = self.connectors.get(action.connector)
        if connector is None:
            raise GatewayError(f"unknown connector '{action.connector}'", "unknown_tool")
        try:
            connector.validate(action.operation, action.params)
        except ConnectorError as e:
            raise GatewayError(str(e), "invalid_params") from e

        try:
            ahash = action_hash(action)
        except ValueError as e:
            raise GatewayError(str(e), "invalid_params") from e

        result = self.policy.evaluate(action)
        op = connector.operations()[action.operation]
        if result.rule_name is None and op.read_only:
            # Reads pass through unless a rule says otherwise.
            result.decision, result.reason = Decision.ALLOW, "read-only operation (default allow)"

        # Pre-check writes that would run or reach a human: reject what can't
        # succeed (e.g. refunding more than is left) before anyone is asked,
        # and collect human-readable context for the approver. Fails closed:
        # if the pre-check itself errors, the action is rejected.
        context = None
        if not op.read_only and result.decision != Decision.DENY:
            try:
                context = connector.inspect(action.operation, action.params)
            except ConnectorError as e:
                self.audit.append("action.rejected", {
                    "tool": action.tool_name, "agent_id": action.agent_id, "params": action.params,
                    "action_hash": ahash, "error": str(e)})
                raise GatewayError(str(e), "precheck_failed") from e

        now = self.clock()
        req = Request(
            id="req_" + uuid.uuid4().hex,
            action=action,
            action_hash=ahash,
            status=Status.PENDING,
            rule_name=result.rule_name,
            approvers=result.approvers,
            reason=result.reason,
            created_at=now,
            expires_at=now + result.timeout_seconds if result.decision == Decision.REQUIRE_APPROVAL else None,
            context=context,
        )

        if result.decision == Decision.DENY:
            req.status, req.decided_by, req.decided_at = Status.DENIED, "policy", now
            self.store.insert_request(req)
            self.audit.append("action.denied", {**_audit_base(req), "by": "policy", "reason": result.reason})
            return Outcome(req.status, req)

        if result.decision == Decision.ALLOW:
            req.status, req.decided_by, req.decided_at = Status.APPROVED, AUTO_APPROVER, now
            self.store.insert_request(req)
            self.audit.append("action.allowed", {**_audit_base(req), "by": AUTO_APPROVER, "reason": result.reason})
            grant = self.grants.issue(request_id=req.id, action_hash=ahash, agent_id=action.agent_id,
                                      approver=AUTO_APPROVER)
            return self._execute(req.id, grant)

        # REQUIRE_APPROVAL
        self.store.insert_request(req)
        self.audit.append("approval.requested", {**_audit_base(req), "approvers": req.approvers,
                                                 "expires_at": int(req.expires_at or 0)})
        try:
            self.notifier.request_approval(req)
        except Exception:  # noqa: BLE001 - notification failure must not change the decision
            log.exception("notifier failed for %s", req.id)
        return Outcome(req.status, req)

    # ---------------------------------------------------------------- decide

    def decide(self, request_id: str, approver: str, approve: bool, note: str | None = None) -> Outcome:
        self.expire_due()
        req = self.store.get_request(request_id)
        if req is None:
            raise GatewayError("unknown request", "not_found")
        if approver not in req.approvers:
            self.audit.append("approval.rejected_approver", {"request_id": req.id, "approver": approver})
            raise GatewayError("you are not an approver for this request", "forbidden")
        if approver == req.action.agent_id:
            raise GatewayError("an agent cannot approve its own action", "forbidden")
        if req.status != Status.PENDING:
            raise GatewayError(f"request is already {req.status.value}", "conflict")

        now = self.clock()
        to_status = Status.APPROVED if approve else Status.DENIED
        if not self.store.transition(req.id, Status.PENDING, to_status, decided_by=approver, decided_at=now):
            # Lost a race with another approver or the timeout sweep.
            current = self.store.get_request(req.id)
            raise GatewayError(f"request is already {current.status.value if current else 'gone'}", "conflict")

        req.status, req.decided_by, req.decided_at = to_status, approver, now
        self.audit.append("approval.approved" if approve else "approval.denied",
                          {**_audit_base(req), "by": approver, "note": note})
        if not approve:
            self._notify_decision(req)
            return Outcome(req.status, req)

        grant = self.grants.issue(request_id=req.id, action_hash=req.action_hash,
                                  agent_id=req.action.agent_id, approver=approver)
        outcome = self._execute(req.id, grant)
        self._notify_decision(outcome.request)
        return outcome

    # --------------------------------------------------------------- execute

    def _execute(self, request_id: str, grant: str) -> Outcome:
        req = self.store.get_request(request_id)
        if req is None or req.status != Status.APPROVED:
            raise GatewayError("request is not approved", "conflict")
        try:
            claims = self.grants.verify_and_consume(grant, request_id=req.id, action_hash=req.action_hash)
        except GrantError as e:
            self.store.transition(req.id, Status.APPROVED, Status.FAILED, error=str(e))
            self.audit.append("execution.blocked", {**_audit_base(req), "error": str(e)})
            return Outcome(Status.FAILED, self.store.get_request(req.id))

        connector = self.connectors[req.action.connector]
        try:
            result = connector.execute(req.action.operation, req.action.params, idempotency_key=req.id)
            self.store.transition(req.id, Status.APPROVED, Status.EXECUTED, result=result)
            self.audit.append("execution.succeeded", {**_audit_base(req), "grant_jti": claims.jti,
                                                      "approver": claims.approver})
        except ConnectorError as e:
            self.store.transition(req.id, Status.APPROVED, Status.FAILED, error=str(e))
            self.audit.append("execution.failed", {**_audit_base(req), "grant_jti": claims.jti, "error": str(e)})
        except Exception as e:  # noqa: BLE001 - never leave a request stuck in APPROVED
            log.exception("connector crashed for %s", req.id)
            self.store.transition(req.id, Status.APPROVED, Status.FAILED, error="internal connector error")
            self.audit.append("execution.failed", {**_audit_base(req), "grant_jti": claims.jti,
                                                   "error": e.__class__.__name__})
        final = self.store.get_request(req.id)
        return Outcome(final.status, final)

    # ------------------------------------------------------------- lifecycle

    def get(self, request_id: str, agent_id: str | None = None) -> Request:
        self.expire_due()
        req = self.store.get_request(request_id)
        if req is None or (agent_id is not None and req.action.agent_id != agent_id):
            # Agents may only see their own requests; don't reveal others exist.
            raise GatewayError("unknown request", "not_found")
        return req

    def expire_due(self) -> int:
        now = self.clock()
        n = 0
        for req in self.store.pending_expired(now):
            if self.store.transition(req.id, Status.PENDING, Status.EXPIRED, decided_by="timeout", decided_at=now):
                req.status, req.decided_by = Status.EXPIRED, "timeout"
                self.audit.append("approval.expired", _audit_base(req))
                self._notify_decision(req)
                n += 1
        return n

    def _notify_decision(self, req: Request) -> None:
        try:
            self.notifier.decision_made(req)
        except Exception:  # noqa: BLE001
            log.exception("notifier failed for %s", req.id)


def _audit_base(req: Request) -> dict[str, Any]:
    return {
        "request_id": req.id,
        "tool": req.action.tool_name,
        "agent_id": req.action.agent_id,
        "on_behalf_of": req.action.on_behalf_of,
        "params": req.action.params,
        "action_hash": req.action_hash,
        "rule": req.rule_name,
    }
