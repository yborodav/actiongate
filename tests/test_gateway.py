from __future__ import annotations

import pytest

from actiongate.gateway import GatewayError
from actiongate.models import Action, Status


def refund(amount, charge="ch_1", agent="support-bot"):
    return Action("pay", "refund", {"charge": charge, "amount": amount}, agent)


def test_small_refund_runs_automatically(env):
    out = env["gw"].submit(refund(1000))
    assert out.status == Status.EXECUTED
    assert env["pay"].calls == [("refund", {"charge": "ch_1", "amount": 1000}, out.request.id)]


def test_large_refund_waits_then_executes_once_on_approval(env):
    gw, pay = env["gw"], env["pay"]
    out = gw.submit(refund(20000))
    assert out.status == Status.PENDING and pay.calls == []
    assert env["notifier"].requested[0].id == out.request.id

    done = gw.decide(out.request.id, "alice", approve=True)
    assert done.status == Status.EXECUTED
    assert len(pay.calls) == 1 and pay.calls[0][2] == out.request.id  # idempotency key

    with pytest.raises(GatewayError) as e:
        gw.decide(out.request.id, "alice", approve=True)  # second click does nothing
    assert e.value.code == "conflict"
    assert len(pay.calls) == 1


def test_denied_by_approver_never_executes(env):
    out = env["gw"].submit(refund(20000))
    assert env["gw"].decide(out.request.id, "alice", approve=False).status == Status.DENIED
    assert env["pay"].calls == []


def test_policy_deny_and_unknown_tools(env):
    gw = env["gw"]
    assert gw.submit(refund(500000)).status == Status.DENIED
    with pytest.raises(GatewayError):
        gw.submit(Action("pay", "drop_database", {}, "support-bot"))
    with pytest.raises(GatewayError):
        gw.submit(Action("nope", "refund", {}, "support-bot"))
    assert env["pay"].calls == []


def test_extra_or_mistyped_params_rejected(env):
    gw = env["gw"]
    with pytest.raises(GatewayError):
        gw.submit(Action("pay", "refund", {"charge": "c", "amount": 10, "to_account": "x"}, "support-bot"))
    with pytest.raises(GatewayError):
        gw.submit(Action("pay", "refund", {"charge": "c", "amount": True}, "support-bot"))


def test_only_named_approver_can_decide(env):
    gw = env["gw"]
    out = gw.submit(refund(20000))
    for who in ("bob", "support-bot", "mallory"):
        with pytest.raises(GatewayError) as e:
            gw.decide(out.request.id, who, approve=True)
        assert e.value.code == "forbidden"
    assert env["pay"].calls == []


def test_timeout_fails_closed(env):
    gw, clock = env["gw"], env["clock"]
    out = gw.submit(refund(20000))
    clock.advance(601)
    with pytest.raises(GatewayError) as e:
        gw.decide(out.request.id, "alice", approve=True)
    assert e.value.code == "conflict"
    assert gw.get(out.request.id).status == Status.EXPIRED
    assert env["pay"].calls == []


def test_reads_pass_through_without_a_rule(env):
    out = env["gw"].submit(Action("pay", "get_charge", {"charge": "ch_1"}, "support-bot"))
    assert out.status == Status.EXECUTED


def test_connector_failure_is_recorded_not_retried(env):
    env["pay"].fail = True
    out = env["gw"].submit(refund(1000))
    assert out.status == Status.FAILED and "upstream" in out.request.error


def test_agents_only_see_their_own_requests(env):
    gw = env["gw"]
    out = gw.submit(refund(20000))
    with pytest.raises(GatewayError):
        gw.get(out.request.id, agent_id="another-agent")


def test_every_step_is_audited_and_chain_verifies(env):
    gw = env["gw"]
    gw.submit(refund(1000))
    out = gw.submit(refund(20000))
    gw.decide(out.request.id, "alice", approve=True)
    events = [r["event"] for r in gw.store.iter_audit()]
    assert events == ["action.allowed", "execution.succeeded", "approval.requested",
                      "approval.approved", "execution.succeeded"]
    assert gw.audit.verify().ok
