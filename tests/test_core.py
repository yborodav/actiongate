from __future__ import annotations

import time

import jwt
import pytest

from actiongate.audit import AuditLog
from actiongate.canonical import action_hash, canonical_json
from actiongate.grants import GrantError, GrantIssuer
from actiongate.keys import SigningKey
from actiongate.models import Action, Decision
from actiongate.policy import PolicyEngine, Rule
from actiongate.store import Store

from .conftest import FakeClock


def act(**params):
    return Action("pay", "refund", params, "support-bot")


# ---------------------------------------------------------------- hashing

def test_hash_is_order_independent_and_param_sensitive():
    a = act(charge="ch_1", amount=100)
    b = Action("pay", "refund", {"amount": 100, "charge": "ch_1"}, "support-bot")
    assert action_hash(a) == action_hash(b)
    assert action_hash(a) != action_hash(act(charge="ch_1", amount=101))
    assert action_hash(a) != action_hash(Action("pay", "refund", a.params, "other-agent"))


def test_floats_rejected():
    with pytest.raises(ValueError):
        canonical_json({"amount": 10.5})


# ---------------------------------------------------------------- policy

def test_first_match_wins_and_default_deny():
    engine = PolicyEngine([
        Rule("small", "pay.refund", Decision.ALLOW, when={"amount": {"lte": 50}}),
        Rule("big", "pay.refund", Decision.REQUIRE_APPROVAL, approvers=["alice"]),
    ])
    assert engine.evaluate(act(charge="c", amount=10)).rule_name == "small"
    assert engine.evaluate(act(charge="c", amount=500)).decision == Decision.REQUIRE_APPROVAL
    other = Action("pay", "delete_everything", {}, "support-bot")
    assert engine.evaluate(other).decision == Decision.DENY


def test_missing_or_mistyped_param_does_not_match_lenient_rule():
    engine = PolicyEngine([Rule("small", "pay.refund", Decision.ALLOW, when={"amount": {"lte": 50}})])
    assert engine.evaluate(act(charge="c")).decision == Decision.DENY
    assert engine.evaluate(act(charge="c", amount="10")).decision == Decision.DENY


def test_rule_validation():
    with pytest.raises(ValueError):
        Rule("x", "pay.refund", Decision.REQUIRE_APPROVAL)  # no approvers
    with pytest.raises(ValueError):
        Rule("x", "pay.refund", Decision.ALLOW, when={"amount": {"approximately": 3}})


# ---------------------------------------------------------------- grants

@pytest.fixture
def issuer():
    clock = FakeClock(time.time())
    return GrantIssuer(SigningKey.generate(), Store(":memory:"), ttl_seconds=60, clock=clock), clock


def test_grant_roundtrip_and_single_use(issuer):
    g, _ = issuer
    tok = g.issue(request_id="r1", action_hash="h1", agent_id="a", approver="alice")
    claims = g.verify_and_consume(tok, request_id="r1", action_hash="h1")
    assert claims.approver == "alice"
    with pytest.raises(GrantError, match="already used"):
        g.verify_and_consume(tok, request_id="r1", action_hash="h1")


def test_grant_bound_to_action_and_request(issuer):
    g, _ = issuer
    tok = g.issue(request_id="r1", action_hash="h1", agent_id="a", approver="alice")
    with pytest.raises(GrantError, match="does not match"):
        g.verify_and_consume(tok, request_id="r1", action_hash="h2")
    with pytest.raises(GrantError, match="different request"):
        g.verify_and_consume(tok, request_id="r2", action_hash="h1")
    # A failed check must not burn the grant.
    assert g.verify_and_consume(tok, request_id="r1", action_hash="h1")


def test_grant_expiry(issuer):
    g, clock = issuer
    tok = g.issue(request_id="r1", action_hash="h1", agent_id="a", approver="alice")
    clock.advance(61)
    with pytest.raises(GrantError):
        g.verify_and_consume(tok, request_id="r1", action_hash="h1")


def test_grant_forged_with_other_key_or_alg_none(issuer):
    g, _ = issuer
    other = GrantIssuer(SigningKey.generate(), g.store, clock=g.clock)
    forged = other.issue(request_id="r1", action_hash="h1", agent_id="a", approver="alice")
    with pytest.raises(GrantError):
        g.verify_and_consume(forged, request_id="r1", action_hash="h1")
    unsigned = jwt.encode({"req": "r1", "ahs": "h1"}, key=None, algorithm="none")
    with pytest.raises(GrantError):
        g.verify_and_consume(unsigned, request_id="r1", action_hash="h1")


# ---------------------------------------------------------------- audit

def test_audit_chain_detects_tampering():
    store, key = Store(":memory:"), SigningKey.generate()
    log = AuditLog(store, key)
    for i in range(5):
        log.append("evt", {"i": i})
    assert log.verify().ok

    store.raw().execute("UPDATE audit SET data_json='{\"i\":99}' WHERE seq=3")
    r = log.verify()
    assert not r.ok and r.bad_seq == 3


def test_audit_detects_deletion_and_resigning_without_key():
    store, key = Store(":memory:"), SigningKey.generate()
    log = AuditLog(store, key)
    for i in range(4):
        log.append("evt", {"i": i})
    store.raw().execute("DELETE FROM audit WHERE seq=2")
    assert not log.verify().ok

    # An attacker who rebuilds the chain with their own key is caught by the signature.
    store2 = Store(":memory:")
    AuditLog(store2, SigningKey.generate()).append("evt", {"i": 1})
    assert not AuditLog(store2, key).verify().ok
