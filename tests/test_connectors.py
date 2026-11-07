from __future__ import annotations

import pytest

from actiongate.connectors import ConnectorError, HttpConnector, StripeConnector


class FakeResp:
    def __init__(self, status=200, body=None):
        self.status_code = status
        self._body = body if body is not None else {"id": "re_1"}
        self.content = b"x"
        self.text = ""

    def json(self):
        return self._body


class FakeSession:
    def __init__(self, resp=None):
        self.calls = []
        self.resp = resp or FakeResp()

    def request(self, method, url, **kw):
        self.calls.append((method, url, kw))
        return self.resp


def test_stripe_refund_sends_idempotency_key_and_secret_only_in_header():
    s = FakeSession()
    c = StripeConnector(lambda: "rk_test_secret", session=s)
    c.validate("create_refund", {"charge": "ch_1", "amount": 500})
    c.execute("create_refund", {"charge": "ch_1", "amount": 500}, idempotency_key="req_abc")
    method, url, kw = s.calls[0]
    assert (method, url) == ("POST", "https://api.stripe.com/v1/refunds")
    assert kw["headers"]["Idempotency-Key"] == "req_abc"
    assert kw["headers"]["Authorization"] == "Bearer rk_test_secret"
    assert kw["data"] == {"charge": "ch_1", "amount": 500}


def test_stripe_errors_and_bad_ids():
    c = StripeConnector(lambda: "k", session=FakeSession(FakeResp(402, {"error": {"message": "card declined"}})))
    with pytest.raises(ConnectorError, match="402"):
        c.execute("create_refund", {"charge": "ch_1", "amount": 5}, "r")
    with pytest.raises(ConnectorError):
        StripeConnector(lambda: "k", session=FakeSession()).execute("get_customer", {"customer": "../x"}, "r")


OPS = {
    "issue_credit": {
        "method": "POST", "path": "/accounts/{account_id}/credits",
        "params": {"account_id": {"type": "string", "in": "path", "required": True},
                   "amount": {"type": "integer", "in": "body", "required": True}},
    },
    "get_account": {"method": "GET", "path": "/accounts/{account_id}", "read_only": True,
                    "params": {"account_id": {"type": "string", "in": "path", "required": True}}},
    "sneaky": {"method": "POST", "path": "/x", "read_only": True, "params": {}},
}


def test_http_connector_builds_requests_and_escapes_path():
    s = FakeSession()
    c = HttpConnector("billing", "https://billing.example.com", OPS, secret_lookup=lambda: "tok", session=s)
    c.execute("issue_credit", {"account_id": "a/../b", "amount": 100}, "req_1")
    method, url, kw = s.calls[0]
    assert method == "POST"
    assert url == "https://billing.example.com/accounts/a%2F..%2Fb/credits"
    assert kw["json"] == {"amount": 100}
    assert kw["headers"]["Authorization"] == "Bearer tok"


def test_http_connector_read_only_only_for_get():
    c = HttpConnector("billing", "https://billing.example.com", OPS, session=FakeSession())
    ops = c.operations()
    assert ops["get_account"].read_only is True
    assert ops["sneaky"].read_only is False  # a POST can't be declared read-only
    assert ops["issue_credit"].read_only is False


def test_http_connector_requires_https():
    with pytest.raises(ConnectorError):
        HttpConnector("x", "http://example.com", {}, session=FakeSession())
