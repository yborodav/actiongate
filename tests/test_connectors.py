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


def test_stripe_inspect_formats_amounts_and_blocks_over_refund():
    charge = {"id": "ch_1", "amount": 30000, "amount_refunded": 1000, "currency": "usd", "customer": "cus_9",
              "billing_details": {"email": "a@example.com"}}
    s = FakeSession(FakeResp(200, charge))
    c = StripeConnector(lambda: "k", session=s)
    ctx = c.inspect("create_refund", {"charge": "ch_1", "amount": 20000})
    assert ctx["summary"] == "Refund $200.00 USD of a $300.00 USD charge ($10.00 USD already refunded)"
    assert ctx["customer_email"] == "a@example.com"
    assert s.calls[0][0] == "GET"  # inspect only reads
    with pytest.raises(ConnectorError, match=r"\$290.00 USD still refundable"):
        c.inspect("create_refund", {"charge": "ch_1", "amount": 29001})
    assert c.inspect("list_charges", {}) is None


def test_format_money():
    from actiongate.connectors.stripe import format_money

    assert format_money(44085, "cad") == "$440.85 CAD"
    assert format_money(500, "jpy") == "500 JPY"
    assert format_money(123456789, "eur") == "€1,234,567.89 EUR"


def test_slack_card_escapes_agent_supplied_values():
    from actiongate.models import Action, Request, Status
    from actiongate.notify import SlackNotifier

    posted = []

    class S:
        def post(self, url, json, headers, timeout):
            posted.append(json)

            class R:
                def json(self_inner):
                    return {"ok": True}
            return R()

    n = SlackNotifier(lambda: "xoxb", "C1", {"alice": "UA"}, session=S())
    req = Request("req_1", Action("stripe", "create_refund",
                                  {"charge": "ch_1", "amount": 1, "reason": "<!channel> click <https://evil|here>"},
                                  "bot"), "h" * 64, Status.PENDING, "r", ["alice"], None, 0.0, 60.0,
                  context={"summary": "Refund $0.01 USD of a $1.00 USD charge"})
    n.request_approval(req)
    text = posted[0]["blocks"][0]["text"]["text"]
    assert "<!channel>" not in text and "<https://evil" not in text
    assert "&lt;!channel&gt;" in text
    assert "*Refund $0.01 USD of a $1.00 USD charge*" in text and "<@UA>" in text


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
