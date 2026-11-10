"""Stripe connector (first demo connector).

Uses the REST API directly with a restricted key from the vault. Every
write sends the ActionGate request ID as Stripe's Idempotency-Key, so a
retried execution cannot refund twice.
"""

from __future__ import annotations

from typing import Any, Callable

import requests

from .base import Connector, ConnectorError, Operation

API_BASE = "https://api.stripe.com/v1"


class StripeConnector(Connector):
    def __init__(self, secret_lookup: Callable[[], str], name: str = "stripe", session: requests.Session | None = None,
                 api_base: str = API_BASE, timeout: float = 20.0):
        self.name = name
        self._secret = secret_lookup
        self._http = session or requests.Session()
        self._base = api_base.rstrip("/")
        self._timeout = timeout

    def operations(self) -> dict[str, Operation]:
        return {
            "list_charges": Operation(
                "list_charges",
                "List recent charges, optionally for one customer.",
                read_only=True,
                input_schema={
                    "type": "object",
                    "properties": {
                        "customer": {"type": "string", "description": "Customer ID (cus_...)"},
                        "limit": {"type": "integer", "description": "1-100, default 10"},
                    },
                },
            ),
            "get_customer": Operation(
                "get_customer",
                "Get a customer by ID.",
                read_only=True,
                input_schema={
                    "type": "object",
                    "properties": {"customer": {"type": "string", "description": "Customer ID (cus_...)"}},
                    "required": ["customer"],
                },
            ),
            "create_refund": Operation(
                "create_refund",
                "Refund a charge. Amount is in the smallest currency unit (cents). "
                "May require human approval depending on policy.",
                read_only=False,
                input_schema={
                    "type": "object",
                    "properties": {
                        "charge": {"type": "string", "description": "Charge ID (ch_...)"},
                        "amount": {"type": "integer", "description": "Amount in cents"},
                        "reason": {
                            "type": "string",
                            "description": "duplicate, fraudulent or requested_by_customer",
                        },
                    },
                    "required": ["charge", "amount"],
                },
            ),
        }

    def inspect(self, operation: str, params: dict[str, Any]) -> dict[str, Any] | None:
        if operation != "create_refund":
            return None
        amount = params["amount"]
        if amount <= 0:
            raise ConnectorError("amount must be positive")
        ch = self._call("GET", f"/charges/{_safe_id(params['charge'])}")
        currency = str(ch.get("currency", "")).lower()
        total = int(ch.get("amount", 0))
        refunded = int(ch.get("amount_refunded", 0))
        remaining = total - refunded
        if amount > remaining:
            raise ConnectorError(
                f"refund of {format_money(amount, currency)} exceeds the {format_money(remaining, currency)} "
                f"still refundable on this charge"
            )
        summary = f"Refund {format_money(amount, currency)} of a {format_money(total, currency)} charge"
        if refunded:
            summary += f" ({format_money(refunded, currency)} already refunded)"
        context = {"summary": summary, "currency": currency.upper(), "charge_amount": total,
                   "already_refunded": refunded}
        if ch.get("customer"):
            context["customer"] = ch["customer"]
        billing = ch.get("billing_details") or {}
        if billing.get("email"):
            context["customer_email"] = billing["email"]
        return context

    def execute(self, operation: str, params: dict[str, Any], idempotency_key: str) -> Any:
        if operation == "list_charges":
            q = {"limit": params.get("limit", 10)}
            if "customer" in params:
                q["customer"] = params["customer"]
            return self._call("GET", "/charges", params=q)
        if operation == "get_customer":
            return self._call("GET", f"/customers/{_safe_id(params['customer'])}")
        if operation == "create_refund":
            if params["amount"] <= 0:
                raise ConnectorError("amount must be positive")
            data = {"charge": params["charge"], "amount": params["amount"]}
            if "reason" in params:
                data["reason"] = params["reason"]
            return self._call("POST", "/refunds", data=data, idempotency_key=idempotency_key)
        raise ConnectorError(f"unknown operation '{operation}'")

    def _call(self, method: str, path: str, *, params=None, data=None, idempotency_key: str | None = None) -> Any:
        headers = {"Authorization": f"Bearer {self._secret()}"}
        if idempotency_key:
            headers["Idempotency-Key"] = idempotency_key
        try:
            resp = self._http.request(method, self._base + path, params=params, data=data, headers=headers,
                                      timeout=self._timeout)
        except requests.RequestException as e:
            raise ConnectorError(f"stripe request failed: {e.__class__.__name__}") from e
        if resp.status_code >= 400:
            try:
                msg = resp.json().get("error", {}).get("message", "")
            except ValueError:
                msg = ""
            raise ConnectorError(f"stripe returned {resp.status_code}: {msg}".strip())
        return resp.json()


# Stripe amounts are in the smallest currency unit; these currencies have none.
_ZERO_DECIMAL = {"bif", "clp", "djf", "gnf", "jpy", "kmf", "krw", "mga", "pyg", "rwf", "ugx", "vnd", "vuv",
                 "xaf", "xof", "xpf"}


def format_money(minor: int, currency: str) -> str:
    """20000, 'usd' -> '$200.00 USD'; 500, 'jpy' -> '500 JPY'."""
    cur = currency.lower()
    if cur in _ZERO_DECIMAL:
        return f"{minor:,} {cur.upper()}"
    symbol = {"usd": "$", "cad": "$", "aud": "$", "nzd": "$", "eur": "€", "gbp": "£"}.get(cur, "")
    return f"{symbol}{minor / 100:,.2f} {cur.upper()}".strip()


def _safe_id(value: str) -> str:
    if not value or not all(c.isalnum() or c == "_" for c in value):
        raise ConnectorError("invalid Stripe ID")
    return value
