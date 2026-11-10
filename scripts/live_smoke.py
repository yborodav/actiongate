"""Live end-to-end smoke test against Stripe TEST mode.

Runs the real gateway in-process with your actiongate.yaml, vault and
database, creates a fresh $300 USD test payment, then walks every policy
path (auto-allow, approve, deny-by-approver, deny-by-policy, a failing
over-refund) and checks the results in Stripe and in the audit log.

Usage (from the project folder, venv active):

    export ACTIONGATE_VAULT_KEY=$(security find-generic-password -a actiongate -s ACTIONGATE_VAULT_KEY -w)
    python scripts/live_smoke.py                     # uses actiongate.yaml
    python scripts/live_smoke.py --slack             # also post approval messages to Slack

Needs a SEPARATE Stripe test key in the vault, so the agent's key stays
least-privilege:

    vault name: stripe_smoke_key
    permissions: PaymentIntents: Write, Charges: Read

This is a local operator tool: it approves on the approver's behalf
directly through the gateway (it already holds the vault key, which is
admin-level access). Never point it at live keys; it refuses to.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from actiongate.config import load  # noqa: E402
from actiongate.gateway import GatewayError  # noqa: E402
from actiongate.models import Action, Decision, Status  # noqa: E402
from actiongate.notify import ConsoleNotifier  # noqa: E402

STRIPE_API = os.environ.get("STRIPE_API_BASE", "https://api.stripe.com/v1")
AGENT_FALLBACK = "smoke-test-agent"

results: list[tuple[bool, str]] = []


def check(ok: bool, label: str, detail: str = "") -> bool:
    results.append((ok, label))
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"  ({detail})" if detail and not ok else ""))
    return ok


def stripe(method: str, path: str, key: str, data=None) -> dict:
    r = requests.request(method, STRIPE_API + path, data=data, headers={"Authorization": f"Bearer {key}"}, timeout=20)
    body = r.json()
    if r.status_code >= 400:
        raise SystemExit(f"Stripe {method} {path} failed ({r.status_code}): {body.get('error', {}).get('message')}")
    return body


def main() -> int:
    p = argparse.ArgumentParser()
    p.add_argument("--config", default=str(ROOT / "actiongate.yaml"))
    p.add_argument("--connector", default="stripe")
    p.add_argument("--slack", action="store_true", help="post approval messages to Slack as well")
    args = p.parse_args()

    app = load(args.config)
    gw = app.gateway
    if not args.slack:
        gw.notifier = ConsoleNotifier(out=lambda s: None)

    connector = gw.connectors.get(args.connector)
    if connector is None:
        raise SystemExit(f"no connector named '{args.connector}' in {args.config}")
    # Same lookup the connector uses; never printed.
    agent_key = connector._secret()  # noqa: SLF001 - local operator tool

    import yaml

    from actiongate.vault import Vault, VaultError

    cfg_path = Path(args.config).resolve()
    data_dir = cfg_path.parent / ((yaml.safe_load(cfg_path.read_text()) or {}).get("data_dir", "data"))
    try:
        smoke_key = Vault(data_dir / "vault.bin").get("stripe_smoke_key")
    except VaultError as e:
        raise SystemExit(f"{e}\nCreate a Stripe TEST key with PaymentIntents: Write + Charges: Read, then run:\n"
                         f"  python -m actiongate put-secret stripe_smoke_key --vault {data_dir / 'vault.bin'}")

    print("Safety")
    for name, k in (("agent connector key", agent_key), ("smoke key", smoke_key)):
        if not check(k.startswith(("rk_test_", "sk_test_")), f"{name} is a TEST key"):
            print("Refusing to run against live keys.")
            return 1

    agent_id = next(iter(app.principals.agents.values()), AGENT_FALLBACK)
    tool = f"{args.connector}.create_refund"

    def refund(amount: int) -> Action:
        return Action(args.connector, "create_refund", {"charge": charge_id, "amount": amount}, agent_id)

    def run(amount: int, approve: bool | None, expect: Status, label: str):
        action = refund(amount)
        decision = gw.policy.evaluate(action).decision
        out = gw.submit(action)
        if decision == Decision.REQUIRE_APPROVAL:
            if not check(out.status == Status.PENDING, f"{label}: held for approval", out.status.value):
                return out
            summary = (out.request.context or {}).get("summary")
            check(bool(summary), f"{label}: approver sees amount and currency", "no context")
            if summary:
                print(f"        approver sees: {summary}")
            approver = out.request.approvers[0]
            out = gw.decide(out.request.id, approver, approve=bool(approve), note="live smoke test")
        check(out.status == expect, f"{label}: {expect.value}",
              f"got {out.status.value}: {out.request.error or out.request.reason}")
        return out

    print("\nSetup")
    pi = stripe("POST", "/payment_intents", smoke_key, {
        "amount": 30000, "currency": "usd", "payment_method": "pm_card_visa", "confirm": "true",
        "automatic_payment_methods[enabled]": "true", "automatic_payment_methods[allow_redirects]": "never",
        "description": "ActionGate live smoke test",
    })
    charge_id = pi.get("latest_charge")
    check(pi.get("status") == "succeeded" and bool(charge_id), "created $300.00 USD test payment", pi.get("status"))
    print(f"        charge {charge_id}")

    print("\nRead passes through")
    out = gw.submit(Action(args.connector, "list_charges", {"limit": 1}, agent_id))
    check(out.status == Status.EXECUTED, "list_charges executed", out.status.value)

    # Pick amounts from the configured rules so the test follows your policy.
    def decision_for(amount: int) -> Decision:
        return gw.policy.evaluate(refund(amount)).decision

    print(f"\nPolicy paths for {tool}")
    expected_refunded = 0
    small, large, huge = 1000, 20000, 5_000_000
    if decision_for(small) == Decision.ALLOW:
        if run(small, None, Status.EXECUTED, "$10 refund (auto)").status == Status.EXECUTED:
            expected_refunded += small
    if decision_for(large) == Decision.REQUIRE_APPROVAL:
        run(large, False, Status.DENIED, "$200 refund, approver denies")
        if run(large, True, Status.EXECUTED, "$200 refund, approver approves").status == Status.EXECUTED:
            expected_refunded += large
        # $300 charge - $210 refunded = $90 left: another $200 must be rejected
        # at submit time, before any approver is asked.
        try:
            gw.submit(refund(large))
            check(False, "$200 over-refund: rejected before approval", "it was accepted")
        except GatewayError as e:
            check(e.code == "precheck_failed", "$200 over-refund: rejected before approval", f"{e.code}: {e}")
    if decision_for(huge) == Decision.DENY:
        run(huge, None, Status.DENIED, "$50,000 refund: blocked by policy")

    print("\nStripe agrees")
    ch = stripe("GET", f"/charges/{charge_id}", smoke_key)
    check(ch.get("amount_refunded") == expected_refunded,
          f"charge shows ${expected_refunded / 100:.2f} refunded",
          f"Stripe says ${ch.get('amount_refunded', 0) / 100:.2f}")

    print("\nAudit log")
    v = gw.audit.verify()
    check(v.ok, f"hash chain and signatures verify ({v.records} records)", v.error or "")

    failed = [label for ok, label in results if not ok]
    print(f"\n{len(results) - len(failed)}/{len(results)} checks passed")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
