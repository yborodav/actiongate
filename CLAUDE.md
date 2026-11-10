# CLAUDE.md: ActionGate

## What this is

ActionGate (working name) is an approval-enforcing execution proxy for AI agents.

- Agents call tools over MCP or REST.
- ActionGate holds the third-party credentials, checks each call against policy, and sends risky calls to a named human approver.
- It executes only with a single-use grant bound to the exact action, and records every step in a signed, hash-chained audit log.

Positioning, from market research done before this code:
- Per-action approval alone is already a commodity (Auth0 async authorization, Permit.io, OpenAI Agents SDK `needs_approval`).
- The gap is **enforcement at the downstream API**: the agent never holds the credential, and the server runs only what was approved.
- Stripe is the first demo connector. The durable market is a company's **own internal APIs**, configured through the generic HTTP connector. Stripe will likely gate its own agent writes.
- Full spec, competitor table and research: https://claude.ai/artifact/7B5dLHiz4bKruNJtyz1hkM

## Security invariants (never weaken these)

1. **Fail closed.**
   - Unknown tools, unknown parameters and wrong types are rejected.
   - No matching rule means deny. Only read-only operations default to allow.
   - An approval timeout means deny.
2. **The stored action is what executes.** The approver approves stored parameters; the agent cannot change them after submitting.
3. **Only approvers named on the matching rule can decide.** An agent can never be an approver; config loading rejects it.
4. **Every execution requires a grant:** an Ed25519 JWT with the algorithm pinned, bound to the request ID and action hash, short-lived and single-use. It is verified immediately before the connector call.
5. **The request ID is the connector idempotency key,** and status changes are compare-and-set (`Store.transition`). A double approval or a race with a timeout must never execute twice.
6. **Agents never see credentials.** Credentials live in the Fernet-encrypted vault; agent keys and approver tokens are stored only as SHA-256 hashes.

Any change touching `gateway.py`, `grants.py`, `audit.py`, `policy.py` or auth in `server.py` / `mcp_server.py` needs a test proving the relevant invariant still holds.

## Layout

| Path | Role |
| --- | --- |
| `actiongate/gateway.py` | Core flow: submit, decide, execute, expire_due |
| `actiongate/policy.py` | YAML rules, first match wins; conditions on params |
| `actiongate/canonical.py` | Canonical JSON + SHA-256 action hash (floats rejected; money in integer cents) |
| `actiongate/grants.py` | Grant issue/verify/consume; time checks use the injected clock |
| `actiongate/audit.py` | Hash-chained, Ed25519-signed audit log + verify |
| `actiongate/store.py` | SQLite (requests, used_grants, audit); schema maps to Postgres |
| `actiongate/vault.py` | Encrypted credential vault (`ACTIONGATE_VAULT_KEY`) |
| `actiongate/connectors/` | `base.py` interface + validation, `stripe.py`, `http.py` |
| `actiongate/notify.py` | Slack notifier, console notifier, Slack signature check |
| `actiongate/mcp_server.py` | MCP server (mcp>=2 `MCPServer`): one tool per connector op + `check_request`; agent-key token verifier |
| `actiongate/server.py` | Starlette app: REST, Slack callback, `/mcp` mount |
| `actiongate/config.py` | YAML loading and wiring (`build()` is what tests use) |
| `tests/` | 31 tests: core, gateway flows, connectors, REST/Slack/MCP end to end |

## Commands

```bash
python -m pip install -e ".[dev]"
python -m pytest -q                                   # must stay green
export ACTIONGATE_VAULT_KEY=$(python -m actiongate vault-key)
python -m actiongate put-secret stripe_restricted_key # prompts
python -m actiongate new-key                          # prints key + hash for config
cp actiongate.example.yaml actiongate.yaml
python -m actiongate serve --config actiongate.yaml   # REST on :8080, MCP at /mcp/
python -m actiongate verify-audit --config actiongate.yaml
python scripts/live_smoke.py                          # live end-to-end check against Stripe TEST mode
```

`scripts/live_smoke.py` runs the real gateway in-process with the local config, vault and database. It needs a separate vault entry `stripe_smoke_key`: a Stripe test key with PaymentIntents Write and Charges Read. It refuses to run on live keys.

Python 3.11+ is required. `starlette` is used directly; there is no FastAPI dependency.

## Next steps, in order

1. **Working demo.**
   - Stripe test account plus a restricted key (refunds only).
   - Slack app with interactivity at `/slack/interactions`.
   - Deploy to Fly.io or Render.
   - Connect a sample agent (Claude or the OpenAI Agents SDK) to `/mcp/`.
   - Record a 60-second video: agent asks for a $300 refund, Slack approval, refund lands, audit verifies.
2. **Background expiry sweep.** Expiry is lazy today (`expire_due` runs on get/decide), so Slack doesn't show "expired" promptly.
3. **OAuth for MCP clients.** Start with client credentials, then token exchange (RFC 8693) with `act` claims for on-behalf-of. This replaces static agent keys.
4. **Postgres store.** Replace the in-process lock with `SELECT … FOR UPDATE` / conditional updates.
5. **Quorum rules (2-of-N approvers)** and a minimal web dashboard for pending requests and rules.
6. **Accept external approvals** (Auth0 CIBA, OpenAI Agents SDK interruptions) as grant sources.

Validation comes before steps 3–6: interview about 10 teams running agents in production. Build further only if most gated actions hit their own internal APIs and teams would pay around $99/month.

## Working conventions

- Keep the security invariants above. If a request would weaken one, say so and propose an alternative.
- Small, reviewed changes; run the full test suite after every change.
- No secrets in code, config files or logs. Use the vault for credentials and hashes for keys.
- The owner prefers brief answers in bullet points with exact recommendations, not lists of options.
