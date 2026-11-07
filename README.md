# ActionGate (working name)

An approval-enforcing execution proxy for AI agents. Agents call tools over MCP or REST.
ActionGate holds the real credentials, checks each call against policy, and sends risky
calls to a named human. It then executes only with a single-use grant bound to that exact action.

```
agent ──MCP/REST──> ActionGate ──(credential from vault)──> Stripe / internal API
                      │  policy: allow · require_approval · deny (default deny)
                      │  approver: Slack button or REST decision
                      │  grant: Ed25519 JWT bound to the action hash, single use, 5 min
                      └─ audit: hash-chained, signed, verifiable
```

## Security invariants

1. **Fail closed.** An unknown tool, unknown parameter or wrong type is rejected. No matching rule means deny, except that read-only operations are allowed by default. An approval timeout means deny.
2. **The stored action is what executes.** The approver approves the parameters stored at submit time, and the agent can't change them afterwards.
3. **Only approvers named on the matching rule can decide.** An agent can never be an approver; config loading rejects it.
4. **Every execution needs a grant.** It is signed with EdDSA (the algorithm is pinned), bound to the request ID and the action hash, short-lived, and single-use. It is verified right before the connector call.
5. **The request ID is the idempotency key.** A retry or a double click cannot execute twice, and status changes are compare-and-set.
6. **Agents never see credentials.** Credentials are encrypted at rest (Fernet), and agent keys and approver tokens are stored only as SHA-256 hashes.

## Layout

| Path | What |
| --- | --- |
| `actiongate/gateway.py` | Core flow: submit, decide, execute, expire |
| `actiongate/policy.py` | YAML rules, first match wins |
| `actiongate/grants.py` | Single-use, action-bound grants |
| `actiongate/audit.py` | Hash-chained, signed audit log |
| `actiongate/connectors/` | `stripe.py` (demo), `http.py` (internal APIs from YAML) |
| `actiongate/mcp_server.py` | One MCP tool per connector operation, plus `check_request` |
| `actiongate/server.py` | REST API, Slack callback, `/mcp` mount |
| `actiongate/vault.py` | Encrypted credential store |

## Run locally

Requirements: Python 3.11+, `starlette`, `uvicorn`, `mcp>=2`, `pyjwt`, `cryptography`, `requests`, `pyyaml`, plus `pytest` for the tests.

```bash
export ACTIONGATE_VAULT_KEY=$(python -m actiongate vault-key)   # keep this safe
python -m actiongate put-secret stripe_restricted_key            # prompts; use a Stripe *restricted* test key
python -m actiongate new-key                                     # agent key + hash for config
cp actiongate.example.yaml actiongate.yaml                       # paste hashes, edit rules
python -m actiongate serve --config actiongate.yaml
```

Run `put-secret` from the same directory as the config file, or pass `--vault <data_dir>/vault.bin`.

### REST

```bash
# Agent submits (agent identity comes from the key, never the body)
curl -X POST localhost:8080/v1/actions -H "Authorization: Bearer $AGENT_KEY" \
  -d '{"tool":"stripe.create_refund","params":{"charge":"ch_123","amount":20000}}'
# → 202 {"status":"pending","request_id":"req_..."}

# Approver decides
curl -X POST localhost:8080/v1/requests/req_.../decision -H "Authorization: Bearer $APPROVER_TOKEN" \
  -d '{"decision":"approve"}'
# → {"status":"executed", ...}
```

Other endpoints:
- `GET /v1/requests/{id}`: request status (agent or approver).
- `GET /v1/audit/verify`: check the audit chain (admin).
- `GET /v1/public-key`: verify grants and audit signatures yourself.
- `POST /slack/interactions`: Slack button callback, signature-checked with a 5-minute replay window.

### MCP

Point an MCP client at `http://localhost:8080/mcp/` with header `Authorization: Bearer <agent key>`.
Tools are named `<connector>_<operation>` (for example `stripe_create_refund`). A gated call returns
`status: pending` with a `request_id`, and the agent polls `check_request`.

## Tests

```bash
python -m pytest -q    # 31 tests: policy, grants, audit tampering, gateway flows, connectors, REST, Slack, MCP
```

## Known gaps (next steps)

- **Agent auth is a static bearer key.** Next is OAuth for MCP clients (client credentials, then token exchange with `act` claims for on-behalf-of).
- **Approvers use static REST tokens or Slack identity.** Add SSO for the dashboard and quorum (2-of-N) rules.
- **Expiry is lazy.** Pending requests expire when next touched, and execution is always blocked after the timeout. A background sweep is still needed so Slack shows "expired" promptly.
- **SQLite means a single process.** Move to Postgres, with `SELECT … FOR UPDATE` replacing the in-process lock.
- **No web dashboard yet.** Rules are edited in YAML.
- **Accept external approvals** (Auth0 CIBA, OpenAI Agents SDK interruptions) as grant sources.
# actiongate
