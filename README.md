# ActionGate

**Let AI agents act on real systems without handing them the keys.**

ActionGate sits between your agents and the APIs they call (Stripe, your own admin APIs). It holds the credentials itself, so the agent never sees them. It checks every call against your rules and sends risky ones to a named person in Slack. It then runs **exactly** the action that person approved, once. Every step goes into a signed, tamper-evident audit log.

```
agent ──MCP / REST──▶ ActionGate ──credential from vault──▶ Stripe · internal APIs
                        │ rules:     allow · require approval · deny (default: deny writes)
                        │ pre-check: rejects actions that can't succeed, before anyone is asked
                        │ approval:  Slack button or API, by approvers named on the rule
                        │ grant:     signed, single-use, bound to the exact action, 5-minute life
                        └ audit:     hash-chained and signed; `verify-audit` proves nothing was changed
```

**Example:** a support agent asks to refund $200. Your rule says refunds over $50 need finance's sign-off. ActionGate:
1. Checks the charge.
2. Posts *"Refund $200.00 USD of a $300.00 USD charge"* to `#agent-approvals`.
3. Waits.
4. Refunds exactly $200 on exactly that charge when someone clicks Approve.

If nobody answers in 15 minutes, nothing happens.

## Why not just give the agent an API key?

| | Agent holds the key | ActionGate |
| --- | --- | --- |
| Agent can read the credential | Yes | No: it stays in an encrypted vault |
| A prompt injection can trigger a $10,000 refund | Yes | Only within your rules; large ones need a person |
| Approver sees exactly what will run | Depends on your code | Yes: the parameters are frozen and hashed |
| Approved once, executed twice | Possible | No: single-use grant plus idempotency key |
| Proof of who approved what | Your logs, if any | Signed, hash-chained audit log |
| Something breaks | Whatever your code does | Fail closed: nothing runs |

## Quickstart (about 5 minutes)

### 1. Run it

**With Docker:**
```bash
git clone https://github.com/<you>/actiongate && cd actiongate
docker build -t actiongate .
```

**Without Docker** (Python 3.11 or newer):
```bash
git clone https://github.com/<you>/actiongate && cd actiongate
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]" && python -m pytest -q
```

### 2. Create keys and store credentials
```bash
export ACTIONGATE_VAULT_KEY=$(python -m actiongate vault-key)  # keep it safe; it decrypts your vault
python -m actiongate put-secret stripe_restricted_key           # paste at the prompt; never in a file
python -m actiongate new-key                                    # agent key (give to the agent) + its hash
```

Use a Stripe **restricted key** with Charges: Read, Customers: Read and Refunds: Write, nothing more.

### 3. Configure
```bash
cp actiongate.example.yaml actiongate.yaml   # paste the key hash, set approvers and rules
```

```yaml
rules:                                   # first match wins
  - name: small-refunds-auto
    tool: stripe.create_refund
    when: {amount: {lte: 5000}}          # up to $50.00 (amounts are in cents)
    decision: allow
  - name: large-refunds-need-approval
    tool: stripe.create_refund
    when: {amount: {lte: 100000}}        # up to $1,000.00
    decision: require_approval
    approvers: [finance-lead]
    timeout_seconds: 900                 # no answer = deny
  - name: everything-else-blocked
    tool: stripe.create_refund
    decision: deny
```

### 4. Start it
```bash
python -m actiongate serve --config actiongate.yaml
# or with Docker:
docker run -p 8080:8080 -e ACTIONGATE_VAULT_KEY \
  -v "$PWD/actiongate.yaml:/app/actiongate.yaml:ro" -v "$PWD/data:/app/data" actiongate
```

### 5. Connect your agent over MCP

The endpoint is `http://localhost:8080/mcp/`, with the header `Authorization: Bearer <agent key>`.

**Claude Code:**
```bash
claude mcp add --transport http actiongate http://localhost:8080/mcp/ --header "Authorization: Bearer $AGENT_KEY"
```

**Cursor** (`~/.cursor/mcp.json`):
```json
{ "mcpServers": { "actiongate": { "url": "http://localhost:8080/mcp/",
  "headers": { "Authorization": "Bearer <agent key>" } } } }
```

**OpenAI Agents SDK:**
```python
from agents.mcp import MCPServerStreamableHttp
gate = MCPServerStreamableHttp(params={"url": "http://localhost:8080/mcp/",
                                       "headers": {"Authorization": f"Bearer {AGENT_KEY}"}})
```

- Tools are named `<connector>_<operation>`, for example `stripe_create_refund`.
- A gated call returns `status: "pending"` with a `request_id`. Your agent should tell the user it's waiting for approval and call `check_request` later. It should not retry.

### 6. Approve in Slack (optional)

Without Slack, approval requests print to the server console, and approvers decide over the REST API. To use Slack:
1. Create a Slack app with the `chat:write` bot scope.
2. Point its Interactivity Request URL at `https://<your host>/slack/interactions`. Socket Mode must be off.
3. Store the bot token and signing secret with `put-secret`.
4. Add the `slack:` block to your config, as in the example file.

## REST API

| Method and path | Who | What |
| --- | --- | --- |
| `POST /v1/actions` | Agent | Submit `{"tool": "stripe.create_refund", "params": {...}}`. Returns `executed`, `denied` or `pending` (202) |
| `GET /v1/requests/{id}` | Agent or approver | Status and result |
| `POST /v1/requests/{id}/decision` | Approver | `{"decision": "approve" \| "deny"}` |
| `GET /v1/audit/verify` | Admin | Verify the audit chain |
| `GET /v1/public-key` | Anyone | Verify grants and audit signatures yourself |
| `POST /slack/interactions` | Slack | Button clicks, signature-checked |

## Your own APIs

The `http` connector turns any internal endpoint into a gated tool, configured in YAML only. See `actiongate.example.yaml` for a `billing.issue_credit` example. Writes are never treated as read-only, even if marked so.

## Security model

The full list is in [SECURITY.md](SECURITY.md). In short:
- **Fail closed:** unknown tool, no matching rule, failed pre-check or timeout means nothing runs.
- **The approver approves the stored, hashed parameters,** and only approvers named on the rule can decide.
- **Every execution needs a single-use grant:** Ed25519 with the algorithm pinned, bound to the request and action hash.
- **The request ID doubles as the idempotency key,** and state changes are compare-and-set, so nothing runs twice.
- **Credentials are encrypted at rest.** Agent keys and approver tokens are stored only as hashes.
- **Agent-supplied values are escaped** before they're shown to approvers.

**Trust boundary:** anyone holding the vault key or signing key can act as ActionGate. Protect them like production database credentials.

## Testing

```bash
python -m pytest -q             # unit and end-to-end tests (Stripe and Slack faked)
python scripts/live_smoke.py    # real Stripe TEST mode: every policy path, refunds and audit
```

`live_smoke.py` needs a separate test key in the vault called `stripe_smoke_key`, with PaymentIntents: Write and Charges: Read. It refuses to run against live keys.

## Status and roadmap

**Early, pre-1.0.** It works end to end against Stripe test mode. Use it in production only after your own review.

Planned:
- OAuth for MCP clients, replacing static agent keys.
- Postgres and multiple instances.
- Recovery for executions interrupted by a crash.
- Background expiry that updates Slack.
- Quorum approvals (2 of N).
- A web dashboard.
- More connectors.

## License

[Apache-2.0](LICENSE)
