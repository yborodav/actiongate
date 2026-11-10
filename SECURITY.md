# Security policy

ActionGate sits between AI agents and systems that move money or data, so security reports get top priority.

## Reporting a vulnerability

- **Do not open a public issue.**
- Report privately with GitHub's **Report a vulnerability** button (Security tab → Advisories).
- Include the affected version or commit, steps to reproduce, and the impact you expect.
- You'll get an acknowledgement within **3 business days** and a fix plan within **14 days** for confirmed issues.
- Please give us a reasonable window to ship a fix before you disclose publicly. We credit reporters who want it.

## In scope

Anything that breaks one of the security invariants:

1. **Fail closed:** an unknown tool, no matching rule, a failed pre-check or an approval timeout must never execute.
2. **The stored action is what executes:** parameters can't change after submission.
3. **Only approvers named on the matching rule can decide,** and an agent can never approve.
4. **A grant is single-use, bound to one request and action hash, short-lived, and verified right before execution.**
5. **A request can never execute twice.**
6. **Agents never receive third-party credentials.**

It also covers:
- Authentication bypass on the REST, MCP or Slack endpoints.
- Audit-log tampering that `verify-audit` doesn't detect.
- Secrets leaking into logs, responses or the audit log.
- Injection through agent-supplied values into approval messages.

## Out of scope

- Attacks that need the vault key, the signing key or write access to the host. These are documented trust boundaries: an attacker with the signing key can forge grants.
- Denial of service from unbounded traffic. Run ActionGate behind a rate-limiting proxy.
- Findings in dependencies with no exploitable path in ActionGate. Report those upstream.

## Supported versions

Only the latest release on `main` gets security fixes before 1.0.
