# AgentFence Security Model

## Protection Mode

**AgentFence is currently in cooperative mode.**

```
Protection Mode:   COOPERATIVE
Security Boundary: LIMITED
```

Only actions routed through AgentFence are controlled. This is **not** a complete OS security boundary.

## Security Invariants

These rules may never be broken — not temporarily, not for convenience, not for tests.

1. **LLM is never the authorization authority.** Authorization is deterministic policy evaluation. LLMs may explain, summarize, or analyze — never decide ALLOW/DENY.

2. **Intent is not permission.** Task descriptions, prompts, plans, and session context are contextual evidence only.

3. **No self-approval.** The agent under control must never be able to approve its own actions, mutate approval state, forge approvals, replay approvals, or bypass the approval service.

4. **No silent privilege expansion.** Never broaden permissions to make tests pass, to make Hermes work, to make MCP work, to make a package install work, or to make a demo work.

5. **No secrets in logs.** Never write raw passwords, API keys, tokens, cookies, private keys, or credentials to audit, stdout, stderr, telemetry, or debug dumps.

6. **No fabricated capabilities.** Never claim AgentFence protects something it does not protect.

7. **Never weaken a security control to make a test or integration pass.** Fix the test, fix the design, or document the limitation.

8. **Never hide a failing test.** Surface it, diagnose it, fix it, or document it as a known limitation.

9. **Cooperative mode is limited.** Never claim OS-wide, process-wide, or host-wide enforcement that does not exist.

10. **The local repository is the source of truth.** Inspect it before changing it.

## Trust Boundaries

| Boundary | Trust Level |
|----------|-------------|
| User | High |
| AgentFence CLI | High |
| AgentFence PDP | High |
| AgentFence PEP | High |
| AgentFence Audit | High |
| AgentFence Approval | High |
| AI Agent | Low |
| MCP Server | Low |
| Shell Commands | Low |
| Network Resources | Low |

## Decision Model

Every authorization decision is structured:

```text
Decision {
    result: ALLOW | DENY | ASK
    rule_id: string
    reason: string
    evidence: ...
    risk_level: ...
    policy_version: ...
}
```

No bare `DENIED`. Every decision carries structured evidence.

## Risk Model

Risk is **advisory**, never authoritative. Authorization remains `Policy → Decision`.

Risk levels: LOW / MEDIUM / HIGH / CRITICAL

Risk is explainable through `rule_id`, `reason`, `evidence`.

## Audit Model

Audit events are tamper-evident through a hash chain:

```
event_1 → hash_1
event_2 + hash_1 → hash_2
event_3 + hash_2 → hash_3
```

Verification: `agentfence audit verify --session <id>`

Output: VALID / INVALID / INCOMPLETE

**Note:** Audit logs are tamper-evident, not tamper-proof. The underlying storage remains user-modifiable.

## Approval Model

Approvals are issued through an external control surface (CLI or UI), never through the agent's own channel.

Supported scopes:
- `once` — Single use
- `session` — Valid for the session
- `repository` — Valid for the repository
- `path` — Valid for the path
- `host` — Valid for the host
- `expiry` — Valid until expiration

Approvals are narrow by default. Never promote a one-shot approval into a permanent permission unless the user explicitly asks.

## Known Limitations

- Cooperative mode only — no OS-level enforcement
- No filesystem enforcement
- No process enforcement
- No container/VM isolation
- Shell command parsing is simplified (not a full shell parser)
- Network proxy supports HTTP and HTTPS CONNECT tunneling only
- MCP proxy supports stdio transport only
- Approval UI is terminal-only
- No connection pooling in network proxy
- Rate limiting is per-connection, not global
