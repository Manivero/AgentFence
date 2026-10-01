# AgentFence

**Local policy / approval / audit broker for AI agents.**

AgentFence sits between an AI agent and the tools/resources the agent wants to use. Every action that passes through AgentFence operates inside explicit, deterministic, least-privilege, and auditable boundaries.

## Status

**Current phase:** Foundation (Phase 1-2 complete)

**Protection Mode:** COOPERATIVE — Only actions routed through AgentFence are controlled. This is **not** a full OS security boundary.

## Quick Start

```bash
# Initialize configuration
agentfence init

# Check policy
agentfence policy check agentfence.yaml

# Test policy
agentfence policy test agentfence.yaml

# Execute a command through AgentFence
agentfence exec --policy agentfence.yaml -- git status

# Run an agent through AgentFence
agentfence run --policy agentfence.yaml -- hermes
```

## Architecture

```
AI Agent
    |
    v
AgentFence
    |
    +---- MCP Gateway
    +---- Shell Gateway
    +---- Network Gateway
    |
    v
Policy Engine (PDP)
    |
    +---- ALLOW
    +---- DENY
    +---- ASK
    |
    v
Target resource
```

## Crates

| Crate | Responsibility |
|-------|---------------|
| `agentfence-core` | Shared domain types |
| `agentfence-policy` | YAML parsing, PDP, decision model |
| `agentfence-enforcement` | PEP interfaces, backend abstractions |
| `agentfence-audit` | Sessions, events, hash chain |
| `agentfence-approval` | Approval records, scopes, expiry |
| `agentfence-mcp` | MCP proxy, tool authorization |
| `agentfence-shell` | Shell gateway, command parsing |
| `agentfence-network` | Network proxy, host allowlist |
| `agentfence-secrets` | Secret detection, redaction |
| `agentfence-cli` | User interaction |

## Security Invariants

1. **LLM is never the authorization authority** — Authorization is deterministic policy evaluation.
2. **Intent is not permission** — Task descriptions are contextual evidence only.
3. **No self-approval** — The agent cannot approve its own actions.
4. **No silent privilege expansion** — Never broaden permissions to make tests pass.
5. **No secrets in logs** — Store hashes, fingerprints, or redacted values.
6. **No fabricated capabilities** — Never claim protection that does not exist.
7. **Never weaken a security control** — Fix the test, fix the design, or document the limitation.
8. **Never hide a failing test** — Surface it, diagnose it, fix it, or document it.
9. **Cooperative mode is limited** — Never claim OS-wide enforcement.
10. **The local repository is the source of truth** — Inspect before changing.

## Documentation

- [ARCHITECTURE.md](ARCHITECTURE.md) — System architecture
- [SECURITY.md](SECURITY.md) — Security model and guarantees
- [THREAT_MODEL.md](THREAT_MODEL.md) — Threat model
- [POLICY.md](POLICY.md) — Policy language reference
- [MCP.md](MCP.md) — MCP integration
- [DEVELOPMENT.md](DEVELOPMENT.md) — Development guide
- [ROADMAP.md](ROADMAP.md) — Development roadmap
- [IMPLEMENTATION_STATUS.md](IMPLEMENTATION_STATUS.md) — Current implementation status

## License

MIT
