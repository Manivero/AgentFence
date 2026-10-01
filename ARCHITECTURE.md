# AgentFence Architecture

## Overview

AgentFence is a local policy / approval / audit broker for AI agents. It uses a layered architecture with clear separation between components.

## Architecture Diagram

```
                AI Agent
                   |
                   v
            +--------------+
            |  AgentFence  |
            +------+-------+
                   |
          +--------+---------+
          |                  |
       Gateways           Session
          |                  |
     +----+----+             v
     |    |    |           Audit
    MCP Shell Network
     |    |    |
     +----+----+
          v
         PEP
          |
          v
         PDP
          |
    +-----+------+
    v     v      v
 ALLOW  DENY    ASK
                 |
                 v
              Human
```

## Component Responsibilities

### PEP (Policy Enforcement Point)

- Applies decisions from the PDP
- Never makes authorization decisions itself
- Delegates to enforcement backends
- Future backends: cooperative, container, OpenShell, WSL, VM, Windows, Linux

### PDP (Policy Decision Point)

- Evaluates actions against policy
- Returns structured decisions with full explanation
- Never executes actions
- Never delegates authorization to an LLM

### Gateways

- **MCP Gateway** — Evaluates MCP tool calls before forwarding
- **Shell Gateway** — Evaluates shell commands before execution
- **Network Gateway** — Evaluates network requests before forwarding

### Audit

- Records all actions with structured events
- Tamper-evident hash chain
- JSONL export
- Session tracking

### Approval

- Manages approval records
- Scopes: once, session, repository, path, host, expiry
- Replay protection
- Separate trust boundary

## Data Flow

```
Gateway → Normalize Action → Build Context → PEP → PDP → ALLOW/DENY/ASK
                                                              |
                                                              v
                                                    Approval Service
                                                              |
                                                              v
                                                    Execute or Block
                                                              |
                                                              v
                                                           Audit
```

## Security Boundaries

- **Cooperative Mode (MVP):** Only actions through AgentFence are controlled
- **Enforced Mode (Future):** Container, WSL, VM, OS-specific enforcement

## Crate Structure

```
crates/
├── core/           # Shared domain types
├── policy/         # YAML parsing, PDP, decision model
├── enforcement/    # PEP interfaces, backend abstractions
├── audit/          # Sessions, events, hash chain
├── approval/       # Approval records, scopes, expiry
├── mcp/            # MCP proxy, tool authorization
├── shell/          # Shell gateway, command parsing
├── network/        # Network proxy, host allowlist
├── secrets/        # Secret detection, redaction
└── cli/            # User interaction
```
