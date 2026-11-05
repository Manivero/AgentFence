# AgentFence Policy Language

## Overview

AgentFence uses YAML for policy configuration. The policy is parsed into a typed internal representation and evaluated deterministically.

## Policy File

Default location: `agentfence.yaml`

## Schema

```yaml
version: 1

defaults:
  filesystem: deny
  shell: deny
  network: deny
  mcp: deny

filesystem:
  read:
    allow:
      - "./project/**"
  write:
    allow:
      - "./project/**"
  deny:
    - "~/.ssh/**"
    - "~/.aws/**"
    - "**/.env"
    - "**/*.pem"

shell:
  allow:
    - git
    - cargo
    - npm
    - python
  deny:
    - powershell
    - reg
    - netsh

network:
  allow:
    - github.com
    - crates.io
    - registry.npmjs.org

mcp:
  allow:
    - github
    - filesystem
```

## Decision Values

- `allow` — Explicitly allow
- `deny` — Explicitly deny
- `ask` — Require approval

## Ask List

Each policy section (shell, network, mcp) supports an `ask` list. Commands/tools/hosts
matching an `ask` entry require human approval before execution.

```yaml
shell:
  allow:
    - git
  ask:
    - npm        # npm install requires approval
    - docker     # docker build requires approval
  deny:
    - powershell
```

## Shell Rule Matching

`allow` and `ask` match the command's **executable** (exact executable, or the
executable followed by a space or tab).

`deny` matches a **substring of the whole command line**, including arguments,
and is evaluated **before** `allow` and `ask`. This is deliberately the most
conservative check: a deny that fails to match falls through to the allow list,
so an over-broad deny is merely inconvenient while a missed deny is a bypass.

Matching is **case-insensitive**. Executables on Windows are case-insensitive, so
a case-sensitive deny would let an entry such as `deny: [powershell]` be evaded
by invoking `PowerShell`. Case-folding therefore only ever *strengthens* the deny
list. Consequence: a deny entry can also be tripped by an argument value (for
example `deny: [reg]` blocks `git log --grep=region`). Prefer deny entries that
name executables.

## Defaults

If no rule matches, the default decision is used.

## Path Matching

Supports glob-like patterns:
- `**` — Matches any depth of directories
- `*` — Matches within a path segment

Examples:
- `./project/**` — All files under `./project/`
- `~/.ssh/**` — All files under `~/.ssh/`
- `**/.env` — All `.env` files
- `**/*.pem` — All `.pem` files

## Shell Matching

Shell commands are matched by executable name:
- `git` — Matches `git status`, `git push`, etc.
- `cargo` — Matches `cargo build`, `cargo test`, etc.

## Network Matching

Network requests are matched by host:
- `github.com` — Matches `https://github.com/...`
- `crates.io` — Matches `https://crates.io/...`

## MCP Matching

MCP tools are matched by tool name:
- `github` — Matches `github.create_issue`, etc.
- `filesystem` — Matches `filesystem.read`, etc.

## Policy Plugins

`agentfence.yaml` may contain an optional `plugins:` section. It is **not**
required: a policy file without it parses and behaves exactly as before.

```yaml
plugins:
  wasm:
    - id: block-dangerous-targets
      enabled: true
      module: ./plugins/deny-all.component.wasm
      expected_fingerprint: "<64 hex characters>"
      max_memory_mb: 64
  native:
    - id: my-host-rule
      enabled: true
      timeout_ms: 1000
      max_memory_mb: 64
```

### WebAssembly entries (`wasm`)

| Field | Required | Meaning |
|---|---|---|
| `id` | yes | Unique, non-empty identifier. Reported as the deciding rule id. |
| `enabled` | no (default `true`) | When `false`, the plugin is never registered and cannot execute. |
| `module` | yes | Path to the compiled `.wasm` component. |
| `expected_fingerprint` | no | SHA-256 of the module bytes, 64 hex characters. Empty = no verification. |
| `max_memory_mb` | no (default `64`) | Per-plugin sandbox memory limit, in megabytes. |

### Native entries (`native`)

A `native:` entry may only **reference** a plugin that the embedding
application registered programmatically. The policy file can never introduce
native code: an id the host did not register is a validation error, and native
plugins are never loaded from a path in the policy file. No production entry
point registers native plugins today, so a `native:` entry fails closed.

### Validation

Loading fails with a clear error (and the process refuses to start enforcement)
on:

- an empty `id`;
- an empty `module` path;
- a malformed `expected_fingerprint` (not 64 hex characters);
- a duplicate id, within `wasm`, within `native`, or across both;
- `max_memory_mb: 0`;
- a missing or unreadable module file;
- an `expected_fingerprint` that does not match the module bytes;
- a `native:` id the host did not register.

**Rationale:** starting enforcement with a partially loaded plugin set would
silently drop the restrictions an administrator configured, so a load failure
is fatal rather than skipped.

### Effect on decisions

A plugin can only **tighten** a decision. A plugin `Deny` or `Ask` overrides a
core `Allow`; a plugin `Allow` is abstained by the sandbox and can never turn a
core `Deny` into an `Allow`. Plugin failures (traps, fuel exhaustion, malformed
results) abstain and never grant permission.

### Commands that load plugins

`agentfence exec`, `agentfence run`, `agentfence mcp`, `agentfence mcp-http`,
`agentfence network`, and the Hermes wrapper all build their PDP through
`plugin_loader::build_pdp`, so a configured plugin is in force on every one of
them. `agentfence policy test` loads plugins too, because it prints decisions:
a plugin module must therefore be present for that command to succeed. Any
command that loads a policy with plugins requires the referenced module files
to exist on disk.

`Pdp::new` consults no plugin. It remains available for callers with no
configuration (tests, embeddings) and never weakens the core policy, but any new
enforcement entry point must use `build_pdp`.

## Policy Evaluation Order

1. Check deny rules first
2. Check ask rules (require approval)
3. Check allow rules
4. Use default decision

## Advanced Conditions (time / location)

Shell, network and MCP sections accept an optional `conditions` block that
**restricts** when an `allow` rule applies.

```yaml
network:
  allow:
    - github.com
  conditions:
    time:
      start: "09:00"        # HH:MM, UTC
      end: "17:00"          # HH:MM, UTC (start > end wraps across midnight)
      days: [1, 2, 3, 4, 5] # 0=Sunday .. 6=Saturday; empty = every day
    location:
      allowed_ips:
        - "192.168.1.0/24"  # exact IPv4 or CIDR block
      allowed_hosts:
        - "github.com"      # case-insensitive exact host match
```

**Fail-closed semantics.** Conditions can only narrow permissions, never widen
them:

- If an `allow` rule matches but its conditions are **not** satisfied, the
  decision is an explicit **DENY** (`rule_id: <section>.conditions`). It does
  **not** fall through to the default decision — a permissive default would
  silently widen the allow rule.
- A malformed `HH:MM` value is treated as *not satisfied*.
- `location` reads `client_ip` and `host` from the action's **typed** context
  fields (`context.client_ip`, `context.host`). These are populated by the
  gateway that owns the action, from a verified source. `context.env_metadata`
  is **not** a location source: it is a public, untyped JSON value, so treating
  it as one would let any caller satisfy a location condition by asserting its
  own location. If the typed fields are absent the condition cannot be
  evaluated and is treated as *not satisfied*.
- Time comparisons use **UTC**; per-condition timezones are not yet supported.

## Policy Versioning

Policies have a version number. The version is included in audit events.

## Policy Hash

Policies have a hash computed from their content. The hash is included in audit events.

## Approval Lifecycle

An `Ask` decision is a request for a human decision, not a permission. The
enforcement point records a pending request and **prevents the side effect**;
nothing is executed or forwarded until a human decides.

```text
policy returns Ask
      |
      v
pending request recorded  (action id, session, agent, action digest,
      |                   reason, scope, expiry, status)
      v
side effect prevented
      |
      v
human decision  -->  Approved -> consumed once -> execute
                -->  Rejected / Expired / timeout -> blocked
```

### Request fields

| Field | Meaning |
|---|---|
| `approval_id` | the operator-facing identifier printed by the gateway |
| `action_id` | the evaluated action, shared with the audit trail |
| `session_id`, `agent_id` | who asked |
| `action_digest` | SHA-256 binding over the action (see below) |
| `tool`, `target` | what is being authorised, for the operator |
| `reason` | the policy reason for escalating |
| `scope` | fixed when the request is created |
| `expires_at` | default 30 minutes (`AGENTFENCE_APPROVAL_TTL_MINUTES`) |
| `status` | `Pending` / `Approved` / `Rejected` / `Expired` / `Consumed` |

### Binding

`action_digest` covers the action type, tool, target, argument hash, session id,
agent id, and the authorization-relevant context: `cwd`, `repository`,
`branch`, `task_id`, `client_ip`, `host`. Consuming an approval re-derives the
digest, so an approval cannot authorise a different command, tool call, target,
session, agent, directory or location.

`env_metadata` is excluded — untrusted, and consulted by neither the PDP nor
plugins.

### Replay prevention

Consumption is a single atomic `Approved` -> `Consumed` transition inside a
SQLite `BEGIN IMMEDIATE` transaction, so concurrent consumers — including
separate processes — cannot both spend the same approval. Expired requests
cannot be decided or consumed, and a pending request can only be decided once.

### Operator commands

```bash
agentfence approve list [--all]
agentfence approve show <approval_id>
agentfence approve <approval_id> --decision allow|deny
```

The command refuses any `approval_id` that is not in the store. It cannot widen
the scope of a request: the scope is fixed when the request is created.

### Trust assumption

`agentfence approve` is **not authenticated** — the trust boundary is the
operator's terminal. The agent can request approval but can never grant it.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AGENTFENCE_APPROVAL_DB` | `<data dir>/approvals.db` | shared approval store |
| `AGENTFENCE_APPROVAL_TIMEOUT_MS` | `300000` | how long a gateway waits for a human |
| `AGENTFENCE_APPROVAL_TTL_MINUTES` | `30` | how long a request stays valid |
