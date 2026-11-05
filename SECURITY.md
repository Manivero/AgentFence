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

## Plugin Security

- **Native plugins** are a separate, trusted mechanism: timeout enforcement and
  worker-thread isolation (cooperative mode — no memory/CPU isolation)
- **WebAssembly plugins** execute as real WebAssembly **components** inside a
  Wasmtime sandbox:
  - Real component-model isolation (not a cooperative timeout wrapper)
  - Fuel-based interruption (a non-terminating guest is stopped within budget)
  - Real memory and table limits (`Store::limiter` + `StoreLimits` on the store)
  - **Empty linker** — no WASI, no host imports, so no filesystem, network,
    environment or process capability can be reached
  - Module fingerprint verification (SHA-256) over the exact bytes executed
  - Module size limit (10 MB) and bounded action size
- Plugin results are sanitized: decision 3 (Allow) → abstain; Deny/Ask preserved
- Plugin results are applied at the PDP: `Pdp::with_plugin_registry` consults the
  registry and can **tighten** a decision (plugin `Deny`/`Ask` overrides a core
  `Allow`) but can never loosen it. `Pdp::new` does not consult plugins, so no
  existing call site changes behaviour.
- Traps, malformed results and fuel exhaustion are explicit execution failures —
  never an Allow
- Plugin failures are logged and ignored (fail-safe)
- **Configuration surface:** `agentfence.yaml` has an optional `plugins:` section.
  Every enforcement entry point (CLI `exec`, `run`, `mcp`, `network`, and the
  Hermes wrapper) builds its PDP through
  `agentfence_policy::plugin_loader::build_pdp`, so configured plugins are
  consulted on every gateway rather than in one of them. See
  `examples/plugins.yaml` and `POLICY.md` "Policy Plugins".
- **Load failures are fatal, not silent:** a configured, enabled plugin that is
  missing, unreadable, or whose fingerprint does not match fails the whole load
  and the process refuses to start enforcement. Starting with a partially loaded
  plugin set would silently drop the restrictions an administrator configured,
  so this fails closed with the plugin id in the error message.
- **Native plugins follow a distinct trust model:** the `native:` section may
  only *reference* a plugin that the embedding application registered
  programmatically before the policy was loaded. `agentfence.yaml` can never
  introduce native code, and an id the host did not register is a validation
  error. No production entry point registers native plugins today, so a
  `native:` entry fails closed rather than being ignored.
- **Disabled plugins do not execute:** an entry with `enabled: false` is never
  registered, so it cannot influence a decision at all.
- **Per-plugin resource limits:** `max_memory_mb` on a WebAssembly entry is
  enforced by the sandbox (`Store::limiter`) over the exact bytes compiled.
  Fuel, module size (10 MB) and action size are sandbox-global and are not
  per-plugin configurable yet.
- **Bounded worker concurrency:** native plugin worker threads are capped at
  `MAX_PLUGIN_WORKERS` (16). A plugin that never returns cannot grow the thread
  count without bound; once the cap is reached, further plugins are skipped
  (fail-closed). This bounds resource growth but does **not** terminate a stuck
  thread — reliable termination is not guaranteed by the current architecture.
- Plugin API is versioned and stable
- Fixtures are committed and regenerable via `crates/wasm-plugin/build-fixtures.sh`

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

## Context Provenance

Authorization context is only as trustworthy as its source. Each gateway fills
`Context` from the most trusted source available to it:

| Gateway | `host` source | `client_ip` source |
|---------|---------------|--------------------|
| MCP | `McpToolCall.server` (server identity from the tool call) | not available |
| Network | parsed request target host | not available |
| Shell | `TrustedShellContext.host` (verified by the trusted integration layer) | `TrustedShellContext.client_ip` |

### Shell: structural enforcement

`ShellCommand` is **untrusted input** — it is parsed from a raw command string an
agent controls. It cannot carry location metadata:

- the `env_metadata` field has been **removed**; there is no public field or
  setter for one (enforced by the `compile_fail` doc-tests on `ShellCommand`);
- verified location data lives in a separate `TrustedShellContext` with
  **private fields** and **no public `Default`**;
- the only constructor requires a `TrustedContextToken`, whose own constructor
  is private to `agentfence-shell`. Tokens are minted by
  `ShellGateway::issue_trusted_context_token()`.

Consequences:

- **Untrusted input cannot assert its own `host`/`client_ip`.** It cannot build
  a `TrustedShellContext`, so it cannot reach `evaluate_with_context` with one.
- **The untrusted path (`evaluate`) supplies no location data**, so any location
  condition that requires a value fails closed (DENY).
- **`cmd.raw` is never parsed for a location.** A command that names a host does
  not authorise itself.

Rules:

- **Missing values stay `None`.** No fabricated defaults; the condition fails
  closed.
- **The token is a capability marker, not a cryptographic proof, and it is not a
  sandbox for in-process code.** `issue_trusted_context_token` is `pub`, and
  `ShellGateway::new` / `Pdp::new` are public, so any code running in the process
  can construct a gateway and mint tokens. The boundary that actually holds is
  that no untrusted component is *given* a gateway: `PluginContext` exposes no
  gateway or PDP, and the MCP/Network proxies hold a `Pdp` directly. Within one
  process the type system cannot distinguish trusted from untrusted *code* —
  only trusted from untrusted *data* — and that is exactly what this boundary
  enforces. Cooperative-mode code can bypass AgentFence entirely (see
  Cooperative Mode).

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

Approval is a separate trust boundary from policy. Policy decides whether a
human is *needed*; a human decides whether the action proceeds.

### Lifecycle

```text
Pending -> Approved -> Consumed     (one execution)
Pending -> Rejected
Pending -> Approved -> Expired      (never executed)
```

A request is created by the enforcement point when the PDP returns `Ask`. The
side effect is prevented while it is outstanding.

### Binding

Every request stores a SHA-256 digest of the action being authorised — action
type, tool, target, argument hash, session id and agent id. Consuming the
approval re-derives that digest, so an approval cannot authorise a different
command, tool call, target, session or agent.

### Replay and atomicity

- Consumption is a single atomic transition (`Approved` -> `Consumed`) inside a
  SQLite `BEGIN IMMEDIATE` transaction. Concurrent consumers, including separate
  processes, cannot both spend the same approval.
- Expired requests cannot be decided or consumed.
- A pending request can only be decided once.

### CLI

```bash
agentfence approve list              # pending requests
agentfence approve list --all        # decided, expired and consumed too
agentfence approve show <approval_id>
agentfence approve <approval_id> --decision allow
agentfence approve <approval_id> --decision deny
agentfence approve <approval_id>     # interactive
```

The command keys on the `approval_id` printed by the enforcement path. It refuses
any id that is not in the store. It can accept or refuse a request, but it cannot
widen the scope: the scope is fixed when the request is created.

### Trust assumption

`agentfence approve` is **not authenticated**. The trust boundary is the
operator's terminal — anyone able to run it in that environment can decide any
pending request.

### Configuration

| Variable | Default | Meaning |
|---|---|---|
| `AGENTFENCE_APPROVAL_DB` | `<data dir>/approvals.db` | shared approval store |
| `AGENTFENCE_APPROVAL_TIMEOUT_MS` | `300000` | how long a gateway waits for a human |
| `AGENTFENCE_APPROVAL_TTL_MINUTES` | `30` | how long a request stays valid |

The broker and the CLI must agree on `AGENTFENCE_APPROVAL_DB`, otherwise a
decision would never be seen.

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
- Shell command parsing is POSIX-compliant (shell-words); complex shell features (process substitution, command substitution) are not fully parsed
- Network proxy supports HTTP and HTTPS CONNECT tunneling only
- MCP proxy supports stdio and HTTP transports; SSE is disabled (501); authentication not implemented
- Approval UI is terminal-only
- Rate limiting is shared across connections (token bucket via Arc<Mutex<>>); connection pooling with configurable max_size and idle timeout
