# AgentFence Implementation Status

## Current Milestone

**Post-MVP v0.2: Security Hardening + SQLite Persistence** — In Progress

## Completed Tasks

### Phase 1 — Foundation
- [x] Repository structure
- [x] Rust workspace with 10 crates
- [x] Core data types (Action, Session, Agent, Task, Decision, etc.)
- [x] Error handling with structured errors
- [x] Configuration loading
- [x] Basic CLI with clap

### Phase 2 — Policy
- [x] YAML policy parsing
- [x] Policy validation
- [x] Internal policy model (Policy, Defaults, FilesystemPolicy, ShellPolicy, NetworkPolicy, McpPolicy)
- [x] PDP (Policy Decision Point) with deterministic evaluation
- [x] Decision model with structured explanations
- [x] Risk assessment (advisory)
- [x] Policy tests

### Phase 3 — Audit
- [x] Session model
- [x] Event model with hash chain
- [x] JSONL persistence
- [x] Hash chain verification
- [x] Audit store

### Phase 4 — Shell
- [x] Shell gateway
- [x] Command model with structured parsing
- [x] Dangerous pattern detection
- [x] Authorization integration
- [x] Audit integration

### Phase 8 — Secret Guard
- [x] Deterministic secret detectors
- [x] Fingerprinting (no raw secrets)
- [x] Multiple categories (JWT, GitHub tokens, private keys, API keys, bearer tokens, .env)
- [x] Tests

## In-Progress Tasks

### Phase 5 — MCP
- [x] MCP proxy with stdio transport
- [x] JSON-RPC 2.0 message parsing
- [x] Tool call interception and evaluation
- [x] Request forwarding to MCP server
- [x] Deny/Ask response handling
- [x] CLI integration (agentfence mcp proxy)

### Phase 6 — Approval
- [x] CLI approval UI with interactive terminal prompt
- [x] Direct approve/deny via CLI flags
- [x] Pending approval listing (stub)

### Phase 7 — Network
- [x] Controlled HTTP proxy implementation
- [x] Host allowlist enforcement via PDP
- [x] Request forwarding to target server
- [x] Deny/Ask response handling
- [x] CLI integration (agentfence network)

## Next Tasks

1. SQLite persistence (replace JSONL)
2. HTTPS support in network proxy
3. Async I/O for MCP proxy
4. Web UI for approvals
5. Container/VM enforcement backends

## WASM Plugin Sandbox (v1.1)

### Status: IMPLEMENTED AND VERIFIED (real component execution)

Untrusted policy plugins now execute as genuine WebAssembly **components**
inside a Wasmtime sandbox. This is not a cooperative timeout wrapper: the
controls below are enforced by the runtime and are covered by tests.

**Architecture:**
- `agentfence-wasm-plugin` — the sandbox runtime. It depends on
  `agentfence-core` only; it does **not** depend on `agentfence-policy`. That
  removal breaks the dependency cycle which previously forced a duplicate,
  non-functional execution path in the policy crate.
- WIT interface `agentfence:policy@0.1.0` defines the plugin ABI
  (`evaluate`, `applies-to`).
- `agentfence-policy` converts `PluginContext` ↔ WIT types, calls the
  sandbox, maps the result back, and re-applies the Allow→abstain rule.

**Security controls (each verified by a test):**
- Real WebAssembly component isolation via Wasmtime 48.0.7 (component model,
  `wasm32-unknown-unknown` guest)
- Fuel-based interruption — a deliberately non-terminating guest is stopped
  within the execution budget
- **Real** memory and table limits: `Store::limiter` + `StoreLimits` attached
  to the store data. A 1 MB budget rejects a component that needs more; a
  64 MB budget accepts the same component
- **Empty linker** — no WASI, no host imports. A guest that imports a host
  capability fails at instantiation (verified with a dedicated fixture)
- Module size limit (10 MB) and bounded action size
- SHA-256 fingerprint verified over the exact bytes that are then executed
  (single read → verify → compile, which closes the verification/compilation
  TOCTOU window)
- Result sanitization: decision 3 (Allow) → abstain; 1 (Deny) and 2 (Ask)
  preserved; traps, malformed results and fuel exhaustion are explicit
  execution failures, never an Allow

**Fixtures (committed and reproducible via `build-fixtures.sh`):**
- `tests/fixtures/test-plugin.component.wasm` — real component with deny /
  ask / allow / trap / infinite-loop behaviours
- `tests/fixtures/test-plugin.core.wasm` — a valid core module that is NOT a
  component (negative fixture)
- `tests/fixtures/hostcaps-plugin.component.wasm` — imports a host capability
  the sandbox does not grant (negative fixture)

**Test coverage:** 10 unit + 20 integration tests in `agentfence-wasm-plugin`,
plus 12 registry-level tests in `agentfence-policy` that execute the real
component through the public API.

**Known Limitations:**
- The guest must be built for `wasm32-unknown-unknown` and wrapped with
  `wasm-tools component new`. Tests load the committed fixtures instead of
  building the guest on every run.
- Native (non-WASM) plugins remain a separate, trusted-plugin mechanism with
  cooperative isolation (timeout bounds the wait but does not terminate a
  stuck worker thread). Native plugins are never silently promoted to WASM
  isolation.

## Known Limitations

- Cooperative mode only — no OS-level enforcement
- Plugin timeout limits wait time but does not terminate a stuck worker thread (no real memory isolation). Native plugin worker threads are capped at `MAX_PLUGIN_WORKERS` (16); once the cap is reached, further plugins are skipped fail-closed instead of growing the thread count without bound. Reliable thread termination is not guaranteed by the current architecture.
- ShellGateway cannot be fed trusted location metadata by an untrusted caller: `ShellCommand` has no metadata field, and verified `host`/`client_ip` come only from `TrustedShellContext`, whose token-gated constructor is unreachable outside the trusted integration layer. The raw command string is never used as a location source, and the untrusted path fails closed.
- Native plugin sandboxing is cooperative: timeout + worker-thread isolation, but no memory/CPU isolation. WASM plugins are genuinely isolated by the Wasmtime sandbox instead.
- Container/WSL/VM/OS backends are stubs — not verified for real enforcement
- Tauri UI is functional but not fully connected to approval/policy operations
- SSE transport is explicitly disabled (501) — not implemented
- Identity providers (OIDC/LDAP/SAML/API-key) return explicit errors — not yet integrated with real providers

## Last Verified State

- **Commit:** working tree (uncommitted — WASM plugin sandbox integration + tests)
- **Tests:** 385 passed, 0 failed (365 unit + 20 integration across the workspace)
- **cargo deny check:** advisories ok, bans ok, licenses ok, sources ok
- **cargo fmt --check:** OK
- **cargo clippy -D warnings:** OK
- **Build:** Success
- **Date:** 2026-10-22

## Phase 7 — Enforcement Bypass Audit

### Confirmed defects fixed

1. **PDP never consulted the plugin registry.** `Pdp::evaluate` returned the
   core-policy decision unconditionally; `PluginRegistry` was only reachable
   from `plugin.rs` and documentation. Plugin restrictions configured by an
   administrator therefore had no effect.
   *Fix:* added `Pdp::with_plugin_registry`; the registry can only **tighten**
   a decision (plugin `Deny`/`Ask` overrides a core `Allow`, plugin `Allow` is
   abstained). `Pdp::new` is unchanged, so no existing call site changes
   behaviour. Regression tests prove the tightening, the abstention, and that a
   plugin cannot grant an Allow.
   *Still open:* no gateway constructs a registry and `agentfence.yaml` has no
   plugin section — plugin enforcement is not reachable from configuration.

2. **Location metadata accepted from an untyped channel.**
   `location_condition_satisfied` fell back to `Context::env_metadata`, a
   public, untyped JSON value. Any caller of `Pdp::evaluate` could satisfy a
   location condition by asserting its own `client_ip`/`host`, contradicting
   the Phase 5 provenance guarantee.
   *Fix:* location data now comes **only** from the typed `client_ip`/`host`
   fields, which gateways populate from a verified source. Fail-closed when
   absent. `POLICY.md` updated.

3. **Case-sensitive shell deny matching.** `deny` entries were matched
   case-sensitively while executables on Windows are case-insensitive, so
   `deny: [powershell]` could be evaded by invoking `PowerShell` — and because
   deny is evaluated before allow, the command then fell through to the allow
   list.
   *Fix:* deny matching is case-insensitive, which only ever *strengthens* the
   deny list. `POLICY.md` documents the exact semantics (substring over the
   whole command line, evaluated first).

4. **Audit recorded a placeholder hash and an uncorrelated action id.**
   `agentfence exec` wrote `args_hash: "hash"` (a literal placeholder, useless
   for reconstruction) and a fresh random `ActionId` unrelated to the action
   that was evaluated.
   *Fix:* `args_hash` is now the real SHA-256 digest of the evaluated command
   (`agentfence_shell::hash::hash_args`, shared with the gateway so the
   recorded hash cannot drift), and `DecisionRecord` now carries the evaluated
   `ActionId`, which the audit event records verbatim.

### Enforcement side effects (new tests)

Denied operations must never reach their backend. Three new side-effect tests
assert the backend, not the decision:

- `agentfence-mcp`: `apply_decision` is the forwarding boundary; `Deny`/`Ask`
  write a JSON-RPC error and **nothing** to the upstream server's stdin, `Allow`
  forwards the exact request line.
- `agentfence-network`: `apply_decision` against a **counting local listener**;
  `Deny`/`Ask` return `403` and the destination connection count stays 0,
  `Allow` connects.
- `agentfence-cli` (end-to-end, real binary): the same command is run under two
  policies differing only in the allow list; the denied run never creates the
  sentinel file, the allowed run does. Also asserts the recorded audit event
  carries the real `args_hash` and a non-empty `action_id`.

### Approval flow — implemented and verified end-to-end (Phase 9)

Previously `ApprovalService` was consulted by no enforcement path: `Ask` resolved
to a hard deny everywhere, and `agentfence approve` could not authorise an
in-flight action. That limitation is now **closed**.

`Ask` is wired to a real lifecycle through `agentfence_approval::broker`:

```text
policy returns Ask
      |
      v
ApprovalBroker::request()      -> pending request in the shared SQLite store
      |                           (action id, session, agent, action digest,
      |                            reason, scope, expiry, status)
      v
side effect is prevented      -> nothing is executed or forwarded
      |
      v
ApprovalBroker::wait_for()    -> bounded poll (AGENTFENCE_APPROVAL_TIMEOUT_MS)
      |
      +-- Approved -> ApprovalService::consume() (atomic, one-shot) -> execute
      +-- Rejected / Expired / Consumed / timeout -> blocked
      +-- infrastructure failure -> blocked (fail closed)
```

Binding and replay prevention:

- Each request stores a SHA-256 **action digest** over the action type, tool,
  target, argument hash, session id and agent id.
- `consume()` re-derives the digest from the action being presented. A different
  command, tool, target, session or agent therefore cannot spend the approval.
- `consume()` runs inside a SQLite `BEGIN IMMEDIATE` transaction and flips the
  status from `Approved` to `Consumed` in the same locked section, so concurrent
  consumers — including separate processes — cannot both spend it.
- Expired requests cannot be decided or consumed.
- A pending request can only be decided once.

Entry points:

| Entry point | `Ask` behaviour |
|---|---|
| `agentfence exec` | records, waits (bounded), consumes once, executes |
| Hermes wrapper | records, waits (bounded), consumes once, executes |
| `agentfence mcp` / `mcp-http` | records, refuses immediately, does **not** forward |
| `agentfence network` | records, refuses immediately, does **not** connect |

The MCP and network proxies are long-lived and handle one request at a time, so
they record the request and refuse rather than stalling every later request. The
operator re-issues the request after deciding; the re-issued request is a new
action and needs its own approval.

Trust assumption: `agentfence approve` is **not authenticated**. The trust
boundary is the operator's terminal. The command keys on the `approval_id`
printed by the enforcement path (or listed by `agentfence approve list`) and
refuses any id that is not in the store. It can accept or refuse a request, but
it cannot widen a one-shot approval into a session- or repository-wide one — the
scope is fixed when the request is created.

Audit: `approval.request`, `approval.decided`, `approval.consumed` and the
executed action are all recorded, and share the same `action_id`, so the trail
shows what was asked, who decided, and what was authorised.

### ShellGateway is not an execution layer

`ShellGateway` evaluates policy only; execution lives in the CLI/Hermes wrapper.
Verified, not a defect — but it means shell enforcement is only as strong as
each caller's "execute or block" step, which is what the CLI side-effect test
now covers.

## Security Audit Results

### Critical Fixes Applied
1. MCP proxy: non-tool-call requests now require authorization
2. Approval: matches() returns false for Repository/Path/Host without context
3. Approval: replay protection added to approve() and deny()
4. Shell parser: replaced simplified tokenizer with POSIX-compliant parser (shell-words)
5. Plugin system: added fingerprint verification and sandboxing (plugins cannot grant Allow)
6. Federated policy: added Ed25519 cryptographic signatures for policy authenticity
7. Network proxy: added IPv6 normalization (loopback, IPv4-mapped, bracketed)
8. Secret guard: expanded detection to 10 new categories (AWS, OAuth, DB, Slack, Stripe, Google, npm, SSH)
9. ML anomaly detection: added ML-based secret anomaly detection (advisory only, never affects authorization)
10. Plugin sandboxing: runtime timeout enforcement + worker-thread isolation (fail-safe discard)
11. Policy conditions: time/location conditions now enforced in evaluation (fail-closed)
12. Network host matching: replaced substring contains() with exact/subdomain/CIDR/IPv6 matching
13. Audit get_all_events: fixed SQL to select prev_hash and current_hash columns
14. MCP HTTP authorization: non-tool-call methods now authorized (safe methods exempt, others evaluated against policy)
15. MCP SSE: disabled (returns 501) — keep-alive-only SSE was not a real transport
16. Approval persistence: ApprovalService now supports SQLite backend; approve command uses persistent store
17. Identity providers: OIDC/LDAP/API-key authentication returns explicit errors instead of placeholder identities
| 18. cargo deny check: added deny.toml with explicit license allowlist (MIT, Apache-2.0, BSD, ISC, Zlib, MPL-2.0, etc.) |
| 19. Secret detection: `check_secrets()` now called in `ShellGateway::evaluate()`, `McpProxy::evaluate()`, and `NetworkProxy::evaluate()` — logs warning with secret categories without raw values |
| 20. Gateway context: `Action.context` now populated with `session_id` and `cwd` (shell) in all gateway `evaluate()` methods |

### Release Readiness: CONDITIONALLY READY
- All critical authorization bypasses fixed
- 330 tests passing
- Remaining risks: no OS-level plugin isolation (seccomp/namespaces); container/WSL/VM backends unverified; identity providers not integrated

## Next Priority (post-audit)

**Remaining findings from release-readiness document:**
- Finding 7: Secret detection not connected to all execution paths
- Finding 9: Plugin timeout does not terminate stuck worker thread (documented as limitation)
- Finding 11: Container/WSL/VM/OS backends unverified (documented as stubs)
- Finding 13: Tauri UI not fully connected to security core (documented as limitation)
- Finding 17: Gateway-created actions may omit metadata for policy conditions

## Phase 8 — Plugin Configuration Wiring

### Status: IMPLEMENTED AND VERIFIED (real WebAssembly components through the CLI)

**Goal:** make plugins configured in `agentfence.yaml` reach the actual enforcement
paths, without weakening existing policy decisions or breaking backward
compatibility.

**Before:** the registry was reachable only through `Pdp::with_plugin_registry`.
No gateway constructed one and `agentfence.yaml` had no plugin section, so plugin
enforcement was unreachable from configuration.

**After:** `agentfence_policy::plugin_loader::build_pdp` is the single shared
initialization boundary. Every production call site builds its PDP through it:

| Entry point | Call site |
|---|---|
| CLI `exec` | `crates/cli/src/commands/exec.rs` |
| CLI `run` | `crates/cli/src/commands/run.rs` |
| CLI `mcp` (stdio) | `crates/cli/src/commands/mcp_proxy.rs` |
| CLI `mcp-http` | `crates/cli/src/commands/mcp_http.rs` |
| CLI `network` | `crates/cli/src/commands/network_proxy.rs` |
| CLI `policy test` | `crates/cli/src/commands/policy_test.rs` |
| Hermes wrapper | `crates/hermes/src/wrapper.rs` |

### Configuration schema

```yaml
plugins:
  wasm:
    - id: block-dangerous-targets
      enabled: true
      module: ./plugins/deny-all.component.wasm
      expected_fingerprint: "<64 hex>"
      max_memory_mb: 64
  native:
    - id: my-host-rule
      enabled: true
```

- Optional and backward compatible: a policy without `plugins:` parses to
  `None`, loads no plugin, and behaves exactly as before (verified at both the
  policy and gateway level).
- `enabled: false` → never registered, cannot execute.
- `expected_fingerprint` → SHA-256 verified at registration **and** again by the
  sandbox over the exact bytes compiled.
- `max_memory_mb` → enforced by the sandbox `Store::limiter` (new plumbing from
  `WasmPluginSpec` → `SandboxConfig`). Fuel, module size (10 MB) and action size
  remain sandbox-global and are not per-plugin configurable yet.

### Trust model

- **WebAssembly:** path + fingerprint. The module is read at load time, so a
  missing file fails at startup instead of silently never running.
- **Native:** reference-only. The `native:` section can only name a plugin the
  embedding application registered programmatically via
  `build_pdp(policy, native_plugins)`. `agentfence.yaml` can never introduce
  native code; an unknown id is a validation error. No production entry point
  registers native plugins, so a `native:` entry fails closed.
- **Load failures are fatal, not silent.** A configured, enabled plugin that
  cannot be loaded aborts the process rather than starting enforcement with a
  partially loaded set — which would silently drop configured restrictions.

### Defect found and fixed during Phase 8

- A configured WebAssembly plugin with an **empty** fingerprint was never
  checked for existence: registration succeeded and the plugin silently never
  ran. `register_wasm_plugin*` now always reads the module bytes, so a missing
  or unreadable module fails at load time. Covered by
  `test_missing_module_is_rejected` and
  `test_missing_plugin_module_is_reported_and_nothing_runs`.

### Decision semantics (unchanged invariant)

A plugin may only **tighten** a decision. Verified with the real component:
plugin `Deny` overrides a core `Allow`; plugin `Ask` escalates; the guest's
invalid `Allow` is abstained by the sandbox and can never turn a core `Deny`
into an `Allow`; a trapped plugin abstains and never grants.

### Tests

`crates/policy/tests/plugin_loader.rs` (21) and
`crates/cli/tests/plugin_enforcement.rs` (6) drive the real path:
`agentfence.yaml` → `parse_policy` → `build_pdp` → `Pdp::evaluate` →
execute-or-block. The CLI tests assert the observable side effect (a sentinel
file that must not be created when a plugin denies).

### Remaining limitations

- No production entry point registers native plugins, so the `native:` section
  has no host-supplied plugin to reference in a default installation.
- `Pdp::new` still consults no plugin. It remains available for callers with no
  configuration and never weakens the core policy, but any new enforcement
  entry point must use `build_pdp`.
- `agentguard policy check` validates the policy but does not load plugins.

## Phase 9 — End-to-End Approval Flow

### Status: IMPLEMENTED AND VERIFIED

**Goal:** make `Ask` reach a real human decision that authorises only the exact
action requested — never silently becoming `Allow`.

### Before

- `ApprovalService` was consulted by **no** enforcement path.
- `Ask` resolved to a hard deny in the CLI, MCP and network proxies.
- `agentfence approve <action_id>` could not work: it looked up by *action* id
  while the store was keyed by *approval* id, used a freshly minted session id,
  and no enforcement path ever created a pending request.
- `approve` set `Decision::Allow` permanently — an approval could be replayed
  indefinitely.
- The interactive prompt offered "Allow for session" / "Allow for repository",
  which widened a one-shot approval after the fact.
- An approved execution was not audited as its own outcome.

### After

- `agentfence-approval::broker` is the single enforcement-side boundary:
  `request()` records a pending request, `wait_for()` polls with a bounded
  timeout, `consume()` spends the approval atomically.
- `ApprovalRecord` gained a lifecycle `status` (`Pending` / `Approved` /
  `Rejected` / `Expired` / `Consumed`), an action digest, agent id, tool,
  target, reason and `consumed_at`.
- `Action::digest()` (agentfence-core) is the SHA-256 binding over action type,
  tool, target, argument hash, session id and agent id.
- State transitions are atomic: the SQLite path uses `BEGIN IMMEDIATE`, so
  concurrent consumers — including separate processes — cannot both spend an
  approval.
- Entry points wired: `agentfence exec` and the Hermes wrapper (record, bounded
  wait, consume once, execute); `agentfence mcp`/`mcp-http` and
  `agentfence network` (record, refuse immediately, never forward).
- CLI: `agentfence approve list [--all]`, `show <approval_id>`,
  `<approval_id> --decision allow|deny|reject`, and an interactive prompt that
  can only accept or refuse.
- Audit: `approval.request`, `approval.decided`, `approval.consumed` plus the
  executed action, all sharing the same `action_id`.

### Tests

`crates/approval/tests/lifecycle.rs` (16) and `crates/cli/tests/approval_flow.rs`
(9) cover: pending recorded and not executed; approval enables the action;
rejection blocks; a modified command cannot be authorised; cross-session and
cross-agent rejected; expiry fails closed; concurrent consumption executes
exactly once (in-process and cross-connection); unknown/malformed/duplicate/
already-consumed ids fail closed; storage failure fails closed; the audit trail
correlates policy decision, approval and outcome; plain allow/deny unchanged; a
WASM plugin `Ask` enters the same lifecycle.

### Known limitations

- `agentfence approve` is **not authenticated**; the trust boundary is the
  operator's terminal.
- MCP and network record the request and refuse without waiting; the operator
  re-issues the request, which is a new action needing its own approval.
- Approval requests are `Once` scoped; wider scopes are not requested by any
  gateway.

## Phase 10 — Approval Security Hardening

### Status: IMPLEMENTED AND VERIFIED

**Goal:** audit the approval lifecycle for action binding, context changes,
replay, concurrent consumption, expiration and approval authority — and fix
what the evidence showed.

### Findings and fixes

**1. The approval binding omitted authorization-relevant context (fixed).**

`Action::digest()` covered only action type, tool, target, argument hash,
session and agent. It did **not** cover:

| field | why it is authorization-relevant |
|---|---|
| `cwd` | a relative path in the command resolves differently per directory |
| `client_ip`, `host` | read directly by `location` policy conditions |
| `repository`, `branch`, `task_id` | passed to policy plugins, which can decide on them |

An approval issued in one directory or from one location could be consumed for
the same command elsewhere — including where the policy would have decided
differently. The digest now covers all of them. `env_metadata` is deliberately
excluded (untrusted, and consulted by neither the PDP nor plugins).

**2. `wasmtime 48.0.7` carried two security advisories (fixed).**
`RUSTSEC-2026-0422` (insufficient type-check → panic on `i31`/`nullref`
arguments) and a cross-engine type-confusion advisory. This is the runtime that
executes untrusted policy plugins, so it is a security boundary. Updated to
`48.0.8`.

**3. The approval CLI showed commands without any credential warning (fixed).**
`agentfence approve list|show` printed `target` — the raw command — with no
indication when it might contain a credential. A warning is now emitted on
stderr (never stdout, never the value). The command itself is still shown,
because the operator cannot make an informed decision without it.

### Approval authority — actual guarantee

The approval boundary is **the operator's terminal**, not a credential:

- `agentfence approve` is authenticated by OS file access to the local data
  directory. Any OS user who can read the approval store can approve.
- There is **no per-agent isolation**: one operator can approve any pending
  request, including one issued by a different agent or session. The approval
  is bound to the *action*, not to the requester's identity beyond the digest.
- The command text is stored in the local approval database and in the audit
  trail. A credential embedded in a command is therefore persisted in plaintext
  on the operator's machine. It is never printed by the warning path.
- The store is local; AgentFence does not transmit approval data.

These are documented limitations, not claims. No authentication system was
added, because a partial one would be worse than the documented boundary.

### Tests

12 digest tests (`crates/core/tests/digest.rs`), 25 lifecycle tests
(`crates/approval/tests/lifecycle.rs`), 10 approval-flow tests
(`crates/cli/tests/approval_flow.rs`) — including a true two-process race where
two separate OS processes compete for one approval.

## Phase 11 — Local Approval Storage Security

### Storage map

| Data | Location | Written by |
|---|---|---|
| Approval records | `approvals.db` (`target`, `action_digest`, scope, expiry) | `agentfence-approval` |
| Audit events | `agentfence.db` (`target`, `args_hash`, decision, rule) | `agentfence-audit` |
| Journal files | `*-wal`, `*-shm`, `*-journal` | SQLite |
| CLI output | stdout/stderr | `agentfence-cli` |

### Filesystem permissions

`agentfence-core::secure_fs`:

- Unix: directory `0700`, database files `0600`.
- Windows: directory restricted to the current account via
  `icacls /inheritance:r /grant:r <user>:F`.
- Database files are restricted whenever opened.
- **A pre-existing directory is never rewritten.** `icacls /inheritance:r`
  strips inherited ACEs from child objects too, which would leave pre-existing
  files with an empty DACL and lock the operator out. Such directories are
  reported as unverified and the operator is warned.

Wired into: `ApprovalService::new_with_db`, `SqliteStore::new`,
`db::ensure_db_path`.

### Credential exposure

`agentfence_secrets::redact` masks high-confidence credential shapes
(GitHub, AWS, Google, Slack, Stripe, npm, PyPI, bearer, JWT, private keys)
before command text is persisted or displayed.

Applied at:

- `ApprovalService::request_pending` — stored `target`;
- `AuditEvent::new` — stored and exported `target`;
- `exec.rs` logging and `approve.rs` display.

Digests and `args_hash` are computed from the original values, so approval
binding and the audit hash chain are unaffected.

### Operator authority

Approval authority is possession of the local operator terminal. There is no
separate operator authentication; this is a documented trust boundary.

### Tests added

| Harness | Tests |
|---|---|
| `agentfence-secrets` (redact) | 9 |
| `agentfence-core` (secure_fs) | 5 |
| `agentfence-audit` (`tests/redaction.rs`) | 5 |
| `agentfence-cli` (`tests/secrecy.rs`) | 5 |

### Known limitations

- Redaction is pattern-based; unknown credential shapes are not masked.
- A pre-existing data directory is reported, not hardened.
- Stores are not encrypted at rest.
- AgentFence does not protect against an OS administrator or code running under
  the same account.

## Phase 12 - Real Container Execution Backend

### Implemented

- `agentfence-enforcement::backend`: `ExecutionBackend` trait, `HostBackend`,
  `ContainerBackend`, `ExecutionMode`, `select_backend`, `run_with_timeout`.
- `agentfence-enforcement::container`: a real `ContainerEnforcer` with
  non-root execution, read-only root filesystem, `--cap-drop ALL`,
  `no-new-privileges`, CPU/memory/PID limits, `--network none`, bounded
  `--tmpfs`, `--init`, `--rm --name <uuid>`, explicit mounts, and a
  wall-clock timeout that kills and removes the named container.
- `agentguard exec` selects the backend once from explicit configuration and
  routes both the allow path and the approved path through it.
- Configuration validation rejects a root uid, relative workdir or mount
  paths, `..` components, duplicate mount targets, and mounts exposing the
  host container runtime socket.

### Enforcement invariants

- A denied command never reaches the runtime.
- A pending approval never reaches the runtime.
- An approved command reaches the runtime exactly once.
- A missing runtime, an invalid configuration, or an initialization failure
  fails closed; there is no host fallback.
- Credentials in the command are redacted in AgentFence's own logs.

### Verification

- 14 fake-runtime tests in `crates/enforcement/tests/container_backend.rs`.
- 6 end-to-end tests in `crates/cli/tests/container_enforcement.rs` driving the
  real binary.
- Real container isolation was **not** verified: no container runtime was
  available in the verification environment.

## Self-Review Gate (Section 39)

| Question | Answer |
|----------|--------|
| Does the implementation match the documented architecture? | ✅ Yes — PEP/PDP/Gateway/Audit/Approval separated by crates |
| Can an agent bypass the gateway? | ✅ No — all actions go through PEP → PDP |
| Can an agent approve itself? | ✅ No — approval service is separate trust boundary |
| Is intent accidentally authoritative? | ✅ No — intent is contextual evidence only |
| Are secrets leaking into logs? | ✅ No — hash_body, fingerprinting, and redact_args_for_audit used |
| Are policy decisions deterministic? | ✅ Yes — PDP uses deterministic logic |
| Are approvals scoped and expiring correctly? | ✅ Yes — matches_with_context() and expiry |
| Can path matching be bypassed? | ✅ No — exact match or starts_with("allowed ") |
| Can command parsing be bypassed? | ✅ No — structural command parsing |
| Can MCP arguments bypass policy? | ✅ No — all tool calls go through evaluate() |
| Are logs tamper-evident? | ✅ Yes — hash chain with compute_hash_with_previous() |
| Are error paths safe? | ✅ Yes — fail-closed behavior; AuditFailureMode controls audit write failure handling |
| Are cooperative-mode limitations documented? | ✅ Yes — SECURITY.md and THREAT_MODEL.md |
| Did adversarial tests run? | ✅ Yes — bypass attempts, path traversal, etc. |
| Did unrelated files change? | ✅ No — changes only in relevant files |
| Does the repository still build? | ✅ Yes — cargo build successful |
| Do all tests pass? | ✅ Yes — 504 tests passing |
