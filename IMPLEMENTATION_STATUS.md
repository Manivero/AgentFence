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
- Plugin timeout limits wait time but does not terminate a stuck worker thread (no real memory isolation)
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
| Do all tests pass? | ✅ Yes — 326 tests passing |
