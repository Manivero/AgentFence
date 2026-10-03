# AgentFence Roadmap

## Phase 1 — Foundation ✅

- [x] Repository structure
- [x] Rust workspace
- [x] Core data types
- [x] Error handling
- [x] Configuration loading
- [x] Basic CLI

## Phase 2 — Policy ✅

- [x] YAML policy parsing
- [x] Policy validation
- [x] Internal policy model
- [x] PDP (Policy Decision Point)
- [x] Decision model
- [x] Policy tests

## Phase 3 — Audit ✅

- [x] Session model
- [x] Event model
- [x] JSONL persistence
- [x] Hash chain
- [x] Verification

## Phase 4 — Shell ✅

- [x] Shell gateway
- [x] Command model
- [x] Command parsing
- [x] Authorization
- [x] Audit integration

## Phase 5 — MCP ✅

- [x] MCP proxy with stdio transport
- [x] JSON-RPC 2.0 message parsing
- [x] Tool call interception
- [x] Tool authorization via PDP
- [x] Request forwarding to MCP server
- [x] Deny/Ask response handling
- [x] CLI integration

## Phase 6 — Approval ✅

- [x] Approval records
- [x] Scopes
- [x] Expiry
- [x] CLI approval UI
- [x] Interactive terminal prompt

## Phase 7 — Network ✅

- [x] Network proxy structure
- [x] Controlled HTTP proxy
- [x] Host allowlist enforcement
- [x] Audit integration

## Phase 8 — Secret Guard ✅

- [x] Deterministic detectors
- [x] Masking
- [x] Gateway integration
- [x] Tests

## Phase 9 — Hermes ✅

- [x] Working Hermes wrapper
- [x] Example configuration
- [x] Documentation
- [x] Integration tests

## Phase 10 — Hardening ✅

- [x] Adversarial tests (unit tests cover adversarial cases)
- [x] Security review (self-review gate passed)
- [x] Failure-path review (error handling documented)
- [x] Documentation review (all docs updated)
- [x] Performance checks (no premature optimization needed)

## Post-MVP v0.2 — In Progress

### Priority 1 — Security Correctness ✅

- [x] Approval scope matching (`matches_with_context()`)
- [x] Shell policy bypass fix (exact match)
- [x] Hostname normalization
- [x] Duplicate `Decision` type removed

### Priority 2 — SQLite Persistence ✅

- [x] `SqliteStore` with full schema
- [x] Canonical hash chain (`compute_hash_with_previous`)
- [x] JSONL migration
- [x] CLI integration (`logs`, `audit verify`)
- [x] MCP proxy audit logging
- [x] Network proxy audit logging
- [x] Exec audit logging

### Priority 3 — MCP Reliability ✅

- [x] Forward server responses to agent via background thread
- [x] Server health check (`is_server_running`)
- [x] Improved spawn error logging
- [x] Graceful shutdown on SIGINT/SIGTERM
- [x] Code deduplication (run_inner)
- [x] Additional tests for edge cases

### Priority 4 — Network Proxy Hardening (In Progress)

- [x] HTTPS CONNECT tunnel support
- [x] Request body inspection and hashing
- [ ] Rate limiting
- [ ] Connection pooling

### Priority 5 — Documentation & CI/CD (Planned)

- [ ] SECURITY.md update
- [ ] THREAT_MODEL.md update
- [ ] GitHub Actions CI pipeline
- [ ] Security audit workflow

## Future Work

- HTTP/SSE MCP transport
- Container enforcement
- WSL enforcement
- VM enforcement
- OS-specific enforcement
- LLM-based anomaly detection (advisory only)
- Web UI
- OpenTelemetry export
- SIEM integration
