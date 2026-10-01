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

## Phase 6 — Approval 🚧

- [x] Approval records
- [x] Scopes
- [x] Expiry
- [ ] CLI approval UI
- [ ] Interactive terminal prompt

## Phase 7 — Network 🚧

- [x] Network proxy structure
- [ ] Controlled HTTP proxy
- [ ] Host allowlist enforcement
- [ ] Audit integration

## Phase 8 — Secret Guard ✅

- [x] Deterministic detectors
- [x] Masking
- [x] Gateway integration
- [x] Tests

## Phase 9 — Hermes 📋

- [ ] Working Hermes wrapper
- [ ] Example configuration
- [ ] Documentation
- [ ] Integration tests

## Phase 10 — Hardening 📋

- [ ] Adversarial tests
- [ ] Security review
- [ ] Failure-path review
- [ ] Documentation review
- [ ] Performance checks

## Future Work

- SQLite persistence
- HTTP/SSE MCP transport
- Container enforcement
- WSL enforcement
- VM enforcement
- OS-specific enforcement
- LLM-based anomaly detection (advisory only)
- Web UI
- OpenTelemetry export
- SIEM integration
