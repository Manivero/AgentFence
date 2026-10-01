# AgentFence Development Guide

## Prerequisites

- Rust 1.70+
- Cargo

## Building

```bash
cargo build
```

## Testing

```bash
cargo test
```

## Running

```bash
# Initialize configuration
cargo run -- init

# Check policy
cargo run -- policy check agentfence.yaml

# Test policy
cargo run -- policy test agentfence.yaml

# Execute a command
cargo run -- exec --policy agentfence.yaml -- git status

# Run an agent
cargo run -- run --policy agentfence.yaml -- hermes
```

## Project Structure

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

## Adding a New Crate

1. Create the crate directory: `crates/<name>/`
2. Add `Cargo.toml` with dependencies
3. Add `src/lib.rs`
4. Add the crate to the workspace `Cargo.toml`
5. Add tests

## Adding Tests

Every significant feature requires tests covering:
- Normal behavior
- Negative behavior
- Boundary behavior
- Adversarial behavior

## Code Style

- Use `cargo fmt` to format code
- Use `cargo clippy` to check for issues
- Follow Rust naming conventions

## Security Review

Before committing:
- Can an agent bypass the gateway?
- Can an agent approve itself?
- Are secrets leaking into logs?
- Are policy decisions deterministic?
- Are approvals scoped and expiring correctly?
