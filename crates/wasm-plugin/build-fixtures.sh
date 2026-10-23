#!/usr/bin/env bash
#
# Rebuilds the WebAssembly component fixtures used by the AgentFence policy
# plugin sandbox tests.
#
# The fixtures are committed so that `cargo test --workspace` works without a
# wasm toolchain. Run this script to regenerate them after changing the WIT
# interface or a guest implementation.
#
# Requirements:
#   - cargo + the wasm32-unknown-unknown target  (rustup target add wasm32-unknown-unknown)
#   - wasm-tools  (cargo install wasm-tools)
#
# Usage:  bash crates/wasm-plugin/build-fixtures.sh

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FIXTURES="$ROOT/tests/fixtures"
mkdir -p "$FIXTURES"

command -v wasm-tools >/dev/null 2>&1 || {
    echo "error: wasm-tools not found on PATH" >&2
    exit 1
}

build_component() {
    local crate_dir="$1"
    local crate_name="$2"
    local output="$3"

    echo "==> building guest: $crate_dir"
    (
        cd "$ROOT/$crate_dir"
        cargo build --release --target wasm32-unknown-unknown
    )

    echo "==> wrapping component: $output"
    wasm-tools component new \
        "$ROOT/$crate_dir/target/wasm32-unknown-unknown/release/$crate_name.wasm" \
        -o "$FIXTURES/$output"

    wasm-tools component wit "$FIXTURES/$output" >/dev/null
}

build_component "guest" "agentfence_test_guest" "test-plugin.component.wasm"
build_component "guest-hostcaps" "agentfence_hostcaps_guest" "hostcaps-plugin.component.wasm"

# The raw core module is intentionally kept as a negative fixture: it is a valid
# WebAssembly module but NOT a component, so it must be rejected by the host.
echo "==> copying raw core module fixture"
cp "$ROOT/guest/target/wasm32-unknown-unknown/release/agentfence_test_guest.wasm" \
    "$FIXTURES/test-plugin.core.wasm"

echo
echo "Fixtures written to $FIXTURES:"
ls -la "$FIXTURES"
