//! Integration tests for the AgentFence WebAssembly plugin sandbox.
//!
//! These tests exercise REAL WebAssembly component execution through Wasmtime's
//! component-model API. They are not mocks: the fixtures in `fixtures/` are
//! genuine components built from `crates/wasm-plugin/guest/` and
//! `crates/wasm-plugin/guest-hostcaps/`.
//!
//! Fixtures:
//! - `test-plugin.component.wasm` — a valid component exporting
//!   `agentfence:policy/plugin@0.1.0`. Behaviour is selected by the action
//!   `target`: deny / ask / allow / trap / loop / abstain.
//! - `test-plugin.core.wasm` — the raw core module, NOT a component.
//! - `hostcaps-plugin.component.wasm` — a component that imports
//!   `agentfence:policy/host-caps` (filesystem/network/env/process).

use std::time::{Duration, Instant};

use agentfence_core::types::Decision;
use agentfence_wasm_plugin::{
    SandboxConfig, SandboxResult, WasmSandbox, WitAction, WitPluginResult,
};

const FIXTURE_DIR: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures");

fn fixture(name: &str) -> Vec<u8> {
    let path = format!("{}/{}", FIXTURE_DIR, name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("failed to read fixture {}: {}", path, e))
}

fn action(target: &str) -> WitAction {
    WitAction {
        id: "test-action".to_string(),
        action_type: "network".to_string(),
        tool: "curl".to_string(),
        target: target.to_string(),
        session_id: "test-session".to_string(),
        agent_id: "test-agent".to_string(),
        task_id: None,
        cwd: None,
        repository: None,
        branch: None,
    }
}

fn sandbox() -> WasmSandbox {
    WasmSandbox::new(SandboxConfig::default()).expect("sandbox creation must succeed")
}

fn decision_of(result: &SandboxResult) -> Option<Decision> {
    match result {
        SandboxResult::Success(r) => agentfence_wasm_plugin::wit_decision_to_decision(r.decision),
        SandboxResult::Failure(_) => None,
    }
}

// ── 1. A valid component can be loaded and invoked ───────────────────────────

#[test]
fn test_valid_component_loads_and_denies() {
    let sandbox = sandbox();
    let bytes = fixture("test-plugin.component.wasm");
    let result = sandbox.evaluate(&bytes, &action("https://deny.example.com/resource"));

    match result {
        SandboxResult::Success(r) => {
            assert_eq!(r.decision, 1, "expected Deny (1)");
            assert_eq!(r.rule_id, "test-plugin");
            assert!(!r.reason.is_empty());
        }
        SandboxResult::Failure(msg) => panic!("valid component must not fail: {}", msg),
    }
}

// ── 3. evaluate() handles Deny, Ask and Allow ────────────────────────────────

#[test]
fn test_evaluate_returns_ask() {
    let sandbox = sandbox();
    let bytes = fixture("test-plugin.component.wasm");
    let result = sandbox.evaluate(&bytes, &action("https://ask.example.com/resource"));

    match result {
        SandboxResult::Success(r) => assert_eq!(r.decision, 2, "expected Ask (2)"),
        SandboxResult::Failure(msg) => panic!("expected Success, got failure: {}", msg),
    }
}

#[test]
fn test_evaluate_returns_abstain_for_unknown_target() {
    let sandbox = sandbox();
    let bytes = fixture("test-plugin.component.wasm");
    let result = sandbox.evaluate(&bytes, &action("https://unrelated.example.org/"));

    match result {
        SandboxResult::Success(r) => assert_eq!(r.decision, 0, "expected abstain (0)"),
        SandboxResult::Failure(msg) => panic!("expected Success, got failure: {}", msg),
    }
}

// ── 4. Allow is sanitized to abstention; Deny and Ask are preserved ──────────

#[test]
fn test_allow_is_sanitized_to_abstain() {
    let sandbox = sandbox();
    let bytes = fixture("test-plugin.component.wasm");
    // The guest deliberately returns decision 3 ("Allow"). The sandbox must
    // never surface that as Allow.
    let result = sandbox.evaluate(&bytes, &action("https://allow.example.com/resource"));

    match result {
        SandboxResult::Success(r) => {
            assert_ne!(
                r.decision, 3,
                "plugin decision 3 (Allow) must not pass through"
            );
            assert_eq!(
                agentfence_wasm_plugin::wit_decision_to_decision(r.decision),
                None,
                "an Allow-shaped value must map to abstain (None)"
            );
        }
        SandboxResult::Failure(msg) => panic!("expected Success, got failure: {}", msg),
    }
}

#[test]
fn test_deny_and_ask_survive_sanitization() {
    let sandbox = sandbox();
    let bytes = fixture("test-plugin.component.wasm");

    let deny = sandbox.evaluate(&bytes, &action("https://deny.example.com/x"));
    assert_eq!(decision_of(&deny), Some(Decision::Deny));

    let ask = sandbox.evaluate(&bytes, &action("https://ask.example.com/x"));
    assert_eq!(decision_of(&ask), Some(Decision::Ask));
}

#[test]
fn test_wit_decision_mapping_cannot_produce_allow() {
    // Exhaustive over the interesting range: 0..=255 must never yield Allow.
    for value in 0u8..=255 {
        assert_ne!(
            agentfence_wasm_plugin::wit_decision_to_decision(value),
            Some(Decision::Allow),
            "decision value {} must never map to Allow",
            value
        );
    }
    assert_eq!(
        agentfence_wasm_plugin::wit_decision_to_decision(1),
        Some(Decision::Deny)
    );
    assert_eq!(
        agentfence_wasm_plugin::wit_decision_to_decision(2),
        Some(Decision::Ask)
    );
}

// ── 2. applies_to() returns correct results ──────────────────────────────────

#[test]
fn test_applies_to_matching_action() {
    let sandbox = sandbox();
    let bytes = fixture("test-plugin.component.wasm");
    let applies = sandbox
        .applies_to(&bytes, &action("https://deny.example.com/x"))
        .expect("applies_to must succeed for a valid component");
    assert!(
        applies,
        "guest applies_to returns true for a non-empty target"
    );
}

#[test]
fn test_applies_to_non_matching_action() {
    let sandbox = sandbox();
    let bytes = fixture("test-plugin.component.wasm");
    let applies = sandbox
        .applies_to(&bytes, &action(""))
        .expect("applies_to must succeed for a valid component");
    assert!(
        !applies,
        "guest applies_to returns false for an empty target"
    );
}

// ── 5. Invalid or incompatible components fail safely ─────────────────────────

#[test]
fn test_garbage_bytes_fail_safely() {
    let sandbox = sandbox();
    let result = sandbox.evaluate(b"this is definitely not wasm", &action("x"));
    match result {
        SandboxResult::Failure(msg) => {
            assert!(
                msg.contains("compilation failed") || msg.contains("instantiation failed"),
                "unexpected failure message: {}",
                msg
            );
        }
        SandboxResult::Success(_) => panic!("garbage bytes must not execute"),
    }
}

#[test]
fn test_core_module_is_rejected_as_non_component() {
    let sandbox = sandbox();
    // The raw core module is valid WebAssembly but is NOT a component.
    let bytes = fixture("test-plugin.core.wasm");
    let result = sandbox.evaluate(&bytes, &action("https://deny.example.com/x"));
    match result {
        SandboxResult::Failure(msg) => {
            assert!(
                msg.contains("compilation failed") || msg.contains("instantiation failed"),
                "unexpected failure message: {}",
                msg
            );
        }
        SandboxResult::Success(_) => panic!("a core module must not be accepted as a component"),
    }
}

#[test]
fn test_empty_input_fails_safely() {
    let sandbox = sandbox();
    let result = sandbox.evaluate(b"", &action("x"));
    assert!(matches!(result, SandboxResult::Failure(_)));
}

// ── 6. Incorrect fingerprints are rejected before execution ──────────────────

#[test]
fn test_incorrect_fingerprint_is_rejected() {
    let config = SandboxConfig {
        expected_digest: "0".repeat(64),
        ..SandboxConfig::default()
    };
    let sandbox = WasmSandbox::new(config).unwrap();
    let bytes = fixture("test-plugin.component.wasm");
    let result = sandbox.evaluate(&bytes, &action("https://deny.example.com/x"));

    match result {
        SandboxResult::Failure(msg) => {
            assert!(
                msg.contains("digest mismatch"),
                "expected a digest mismatch, got: {}",
                msg
            );
            assert!(
                !msg.contains("compilation failed"),
                "fingerprint must be checked before compilation"
            );
        }
        SandboxResult::Success(_) => panic!("a wrong fingerprint must be rejected"),
    }
}

#[test]
fn test_correct_fingerprint_allows_execution() {
    let bytes = fixture("test-plugin.component.wasm");
    let config = SandboxConfig {
        expected_digest: agentfence_wasm_plugin::compute_digest(&bytes),
        ..SandboxConfig::default()
    };
    let sandbox = WasmSandbox::new(config).unwrap();
    let result = sandbox.evaluate(&bytes, &action("https://deny.example.com/x"));
    assert!(
        matches!(result, SandboxResult::Success(_)),
        "the correct fingerprint must allow execution: {:?}",
        result
    );
}

// ── 7. Oversized components are rejected ─────────────────────────────────────

#[test]
fn test_oversized_component_is_rejected() {
    let config = SandboxConfig {
        max_module_size: 1024, // 1 KB — far smaller than the fixture
        ..SandboxConfig::default()
    };
    let sandbox = WasmSandbox::new(config).unwrap();
    let bytes = fixture("test-plugin.component.wasm");
    let result = sandbox.evaluate(&bytes, &action("x"));

    match result {
        SandboxResult::Failure(msg) => {
            assert!(
                msg.contains("Module size") && msg.contains("exceeds limit"),
                "unexpected failure message: {}",
                msg
            );
        }
        SandboxResult::Success(_) => panic!("an oversized component must be rejected"),
    }
}

// ── 8. Fuel exhaustion terminates a non-terminating guest ────────────────────

#[test]
fn test_fuel_exhaustion_terminates_nonterminating_guest() {
    // A deliberately tiny fuel budget makes the trap immediate.
    let config = SandboxConfig {
        fuel: 1_000_000,
        ..SandboxConfig::default()
    };
    let sandbox = WasmSandbox::new(config).unwrap();
    let bytes = fixture("test-plugin.component.wasm");

    let started = Instant::now();
    let result = sandbox.evaluate(&bytes, &action("https://loop.example.com/spin"));
    let elapsed = started.elapsed();

    match result {
        SandboxResult::Failure(msg) => {
            // The trap must not be reported as an Allow or a success.
            assert!(
                !msg.to_lowercase().contains("allow"),
                "fuel exhaustion must not surface as Allow: {}",
                msg
            );
        }
        SandboxResult::Success(r) => {
            panic!(
                "a non-terminating guest must not return a result, got decision {}",
                r.decision
            )
        }
    }

    assert!(
        elapsed < Duration::from_secs(10),
        "fuel exhaustion took {:?} — the budget is not bounding execution",
        elapsed
    );
}

#[test]
fn test_guest_trap_fails_safely() {
    let sandbox = sandbox();
    let bytes = fixture("test-plugin.component.wasm");
    let result = sandbox.evaluate(&bytes, &action("https://trap.example.com/boom"));

    match result {
        SandboxResult::Failure(_) => {} // expected
        SandboxResult::Success(r) => panic!(
            "a trapping guest must fail, not succeed with decision {}",
            r.decision
        ),
    }
}

// ── 9. Guest cannot reach capabilities the host did not grant ────────────────

#[test]
fn test_guest_cannot_reach_unganted_host_capabilities() {
    let sandbox = sandbox();
    // This component imports `agentfence:policy/host-caps` (filesystem,
    // network, environment, process). The sandbox linker is empty, so
    // instantiation must fail before any guest code runs.
    let bytes = fixture("hostcaps-plugin.component.wasm");
    let result = sandbox.evaluate(&bytes, &action("https://deny.example.com/x"));

    match result {
        SandboxResult::Failure(msg) => {
            assert!(
                msg.contains("instantiation failed"),
                "expected an instantiation failure, got: {}",
                msg
            );
        }
        SandboxResult::Success(r) => panic!(
            "a guest importing ungranted host capabilities must not run, got decision {}",
            r.decision
        ),
    }
}

#[test]
fn test_guest_cannot_reach_unganted_capabilities_via_applies_to() {
    let sandbox = sandbox();
    let bytes = fixture("hostcaps-plugin.component.wasm");
    let result = sandbox.applies_to(&bytes, &action("https://deny.example.com/x"));
    assert!(
        result.is_err(),
        "applies_to must fail for a component importing ungranted capabilities"
    );
}

// ── Resource limits are actually attached to the store ───────────────────────

#[test]
fn test_memory_limit_is_configurable_and_enforced() {
    let bytes = fixture("test-plugin.component.wasm");

    // The fixture requests ~1.06 MB of linear memory. A 1 MB budget must
    // therefore reject it — which proves the ResourceLimiter is genuinely
    // attached to the store rather than merely configured.
    let tight = SandboxConfig {
        max_memory_bytes: 1024 * 1024,
        ..SandboxConfig::default()
    };
    let sandbox = WasmSandbox::new(tight).unwrap();
    assert_eq!(sandbox.config().max_memory_bytes, 1024 * 1024);
    match sandbox.evaluate(&bytes, &action("https://deny.example.com/x")) {
        SandboxResult::Failure(msg) => {
            assert!(
                msg.contains("instantiation failed"),
                "expected an instantiation failure caused by the memory limit, got: {}",
                msg
            );
        }
        SandboxResult::Success(_) => {
            panic!("a 1 MB budget must reject a component that needs more")
        }
    }

    // A generous budget must allow the same component to run.
    let generous = SandboxConfig {
        max_memory_bytes: 64 * 1024 * 1024,
        ..SandboxConfig::default()
    };
    let sandbox = WasmSandbox::new(generous).unwrap();
    let result = sandbox.evaluate(&bytes, &action("https://deny.example.com/x"));
    assert!(
        matches!(result, SandboxResult::Success(_)),
        "a 64 MB budget must be sufficient: {:?}",
        result
    );
}

// ── Result type sanity ───────────────────────────────────────────────────────

#[test]
fn test_wit_plugin_result_fields_are_populated() {
    let sandbox = sandbox();
    let bytes = fixture("test-plugin.component.wasm");
    match sandbox.evaluate(&bytes, &action("https://ask.example.com/x")) {
        SandboxResult::Success(WitPluginResult {
            decision,
            rule_id,
            reason,
            evidence,
        }) => {
            assert_eq!(decision, 2);
            assert_eq!(rule_id, "test-plugin");
            assert!(reason.contains("ask.example.com"));
            assert!(evidence.is_none());
        }
        other => panic!("unexpected result: {:?}", other),
    }
}
