//! Test WebAssembly guest for the AgentFence policy plugin sandbox.
//!
//! This is a REAL WebAssembly component: it is compiled to `wasm32-wasip1` and
//! then wrapped with `wasm-tools component new -w test-plugin`.
//!
//! Behaviour is selected by the `target` field of the incoming action so that a
//! single fixture can drive several distinct security-relevant tests:
//!
//! | target contains          | behaviour                                   |
//! |--------------------------|---------------------------------------------|
//! | `deny.example.com`       | returns decision 1 (Deny)                   |
//! | `ask.example.com`        | returns decision 2 (Ask)                    |
//! | `abstain.example.com`    | returns decision 0 (abstain)                |
//! | `trap.example.com`       | executes `unreachable` (guest trap)         |
//! | `loop.example.com`       | spins forever (fuel exhaustion)             |
//! | anything else            | returns decision 0 (abstain)                |
//!
//! SECURITY: the guest performs pure computation only. It imports no WASI
//! interface, so the host's empty linker is sufficient to instantiate it —
//! and any guest that *does* import WASI will fail to instantiate.

wit_bindgen::generate!({
    path: "wit",
    world: "test-plugin",
});

use crate::exports::agentfence::policy::plugin::{Action, PluginResult};

struct TestPlugin;

export!(TestPlugin);

impl crate::exports::agentfence::policy::plugin::Guest for TestPlugin {
    fn applies_to(action: Action) -> bool {
        // Applies to any action that names a target.
        !action.target.is_empty()
    }

    fn evaluate(action: Action) -> Result<PluginResult, String> {
        if action.target.contains("trap.example.com") {
            // Guest trap: must surface as an execution failure, never as Allow.
            unreachable!("guest trap requested by fixture");
        }

        if action.target.contains("loop.example.com") {
            // Non-terminating guest: must be stopped by the fuel budget.
            loop {
                std::hint::spin_loop();
            }
        }

        let decision = if action.target.contains("deny.example.com") {
            1 // Deny
        } else if action.target.contains("ask.example.com") {
            2 // Ask
        } else if action.target.contains("allow.example.com") {
            3 // INVALID: plugins cannot grant Allow — must be sanitized to abstain
        } else {
            0 // Abstain
        };

        Ok(PluginResult {
            decision,
            rule_id: "test-plugin".to_string(),
            reason: format!("test-plugin evaluated target={}", action.target),
            evidence: None,
        })
    }
}
