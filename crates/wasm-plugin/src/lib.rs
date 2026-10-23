//! WebAssembly sandbox runtime for AgentFence policy plugins.
//!
//! SECURITY: This crate provides genuine isolation for untrusted policy
//! plugins through WebAssembly. It depends ONLY on `agentfence-core` for the
//! `Decision` type — it does NOT depend on `agentfence-policy`, which keeps
//! the dependency graph acyclic (policy depends on this crate, never the
//! reverse).
//!
//! Guarantees:
//! - Fuel-based interruption: an infinite loop traps within a bounded budget.
//! - Memory and table limits enforced through a `ResourceLimiter` on the
//!   store (`StoreLimits`), not merely advertised in configuration.
//! - Bounded module, input, output and diagnostic sizes.
//! - NO WASI: the store data type is `()` and the linker is created empty, so
//!   the guest has no filesystem, network, environment or process capability.
//! - SHA-256 verification of the exact bytes that are compiled and executed
//!   (no file-read race between verification and execution).
//! - The guest can never grant `Allow`: only Deny (1) or Ask (2) are mapped;
//!   any other value becomes abstain (0).
//!
//! The guest CAN:
//! - Receive a bounded `action` record.
//! - Return a bounded `plugin-result`.
//! - Perform pure computation within the configured resource limits.

use anyhow::{anyhow, Result};
use sha2::{Digest, Sha256};
use wasmtime::{
    component::{Component, Linker},
    Config, Engine, Store, StoreLimits, StoreLimitsBuilder,
};

use agentfence_core::types::Decision;

// Generate WIT bindings using wasmtime's bindgen macro.
wasmtime::component::bindgen!({
    path: "wit",
    world: "agentfence-policy",
});

// Re-export WIT types so callers (agentfence-policy) can build them without
// depending on wasmtime directly.
pub use crate::exports::agentfence::policy::plugin::{
    Action as WitAction, PluginResult as WitPluginResult,
};

/// Maximum module size in bytes (default: 10 MB).
pub const MAX_MODULE_SIZE: usize = 10 * 1024 * 1024;

/// Maximum input payload size in bytes (default: 1 MB).
pub const MAX_INPUT_SIZE: usize = 1024 * 1024;

/// Maximum output payload size in bytes (default: 1 MB).
pub const MAX_OUTPUT_SIZE: usize = 1024 * 1024;

/// Maximum diagnostic text length (default: 10 KB).
pub const MAX_DIAGNOSTIC_LEN: usize = 10 * 1024;

/// Default fuel budget for plugin execution.
pub const DEFAULT_FUEL: u64 = 10_000_000_000;

/// WIT decision value for "deny".
pub const WIT_DECISION_DENY: u8 = 1;
/// WIT decision value for "ask".
pub const WIT_DECISION_ASK: u8 = 2;

/// Compute the SHA-256 digest of the given bytes, hex-encoded.
///
/// SECURITY: Always hash the *actual* component bytes. Never trust a
/// fingerprint copied from plugin metadata.
pub fn compute_digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// Sandbox configuration.
#[derive(Debug, Clone)]
pub struct SandboxConfig {
    /// Maximum memory in bytes (default: 64 MB).
    pub max_memory_bytes: usize,
    /// Maximum table elements (default: 1000).
    pub max_table_elements: u32,
    /// Maximum module size in bytes (default: 10 MB).
    pub max_module_size: usize,
    /// Maximum input size in bytes (default: 1 MB).
    pub max_input_size: usize,
    /// Maximum output size in bytes (default: 1 MB).
    pub max_output_size: usize,
    /// Maximum diagnostic text length (default: 10 KB).
    pub max_diagnostic_len: usize,
    /// Fuel budget for execution (default: 10B units).
    pub fuel: u64,
    /// Expected SHA-256 digest of the module (empty = no verification).
    pub expected_digest: String,
}

impl Default for SandboxConfig {
    fn default() -> Self {
        Self {
            max_memory_bytes: 64 * 1024 * 1024,
            max_table_elements: 1000,
            max_module_size: MAX_MODULE_SIZE,
            max_input_size: MAX_INPUT_SIZE,
            max_output_size: MAX_OUTPUT_SIZE,
            max_diagnostic_len: MAX_DIAGNOSTIC_LEN,
            fuel: DEFAULT_FUEL,
            expected_digest: String::new(),
        }
    }
}

/// Sandboxed plugin execution result.
#[derive(Debug, Clone)]
pub enum SandboxResult {
    /// Plugin returned a valid, sanitized result.
    Success(WitPluginResult),
    /// Plugin execution failed (trap, resource exhaustion, ABI mismatch, ...).
    Failure(String),
}

impl SandboxResult {
    /// Convenience constructor for a failure.
    pub fn failure(msg: impl Into<String>) -> Self {
        SandboxResult::Failure(msg.into())
    }
}

/// Per-invocation store state.
///
/// SECURITY: The resource limits live in the *store data* so the limiter
/// closure can return a reference into it (the documented `Store::limiter`
/// pattern). This is what makes the memory/table limits real rather than
/// merely configured.
struct SandboxState {
    limits: StoreLimits,
}

/// WebAssembly sandbox runtime for policy plugins.
pub struct WasmSandbox {
    engine: Engine,
    config: SandboxConfig,
}

impl WasmSandbox {
    /// Create a new sandbox with the given configuration.
    pub fn new(config: SandboxConfig) -> Result<Self> {
        let mut wasm_config = Config::new();
        wasm_config.wasm_component_model(true);
        wasm_config.consume_fuel(true);
        wasm_config.max_wasm_stack(1024 * 1024); // 1 MB stack

        let engine = Engine::new(&wasm_config).map_err(|e| anyhow!("{}", e))?;

        Ok(Self { engine, config })
    }

    /// The configured resource limits.
    pub fn config(&self) -> &SandboxConfig {
        &self.config
    }

    /// Verify the SHA-256 digest of the given bytes against the configured
    /// expected digest. An empty expected digest disables verification.
    fn verify_digest(&self, module_bytes: &[u8]) -> Result<()> {
        if self.config.expected_digest.is_empty() {
            return Ok(());
        }

        let digest_hex = compute_digest(module_bytes);
        if digest_hex != self.config.expected_digest {
            return Err(anyhow!(
                "Module digest mismatch: expected {}, got {}",
                self.config.expected_digest,
                digest_hex
            ));
        }

        Ok(())
    }

    /// Enforce the configured input size bound on a WIT action.
    fn validate_input(&self, action: &WitAction) -> Result<()> {
        let size = action.id.len()
            + action.action_type.len()
            + action.tool.len()
            + action.target.len()
            + action.session_id.len()
            + action.agent_id.len()
            + action.task_id.as_ref().map_or(0, |s| s.len())
            + action.cwd.as_ref().map_or(0, |s| s.len())
            + action.repository.as_ref().map_or(0, |s| s.len())
            + action.branch.as_ref().map_or(0, |s| s.len());

        if size > self.config.max_input_size {
            return Err(anyhow!(
                "Input size {} exceeds limit {}",
                size,
                self.config.max_input_size
            ));
        }
        Ok(())
    }

    /// Enforce the configured output/diagnostic bounds on a WIT result.
    fn validate_output(&self, result: &WitPluginResult) -> Result<()> {
        let size = result.rule_id.len() + result.reason.len();
        if size > self.config.max_output_size {
            return Err(anyhow!(
                "Output size {} exceeds limit {}",
                size,
                self.config.max_output_size
            ));
        }
        if let Some(evidence) = &result.evidence {
            if evidence.len() > self.config.max_diagnostic_len {
                return Err(anyhow!(
                    "Diagnostic length {} exceeds limit {}",
                    evidence.len(),
                    self.config.max_diagnostic_len
                ));
            }
        }
        Ok(())
    }

    /// Build a store with fuel and real memory/table resource limits.
    fn new_store(&self) -> Store<SandboxState> {
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.config.max_memory_bytes)
            .table_elements(self.config.max_table_elements as usize)
            .trap_on_grow_failure(true)
            .build();

        let mut store = Store::new(&self.engine, SandboxState { limits });
        store.set_fuel(self.config.fuel).ok();
        // SECURITY: attach a real ResourceLimiter so memory/table growth is
        // actually bounded. The closure returns a reference into the store
        // data, which is the documented `Store::limiter` pattern.
        store.limiter(|state| &mut state.limits);
        store
    }

    /// Compile a component from the already-verified bytes.
    fn compile(&self, component_bytes: &[u8]) -> Result<Component> {
        Component::new(&self.engine, component_bytes)
            .map_err(|e| anyhow!("Component compilation failed: {}", e))
    }

    /// Instantiate a component with an empty linker (no WASI, no host imports)
    /// and return the generated WIT bindings.
    fn instantiate<'a>(
        &self,
        store: &'a mut Store<SandboxState>,
        component: &'a Component,
    ) -> Result<AgentfencePolicy> {
        // SECURITY: the linker is created empty. The guest can only use the
        // imports that its own component declares and that the host explicitly
        // adds. Nothing is added here, so no filesystem, network, environment
        // or process capability can be reached.
        let linker: Linker<SandboxState> = Linker::new(&self.engine);
        AgentfencePolicy::instantiate(&mut *store, component, &linker)
            .map_err(|e| anyhow!("Component instantiation failed: {}", e))
    }

    /// Execute `evaluate` for the given action inside the sandbox.
    ///
    /// SECURITY: The returned decision is sanitized. Only Deny (1) and Ask (2)
    /// are preserved; every other value — including any "Allow" encoding —
    /// becomes abstain (0).
    pub fn evaluate(&self, component_bytes: &[u8], action: &WitAction) -> SandboxResult {
        // 1. Module size bound.
        if component_bytes.len() > self.config.max_module_size {
            return SandboxResult::failure(format!(
                "Module size {} exceeds limit {}",
                component_bytes.len(),
                self.config.max_module_size
            ));
        }

        // 2. Input bound.
        if let Err(e) = self.validate_input(action) {
            return SandboxResult::Failure(e.to_string());
        }

        // 3. Digest verification over the exact bytes that will be compiled.
        if let Err(e) = self.verify_digest(component_bytes) {
            return SandboxResult::Failure(e.to_string());
        }

        // 4. Compile from the verified bytes (no re-read, no TOCTOU).
        let component = match self.compile(component_bytes) {
            Ok(c) => c,
            Err(e) => return SandboxResult::Failure(e.to_string()),
        };

        // 5. Instantiate and call.
        let mut store = self.new_store();
        let bindings = match self.instantiate(&mut store, &component) {
            Ok(b) => b,
            Err(e) => return SandboxResult::Failure(e.to_string()),
        };
        let plugin = bindings.agentfence_policy_plugin();

        let call_result = plugin
            .call_evaluate(&mut store, action)
            .map_err(|e| format!("evaluate() call failed: {}", e));

        let wit_result = match call_result {
            Ok(Ok(r)) => r,
            Ok(Err(e)) => return SandboxResult::Failure(format!("Plugin returned error: {}", e)),
            Err(e) => return SandboxResult::Failure(e),
        };

        // 6. Output/diagnostic bounds.
        if let Err(e) = self.validate_output(&wit_result) {
            return SandboxResult::Failure(e.to_string());
        }

        // 7. SECURITY: sanitize the decision. A plugin can never grant Allow.
        let decision = match wit_result.decision {
            WIT_DECISION_DENY => WIT_DECISION_DENY,
            WIT_DECISION_ASK => WIT_DECISION_ASK,
            _ => 0,
        };

        SandboxResult::Success(WitPluginResult {
            decision,
            rule_id: wit_result.rule_id,
            reason: wit_result.reason,
            evidence: wit_result.evidence,
        })
    }

    /// Execute `applies_to` for the given action inside the sandbox.
    pub fn applies_to(&self, component_bytes: &[u8], action: &WitAction) -> Result<bool, String> {
        // 1. Module size bound.
        if component_bytes.len() > self.config.max_module_size {
            return Err(format!(
                "Module size {} exceeds limit {}",
                component_bytes.len(),
                self.config.max_module_size
            ));
        }

        // 2. Input bound.
        self.validate_input(action).map_err(|e| e.to_string())?;

        // 3. Digest verification over the exact bytes that will be compiled.
        self.verify_digest(component_bytes)
            .map_err(|e| e.to_string())?;

        // 4. Compile from the verified bytes.
        let component = self.compile(component_bytes).map_err(|e| e.to_string())?;

        // 5. Instantiate and call.
        let mut store = self.new_store();
        let bindings = self
            .instantiate(&mut store, &component)
            .map_err(|e| e.to_string())?;
        let plugin = bindings.agentfence_policy_plugin();

        match plugin.call_applies_to(&mut store, action) {
            Ok(applies) => Ok(applies),
            Err(e) => Err(format!("applies_to() call failed: {}", e)),
        }
    }
}

/// Map a sanitized WIT decision value to a core `Decision`.
///
/// SECURITY: This is the single mapping point. Any value other than Deny (1)
/// or Ask (2) maps to `None` (abstain), so a plugin can never grant `Allow`.
pub fn wit_decision_to_decision(value: u8) -> Option<Decision> {
    match value {
        WIT_DECISION_DENY => Some(Decision::Deny),
        WIT_DECISION_ASK => Some(Decision::Ask),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_action(target: &str) -> WitAction {
        WitAction {
            id: "test-action".to_string(),
            action_type: "shell".to_string(),
            tool: "test".to_string(),
            target: target.to_string(),
            session_id: "test-session".to_string(),
            agent_id: "test-agent".to_string(),
            task_id: None,
            cwd: None,
            repository: None,
            branch: None,
        }
    }

    #[test]
    fn test_sandbox_config_default() {
        let config = SandboxConfig::default();
        assert_eq!(config.max_memory_bytes, 64 * 1024 * 1024);
        assert_eq!(config.max_table_elements, 1000);
        assert_eq!(config.max_module_size, MAX_MODULE_SIZE);
        assert_eq!(config.fuel, DEFAULT_FUEL);
    }

    #[test]
    fn test_sandbox_new() {
        let sandbox = WasmSandbox::new(SandboxConfig::default());
        assert!(sandbox.is_ok());
    }

    #[test]
    fn test_compute_digest_is_stable_and_hex() {
        let d1 = compute_digest(b"hello");
        let d2 = compute_digest(b"hello");
        let d3 = compute_digest(b"world");
        assert_eq!(d1, d2);
        assert_ne!(d1, d3);
        assert_eq!(d1.len(), 64);
        assert!(d1.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_module_size_limit_rejects_oversized_module() {
        let config = SandboxConfig {
            max_module_size: 10,
            ..SandboxConfig::default()
        };
        let sandbox = WasmSandbox::new(config).unwrap();
        let result = sandbox.evaluate(b"this is a module that is too large", &test_action("x"));
        assert!(matches!(result, SandboxResult::Failure(_)));
    }

    #[test]
    fn test_digest_mismatch_rejected_before_execution() {
        let config = SandboxConfig {
            expected_digest: "0".repeat(64),
            ..SandboxConfig::default()
        };
        let sandbox = WasmSandbox::new(config).unwrap();
        let result = sandbox.evaluate(b"some module bytes", &test_action("x"));
        match result {
            SandboxResult::Failure(msg) => {
                assert!(
                    msg.contains("digest mismatch"),
                    "unexpected message: {}",
                    msg
                )
            }
            other => panic!("expected Failure, got {:?}", other),
        }
    }

    #[test]
    fn test_digest_match_accepted_then_fails_on_compilation() {
        let bytes = b"some module bytes";
        let config = SandboxConfig {
            expected_digest: compute_digest(bytes),
            ..SandboxConfig::default()
        };
        let sandbox = WasmSandbox::new(config).unwrap();
        let result = sandbox.evaluate(bytes, &test_action("x"));
        // Digest matches, so the failure must be a compilation/instantiation failure.
        match result {
            SandboxResult::Failure(msg) => {
                assert!(
                    msg.contains("compilation failed") || msg.contains("instantiation failed"),
                    "unexpected message: {}",
                    msg
                )
            }
            other => panic!("expected Failure, got {:?}", other),
        }
    }

    #[test]
    fn test_empty_module_fails_safely() {
        let sandbox = WasmSandbox::new(SandboxConfig::default()).unwrap();
        let result = sandbox.evaluate(b"", &test_action("x"));
        assert!(matches!(result, SandboxResult::Failure(_)));
    }

    #[test]
    fn test_input_size_limit_rejects_oversized_action() {
        let config = SandboxConfig {
            max_input_size: 8,
            ..SandboxConfig::default()
        };
        let sandbox = WasmSandbox::new(config).unwrap();
        let result = sandbox.evaluate(b"", &test_action("a very long target"));
        match result {
            SandboxResult::Failure(msg) => {
                assert!(msg.contains("Input size"), "unexpected message: {}", msg)
            }
            other => panic!("expected Failure, got {:?}", other),
        }
    }

    #[test]
    fn test_wit_decision_mapping_never_yields_allow() {
        assert_eq!(wit_decision_to_decision(1), Some(Decision::Deny));
        assert_eq!(wit_decision_to_decision(2), Some(Decision::Ask));
        // 0 (abstain) and 3 (a hypothetical "allow") both abstain.
        assert_eq!(wit_decision_to_decision(0), None);
        assert_eq!(wit_decision_to_decision(3), None);
        assert_eq!(wit_decision_to_decision(255), None);
    }

    #[test]
    fn test_applies_to_on_invalid_module_fails() {
        let sandbox = WasmSandbox::new(SandboxConfig::default()).unwrap();
        let result = sandbox.applies_to(b"not a component", &test_action("x"));
        assert!(result.is_err());
    }
}
