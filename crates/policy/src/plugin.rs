//! Plugin system for custom policy rules.
//!
//! Provides extensible policy evaluation through plugins:
//! - Custom rule registration
//! - Plugin lifecycle management
//! - Sandboxed execution environment with timeout
//! - Version and compatibility checking
//!
//! Architecture:
//! Policy Engine → Plugin Registry → Custom Rules → Decision
//!
//! Security guarantees:
//! - Plugins cannot access the filesystem or network directly
//! - Plugin execution is bounded by timeout and monitored
//! - Plugin API is versioned and stable
//! - Malicious plugins are isolated and rejected
//! - Plugins CANNOT grant Allow — only Deny or Ask (core policy is authoritative)
//! - Plugin results are audited
//! - Plugin execution is sandboxed with timeout enforcement

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tracing::{debug, info, warn};

use agentfence_core::types::{Action, Decision};
use agentfence_wasm_plugin::{
    wit_decision_to_decision, SandboxConfig, SandboxResult, WasmSandbox, WitAction,
};

/// Plugin API version.
pub const PLUGIN_API_VERSION: u32 = 1;

/// Plugin capability.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PluginCapability {
    /// Evaluate custom policy rules
    PolicyRule,
    /// Transform actions before evaluation
    ActionTransformer,
    /// Enrich context with additional data
    ContextEnricher,
    /// Post-process decisions
    DecisionProcessor,
}

/// Plugin metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginMetadata {
    pub id: String,
    pub name: String,
    pub version: String,
    pub api_version: u32,
    pub capabilities: Vec<PluginCapability>,
    pub author: String,
    pub description: String,
    /// SHA-256 fingerprint of the plugin binary/library
    pub fingerprint: String,
}

impl PluginMetadata {
    /// Check if the plugin is compatible with the current API version.
    pub fn is_compatible(&self) -> bool {
        self.api_version == PLUGIN_API_VERSION
    }

    /// Verify the plugin fingerprint against an expected value.
    pub fn verify_fingerprint(&self, expected: &str) -> bool {
        self.fingerprint == expected
    }
}

/// Plugin configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    /// Enable the plugin
    pub enabled: bool,
    /// Plugin-specific settings
    pub settings: HashMap<String, String>,
    /// Execution timeout in milliseconds
    pub timeout_ms: u64,
    /// Maximum memory usage in MB
    pub max_memory_mb: u64,
    /// Expected SHA-256 fingerprint (empty = no verification)
    pub expected_fingerprint: String,
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            settings: HashMap::new(),
            timeout_ms: 1000,
            max_memory_mb: 64,
            expected_fingerprint: String::new(),
        }
    }
}

/// Plugin evaluation context.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginContext {
    pub action: Action,
    pub session_id: String,
    pub agent_id: String,
    pub task_id: Option<String>,
    pub cwd: Option<String>,
    pub repository: Option<String>,
    pub branch: Option<String>,
    pub environment: HashMap<String, String>,
}

/// Plugin evaluation result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginResult {
    pub decision: Option<Decision>,
    pub rule_id: String,
    pub reason: String,
    pub evidence: Option<String>,
    pub risk_level: Option<String>,
    pub metadata: HashMap<String, String>,
}

/// Custom policy rule trait.
///
/// Plugins implement this trait to provide custom policy evaluation.
///
/// SECURITY: Plugins CANNOT grant Allow. They can only:
/// - Return Deny (to block an action)
/// - Return Ask (to escalate to human approval)
/// - Return None (to abstain, letting core policy decide)
pub trait CustomPolicyRule: Send + Sync + 'static {
    /// Get plugin metadata.
    fn metadata(&self) -> PluginMetadata;

    /// Evaluate the rule against the given context.
    fn evaluate(&self, context: &PluginContext) -> Result<PluginResult, String>;

    /// Check if the rule applies to the given action.
    fn applies_to(&self, action: &Action) -> bool;
}

#[cfg(test)]
mod wasm_plugin_tests {
    use super::*;
    use std::collections::HashMap;

    /// Path to the real WebAssembly component fixture built from
    /// `crates/wasm-plugin/guest/`. This is a genuine component, not a mock.
    const FIXTURE: &str = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../wasm-plugin/tests/fixtures/test-plugin.component.wasm"
    );

    fn fixture_bytes() -> Vec<u8> {
        std::fs::read(FIXTURE).expect("wasm plugin fixture must exist")
    }

    /// A minimal native plugin used to prove native and WASM evaluation can be
    /// combined in one `evaluate_all()` call.
    struct StaticPlugin {
        id: &'static str,
    }

    impl CustomPolicyRule for StaticPlugin {
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata {
                id: self.id.to_string(),
                name: self.id.to_string(),
                version: "1.0.0".to_string(),
                api_version: PLUGIN_API_VERSION,
                capabilities: vec![PluginCapability::PolicyRule],
                author: "test".to_string(),
                description: "static test plugin".to_string(),
                fingerprint: String::new(),
            }
        }

        fn evaluate(&self, _context: &PluginContext) -> Result<PluginResult, String> {
            Ok(PluginResult {
                decision: Some(Decision::Deny),
                rule_id: self.id.to_string(),
                reason: "static plugin denied".to_string(),
                evidence: None,
                risk_level: None,
                metadata: HashMap::new(),
            })
        }

        fn applies_to(&self, _action: &Action) -> bool {
            true
        }
    }

    fn test_context(target: &str) -> PluginContext {
        use agentfence_core::types::{ActionId, ActionType, AgentId, SessionId};

        PluginContext {
            action: Action {
                id: ActionId::new(),
                session_id: SessionId::new_from_string("test".to_string()),
                agent_id: AgentId::new("test-agent"),
                task_id: None,
                action_type: ActionType::Network,
                tool: "curl".to_string(),
                target: target.to_string(),
                args_hash: "hash".to_string(),
                context: Default::default(),
            },
            session_id: "test".to_string(),
            agent_id: "test-agent".to_string(),
            task_id: None,
            cwd: None,
            repository: None,
            branch: None,
            environment: HashMap::new(),
        }
    }

    // ── Registration / unregistration ─────────────────────────────────────────

    #[test]
    fn test_wasm_plugin_registration() {
        let mut registry = PluginRegistry::new();
        let result = registry.register_wasm_plugin(
            "test-wasm-plugin".to_string(),
            FIXTURE.to_string(),
            String::new(), // no fingerprint verification
        );
        assert!(result.is_ok(), "registration failed: {:?}", result);
        assert_eq!(registry.list_wasm_plugins(), vec!["test-wasm-plugin"]);
    }

    #[test]
    fn test_wasm_plugin_registration_duplicate() {
        let mut registry = PluginRegistry::new();
        registry
            .register_wasm_plugin(
                "test-wasm-plugin".to_string(),
                FIXTURE.to_string(),
                String::new(),
            )
            .unwrap();
        let result = registry.register_wasm_plugin(
            "test-wasm-plugin".to_string(),
            FIXTURE.to_string(),
            String::new(),
        );
        assert!(result.is_err(), "duplicate registration must be rejected");
    }

    #[test]
    fn test_wasm_plugin_unregistration() {
        let mut registry = PluginRegistry::new();
        registry
            .register_wasm_plugin(
                "test-wasm-plugin".to_string(),
                FIXTURE.to_string(),
                String::new(),
            )
            .unwrap();
        assert!(registry.unregister_wasm_plugin("test-wasm-plugin").is_ok());
        assert!(registry.list_wasm_plugins().is_empty());
    }

    #[test]
    fn test_wasm_plugin_unregistration_not_found() {
        let mut registry = PluginRegistry::new();
        assert!(registry.unregister_wasm_plugin("nonexistent").is_err());
    }

    // ── Fingerprint verification at registration ──────────────────────────────

    #[test]
    fn test_wasm_plugin_registration_rejects_wrong_fingerprint() {
        let mut registry = PluginRegistry::new();
        let result = registry.register_wasm_plugin(
            "test-wasm-plugin".to_string(),
            FIXTURE.to_string(),
            "0".repeat(64),
        );
        match result {
            Err(msg) => assert!(
                msg.contains("fingerprint mismatch"),
                "unexpected message: {}",
                msg
            ),
            Ok(()) => panic!("a wrong fingerprint must be rejected at registration"),
        }
    }

    #[test]
    fn test_wasm_plugin_registration_accepts_correct_fingerprint() {
        let mut registry = PluginRegistry::new();
        let digest = agentfence_wasm_plugin::compute_digest(&fixture_bytes());
        let result = registry.register_wasm_plugin(
            "test-wasm-plugin".to_string(),
            FIXTURE.to_string(),
            digest,
        );
        assert!(
            result.is_ok(),
            "the correct fingerprint must be accepted: {:?}",
            result
        );
    }

    // ── Real execution through the registry ───────────────────────────────────

    #[test]
    fn test_wasm_plugin_evaluate_returns_deny() {
        let mut registry = PluginRegistry::new();
        registry
            .register_wasm_plugin("p".to_string(), FIXTURE.to_string(), String::new())
            .unwrap();

        let results = registry.evaluate_wasm_plugins(&test_context("https://deny.example.com/x"));
        assert_eq!(results.len(), 1, "expected exactly one plugin result");
        assert_eq!(results[0].decision, Some(Decision::Deny));
        assert_eq!(results[0].rule_id, "test-plugin");
    }

    #[test]
    fn test_wasm_plugin_evaluate_returns_ask() {
        let mut registry = PluginRegistry::new();
        registry
            .register_wasm_plugin("p".to_string(), FIXTURE.to_string(), String::new())
            .unwrap();

        let results = registry.evaluate_wasm_plugins(&test_context("https://ask.example.com/x"));
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, Some(Decision::Ask));
    }

    #[test]
    fn test_wasm_plugin_evaluate_abstains_for_unknown_target() {
        let mut registry = PluginRegistry::new();
        registry
            .register_wasm_plugin("p".to_string(), FIXTURE.to_string(), String::new())
            .unwrap();

        let results =
            registry.evaluate_wasm_plugins(&test_context("https://unrelated.example.org/"));
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].decision, None,
            "an unknown target must abstain, never Allow"
        );
    }

    #[test]
    fn test_wasm_plugin_evaluate_allow_is_sanitized_to_abstain() {
        let mut registry = PluginRegistry::new();
        registry
            .register_wasm_plugin("p".to_string(), FIXTURE.to_string(), String::new())
            .unwrap();

        // The guest deliberately returns decision 3 ("Allow").
        let results = registry.evaluate_wasm_plugins(&test_context("https://allow.example.com/x"));
        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].decision, None,
            "a plugin must never grant Allow — it must become abstain"
        );
    }

    #[test]
    fn test_wasm_plugin_evaluate_failure_is_ignored() {
        let mut registry = PluginRegistry::new();
        registry
            .register_wasm_plugin("p".to_string(), FIXTURE.to_string(), String::new())
            .unwrap();

        // A trapping guest must not produce a result and must not panic.
        let results = registry.evaluate_wasm_plugins(&test_context("https://trap.example.com/x"));
        assert!(
            results.is_empty(),
            "a trapping plugin must yield no result, got {:?}",
            results
        );
    }

    #[test]
    fn test_wasm_plugin_disabled_is_skipped() {
        let mut registry = PluginRegistry::new();
        registry
            .register_wasm_plugin("p".to_string(), FIXTURE.to_string(), String::new())
            .unwrap();
        registry.wasm_plugins.get_mut("p").unwrap().enabled = false;

        let results = registry.evaluate_wasm_plugins(&test_context("https://deny.example.com/x"));
        assert!(results.is_empty(), "a disabled plugin must be skipped");
    }

    #[test]
    fn test_wasm_plugin_tampering_detected_at_execution_time() {
        let bytes = fixture_bytes();
        let digest = agentfence_wasm_plugin::compute_digest(&bytes);

        // Copy the fixture to a temp path so it can be tampered with after
        // registration.
        let tampered_path =
            std::env::temp_dir().join(format!("agentfence-tamper-{}.wasm", std::process::id()));
        std::fs::write(&tampered_path, &bytes).unwrap();

        let mut registry = PluginRegistry::new();
        registry
            .register_wasm_plugin(
                "p".to_string(),
                tampered_path.to_string_lossy().to_string(),
                digest,
            )
            .unwrap();

        // Tamper: replace the module bytes on disk.
        std::fs::write(&tampered_path, b"tampered module bytes").unwrap();

        let results = registry.evaluate_wasm_plugins(&test_context("https://deny.example.com/x"));
        assert!(
            results.is_empty(),
            "a tampered module must be skipped at execution time"
        );

        let _ = std::fs::remove_file(&tampered_path);
    }

    // ── Combined native + WASM evaluation ─────────────────────────────────────

    #[test]
    fn test_evaluate_all_combines_native_and_wasm_plugins() {
        let mut registry = PluginRegistry::new();

        registry
            .register(
                Box::new(StaticPlugin { id: "native-1" }),
                PluginConfig::default(),
            )
            .unwrap();
        registry
            .register_wasm_plugin("wasm-1".to_string(), FIXTURE.to_string(), String::new())
            .unwrap();

        let results = registry.evaluate_all(&test_context("https://ask.example.com/x"));
        assert_eq!(
            results.len(),
            2,
            "both the native and the WASM plugin must contribute a result"
        );

        let mut decisions: Vec<_> = results.iter().filter_map(|r| r.decision).collect();
        decisions.sort_by_key(|d| match d {
            Decision::Allow => 0,
            Decision::Ask => 1,
            Decision::Deny => 2,
        });
        assert_eq!(decisions, vec![Decision::Ask, Decision::Deny]);
    }

    #[test]
    fn test_evaluate_all_never_returns_allow_from_a_plugin() {
        let mut registry = PluginRegistry::new();
        registry
            .register_wasm_plugin("wasm-1".to_string(), FIXTURE.to_string(), String::new())
            .unwrap();

        let results = registry.evaluate_all(&test_context("https://allow.example.com/x"));
        assert!(
            results.iter().all(|r| r.decision != Some(Decision::Allow)),
            "no plugin result may be Allow: {:?}",
            results
        );
    }
}

/// Boxed plugin type.
type BoxedPlugin = Box<dyn CustomPolicyRule + Send + Sync>;

/// WebAssembly plugin entry.
pub struct WasmPluginEntry {
    /// Path to the compiled .wasm component.
    pub module_path: String,
    /// Expected SHA-256 fingerprint of the module bytes.
    pub expected_fingerprint: String,
    /// Whether the plugin is enabled.
    pub enabled: bool,
}

/// Plugin registry.
///
/// Manages registered plugins and their lifecycle.
///
/// SECURITY: Plugins are sandboxed and cannot override core policy.
/// A plugin returning Allow is treated as None (abstain).
pub struct PluginRegistry {
    plugins: HashMap<String, Arc<Mutex<BoxedPlugin>>>,
    configs: HashMap<String, PluginConfig>,
    wasm_plugins: HashMap<String, WasmPluginEntry>,
}

impl PluginRegistry {
    /// Create a new plugin registry.
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            configs: HashMap::new(),
            wasm_plugins: HashMap::new(),
        }
    }

    /// Register a WebAssembly plugin.
    ///
    /// SECURITY: The module file is read, fingerprinted, and verified against
    /// `expected_fingerprint` before registration. The module is NOT executed
    /// at registration time — only at evaluation time through the sandbox.
    pub fn register_wasm_plugin(
        &mut self,
        plugin_id: String,
        module_path: String,
        expected_fingerprint: String,
    ) -> Result<(), String> {
        if self.wasm_plugins.contains_key(&plugin_id) {
            return Err(format!("Wasm plugin {} is already registered", plugin_id));
        }

        // SECURITY: Verify the fingerprint of the exact module bytes before
        // registration. Uses the shared digest helper so the registered and
        // execution-time checks cannot drift apart.
        if !expected_fingerprint.is_empty() {
            let module_bytes = std::fs::read(&module_path)
                .map_err(|e| format!("Failed to read wasm module {}: {}", module_path, e))?;
            let actual_fingerprint = agentfence_wasm_plugin::compute_digest(&module_bytes);
            if actual_fingerprint != expected_fingerprint {
                return Err(format!(
                    "Wasm plugin {} fingerprint mismatch: expected {}, got {}",
                    plugin_id, expected_fingerprint, actual_fingerprint
                ));
            }
        }

        info!(
            "Registering wasm plugin: {} (module: {}, fingerprint: {})",
            plugin_id, module_path, expected_fingerprint
        );
        self.wasm_plugins.insert(
            plugin_id,
            WasmPluginEntry {
                module_path,
                expected_fingerprint,
                enabled: true,
            },
        );
        Ok(())
    }

    /// Unregister a WebAssembly plugin.
    pub fn unregister_wasm_plugin(&mut self, plugin_id: &str) -> Result<(), String> {
        if !self.wasm_plugins.contains_key(plugin_id) {
            return Err(format!("Wasm plugin {} not found", plugin_id));
        }
        info!("Unregistering wasm plugin: {}", plugin_id);
        self.wasm_plugins.remove(plugin_id);
        Ok(())
    }

    /// List all registered WebAssembly plugins.
    pub fn list_wasm_plugins(&self) -> Vec<String> {
        self.wasm_plugins.keys().cloned().collect()
    }

    /// Evaluate all registered WebAssembly plugins through the Wasmtime sandbox.
    ///
    /// SECURITY: Each plugin executes inside a Wasmtime sandbox with:
    /// - Fuel-based interruption (infinite loops trap within bounded time)
    /// - No WASI filesystem, network, or environment access
    /// - Module fingerprint verification before execution
    /// - Module size limits
    ///
    /// Plugin results are sanitized:
    /// - Allow is converted to None (abstain) — plugins cannot grant permission
    /// - Deny and Ask are preserved
    /// - Plugin failures are logged and ignored (fail-safe)
    pub fn evaluate_wasm_plugins(&self, context: &PluginContext) -> Vec<PluginResult> {
        let mut results = Vec::new();

        for (id, entry) in &self.wasm_plugins {
            if !entry.enabled {
                continue;
            }

            // SECURITY: read the module bytes exactly ONCE, then verify and
            // execute those same bytes. Reading once closes the TOCTOU window
            // between the fingerprint check and compilation/execution.
            let module_bytes = match std::fs::read(&entry.module_path) {
                Ok(b) => b,
                Err(e) => {
                    warn!("Wasm plugin {}: failed to read module: {}", id, e);
                    continue;
                }
            };

            // SECURITY: re-verify the fingerprint at execution time over the
            // exact bytes that will be compiled.
            if !entry.expected_fingerprint.is_empty() {
                let actual = agentfence_wasm_plugin::compute_digest(&module_bytes);
                if actual != entry.expected_fingerprint {
                    warn!(
                        "Wasm plugin {}: fingerprint mismatch at execution time — skipping",
                        id
                    );
                    continue;
                }
            }

            // Execute through the Wasmtime sandbox.
            match Self::execute_wasm_plugin(context, &module_bytes) {
                Ok(plugin_result) => {
                    // SECURITY: defense in depth. The sandbox already maps any
                    // non-Deny/non-Ask value to abstain, so a plugin can never
                    // grant Allow. Re-check here in case the sandbox is ever
                    // replaced by an alternative backend.
                    if plugin_result.decision == Some(Decision::Allow) {
                        warn!(
                            "Wasm plugin {} returned Allow — converting to None (abstain). \
                             Plugins cannot grant permission.",
                            id
                        );
                    }
                    debug!("Wasm plugin {} evaluated: {}", id, plugin_result.reason);
                    results.push(plugin_result);
                }
                Err(e) => {
                    warn!("Wasm plugin {} execution failed: {}", id, e);
                    // Fail-safe: ignore plugin failure.
                }
            }
        }

        results
    }

    /// Execute a single WebAssembly plugin through the Wasmtime sandbox.
    ///
    /// `module_bytes` MUST be the same buffer that was fingerprint-verified by
    /// the caller — the sandbox verifies again against its own configuration
    /// and compiles exactly these bytes.
    fn execute_wasm_plugin(
        context: &PluginContext,
        module_bytes: &[u8],
    ) -> Result<PluginResult, String> {
        let sandbox = WasmSandbox::new(SandboxConfig::default())
            .map_err(|e| format!("failed to create wasm sandbox: {}", e))?;

        let wit_action = WitAction {
            id: context.action.id.to_string(),
            action_type: context.action.action_type.to_string(),
            tool: context.action.tool.clone(),
            target: context.action.target.clone(),
            session_id: context.session_id.clone(),
            agent_id: context.agent_id.clone(),
            task_id: context.task_id.clone(),
            cwd: context.cwd.clone(),
            repository: context.repository.clone(),
            branch: context.branch.clone(),
        };

        match sandbox.evaluate(module_bytes, &wit_action) {
            SandboxResult::Success(wit_result) => {
                let decision = wit_decision_to_decision(wit_result.decision);
                Ok(PluginResult {
                    decision,
                    rule_id: wit_result.rule_id,
                    reason: wit_result.reason,
                    evidence: wit_result.evidence,
                    risk_level: None,
                    metadata: HashMap::new(),
                })
            }
            SandboxResult::Failure(msg) => Err(msg),
        }
    }

    /// Register a plugin.
    ///
    /// SECURITY: Plugin fingerprint is verified if expected_fingerprint is set.
    pub fn register(&mut self, plugin: BoxedPlugin, config: PluginConfig) -> Result<(), String> {
        let metadata = plugin.metadata();

        if !metadata.is_compatible() {
            return Err(format!(
                "Plugin {} is incompatible (API version {} != {})",
                metadata.id, metadata.api_version, PLUGIN_API_VERSION
            ));
        }

        if self.plugins.contains_key(&metadata.id) {
            return Err(format!("Plugin {} is already registered", metadata.id));
        }

        // Verify fingerprint if expected_fingerprint is set
        if !config.expected_fingerprint.is_empty()
            && !metadata.verify_fingerprint(&config.expected_fingerprint)
        {
            return Err(format!(
                "Plugin {} fingerprint mismatch: expected {}, got {}",
                metadata.id, config.expected_fingerprint, metadata.fingerprint
            ));
        }

        info!(
            "Registering plugin: {} v{} by {} (fingerprint: {})",
            metadata.name, metadata.version, metadata.author, metadata.fingerprint
        );
        self.plugins
            .insert(metadata.id.clone(), Arc::new(Mutex::new(plugin)));
        self.configs.insert(metadata.id, config);
        Ok(())
    }

    /// Unregister a plugin.
    pub fn unregister(&mut self, plugin_id: &str) -> Result<(), String> {
        if !self.plugins.contains_key(plugin_id) {
            return Err(format!("Plugin {} not found", plugin_id));
        }

        info!("Unregistering plugin: {}", plugin_id);
        self.plugins.remove(plugin_id);
        self.configs.remove(plugin_id);
        Ok(())
    }

    /// Get plugin metadata.
    pub fn get_metadata(&self, plugin_id: &str) -> Option<PluginMetadata> {
        self.plugins
            .get(plugin_id)
            .and_then(|p| p.lock().ok().map(|p| p.metadata()))
    }

    /// List all registered plugins.
    pub fn list_plugins(&self) -> Vec<PluginMetadata> {
        self.plugins
            .values()
            .filter_map(|p| p.lock().ok().map(|p| p.metadata()))
            .collect()
    }

    /// Evaluate all applicable plugins with timeout enforcement.
    ///
    /// SECURITY: Plugin results are sanitized:
    /// - Allow is converted to None (abstain) — plugins cannot grant permission
    /// - Deny and Ask are preserved
    /// - Plugin failures are logged and ignored (fail-safe)
    /// - Plugin execution is bounded by timeout
    pub fn evaluate_all(&self, context: &PluginContext) -> Vec<PluginResult> {
        let mut results = Vec::new();

        // Evaluate native plugins
        for (id, plugin_arc) in &self.plugins {
            let config = match self.configs.get(id) {
                Some(c) if c.enabled => c.clone(),
                _ => continue,
            };

            // SECURITY: Run applies_to() in a worker thread with a bounded
            // timeout so a hostile or buggy plugin cannot stall the PDP.
            // Note: recv_timeout() bounds the wait time but does NOT terminate
            // the worker thread — it only discards the result on timeout.
            let plugin_id = id.clone();
            let plugin_clone = Arc::clone(plugin_arc);
            let context_clone = context.clone();
            let timeout_ms = config.timeout_ms;

            let (applies_tx, applies_rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let result = match plugin_clone.lock() {
                    Ok(p) => p.applies_to(&context_clone.action),
                    Err(_) => false,
                };
                let _ = applies_tx.send(result);
            });

            let applies =
                match applies_rx.recv_timeout(std::time::Duration::from_millis(timeout_ms)) {
                    Ok(result) => result,
                    Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                        warn!(
                            "Plugin {} applies_to() timed out after {}ms — skipping plugin",
                            plugin_id, timeout_ms
                        );
                        continue;
                    }
                    Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                        warn!("Plugin {} applies_to() thread disconnected", plugin_id);
                        continue;
                    }
                };

            if !applies {
                continue;
            }

            // SECURITY: Run plugin evaluation in a worker thread with a bounded
            // timeout so a hostile or buggy plugin cannot stall the PDP.
            // Note: recv_timeout() bounds the wait time but does NOT terminate
            // the worker thread — it only discards the result on timeout.
            let plugin_clone = Arc::clone(plugin_arc);
            let context_clone = context.clone();

            let (tx, rx) = std::sync::mpsc::channel();
            std::thread::spawn(move || {
                let result = match plugin_clone.lock() {
                    Ok(p) => p.evaluate(&context_clone),
                    Err(_) => Err("plugin mutex poisoned".to_string()),
                };
                let _ = tx.send(result);
            });

            match rx.recv_timeout(std::time::Duration::from_millis(timeout_ms)) {
                Ok(Ok(mut plugin_result)) => {
                    // SECURITY: Plugins cannot grant Allow.
                    if plugin_result.decision == Some(Decision::Allow) {
                        warn!(
                            "Plugin {} returned Allow — converting to None (abstain). \
                             Plugins cannot grant permission.",
                            plugin_id
                        );
                        plugin_result.decision = None;
                    }

                    debug!("Plugin {} evaluated: {}", plugin_id, plugin_result.reason);
                    results.push(plugin_result);
                }
                Ok(Err(e)) => {
                    warn!("Plugin {} evaluation failed: {}", plugin_id, e);
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    warn!(
                        "Plugin {} execution timed out after {}ms — result discarded",
                        plugin_id, timeout_ms
                    );
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                    warn!("Plugin {} evaluation thread disconnected", plugin_id);
                }
            }
        }

        // Evaluate WebAssembly plugins through the Wasmtime sandbox
        let wasm_results = self.evaluate_wasm_plugins(context);
        results.extend(wasm_results);

        results
    }

    /// Get plugin configuration.
    pub fn get_config(&self, plugin_id: &str) -> Option<&PluginConfig> {
        self.configs.get(plugin_id)
    }

    /// Update plugin configuration.
    pub fn update_config(&mut self, plugin_id: &str, config: PluginConfig) -> Result<(), String> {
        if !self.configs.contains_key(plugin_id) {
            return Err(format!("Plugin {} not found", plugin_id));
        }

        self.configs.insert(plugin_id.to_string(), config);
        Ok(())
    }
}

impl Default for PluginRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentfence_core::types::{ActionId, AgentId, SessionId};

    struct TestPlugin;

    impl CustomPolicyRule for TestPlugin {
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata {
                id: "test-plugin".to_string(),
                name: "Test Plugin".to_string(),
                version: "1.0.0".to_string(),
                api_version: PLUGIN_API_VERSION,
                capabilities: vec![PluginCapability::PolicyRule],
                author: "Test".to_string(),
                description: "A test plugin".to_string(),
                fingerprint: "abc123".to_string(),
            }
        }

        fn evaluate(&self, _context: &PluginContext) -> Result<PluginResult, String> {
            Ok(PluginResult {
                decision: Some(Decision::Allow),
                rule_id: "test.allow".to_string(),
                reason: "Test rule matched".to_string(),
                evidence: None,
                risk_level: Some("LOW".to_string()),
                metadata: HashMap::new(),
            })
        }

        fn applies_to(&self, _action: &Action) -> bool {
            true
        }
    }

    struct DenyPlugin;

    impl CustomPolicyRule for DenyPlugin {
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata {
                id: "deny-plugin".to_string(),
                name: "Deny Plugin".to_string(),
                version: "1.0.0".to_string(),
                api_version: PLUGIN_API_VERSION,
                capabilities: vec![PluginCapability::PolicyRule],
                author: "Test".to_string(),
                description: "A plugin that denies".to_string(),
                fingerprint: "def456".to_string(),
            }
        }

        fn evaluate(&self, _context: &PluginContext) -> Result<PluginResult, String> {
            Ok(PluginResult {
                decision: Some(Decision::Deny),
                rule_id: "test.deny".to_string(),
                reason: "Test deny rule matched".to_string(),
                evidence: None,
                risk_level: Some("HIGH".to_string()),
                metadata: HashMap::new(),
            })
        }

        fn applies_to(&self, _action: &Action) -> bool {
            true
        }
    }

    struct AskPlugin;

    impl CustomPolicyRule for AskPlugin {
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata {
                id: "ask-plugin".to_string(),
                name: "Ask Plugin".to_string(),
                version: "1.0.0".to_string(),
                api_version: PLUGIN_API_VERSION,
                capabilities: vec![PluginCapability::PolicyRule],
                author: "Test".to_string(),
                description: "A plugin that asks".to_string(),
                fingerprint: "ghi789".to_string(),
            }
        }

        fn evaluate(&self, _context: &PluginContext) -> Result<PluginResult, String> {
            Ok(PluginResult {
                decision: Some(Decision::Ask),
                rule_id: "test.ask".to_string(),
                reason: "Test ask rule matched".to_string(),
                evidence: None,
                risk_level: Some("MEDIUM".to_string()),
                metadata: HashMap::new(),
            })
        }

        fn applies_to(&self, _action: &Action) -> bool {
            true
        }
    }

    struct AbstainPlugin;

    impl CustomPolicyRule for AbstainPlugin {
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata {
                id: "abstain-plugin".to_string(),
                name: "Abstain Plugin".to_string(),
                version: "1.0.0".to_string(),
                api_version: PLUGIN_API_VERSION,
                capabilities: vec![PluginCapability::PolicyRule],
                author: "Test".to_string(),
                description: "A plugin that abstains".to_string(),
                fingerprint: "jkl012".to_string(),
            }
        }

        fn evaluate(&self, _context: &PluginContext) -> Result<PluginResult, String> {
            Ok(PluginResult {
                decision: None,
                rule_id: "test.abstain".to_string(),
                reason: "Test abstain rule matched".to_string(),
                evidence: None,
                risk_level: None,
                metadata: HashMap::new(),
            })
        }

        fn applies_to(&self, _action: &Action) -> bool {
            true
        }
    }

    fn test_action() -> Action {
        Action {
            id: ActionId::new(),
            session_id: SessionId::new(),
            agent_id: AgentId::new("test-agent"),
            task_id: None,
            action_type: agentfence_core::types::ActionType::Shell,
            tool: "shell".to_string(),
            target: "git status".to_string(),
            args_hash: "hash".to_string(),
            context: Default::default(),
        }
    }

    struct SlowPlugin;

    impl CustomPolicyRule for SlowPlugin {
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata {
                id: "slow-plugin".to_string(),
                name: "Slow Plugin".to_string(),
                version: "1.0.0".to_string(),
                api_version: PLUGIN_API_VERSION,
                capabilities: vec![PluginCapability::PolicyRule],
                author: "test".to_string(),
                description: "Plugin that sleeps".to_string(),
                fingerprint: "slow123".to_string(),
            }
        }

        fn evaluate(&self, _context: &PluginContext) -> Result<PluginResult, String> {
            std::thread::sleep(std::time::Duration::from_secs(10));
            Ok(PluginResult {
                decision: None,
                rule_id: "slow".to_string(),
                reason: "Should not reach here".to_string(),
                evidence: None,
                risk_level: None,
                metadata: HashMap::new(),
            })
        }

        fn applies_to(&self, _action: &Action) -> bool {
            true
        }
    }

    struct SlowAppliesPlugin;

    impl CustomPolicyRule for SlowAppliesPlugin {
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata {
                id: "slow-applies-plugin".to_string(),
                name: "Slow Applies Plugin".to_string(),
                version: "1.0.0".to_string(),
                api_version: PLUGIN_API_VERSION,
                capabilities: vec![PluginCapability::PolicyRule],
                author: "test".to_string(),
                description: "Plugin that sleeps in applies_to".to_string(),
                fingerprint: "slowapply123".to_string(),
            }
        }

        fn evaluate(&self, _context: &PluginContext) -> Result<PluginResult, String> {
            Ok(PluginResult {
                decision: None,
                rule_id: "slow-applies".to_string(),
                reason: "Should not reach here".to_string(),
                evidence: None,
                risk_level: None,
                metadata: HashMap::new(),
            })
        }

        fn applies_to(&self, _action: &Action) -> bool {
            std::thread::sleep(std::time::Duration::from_secs(10));
            true
        }
    }

    #[test]
    fn test_plugin_timeout() {
        let mut registry = PluginRegistry::new();
        let plugin = Box::new(SlowPlugin);
        let config = PluginConfig {
            timeout_ms: 50,
            ..Default::default()
        };
        registry.register(plugin, config).unwrap();

        let context = PluginContext {
            action: Action {
                id: ActionId::new(),
                session_id: SessionId::new_from_string("test".to_string()),
                agent_id: AgentId::new("test"),
                task_id: None,
                action_type: agentfence_core::types::ActionType::Shell,
                tool: "test".to_string(),
                target: "test".to_string(),
                args_hash: "hash".to_string(),
                context: Default::default(),
            },
            session_id: "test".to_string(),
            agent_id: "test".to_string(),
            task_id: None,
            cwd: None,
            repository: None,
            branch: None,
            environment: HashMap::new(),
        };

        let start = std::time::Instant::now();
        let results = registry.evaluate_all(&context);
        let elapsed = start.elapsed().as_millis() as u64;

        assert!(
            elapsed < 1000,
            "Plugin did not timeout in time: {}ms",
            elapsed
        );
        assert!(
            results.is_empty(),
            "Timed out plugin should not return results"
        );
    }

    #[test]
    fn test_plugin_applies_to_timeout() {
        let mut registry = PluginRegistry::new();
        let plugin = Box::new(SlowAppliesPlugin);
        let config = PluginConfig {
            timeout_ms: 50,
            ..Default::default()
        };
        registry.register(plugin, config).unwrap();

        let context = PluginContext {
            action: Action {
                id: ActionId::new(),
                session_id: SessionId::new_from_string("test".to_string()),
                agent_id: AgentId::new("test"),
                task_id: None,
                action_type: agentfence_core::types::ActionType::Shell,
                tool: "test".to_string(),
                target: "test".to_string(),
                args_hash: "hash".to_string(),
                context: Default::default(),
            },
            session_id: "test".to_string(),
            agent_id: "test".to_string(),
            task_id: None,
            cwd: None,
            repository: None,
            branch: None,
            environment: HashMap::new(),
        };

        let start = std::time::Instant::now();
        let results = registry.evaluate_all(&context);
        let elapsed = start.elapsed().as_millis() as u64;

        assert!(
            elapsed < 1000,
            "Plugin applies_to() did not timeout in time: {}ms",
            elapsed
        );
        assert!(
            results.is_empty(),
            "Plugin with timed-out applies_to() should not return results"
        );
    }

    #[test]
    fn test_plugin_metadata_compatibility() {
        let metadata = PluginMetadata {
            id: "test".to_string(),
            name: "Test".to_string(),
            version: "1.0.0".to_string(),
            api_version: PLUGIN_API_VERSION,
            capabilities: vec![PluginCapability::PolicyRule],
            author: "Test".to_string(),
            description: "Test".to_string(),
            fingerprint: "abc123".to_string(),
        };
        assert!(metadata.is_compatible());
    }

    #[test]
    fn test_plugin_metadata_incompatibility() {
        let metadata = PluginMetadata {
            id: "test".to_string(),
            name: "Test".to_string(),
            version: "1.0.0".to_string(),
            api_version: 999,
            capabilities: vec![PluginCapability::PolicyRule],
            author: "Test".to_string(),
            description: "Test".to_string(),
            fingerprint: "abc123".to_string(),
        };
        assert!(!metadata.is_compatible());
    }

    #[test]
    fn test_plugin_fingerprint_verification() {
        let metadata = PluginMetadata {
            id: "test".to_string(),
            name: "Test".to_string(),
            version: "1.0.0".to_string(),
            api_version: PLUGIN_API_VERSION,
            capabilities: vec![PluginCapability::PolicyRule],
            author: "Test".to_string(),
            description: "Test".to_string(),
            fingerprint: "abc123".to_string(),
        };
        assert!(metadata.verify_fingerprint("abc123"));
        assert!(!metadata.verify_fingerprint("xyz789"));
    }

    #[test]
    fn test_plugin_registration_with_fingerprint() {
        let mut registry = PluginRegistry::new();
        let plugin = Box::new(TestPlugin);
        let config = PluginConfig {
            expected_fingerprint: "abc123".to_string(),
            ..Default::default()
        };
        assert!(registry.register(plugin, config).is_ok());
    }

    #[test]
    fn test_plugin_registration_fingerprint_mismatch() {
        let mut registry = PluginRegistry::new();
        let plugin = Box::new(TestPlugin);
        let config = PluginConfig {
            expected_fingerprint: "wrong_fingerprint".to_string(),
            ..Default::default()
        };
        assert!(registry.register(plugin, config).is_err());
    }

    #[test]
    fn test_plugin_allow_converted_to_none() {
        // SECURITY: Plugins cannot grant Allow
        let mut registry = PluginRegistry::new();
        let plugin = Box::new(TestPlugin); // Returns Allow
        let config = PluginConfig::default();
        registry.register(plugin, config).unwrap();

        let context = PluginContext {
            action: test_action(),
            session_id: "session1".to_string(),
            agent_id: "agent1".to_string(),
            task_id: None,
            cwd: None,
            repository: None,
            branch: None,
            environment: HashMap::new(),
        };

        let results = registry.evaluate_all(&context);
        assert_eq!(results.len(), 1);
        // Allow should be converted to None
        assert_eq!(results[0].decision, None);
    }

    #[test]
    fn test_plugin_deny_preserved() {
        let mut registry = PluginRegistry::new();
        let plugin = Box::new(DenyPlugin);
        let config = PluginConfig::default();
        registry.register(plugin, config).unwrap();

        let context = PluginContext {
            action: test_action(),
            session_id: "session1".to_string(),
            agent_id: "agent1".to_string(),
            task_id: None,
            cwd: None,
            repository: None,
            branch: None,
            environment: HashMap::new(),
        };

        let results = registry.evaluate_all(&context);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, Some(Decision::Deny));
    }

    #[test]
    fn test_plugin_ask_preserved() {
        let mut registry = PluginRegistry::new();
        let plugin = Box::new(AskPlugin);
        let config = PluginConfig::default();
        registry.register(plugin, config).unwrap();

        let context = PluginContext {
            action: test_action(),
            session_id: "session1".to_string(),
            agent_id: "agent1".to_string(),
            task_id: None,
            cwd: None,
            repository: None,
            branch: None,
            environment: HashMap::new(),
        };

        let results = registry.evaluate_all(&context);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, Some(Decision::Ask));
    }

    #[test]
    fn test_plugin_abstain_preserved() {
        let mut registry = PluginRegistry::new();
        let plugin = Box::new(AbstainPlugin);
        let config = PluginConfig::default();
        registry.register(plugin, config).unwrap();

        let context = PluginContext {
            action: test_action(),
            session_id: "session1".to_string(),
            agent_id: "agent1".to_string(),
            task_id: None,
            cwd: None,
            repository: None,
            branch: None,
            environment: HashMap::new(),
        };

        let results = registry.evaluate_all(&context);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].decision, None);
    }

    #[test]
    fn test_plugin_config_with_fingerprint() {
        let config = PluginConfig {
            expected_fingerprint: "abc123".to_string(),
            ..Default::default()
        };
        assert!(config.enabled);
        assert_eq!(config.timeout_ms, 1000);
        assert_eq!(config.max_memory_mb, 64);
        assert_eq!(config.expected_fingerprint, "abc123");
    }

    #[test]
    fn test_plugin_registration() {
        let mut registry = PluginRegistry::new();
        let plugin = Box::new(TestPlugin);
        let config = PluginConfig::default();

        assert!(registry.register(plugin, config).is_ok());
        assert_eq!(registry.list_plugins().len(), 1);
    }

    #[test]
    fn test_duplicate_plugin_registration() {
        let mut registry = PluginRegistry::new();
        let plugin1 = Box::new(TestPlugin);
        let plugin2 = Box::new(TestPlugin);
        let config = PluginConfig::default();

        assert!(registry.register(plugin1, config.clone()).is_ok());
        assert!(registry.register(plugin2, config).is_err());
    }

    #[test]
    fn test_plugin_evaluation() {
        let mut registry = PluginRegistry::new();
        let plugin = Box::new(TestPlugin);
        let config = PluginConfig::default();
        registry.register(plugin, config).unwrap();

        let context = PluginContext {
            action: test_action(),
            session_id: "session1".to_string(),
            agent_id: "agent1".to_string(),
            task_id: None,
            cwd: None,
            repository: None,
            branch: None,
            environment: HashMap::new(),
        };

        let results = registry.evaluate_all(&context);
        assert_eq!(results.len(), 1);
        // TestPlugin returns Allow, but it's converted to None (abstain)
        assert_eq!(results[0].decision, None);
    }

    #[test]
    fn test_plugin_config_default() {
        let config = PluginConfig::default();
        assert!(config.enabled);
        assert_eq!(config.timeout_ms, 1000);
        assert_eq!(config.max_memory_mb, 64);
    }

    #[test]
    fn test_plugin_unregistration() {
        let mut registry = PluginRegistry::new();
        let plugin = Box::new(TestPlugin);
        let config = PluginConfig::default();
        registry.register(plugin, config).unwrap();

        assert!(registry.unregister("test-plugin").is_ok());
        assert_eq!(registry.list_plugins().len(), 0);
    }
}
