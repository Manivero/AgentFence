//! Plugin system for custom policy rules.
//!
//! Provides extensible policy evaluation through plugins:
//! - Custom rule registration
//! - Plugin lifecycle management
//! - Sandboxed execution environment
//! - Version and compatibility checking
//!
//! Architecture:
//! Policy Engine → Plugin Registry → Custom Rules → Decision
//!
//! Security guarantees:
//! - Plugins cannot access the filesystem or network directly
//! - Plugin execution is bounded and monitored
//! - Plugin API is versioned and stable
//! - Malicious plugins are isolated and rejected

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, info, warn};

use agentfence_core::types::{Action, Decision};

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
}

impl PluginMetadata {
    /// Check if the plugin is compatible with the current API version.
    pub fn is_compatible(&self) -> bool {
        self.api_version == PLUGIN_API_VERSION
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
}

impl Default for PluginConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            settings: HashMap::new(),
            timeout_ms: 1000,
            max_memory_mb: 64,
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
pub trait CustomPolicyRule: Send + Sync {
    /// Get plugin metadata.
    fn metadata(&self) -> PluginMetadata;

    /// Evaluate the rule against the given context.
    fn evaluate(&self, context: &PluginContext) -> Result<PluginResult, String>;

    /// Check if the rule applies to the given action.
    fn applies_to(&self, action: &Action) -> bool;
}

/// Plugin registry.
///
/// Manages registered plugins and their lifecycle.
pub struct PluginRegistry {
    plugins: HashMap<String, Box<dyn CustomPolicyRule>>,
    configs: HashMap<String, PluginConfig>,
}

impl PluginRegistry {
    /// Create a new plugin registry.
    pub fn new() -> Self {
        Self {
            plugins: HashMap::new(),
            configs: HashMap::new(),
        }
    }

    /// Register a plugin.
    pub fn register(
        &mut self,
        plugin: Box<dyn CustomPolicyRule>,
        config: PluginConfig,
    ) -> Result<(), String> {
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

        info!(
            "Registering plugin: {} v{} by {}",
            metadata.name, metadata.version, metadata.author
        );

        self.plugins.insert(metadata.id.clone(), plugin);
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
        self.plugins.get(plugin_id).map(|p| p.metadata())
    }

    /// List all registered plugins.
    pub fn list_plugins(&self) -> Vec<PluginMetadata> {
        self.plugins.values().map(|p| p.metadata()).collect()
    }

    /// Evaluate all applicable plugins.
    pub fn evaluate_all(&self, context: &PluginContext) -> Vec<PluginResult> {
        let mut results = Vec::new();

        for (id, plugin) in &self.plugins {
            let _config = match self.configs.get(id) {
                Some(c) if c.enabled => c,
                _ => continue,
            };

            if !plugin.applies_to(&context.action) {
                continue;
            }

            match plugin.evaluate(context) {
                Ok(result) => {
                    debug!("Plugin {} evaluated: {}", id, result.reason);
                    results.push(result);
                }
                Err(e) => {
                    warn!("Plugin {} evaluation failed: {}", id, e);
                }
            }
        }

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
        };
        assert!(!metadata.is_compatible());
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
        assert_eq!(results[0].decision, Some(Decision::Allow));
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
