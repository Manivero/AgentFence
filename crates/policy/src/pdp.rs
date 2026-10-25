//! Policy Decision Point (PDP) for AgentFence.
//!
//! Evaluates actions against policy and produces structured decisions.
//! Never executes actions. Only decides.

use std::sync::Arc;

use agentfence_core::types::{Action, Decision, DecisionRecord, RiskLevel};

use crate::model::{evaluate, Policy};
use crate::plugin::{PluginContext, PluginRegistry};

/// Policy Decision Point.
///
/// The PDP is the single authorization authority in AgentFence.
/// It evaluates actions against policy and returns structured decisions.
/// It never executes actions and never delegates authorization to an LLM.
#[derive(Clone)]
pub struct Pdp {
    policy: Policy,
    /// Optional plugin registry. When present, plugin results may *tighten*
    /// the core decision but never loosen it.
    plugins: Option<Arc<PluginRegistry>>,
}

impl Pdp {
    /// Create a new PDP with the given policy.
    pub fn new(policy: Policy) -> Self {
        Self {
            policy,
            plugins: None,
        }
    }

    /// Create a PDP that also consults a plugin registry.
    ///
    /// SECURITY: plugins are an **additive restriction** mechanism. The
    /// registry already converts a plugin `Allow` to abstain, so a plugin can
    /// only ever turn an `Allow` into `Deny`/`Ask` or leave it untouched. A
    /// plugin that fails, times out, or exceeds the worker cap is skipped and
    /// the core policy still decides — a broken plugin cannot grant permission
    /// the core policy withheld, and cannot silently disable the core policy
    /// either. Plugins never grant `Allow`.
    pub fn with_plugin_registry(policy: Policy, plugins: Arc<PluginRegistry>) -> Self {
        Self {
            policy,
            plugins: Some(plugins),
        }
    }

    /// Get a reference to the underlying policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Evaluate an action against the policy.
    ///
    /// This is the single entry point for authorization decisions.
    /// It returns a structured `DecisionRecord` with full explanation.
    ///
    /// SECURITY: the returned record carries the evaluated action's id, so an
    /// audit event can be correlated with the action that produced it.
    pub fn evaluate(&self, action: &Action) -> DecisionRecord {
        let mut record = evaluate(&self.policy, action);
        record.policy_version = self.policy.version_string();
        record.action_id = action.id.clone();

        let Some(plugins) = &self.plugins else {
            return record;
        };

        let plugin_ctx = PluginContext::from_action(action);
        for result in plugins.evaluate_all(&plugin_ctx) {
            let (decision, rule_id, reason) = match result.decision {
                // SECURITY: `Allow` is never honoured from a plugin; the
                // registry converts it to `None`, but it is re-checked here so
                // the PDP does not depend on the registry's sanitisation.
                Some(Decision::Allow) | None => continue,
                Some(Decision::Deny) => (
                    Decision::Deny,
                    result.rule_id,
                    format!("Blocked by policy plugin: {}", result.reason),
                ),
                Some(Decision::Ask) => (
                    Decision::Ask,
                    result.rule_id,
                    format!("Escalated by policy plugin: {}", result.reason),
                ),
            };

            let mut tightened = match decision {
                Decision::Deny => DecisionRecord::deny(rule_id, reason),
                Decision::Ask => DecisionRecord::ask(rule_id, reason),
                _ => unreachable!(),
            };
            tightened.policy_version = record.policy_version.clone();
            tightened.action_id = action.id.clone();
            tightened.evidence = result.evidence.as_ref().map(|e| format!("plugin: {}", e));
            return tightened;
        }

        record
    }

    /// Evaluate with risk assessment.
    ///
    /// Risk is advisory, never authoritative.
    /// Authorization remains `Policy → Decision`.
    pub fn evaluate_with_risk(&self, action: &Action) -> DecisionRecord {
        let mut record = self.evaluate(action);
        record.risk_level = assess_risk(action, &record);
        record
    }
}

/// Assess risk level for an action.
///
/// Risk is advisory only. It never affects the authorization decision.
fn assess_risk(action: &Action, record: &DecisionRecord) -> RiskLevel {
    // Assess based on action type and target
    let base_risk = match action.action_type {
        agentfence_core::types::ActionType::Shell => assess_shell_risk(&action.target),
        agentfence_core::types::ActionType::Network => assess_network_risk(&action.target),
        agentfence_core::types::ActionType::Filesystem => assess_filesystem_risk(&action.target),
        agentfence_core::types::ActionType::Mcp => RiskLevel::Low,
    };

    // If asking for approval, risk is at least medium
    if record.decision == agentfence_core::types::Decision::Ask && base_risk < RiskLevel::Medium {
        return RiskLevel::Medium;
    }

    base_risk
}

fn assess_shell_risk(target: &str) -> RiskLevel {
    let lower = target.to_lowercase();

    if lower.contains("rm ") || lower.contains("del ") || lower.contains("format") {
        return RiskLevel::Critical;
    }
    if lower.contains("push") || lower.contains("deploy") || lower.contains("publish") {
        return RiskLevel::High;
    }
    if lower.contains("commit") || lower.contains("install") || lower.contains("build") {
        return RiskLevel::Medium;
    }
    RiskLevel::Low
}

fn assess_network_risk(target: &str) -> RiskLevel {
    let lower = target.to_lowercase();

    if lower.contains("localhost") || lower.contains("127.0.0.1") {
        return RiskLevel::Low;
    }
    if lower.contains("github.com") || lower.contains("crates.io") {
        return RiskLevel::Low;
    }
    RiskLevel::Medium
}

fn assess_filesystem_risk(target: &str) -> RiskLevel {
    let lower = target.to_lowercase();

    if lower.contains(".ssh") || lower.contains(".aws") || lower.contains(".env") {
        return RiskLevel::Critical;
    }
    if lower.contains(".pem") || lower.contains(".key") || lower.contains("credentials") {
        return RiskLevel::Critical;
    }
    if lower.contains("src/") || lower.contains("docs/") {
        return RiskLevel::Low;
    }
    RiskLevel::Medium
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentfence_core::types::{ActionId, AgentId, SessionId};

    fn test_action(
        action_type: agentfence_core::types::ActionType,
        tool: &str,
        target: &str,
    ) -> Action {
        Action {
            id: ActionId::new(),
            session_id: SessionId::new(),
            agent_id: AgentId::new("test-agent"),
            task_id: None,
            action_type,
            tool: tool.to_string(),
            target: target.to_string(),
            args_hash: "hash".to_string(),
            context: Default::default(),
        }
    }

    fn test_policy() -> Policy {
        let yaml = r#"
version: 1
defaults:
  shell: deny
  network: deny
  mcp: deny
  filesystem: deny
shell:
  allow:
    - git
    - cargo
  deny:
    - powershell
    - reg
network:
  allow:
    - github.com
    - crates.io
mcp:
  allow:
    - github
    - filesystem
"#;
        crate::parser::parse_policy(yaml).unwrap()
    }

    #[test]
    fn test_pdp_allow() {
        let pdp = Pdp::new(test_policy());
        let action = test_action(
            agentfence_core::types::ActionType::Shell,
            "shell",
            "git status",
        );
        let record = pdp.evaluate(&action);
        assert_eq!(record.decision, agentfence_core::types::Decision::Allow);
    }

    #[test]
    fn test_pdp_deny() {
        let pdp = Pdp::new(test_policy());
        let action = test_action(
            agentfence_core::types::ActionType::Shell,
            "shell",
            "powershell -Command 'Remove-Item -Recurse -Force C:\'",
        );
        let record = pdp.evaluate(&action);
        assert_eq!(record.decision, agentfence_core::types::Decision::Deny);
    }

    #[test]
    fn test_pdp_default_deny() {
        let pdp = Pdp::new(test_policy());
        let action = test_action(
            agentfence_core::types::ActionType::Shell,
            "shell",
            "unknown-command --flag",
        );
        let record = pdp.evaluate(&action);
        assert_eq!(record.decision, agentfence_core::types::Decision::Deny);
    }

    #[test]
    fn test_pdp_network_allow() {
        let pdp = Pdp::new(test_policy());
        let action = test_action(
            agentfence_core::types::ActionType::Network,
            "http",
            "https://github.com/api/v3/repos",
        );
        let record = pdp.evaluate(&action);
        assert_eq!(record.decision, agentfence_core::types::Decision::Allow);
    }

    #[test]
    fn test_pdp_mcp_allow() {
        let pdp = Pdp::new(test_policy());
        let action = test_action(
            agentfence_core::types::ActionType::Mcp,
            "github.create_issue",
            "example/repo",
        );
        let record = pdp.evaluate(&action);
        assert_eq!(record.decision, agentfence_core::types::Decision::Allow);
    }

    #[test]
    fn test_pdp_risk_assessment() {
        let pdp = Pdp::new(test_policy());
        let action = test_action(
            agentfence_core::types::ActionType::Shell,
            "shell",
            "rm -rf /",
        );
        let record = pdp.evaluate_with_risk(&action);
        assert_eq!(record.risk_level, RiskLevel::Critical);
    }

    // ── Plugin integration through the real PDP entry point ──────────────

    use crate::plugin::{
        CustomPolicyRule, PluginCapability, PluginConfig, PluginMetadata, PluginResult,
        PLUGIN_API_VERSION,
    };
    use std::collections::HashMap;

    /// A plugin that denies every action it applies to.
    struct DenyAllPlugin;

    impl CustomPolicyRule for DenyAllPlugin {
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata {
                id: "deny-all".to_string(),
                name: "Deny All".to_string(),
                version: "1.0.0".to_string(),
                api_version: PLUGIN_API_VERSION,
                capabilities: vec![PluginCapability::PolicyRule],
                author: "test".to_string(),
                description: "Denies everything".to_string(),
                fingerprint: String::new(),
            }
        }

        fn evaluate(
            &self,
            _context: &crate::plugin::PluginContext,
        ) -> Result<PluginResult, String> {
            Ok(PluginResult {
                decision: Some(agentfence_core::types::Decision::Deny),
                rule_id: "plugin.deny-all".to_string(),
                reason: "deny-all matched".to_string(),
                evidence: Some("plugin evidence".to_string()),
                risk_level: Some("HIGH".to_string()),
                metadata: HashMap::new(),
            })
        }

        fn applies_to(&self, _action: &Action) -> bool {
            true
        }
    }

    /// A plugin that tries to grant `Allow` for everything.
    struct AllowAllPlugin;

    impl CustomPolicyRule for AllowAllPlugin {
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata {
                id: "allow-all".to_string(),
                name: "Allow All".to_string(),
                version: "1.0.0".to_string(),
                api_version: PLUGIN_API_VERSION,
                capabilities: vec![PluginCapability::PolicyRule],
                author: "test".to_string(),
                description: "Tries to allow everything".to_string(),
                fingerprint: String::new(),
            }
        }

        fn evaluate(
            &self,
            _context: &crate::plugin::PluginContext,
        ) -> Result<PluginResult, String> {
            Ok(PluginResult {
                decision: Some(agentfence_core::types::Decision::Allow),
                rule_id: "plugin.allow-all".to_string(),
                reason: "allow-all matched".to_string(),
                evidence: None,
                risk_level: Some("LOW".to_string()),
                metadata: HashMap::new(),
            })
        }

        fn applies_to(&self, _action: &Action) -> bool {
            true
        }
    }

    /// A plugin that always fails.
    struct FailingPlugin;

    impl CustomPolicyRule for FailingPlugin {
        fn metadata(&self) -> PluginMetadata {
            PluginMetadata {
                id: "failing".to_string(),
                name: "Failing".to_string(),
                version: "1.0.0".to_string(),
                api_version: PLUGIN_API_VERSION,
                capabilities: vec![PluginCapability::PolicyRule],
                author: "test".to_string(),
                description: "Always errors".to_string(),
                fingerprint: String::new(),
            }
        }

        fn evaluate(
            &self,
            _context: &crate::plugin::PluginContext,
        ) -> Result<PluginResult, String> {
            Err("plugin exploded".to_string())
        }

        fn applies_to(&self, _action: &Action) -> bool {
            true
        }
    }

    fn registry_with(plugin: Box<dyn CustomPolicyRule>) -> std::sync::Arc<PluginRegistry> {
        let mut registry = PluginRegistry::new();
        registry
            .register(plugin, PluginConfig::default())
            .expect("register failed");
        std::sync::Arc::new(registry)
    }

    #[test]
    fn test_pdp_without_registry_is_unchanged() {
        // SECURITY: `Pdp::new` must not consult any plugin. A caller that has
        // not opted into plugins gets exactly the core policy decision.
        let pdp = Pdp::new(test_policy());
        let action = test_action(
            agentfence_core::types::ActionType::Shell,
            "shell",
            "git status",
        );
        let record = pdp.evaluate(&action);
        assert_eq!(record.decision, Decision::Allow);
        assert_eq!(record.rule_id, "shell.allow");
    }

    #[test]
    fn test_plugin_deny_tightens_a_core_allow() {
        // SECURITY: a plugin must be able to block an action the core policy
        // allows. Before this wiring existed, `PluginRegistry` was never
        // consulted by the PDP and plugin restrictions had no effect.
        let pdp = Pdp::with_plugin_registry(test_policy(), registry_with(Box::new(DenyAllPlugin)));
        let action = test_action(
            agentfence_core::types::ActionType::Shell,
            "shell",
            "git status",
        );
        let record = pdp.evaluate(&action);
        assert_eq!(record.decision, Decision::Deny);
        assert_eq!(record.rule_id, "plugin.deny-all");
        assert!(record.reason.contains("deny-all matched"));
        // Correlation fields must survive a plugin tightening.
        assert_eq!(record.action_id.0, action.id.0);
        assert!(!record.policy_version.is_empty());
    }

    #[test]
    fn test_plugin_allow_cannot_loosen_a_core_deny() {
        // SECURITY: a plugin returning `Allow` must never grant permission.
        let pdp = Pdp::with_plugin_registry(test_policy(), registry_with(Box::new(AllowAllPlugin)));
        let action = test_action(
            agentfence_core::types::ActionType::Shell,
            "shell",
            "unknown-command --flag",
        );
        let record = pdp.evaluate(&action);
        assert_eq!(record.decision, Decision::Deny);
        assert_eq!(record.rule_id, "shell.default");
    }

    #[test]
    fn test_plugin_allow_cannot_loosen_a_core_allow() {
        // The plugin abstains; the core decision stands unchanged.
        let pdp = Pdp::with_plugin_registry(test_policy(), registry_with(Box::new(AllowAllPlugin)));
        let action = test_action(
            agentfence_core::types::ActionType::Shell,
            "shell",
            "git status",
        );
        let record = pdp.evaluate(&action);
        assert_eq!(record.decision, Decision::Allow);
        assert_eq!(record.rule_id, "shell.allow");
    }

    #[test]
    fn test_failing_plugin_does_not_change_the_decision() {
        // SECURITY: a plugin that errors is skipped; the core policy still
        // decides. A broken plugin must not silently disable enforcement, and
        // must not be able to grant anything.
        let pdp = Pdp::with_plugin_registry(test_policy(), registry_with(Box::new(FailingPlugin)));
        let action = test_action(
            agentfence_core::types::ActionType::Shell,
            "shell",
            "git status",
        );
        let record = pdp.evaluate(&action);
        assert_eq!(record.decision, Decision::Allow);
        assert_eq!(record.rule_id, "shell.allow");
    }

    #[test]
    fn test_disabled_plugin_is_not_consulted() {
        let mut registry = PluginRegistry::new();
        registry
            .register(
                Box::new(DenyAllPlugin),
                PluginConfig {
                    enabled: false,
                    ..Default::default()
                },
            )
            .expect("register failed");
        let pdp = Pdp::with_plugin_registry(test_policy(), std::sync::Arc::new(registry));
        let action = test_action(
            agentfence_core::types::ActionType::Shell,
            "shell",
            "git status",
        );
        let record = pdp.evaluate(&action);
        assert_eq!(record.decision, Decision::Allow);
        assert_eq!(record.rule_id, "shell.allow");
    }

    #[test]
    fn test_plugin_context_exposes_no_enforcement_handle() {
        // SECURITY: the plugin receives a copy of the action only. It cannot
        // re-enter the PDP, so it cannot approve its own action.
        let action = test_action(
            agentfence_core::types::ActionType::Shell,
            "shell",
            "git status",
        );
        let ctx = crate::plugin::PluginContext::from_action(&action);
        assert_eq!(ctx.action.id.0, action.id.0);
        assert_eq!(ctx.session_id, action.session_id.0);
        assert_eq!(ctx.agent_id, action.agent_id.0);
    }
}
