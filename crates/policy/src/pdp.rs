//! Policy Decision Point (PDP) for AgentFence.
//!
//! Evaluates actions against policy and produces structured decisions.
//! Never executes actions. Only decides.

use agentfence_core::types::{Action, DecisionRecord, RiskLevel};

use crate::model::{evaluate, Policy};

/// Policy Decision Point.
///
/// The PDP is the single authorization authority in AgentFence.
/// It evaluates actions against policy and returns structured decisions.
/// It never executes actions and never delegates authorization to an LLM.
#[derive(Clone)]
pub struct Pdp {
    policy: Policy,
}

impl Pdp {
    /// Create a new PDP with the given policy.
    pub fn new(policy: Policy) -> Self {
        Self { policy }
    }

    /// Get a reference to the underlying policy.
    pub fn policy(&self) -> &Policy {
        &self.policy
    }

    /// Evaluate an action against the policy.
    ///
    /// This is the single entry point for authorization decisions.
    /// It returns a structured `DecisionRecord` with full explanation.
    pub fn evaluate(&self, action: &Action) -> DecisionRecord {
        let mut record = evaluate(&self.policy, action);
        record.policy_version = self.policy.version_string();
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
}
