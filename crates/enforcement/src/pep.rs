//! Policy Enforcement Point (PEP) for AgentFence.
//!
//! The PEP applies decisions from the PDP to actual enforcement.
//! It never makes authorization decisions itself.

use agentfence_core::types::{Action, DecisionRecord};

/// Enforcement backend trait.
///
/// Future backends: cooperative, container, OpenShell, WSL, VM, Windows, Linux.
/// The PEP delegates actual enforcement to a backend implementation.
pub trait EnforcementBackend {
    /// Apply a decision to an action.
    fn enforce(&self, action: &Action, decision: &DecisionRecord) -> EnforcementResult;
}

/// Result of applying an enforcement decision.
#[derive(Debug, Clone)]
pub struct EnforcementResult {
    pub allowed: bool,
    pub reason: String,
}

/// Cooperative enforcement backend.
///
/// In cooperative mode, the PEP relies on the agent to respect the decision.
/// This is not a complete OS security boundary.
pub struct CooperativeBackend;

impl EnforcementBackend for CooperativeBackend {
    fn enforce(&self, _action: &Action, decision: &DecisionRecord) -> EnforcementResult {
        match decision.decision {
            agentfence_core::types::Decision::Allow => EnforcementResult {
                allowed: true,
                reason: format!("ALLOWED by rule {}", decision.rule_id),
            },
            agentfence_core::types::Decision::Deny => EnforcementResult {
                allowed: false,
                reason: format!("DENIED by rule {}: {}", decision.rule_id, decision.reason),
            },
            agentfence_core::types::Decision::Ask => EnforcementResult {
                allowed: false,
                reason: format!("REQUIRES APPROVAL: {}", decision.reason),
            },
        }
    }
}

/// Policy Enforcement Point.
///
/// The PEP is the single point where decisions are applied.
/// It never makes authorization decisions itself.
pub struct Pep {
    backend: Box<dyn EnforcementBackend>,
}

impl Pep {
    /// Create a new PEP with the given backend.
    pub fn new(backend: Box<dyn EnforcementBackend>) -> Self {
        Self { backend }
    }

    /// Create a new PEP with the cooperative backend.
    pub fn cooperative() -> Self {
        Self::new(Box::new(CooperativeBackend))
    }

    /// Apply a decision to an action.
    pub fn enforce(&self, action: &Action, decision: &DecisionRecord) -> EnforcementResult {
        self.backend.enforce(action, decision)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentfence_core::types::{ActionId, AgentId, SessionId};

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
    fn test_cooperative_allow() {
        let pep = Pep::cooperative();
        let action = test_action();
        let decision = DecisionRecord::allow("test.rule", "Test allow");
        let result = pep.enforce(&action, &decision);
        assert!(result.allowed);
    }

    #[test]
    fn test_cooperative_deny() {
        let pep = Pep::cooperative();
        let action = test_action();
        let decision = DecisionRecord::deny("test.rule", "Test deny");
        let result = pep.enforce(&action, &decision);
        assert!(!result.allowed);
    }

    #[test]
    fn test_cooperative_ask() {
        let pep = Pep::cooperative();
        let action = test_action();
        let decision = DecisionRecord::ask("test.rule", "Test ask");
        let result = pep.enforce(&action, &decision);
        assert!(!result.allowed);
    }
}
