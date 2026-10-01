//! Hermes wrapper for AgentFence.
//!
//! This module provides a wrapper that can be used as Hermes terminal backend
//! to route shell commands through AgentFence policy evaluation.

use std::process::Command;

use agentfence_core::types::{AgentId, SessionId};
use agentfence_policy::{parser::load_policy, pdp::Pdp};
use agentfence_shell::{command::ShellCommand, gateway::ShellGateway};
use tracing::info;

/// Hermes wrapper for AgentFence.
///
/// Wraps shell commands from Hermes through AgentFence policy evaluation.
pub struct HermesWrapper {
    pdp: Pdp,
    session_id: SessionId,
    agent_id: AgentId,
}

impl HermesWrapper {
    /// Create a new Hermes wrapper with the given policy.
    pub fn new(policy_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let policy = load_policy(policy_path)?;
        let pdp = Pdp::new(policy);

        Ok(Self {
            pdp,
            session_id: SessionId::new(),
            agent_id: AgentId::new("hermes"),
        })
    }

    /// Execute a shell command through AgentFence.
    ///
    /// Returns true if the command was allowed and executed.
    pub fn execute(&self, command: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let cmd = ShellCommand::parse(command)?;
        let gateway = ShellGateway::new(self.pdp.clone());

        let record = gateway.evaluate(&cmd, &self.session_id, &self.agent_id);

        match record.decision {
            agentfence_core::types::Decision::Allow => {
                info!("ALLOWED: {} (rule: {})", command, record.rule_id);
                let status = Command::new(&cmd.executable)
                    .args(&cmd.arguments)
                    .status()?;

                Ok(status.success())
            }
            agentfence_core::types::Decision::Deny => {
                info!("DENIED: {} (rule: {})", command, record.rule_id);
                Ok(false)
            }
            agentfence_core::types::Decision::Ask => {
                info!("ASK: {} (rule: {})", command, record.reason);
                Ok(false)
            }
        }
    }

    /// Get the session ID.
    pub fn session_id(&self) -> &SessionId {
        &self.session_id
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentfence_policy::parser::parse_policy;

    const TEST_POLICY: &str = r#"
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
"#;

    fn test_wrapper() -> HermesWrapper {
        let policy = parse_policy(TEST_POLICY).unwrap();
        let pdp = Pdp::new(policy);
        HermesWrapper {
            pdp,
            session_id: SessionId::new(),
            agent_id: AgentId::new("hermes"),
        }
    }

    #[test]
    fn test_wrapper_creation() {
        let wrapper = test_wrapper();
        assert!(!wrapper.session_id().to_string().is_empty());
    }

    #[test]
    fn test_wrapper_session() {
        let wrapper = test_wrapper();
        assert!(!wrapper.session_id().to_string().is_empty());
    }

    #[test]
    fn test_wrapper_execute_allowed() {
        let wrapper = test_wrapper();
        let result = wrapper.execute("git status");
        assert!(result.is_ok());
    }

    #[test]
    fn test_wrapper_execute_denied() {
        let wrapper = test_wrapper();
        let result = wrapper.execute("powershell -Command 'Remove-Item'");
        assert!(result.is_ok());
        assert!(!result.unwrap());
    }
}
