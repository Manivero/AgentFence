//! Hermes wrapper for AgentFence.
//!
//! This module provides a wrapper that can be used as Hermes terminal backend
//! to route shell commands through AgentFence policy evaluation.

use agentfence_approval::broker::{ApprovalBroker, ApprovalConfig};
use agentfence_core::types::{AgentId, SessionId};
use agentfence_enforcement::backend::{
    select_backend, ExecutionBackend, ExecutionMode, ExecutionRequest,
};
use agentfence_policy::{parser::load_policy, pdp::Pdp, plugin_loader};
use agentfence_shell::{command::ShellCommand, gateway::ShellGateway};
use tracing::{error, info};

/// Hermes wrapper for AgentFence.
///
/// Wraps shell commands from Hermes through AgentFence policy evaluation.
pub struct HermesWrapper {
    pdp: Pdp,
    session_id: SessionId,
    agent_id: AgentId,
    /// The only path from a policy decision to a running process.
    ///
    /// Both the plain allow path and the approved path go through this backend,
    /// so selecting the container backend removes host execution here rather
    /// than adding a second, host-only route.
    backend: Box<dyn ExecutionBackend>,
}

impl HermesWrapper {
    /// Create a new Hermes wrapper with the given policy.
    pub fn new(policy_path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let policy = load_policy(policy_path)?;
        let pdp = plugin_loader::build_pdp(policy, Vec::new())?;
        Self::with_pdp(pdp)
    }

    /// Build a wrapper around an already-constructed PDP.
    ///
    /// The backend is selected once, from explicit configuration. If the
    /// container backend is selected and its runtime is unavailable, this
    /// fails closed: the wrapper is not created and nothing executes on the
    /// host in its place.
    pub fn with_pdp(pdp: Pdp) -> Result<Self, Box<dyn std::error::Error>> {
        let backend = select_backend(ExecutionMode::from_env()?)?;
        Ok(Self {
            pdp,
            session_id: SessionId::new(),
            agent_id: AgentId::new("hermes"),
            backend,
        })
    }

    /// Execute a shell command through AgentFence.
    ///
    /// Returns true if the command was allowed and executed.
    pub fn execute(&self, command: &str) -> Result<bool, Box<dyn std::error::Error>> {
        let cmd = ShellCommand::parse(command)?;
        let gateway = ShellGateway::new(self.pdp.clone());

        // SECURITY: the action is built once and shared by the policy decision
        // and any approval request, so they are bound to the same action id.
        let action = gateway.action_for(&cmd, &self.session_id, &self.agent_id);
        let record = gateway.evaluate_action(&action);

        match record.decision {
            agentfence_core::types::Decision::Allow => {
                info!("ALLOWED: {} (rule: {})", command, record.rule_id);
                Ok(self.run(&cmd))
            }
            agentfence_core::types::Decision::Deny => {
                info!("DENIED: {} (rule: {})", command, record.rule_id);
                Ok(false)
            }
            agentfence_core::types::Decision::Ask => {
                info!("ASK: {} (rule: {})", command, record.reason);

                // SECURITY: an `Ask` must never silently become `Allow`. The
                // pending request is recorded, the command is NOT executed, and
                // it runs only if a human approves this exact action and the
                // approval is consumed exactly once.
                let broker = match ApprovalBroker::open(ApprovalConfig::from_env()) {
                    Ok(b) => b,
                    Err(e) => {
                        error!("Approval service unavailable: {}", e);
                        return Ok(false);
                    }
                };

                let approval = match broker.request(&action, &record.reason, &record.policy_version)
                {
                    Ok(a) => a,
                    Err(e) => {
                        error!("Failed to record approval request: {}", e);
                        return Ok(false);
                    }
                };

                info!(
                    "Approval requested: {} for action {}",
                    approval.approval_id, approval.action_id.0
                );

                match broker.wait_for(&approval.approval_id, &action, None) {
                    Ok(true) => {
                        info!("APPROVED: {} (rule: {})", command, record.rule_id);
                        Ok(self.run(&cmd))
                    }
                    Ok(false) => {
                        info!(
                            "APPROVAL NOT GRANTED: {} (rule: {})",
                            command, record.rule_id
                        );
                        Ok(false)
                    }
                    Err(e) => {
                        error!("Approval failed: {}", e);
                        Ok(false)
                    }
                }
            }
        }
    }

    /// Execute through the selected backend.
    ///
    /// Returns `false` when the backend refused or the command failed, so a
    /// policy-allowed action can never report success it did not achieve.
    fn run(&self, cmd: &ShellCommand) -> bool {
        let request = ExecutionRequest {
            executable: &cmd.executable,
            arguments: &cmd.arguments,
            cwd: cmd.cwd.as_deref().map(std::path::Path::new),
        };
        match self.backend.execute(&request) {
            Ok(result) => result.exit_code == 0,
            Err(e) => {
                error!("Execution backend failure: {}", e);
                false
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
        HermesWrapper::with_pdp(pdp).expect("wrapper")
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
