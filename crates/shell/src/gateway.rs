//! Shell gateway for AgentFence.
//!
//! Evaluates shell commands against policy before execution.
//! Never uses naive substring checks as the security model.

use agentfence_core::types::{Action, ActionId, ActionType, AgentId, DecisionRecord, SessionId};
use agentfence_policy::pdp::Pdp;

use crate::command::ShellCommand;

/// Shell gateway.
///
/// Evaluates shell commands against policy before execution.
/// Never uses naive substring checks as the security model.
pub struct ShellGateway {
    pdp: Pdp,
}

impl ShellGateway {
    /// Create a new shell gateway with the given PDP.
    pub fn new(pdp: Pdp) -> Self {
        Self { pdp }
    }

    /// Evaluate a shell command.
    ///
    /// Returns a decision record with full explanation.
    pub fn evaluate(
        &self,
        cmd: &ShellCommand,
        session_id: &SessionId,
        agent_id: &AgentId,
    ) -> DecisionRecord {
        let action = Action {
            id: ActionId::new(),
            session_id: session_id.clone(),
            agent_id: agent_id.clone(),
            task_id: None,
            action_type: ActionType::Shell,
            tool: "shell".to_string(),
            target: cmd.raw.clone(),
            args_hash: hash_args(&cmd.raw),
            context: Default::default(),
        };

        self.pdp.evaluate(&action)
    }

    /// Check if a shell command is allowed.
    pub fn is_allowed(
        &self,
        cmd: &ShellCommand,
        session_id: &SessionId,
        agent_id: &AgentId,
    ) -> bool {
        let record = self.evaluate(cmd, session_id, agent_id);
        matches!(record.decision, agentfence_core::types::Decision::Allow)
    }
}

fn hash_args(args: &str) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(args.as_bytes());
    hex::encode(hasher.finalize())
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentfence_core::types::*;
    use agentfence_policy::parser::parse_policy;

    fn test_pdp() -> Pdp {
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
"#;
        Pdp::new(parse_policy(yaml).unwrap())
    }

    #[test]
    fn test_shell_allow() {
        let gateway = ShellGateway::new(test_pdp());
        let cmd = ShellCommand::parse("git status").unwrap();
        let session_id = SessionId::new();
        let agent_id = AgentId::new("test-agent");

        let record = gateway.evaluate(&cmd, &session_id, &agent_id);
        assert_eq!(record.decision, Decision::Allow);
    }

    #[test]
    fn test_shell_deny() {
        let gateway = ShellGateway::new(test_pdp());
        let cmd =
            ShellCommand::parse("powershell -Command 'Remove-Item -Recurse -Force C:\'").unwrap();
        let session_id = SessionId::new();
        let agent_id = AgentId::new("test-agent");

        let record = gateway.evaluate(&cmd, &session_id, &agent_id);
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_shell_default_deny() {
        let gateway = ShellGateway::new(test_pdp());
        let cmd = ShellCommand::parse("unknown-command --flag").unwrap();
        let session_id = SessionId::new();
        let agent_id = AgentId::new("test-agent");

        let record = gateway.evaluate(&cmd, &session_id, &agent_id);
        assert_eq!(record.decision, Decision::Deny);
    }
}
