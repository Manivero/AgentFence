//! MCP proxy for AgentFence.
//!
//! Evaluates tool calls before forwarding them to MCP servers.
//! Never trusts tool metadata blindly.

use serde::{Deserialize, Serialize};

use agentfence_core::types::{Action, ActionId, ActionType, AgentId, DecisionRecord, SessionId};
use agentfence_policy::pdp::Pdp;

/// MCP tool call request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpToolCall {
    pub tool: String,
    pub arguments: serde_json::Value,
    pub server: Option<String>,
}

/// MCP proxy.
///
/// Evaluates tool calls against policy before forwarding.
/// Never trusts tool metadata blindly.
pub struct McpProxy {
    pdp: Pdp,
}

impl McpProxy {
    /// Create a new MCP proxy with the given PDP.
    pub fn new(pdp: Pdp) -> Self {
        Self { pdp }
    }

    /// Evaluate a tool call.
    ///
    /// Returns a decision record with full explanation.
    pub fn evaluate(
        &self,
        call: &McpToolCall,
        session_id: &SessionId,
        agent_id: &AgentId,
    ) -> DecisionRecord {
        let action = Action {
            id: ActionId::new(),
            session_id: session_id.clone(),
            agent_id: agent_id.clone(),
            task_id: None,
            action_type: ActionType::Mcp,
            tool: call.tool.clone(),
            target: call.server.clone().unwrap_or_else(|| "unknown".to_string()),
            args_hash: hash_args(&call.arguments),
            context: Default::default(),
        };

        self.pdp.evaluate(&action)
    }

    /// Check if a tool call is allowed.
    pub fn is_allowed(
        &self,
        call: &McpToolCall,
        session_id: &SessionId,
        agent_id: &AgentId,
    ) -> bool {
        let record = self.evaluate(call, session_id, agent_id);
        matches!(record.decision, agentfence_core::types::Decision::Allow)
    }
}

fn hash_args(args: &serde_json::Value) -> String {
    use sha2::{Digest, Sha256};
    let json = serde_json::to_string(args).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(json.as_bytes());
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
mcp:
  allow:
    - github
    - filesystem
  deny:
    - shell
"#;
        Pdp::new(parse_policy(yaml).unwrap())
    }

    #[test]
    fn test_mcp_allow() {
        let proxy = McpProxy::new(test_pdp());
        let call = McpToolCall {
            tool: "github.create_issue".to_string(),
            arguments: serde_json::json!({"repo": "example/repo"}),
            server: Some("github".to_string()),
        };
        let session_id = SessionId::new();
        let agent_id = AgentId::new("test-agent");

        let record = proxy.evaluate(&call, &session_id, &agent_id);
        assert_eq!(record.decision, Decision::Allow);
    }

    #[test]
    fn test_mcp_deny() {
        let proxy = McpProxy::new(test_pdp());
        let call = McpToolCall {
            tool: "shell.execute".to_string(),
            arguments: serde_json::json!({"command": "rm -rf /"}),
            server: Some("shell".to_string()),
        };
        let session_id = SessionId::new();
        let agent_id = AgentId::new("test-agent");

        let record = proxy.evaluate(&call, &session_id, &agent_id);
        assert_eq!(record.decision, Decision::Deny);
    }

    #[test]
    fn test_mcp_default_deny() {
        let proxy = McpProxy::new(test_pdp());
        let call = McpToolCall {
            tool: "unknown.tool".to_string(),
            arguments: serde_json::json!({}),
            server: Some("unknown".to_string()),
        };
        let session_id = SessionId::new();
        let agent_id = AgentId::new("test-agent");

        let record = proxy.evaluate(&call, &session_id, &agent_id);
        assert_eq!(record.decision, Decision::Deny);
    }
}
