//! Network proxy for AgentFence.
//!
//! Evaluates network requests against policy before forwarding.
//! Never claims complete network isolation in cooperative mode.

use agentfence_core::types::{Action, ActionId, ActionType, AgentId, DecisionRecord, SessionId};
use agentfence_policy::pdp::Pdp;

/// Network request.
#[derive(Debug, Clone)]
pub struct NetworkRequest {
    pub host: String,
    pub port: Option<u16>,
    pub protocol: String,
    pub path: Option<String>,
}

/// Network proxy.
///
/// Evaluates network requests against policy before forwarding.
/// Never claims complete network isolation in cooperative mode.
pub struct NetworkProxy {
    pdp: Pdp,
}

impl NetworkProxy {
    /// Create a new network proxy with the given PDP.
    pub fn new(pdp: Pdp) -> Self {
        Self { pdp }
    }

    /// Evaluate a network request.
    ///
    /// Returns a decision record with full explanation.
    pub fn evaluate(
        &self,
        req: &NetworkRequest,
        session_id: &SessionId,
        agent_id: &AgentId,
    ) -> DecisionRecord {
        let target = format!(
            "{}://{}:{}{}",
            req.protocol,
            req.host,
            req.port.unwrap_or(0),
            req.path.as_deref().unwrap_or("")
        );

        let action = Action {
            id: ActionId::new(),
            session_id: session_id.clone(),
            agent_id: agent_id.clone(),
            task_id: None,
            action_type: ActionType::Network,
            tool: "network".to_string(),
            target,
            args_hash: String::new(),
            context: Default::default(),
        };

        self.pdp.evaluate(&action)
    }

    /// Check if a network request is allowed.
    pub fn is_allowed(
        &self,
        req: &NetworkRequest,
        session_id: &SessionId,
        agent_id: &AgentId,
    ) -> bool {
        let record = self.evaluate(req, session_id, agent_id);
        matches!(record.decision, agentfence_core::types::Decision::Allow)
    }
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
network:
  allow:
    - github.com
    - crates.io
"#;
        Pdp::new(parse_policy(yaml).unwrap())
    }

    #[test]
    fn test_network_allow() {
        let proxy = NetworkProxy::new(test_pdp());
        let req = NetworkRequest {
            host: "github.com".to_string(),
            port: Some(443),
            protocol: "https".to_string(),
            path: Some("/api/v3".to_string()),
        };
        let session_id = SessionId::new();
        let agent_id = AgentId::new("test-agent");

        let record = proxy.evaluate(&req, &session_id, &agent_id);
        assert_eq!(record.decision, Decision::Allow);
    }

    #[test]
    fn test_network_default_deny() {
        let proxy = NetworkProxy::new(test_pdp());
        let req = NetworkRequest {
            host: "evil.com".to_string(),
            port: Some(443),
            protocol: "https".to_string(),
            path: None,
        };
        let session_id = SessionId::new();
        let agent_id = AgentId::new("test-agent");

        let record = proxy.evaluate(&req, &session_id, &agent_id);
        assert_eq!(record.decision, Decision::Deny);
    }
}
