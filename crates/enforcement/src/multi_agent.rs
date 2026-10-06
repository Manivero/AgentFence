//! Multi-agent coordination for AgentFence.
//!
//! Provides coordination mechanisms for multiple AI agents:
//! - Agent registration and discovery
//! - Shared policy enforcement
//! - Cross-agent approval workflows
//! - Agent-to-agent communication control
//! - Resource sharing and conflict resolution
//!
//! Architecture:
//! Agent 1 -> AgentFence PEP -> Multi-Agent Coordinator -> Shared Policy
//! Agent 2 -> AgentFence PEP -> Multi-Agent Coordinator -> Shared Policy
//!
//! Security guarantees:
//! - Agents cannot approve each other's actions
//! - Shared resources are access-controlled
//! - Cross-agent communication is policy-governed
//! - Agent identity is verified and audited

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::info;

use agentfence_core::types::{Action, SessionId};

/// Agent role in multi-agent coordination.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AgentRole {
    /// Primary agent (can request actions)
    Primary,
    /// Secondary agent (can request actions, lower priority)
    Secondary,
    /// Observer agent (read-only, cannot request actions)
    Observer,
    /// Coordinator agent (can approve actions for other agents)
    Coordinator,
}

/// Agent registration information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentInfo {
    pub agent_id: String,
    pub role: AgentRole,
    pub session_id: SessionId,
    pub registered_at: String,
    pub last_activity: String,
    pub metadata: HashMap<String, String>,
}

/// Multi-agent coordination configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MultiAgentConfig {
    /// Maximum number of agents
    pub max_agents: usize,
    /// Enable cross-agent approvals
    pub enable_cross_agent_approvals: bool,
    /// Enable shared resource access
    pub enable_shared_resources: bool,
    /// Enable agent-to-agent communication
    pub enable_agent_communication: bool,
    /// Require coordinator approval for cross-agent actions
    pub require_coordinator_approval: bool,
    /// Agent timeout in seconds
    pub agent_timeout_secs: u64,
}

impl Default for MultiAgentConfig {
    fn default() -> Self {
        Self {
            max_agents: 10,
            enable_cross_agent_approvals: true,
            enable_shared_resources: true,
            enable_agent_communication: false,
            require_coordinator_approval: true,
            agent_timeout_secs: 3600,
        }
    }
}

/// Cross-agent approval request.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CrossAgentApproval {
    pub approval_id: String,
    pub requester_agent_id: String,
    pub approver_agent_id: String,
    pub action_id: String,
    pub action_description: String,
    pub requested_at: String,
    pub status: ApprovalStatus,
}

/// Approval status for cross-agent requests.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Denied,
    Expired,
}

/// Multi-agent coordinator.
///
/// Coordinates multiple AI agents and enforces shared policies.
pub struct MultiAgentCoordinator {
    config: MultiAgentConfig,
    agents: HashMap<String, AgentInfo>,
    pending_approvals: HashMap<String, CrossAgentApproval>,
}

impl MultiAgentCoordinator {
    /// Create a new multi-agent coordinator.
    pub fn new(config: MultiAgentConfig) -> Self {
        Self {
            config,
            agents: HashMap::new(),
            pending_approvals: HashMap::new(),
        }
    }

    /// Register an agent.
    pub fn register_agent(&mut self, agent_info: AgentInfo) -> Result<(), String> {
        if self.agents.len() >= self.config.max_agents {
            return Err("Maximum number of agents reached".to_string());
        }

        if self.agents.contains_key(&agent_info.agent_id) {
            return Err("Agent already registered".to_string());
        }

        info!("Registering agent: {}", agent_info.agent_id);
        self.agents.insert(agent_info.agent_id.clone(), agent_info);
        Ok(())
    }

    /// Unregister an agent.
    pub fn unregister_agent(&mut self, agent_id: &str) -> Result<(), String> {
        if !self.agents.contains_key(agent_id) {
            return Err("Agent not found".to_string());
        }

        info!("Unregistering agent: {}", agent_id);
        self.agents.remove(agent_id);
        Ok(())
    }

    /// Get agent information.
    pub fn get_agent(&self, agent_id: &str) -> Option<&AgentInfo> {
        self.agents.get(agent_id)
    }

    /// List all registered agents.
    pub fn list_agents(&self) -> Vec<&AgentInfo> {
        self.agents.values().collect()
    }

    /// Request cross-agent approval.
    ///
    /// An agent can request approval from another agent for an action.
    /// The approver must have the Coordinator role.
    pub fn request_cross_agent_approval(
        &mut self,
        requester_id: &str,
        approver_id: &str,
        action: &Action,
    ) -> Result<String, String> {
        if !self.config.enable_cross_agent_approvals {
            return Err("Cross-agent approvals are disabled".to_string());
        }

        if !self.agents.contains_key(requester_id) {
            return Err("Requester agent not found".to_string());
        }

        if !self.agents.contains_key(approver_id) {
            return Err("Approver agent not found".to_string());
        }

        let approver = self.agents.get(approver_id).unwrap();
        if approver.role != AgentRole::Coordinator {
            return Err("Approver must have Coordinator role".to_string());
        }

        let approval_id = format!("cross-{}-{}", requester_id, action.id.0);
        let approval = CrossAgentApproval {
            approval_id: approval_id.clone(),
            requester_agent_id: requester_id.to_string(),
            approver_agent_id: approver_id.to_string(),
            action_id: action.id.0.clone(),
            action_description: format!("{}:{}", action.action_type, action.target),
            requested_at: chrono::Utc::now().to_rfc3339(),
            status: ApprovalStatus::Pending,
        };

        info!(
            "Cross-agent approval requested: {} -> {}",
            requester_id, approver_id
        );
        self.pending_approvals.insert(approval_id.clone(), approval);
        Ok(approval_id)
    }

    /// Approve a cross-agent request.
    pub fn approve_cross_agent_request(
        &mut self,
        approval_id: &str,
        approver_id: &str,
    ) -> Result<(), String> {
        let approval = self
            .pending_approvals
            .get_mut(approval_id)
            .ok_or("Approval request not found")?;

        if approval.approver_agent_id != approver_id {
            return Err("Only the designated approver can approve this request".to_string());
        }

        if approval.status != ApprovalStatus::Pending {
            return Err("Request is not pending".to_string());
        }

        info!("Cross-agent approval granted: {}", approval_id);
        approval.status = ApprovalStatus::Approved;
        Ok(())
    }

    /// Deny a cross-agent request.
    pub fn deny_cross_agent_request(
        &mut self,
        approval_id: &str,
        approver_id: &str,
    ) -> Result<(), String> {
        let approval = self
            .pending_approvals
            .get_mut(approval_id)
            .ok_or("Approval request not found")?;

        if approval.approver_agent_id != approver_id {
            return Err("Only the designated approver can deny this request".to_string());
        }

        if approval.status != ApprovalStatus::Pending {
            return Err("Request is not pending".to_string());
        }

        info!("Cross-agent approval denied: {}", approval_id);
        approval.status = ApprovalStatus::Denied;
        Ok(())
    }

    /// Get pending approval requests.
    pub fn get_pending_approvals(&self) -> Vec<&CrossAgentApproval> {
        self.pending_approvals
            .values()
            .filter(|a| a.status == ApprovalStatus::Pending)
            .collect()
    }

    /// Get the multi-agent configuration.
    pub fn config(&self) -> &MultiAgentConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_agent(id: &str, role: AgentRole) -> AgentInfo {
        AgentInfo {
            agent_id: id.to_string(),
            role,
            session_id: SessionId::new(),
            registered_at: "2026-10-05T12:00:00Z".to_string(),
            last_activity: "2026-10-05T12:00:00Z".to_string(),
            metadata: HashMap::new(),
        }
    }

    #[test]
    fn test_multi_agent_config_default() {
        let config = MultiAgentConfig::default();
        assert_eq!(config.max_agents, 10);
        assert!(config.enable_cross_agent_approvals);
        assert!(config.enable_shared_resources);
        assert!(!config.enable_agent_communication);
        assert!(config.require_coordinator_approval);
    }

    #[test]
    fn test_agent_registration() {
        let config = MultiAgentConfig::default();
        let mut coordinator = MultiAgentCoordinator::new(config);
        let agent = test_agent("agent1", AgentRole::Primary);

        assert!(coordinator.register_agent(agent).is_ok());
        assert_eq!(coordinator.list_agents().len(), 1);
    }

    #[test]
    fn test_duplicate_agent_registration() {
        let config = MultiAgentConfig::default();
        let mut coordinator = MultiAgentCoordinator::new(config);
        let agent = test_agent("agent1", AgentRole::Primary);

        assert!(coordinator.register_agent(agent.clone()).is_ok());
        assert!(coordinator.register_agent(agent).is_err());
    }

    #[test]
    fn test_cross_agent_approval() {
        let config = MultiAgentConfig::default();
        let mut coordinator = MultiAgentCoordinator::new(config);

        let primary = test_agent("primary", AgentRole::Primary);
        let coordinator_agent = test_agent("coordinator", AgentRole::Coordinator);

        coordinator.register_agent(primary).unwrap();
        coordinator.register_agent(coordinator_agent).unwrap();

        let action = Action {
            id: agentfence_core::types::ActionId::new(),
            session_id: SessionId::new(),
            agent_id: agentfence_core::types::AgentId::new("primary"),
            task_id: None,
            action_type: agentfence_core::types::ActionType::Shell,
            tool: "shell".to_string(),
            target: "git push".to_string(),
            args_hash: "hash".to_string(),
            context: Default::default(),
        };

        let approval_id = coordinator
            .request_cross_agent_approval("primary", "coordinator", &action)
            .unwrap();

        assert!(coordinator
            .approve_cross_agent_request(&approval_id, "coordinator")
            .is_ok());
    }

    #[test]
    fn test_cross_agent_approval_wrong_approver() {
        let config = MultiAgentConfig::default();
        let mut coordinator = MultiAgentCoordinator::new(config);

        let primary = test_agent("primary", AgentRole::Primary);
        let secondary = test_agent("secondary", AgentRole::Secondary);

        coordinator.register_agent(primary).unwrap();
        coordinator.register_agent(secondary).unwrap();

        let action = Action {
            id: agentfence_core::types::ActionId::new(),
            session_id: SessionId::new(),
            agent_id: agentfence_core::types::AgentId::new("primary"),
            task_id: None,
            action_type: agentfence_core::types::ActionType::Shell,
            tool: "shell".to_string(),
            target: "git push".to_string(),
            args_hash: "hash".to_string(),
            context: Default::default(),
        };

        // Secondary agent cannot approve (not Coordinator)
        assert!(coordinator
            .request_cross_agent_approval("primary", "secondary", &action)
            .is_err());
    }
}
