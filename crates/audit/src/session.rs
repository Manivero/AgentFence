//! Session model for AgentFence.

use serde::{Deserialize, Serialize};

use agentfence_core::types::{AgentId, ProtectionMode, SessionId};

/// A session represents a single agent invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub task_id: Option<agentfence_core::types::TaskId>,
    pub started_at: chrono::DateTime<chrono::Utc>,
    pub ended_at: Option<chrono::DateTime<chrono::Utc>>,
    pub policy_version: String,
    pub policy_hash: String,
    pub protection_mode: ProtectionMode,
}

impl Session {
    /// Create a new session.
    pub fn new(
        agent_id: AgentId,
        task_id: Option<agentfence_core::types::TaskId>,
        policy_version: impl Into<String>,
        policy_hash: impl Into<String>,
        protection_mode: ProtectionMode,
    ) -> Self {
        Self {
            session_id: SessionId::new(),
            agent_id,
            task_id,
            started_at: chrono::Utc::now(),
            ended_at: None,
            policy_version: policy_version.into(),
            policy_hash: policy_hash.into(),
            protection_mode,
        }
    }

    /// End the session.
    pub fn end(&mut self) {
        self.ended_at = Some(chrono::Utc::now());
    }
}
