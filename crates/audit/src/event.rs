//! Audit event model for AgentFence.

use serde::{Deserialize, Serialize};

use agentfence_core::types::{ActionId, AgentId, Decision, RiskLevel, SessionId, TaskId};

/// Audit event schema version.
pub const EVENT_SCHEMA_VERSION: u32 = 1;

/// A single audit event.
///
/// Events are tamper-evident through a hash chain.
/// Never store raw secrets — store hashes, fingerprints, or redacted values.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub event_id: String,
    pub schema_version: u32,
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub task_id: Option<TaskId>,
    pub action_id: ActionId,
    pub parent_action_id: Option<ActionId>,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub action_type: String,
    pub tool: String,
    pub target: String,
    pub args_hash: String,
    pub decision: Decision,
    pub risk_level: RiskLevel,
    pub rule_id: String,
    pub policy_version: String,
    pub policy_hash: String,
    pub previous_hash: String,
    pub current_hash: String,
}

impl AuditEvent {
    /// Create a new audit event.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        session_id: SessionId,
        agent_id: AgentId,
        task_id: Option<TaskId>,
        action_id: ActionId,
        parent_action_id: Option<ActionId>,
        action_type: impl Into<String>,
        tool: impl Into<String>,
        target: impl Into<String>,
        args_hash: impl Into<String>,
        decision: Decision,
        risk_level: RiskLevel,
        rule_id: impl Into<String>,
        policy_version: impl Into<String>,
        policy_hash: impl Into<String>,
        previous_hash: impl Into<String>,
    ) -> Self {
        let event_id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now();
        let previous_hash = previous_hash.into();

        let mut event = Self {
            event_id,
            schema_version: EVENT_SCHEMA_VERSION,
            session_id,
            agent_id,
            task_id,
            action_id,
            parent_action_id,
            timestamp,
            action_type: action_type.into(),
            tool: tool.into(),
            target: target.into(),
            args_hash: args_hash.into(),
            decision,
            risk_level,
            rule_id: rule_id.into(),
            policy_version: policy_version.into(),
            policy_hash: policy_hash.into(),
            previous_hash,
            current_hash: String::new(),
        };

        event.current_hash = event.compute_hash();
        event
    }

    /// Compute the hash of this event using the canonical serialization.
    ///
    /// This is the single source of truth for event hashing.
    /// Includes `self.previous_hash` to form a tamper-evident chain.
    pub fn compute_hash(&self) -> String {
        self.compute_hash_with_previous(&self.previous_hash)
    }

    /// Compute the hash with an explicit previous hash value.
    ///
    /// This is the canonical serialization + SHA-256 implementation.
    /// All other hash methods must delegate to this one.
    fn compute_hash_with_previous(&self, previous_hash: &str) -> String {
        use sha2::{Digest, Sha256};

        let data = format!(
            "{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}:{}",
            self.event_id,
            self.schema_version,
            self.session_id,
            self.agent_id,
            self.task_id.as_ref().map(|t| t.0.as_str()).unwrap_or(""),
            self.action_id,
            self.parent_action_id
                .as_ref()
                .map(|a| a.0.as_str())
                .unwrap_or(""),
            self.timestamp.to_rfc3339(),
            self.action_type,
            self.tool,
            self.target,
            self.args_hash,
            self.decision,
            self.risk_level,
            self.rule_id,
            self.policy_version,
            self.policy_hash,
            previous_hash,
        );

        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        hex::encode(hasher.finalize())
    }

    /// Compute the hash of this event including the previous hash for chain integrity.
    ///
    /// Delegates to the canonical `compute_hash_with_previous` implementation.
    pub fn compute_chain_hash(&self, previous_hash: &str) -> String {
        self.compute_hash_with_previous(previous_hash)
    }

    /// Verify the integrity of this event.
    ///
    /// Validates that `current_hash` matches the computed hash.
    pub fn verify(&self) -> bool {
        self.current_hash == self.compute_hash()
    }
}
