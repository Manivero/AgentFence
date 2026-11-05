//! Core domain types for AgentFence.

use serde::{Deserialize, Serialize};
use std::fmt;
use uuid::Uuid;

// ─── ID Types ───────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ActionId(pub String);

impl ActionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn new_from_string(s: String) -> Self {
        Self(s)
    }
}

impl Default for ActionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for ActionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct SessionId(pub String);

impl SessionId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn new_from_string(s: String) -> Self {
        Self(s)
    }
}

impl Default for SessionId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for SessionId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct AgentId(pub String);

impl AgentId {
    pub fn new(name: impl Into<String>) -> Self {
        Self(name.into())
    }

    pub fn new_from_string(s: String) -> Self {
        Self(s)
    }
}

impl fmt::Display for AgentId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TaskId(pub String);

impl TaskId {
    pub fn new() -> Self {
        Self(Uuid::new_v4().to_string())
    }

    pub fn new_from_string(s: String) -> Self {
        Self(s)
    }
}

impl Default for TaskId {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Display for TaskId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// ─── Decision ────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
    Ask,
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Decision::Allow => write!(f, "ALLOW"),
            Decision::Deny => write!(f, "DENY"),
            Decision::Ask => write!(f, "ASK"),
        }
    }
}

// ─── Risk Level ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for RiskLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            RiskLevel::Low => write!(f, "LOW"),
            RiskLevel::Medium => write!(f, "MEDIUM"),
            RiskLevel::High => write!(f, "HIGH"),
            RiskLevel::Critical => write!(f, "CRITICAL"),
        }
    }
}

// ─── Protection Mode ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ProtectionMode {
    Cooperative,
    Enforced,
}

impl fmt::Display for ProtectionMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtectionMode::Cooperative => write!(f, "COOPERATIVE"),
            ProtectionMode::Enforced => write!(f, "ENFORCED"),
        }
    }
}

// ─── Action ──────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ActionType {
    Shell,
    Mcp,
    Network,
    Filesystem,
}

impl fmt::Display for ActionType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ActionType::Shell => write!(f, "shell"),
            ActionType::Mcp => write!(f, "mcp"),
            ActionType::Network => write!(f, "network"),
            ActionType::Filesystem => write!(f, "filesystem"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Action {
    pub id: ActionId,
    pub session_id: SessionId,
    pub agent_id: AgentId,
    pub task_id: Option<TaskId>,
    pub action_type: ActionType,
    pub tool: String,
    pub target: String,
    pub args_hash: String,
    pub context: Context,
}

impl Action {
    /// Canonical SHA-256 digest of the *content* of this action.
    ///
    /// SECURITY: this is what an approval is bound to. The digest covers every
    /// field that can change either the policy decision or the meaning of the
    /// protected operation:
    ///
    /// | field | why it is included |
    /// |---|---|
    /// | `action_type` | selects the policy section that decides |
    /// | `tool` | the executable / tool name the policy matched |
    /// | `target` | the raw command, URL or server the operation acts on |
    /// | `args_hash` | the arguments or body |
    /// | `session_id` | policy is evaluated per session |
    /// | `agent_id` | policy is evaluated per agent |
    /// | `cwd` | a relative path in `target` resolves differently per directory |
    /// | `repository`, `branch` | plugin decisions can depend on them |
    /// | `task_id` | plugin decisions can depend on it |
    /// | `client_ip`, `host` | location conditions read exactly these |
    ///
    /// Deliberately **excluded**:
    /// - `id` — not content. It is correlation metadata stored alongside the
    ///   digest; including it would make an approval unusable for the same
    ///   operation re-presented in the same context.
    /// - `context.env_metadata` — untyped, untrusted, and consulted by neither
    ///   the PDP nor the plugins (see `Context::env_metadata`).
    ///
    /// Fields are length-prefixed, so no two different field values can be
    /// concatenated into the same input. `None` is encoded as an explicit
    /// absent marker, never as an empty string, so `Some("")` and `None` differ.
    pub fn digest(&self) -> String {
        use sha2::{Digest, Sha256};

        let mut hasher = Sha256::new();

        feed(&mut hasher, self.action_type.to_string().as_bytes());
        feed(&mut hasher, self.tool.as_bytes());
        feed(&mut hasher, self.target.as_bytes());
        feed(&mut hasher, self.args_hash.as_bytes());
        feed(&mut hasher, self.session_id.0.as_bytes());
        feed(&mut hasher, self.agent_id.0.as_bytes());

        // Authorization-relevant context.
        feed_option(&mut hasher, self.context.cwd.as_deref());
        feed_option(&mut hasher, self.context.repository.as_deref());
        feed_option(&mut hasher, self.context.branch.as_deref());
        feed_option(&mut hasher, self.task_id.as_ref().map(|t| t.0.as_str()));
        feed_option(&mut hasher, self.context.client_ip.as_deref());
        feed_option(&mut hasher, self.context.host.as_deref());

        hex::encode(hasher.finalize())
    }
}

/// Length-prefix a value so distinct inputs cannot collide.
fn feed(hasher: &mut sha2::Sha256, bytes: &[u8]) {
    use sha2::Digest;
    hasher.update((bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

/// Encode an optional value: `None` is an explicit marker, never an empty string.
fn feed_option(hasher: &mut sha2::Sha256, value: Option<&str>) {
    use sha2::Digest;
    match value {
        Some(bytes) => {
            hasher.update(1u8.to_le_bytes());
            feed(hasher, bytes.as_bytes());
        }
        None => hasher.update(0u8.to_le_bytes()),
    }
}

// ─── Context ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Context {
    pub cwd: Option<String>,
    pub repository: Option<String>,
    pub branch: Option<String>,
    pub session_id: Option<SessionId>,
    pub task_id: Option<TaskId>,
    pub env_metadata: Option<serde_json::Value>,
    /// Client IP address for location-based policy conditions.
    pub client_ip: Option<String>,
    /// Target host for location-based policy conditions.
    pub host: Option<String>,
}

// ─── Decision Reason ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionReason {
    pub rule_id: String,
    pub reason: String,
    pub evidence: Option<String>,
}

// ─── Decision Object ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DecisionRecord {
    pub decision: Decision,
    pub rule_id: String,
    pub reason: String,
    pub evidence: Option<String>,
    pub risk_level: RiskLevel,
    pub policy_version: String,
    /// The action this decision was made for.
    ///
    /// SECURITY: this is what lets an audit event be correlated back to the
    /// action that produced it, and what an approval record is validated
    /// against. It is stamped by the PDP from the evaluated action; a fresh
    /// identifier minted at the audit-write site would break that correlation.
    pub action_id: ActionId,
}

impl DecisionRecord {
    pub fn allow(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Allow,
            rule_id: rule_id.into(),
            reason: reason.into(),
            evidence: None,
            risk_level: RiskLevel::Low,
            policy_version: String::new(),
            action_id: ActionId::new(),
        }
    }

    pub fn deny(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Deny,
            rule_id: rule_id.into(),
            reason: reason.into(),
            evidence: None,
            risk_level: RiskLevel::High,
            policy_version: String::new(),
            action_id: ActionId::new(),
        }
    }

    pub fn ask(rule_id: impl Into<String>, reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Ask,
            rule_id: rule_id.into(),
            reason: reason.into(),
            evidence: None,
            risk_level: RiskLevel::Medium,
            policy_version: String::new(),
            action_id: ActionId::new(),
        }
    }
}
