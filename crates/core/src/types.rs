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

// ─── Context ─────────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Context {
    pub cwd: Option<String>,
    pub repository: Option<String>,
    pub branch: Option<String>,
    pub session_id: Option<SessionId>,
    pub task_id: Option<TaskId>,
    pub env_metadata: Option<serde_json::Value>,
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
        }
    }
}
