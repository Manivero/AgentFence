//! Audit system for AgentFence.
//!
//! Sessions, events, SQLite persistence, JSONL export,
//! hash-chain generation, hash-chain verification.
//! Must **not** contain policy decisions.

pub mod event;
pub mod hashchain;
pub mod otel;
pub mod session;
pub mod siem;
pub mod sqlite_store;
pub mod store;

/// Behavior when audit persistence fails.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, serde::Serialize, serde::Deserialize)]
pub enum AuditFailureMode {
    /// Fail closed: deny the action if audit cannot be persisted.
    #[default]
    FailClosed,
    /// Fail open: allow the action but log the audit failure.
    FailOpen,
}

impl std::fmt::Display for AuditFailureMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FailClosed => write!(f, "fail-closed"),
            Self::FailOpen => write!(f, "fail-open"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_audit_failure_mode_default_is_fail_closed() {
        assert_eq!(AuditFailureMode::default(), AuditFailureMode::FailClosed);
    }

    #[test]
    fn test_audit_failure_mode_display() {
        assert_eq!(format!("{}", AuditFailureMode::FailClosed), "fail-closed");
        assert_eq!(format!("{}", AuditFailureMode::FailOpen), "fail-open");
    }
}
