//! Approval records and validation for AgentFence.
//!
//! Approval must happen **outside** the agent process.
//! The agent must never be able to approve its own actions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tracing::warn;
use uuid::Uuid;

use agentfence_core::error::{AgentFenceError, Result};
use agentfence_core::types::{ActionId, Decision, SessionId};

/// Approval scope.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalScope {
    Once,
    Session,
    Repository,
    Path,
    Host,
    Expiry(DateTime<Utc>),
}

/// Approval record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub action_id: ActionId,
    pub session_id: SessionId,
    pub scope: ApprovalScope,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub decision: Decision,
    pub policy_version: String,
}

impl ApprovalRecord {
    /// Check if this approval is still valid.
    pub fn is_valid(&self) -> bool {
        if let Some(expires_at) = self.expires_at {
            Utc::now() <= expires_at
        } else {
            true
        }
    }

    /// Check if this approval matches the given action.
    ///
    /// Scope matching is strict:
    /// - `Once`: matches only the exact action_id
    /// - `Session`: matches any action in the same session
    /// - `Repository`: matches if the action target contains the repository
    /// - `Path`: matches if the action target starts with the path prefix
    /// - `Host`: matches if the action target contains the host
    /// - `Expiry`: matches if not expired (checked separately)
    ///
    /// For Repository/Path/Host scopes, this method requires context (target).
    /// Use `matches_with_context` when target is available.
    /// This method returns `false` for scopes that require context.
    pub fn matches(&self, action_id: &ActionId, session_id: &SessionId) -> bool {
        if self.action_id != *action_id {
            return false;
        }

        match &self.scope {
            ApprovalScope::Once => true,
            ApprovalScope::Session => self.session_id == *session_id,
            ApprovalScope::Repository => {
                // Repository scope requires target context — cannot match without it
                false
            }
            ApprovalScope::Path => {
                // Path scope requires target context — cannot match without it
                false
            }
            ApprovalScope::Host => {
                // Host scope requires target context — cannot match without it
                false
            }
            ApprovalScope::Expiry(_) => true,
        }
    }

    /// Check if this approval matches the given action with full context.
    ///
    /// This is the preferred matching method when action context is available.
    pub fn matches_with_context(
        &self,
        action_id: &ActionId,
        session_id: &SessionId,
        target: &str,
    ) -> bool {
        if self.action_id != *action_id {
            return false;
        }

        match &self.scope {
            ApprovalScope::Once => true,
            ApprovalScope::Session => self.session_id == *session_id,
            ApprovalScope::Repository => {
                // Repository scope: target must contain the repository identifier
                // Repository is derived from the approval_id (stored as prefix)
                let repo = self.extract_scope_value();
                !repo.is_empty() && target.contains(&repo)
            }
            ApprovalScope::Path => {
                // Path scope: target must start with the path prefix
                let path = self.extract_scope_value();
                !path.is_empty() && target.starts_with(&path)
            }
            ApprovalScope::Host => {
                // Host scope: target must contain the host
                let host = self.extract_scope_value();
                !host.is_empty() && target.contains(&host)
            }
            ApprovalScope::Expiry(_) => true,
        }
    }

    /// Extract the scope value from the approval_id.
    ///
    /// For scoped approvals, the approval_id format is: `{uuid}:{scope_value}`
    fn extract_scope_value(&self) -> String {
        if let Some(idx) = self.approval_id.find(':') {
            self.approval_id[idx + 1..].to_string()
        } else {
            String::new()
        }
    }
}

/// Approval service.
///
/// Manages approval records and validates them.
/// The agent must never be able to create or forge approvals.
///
/// Supports both in-memory and persistent (SQLite) storage.
pub struct ApprovalService {
    approvals: Arc<Mutex<HashMap<String, ApprovalRecord>>>,
    db_path: Option<std::path::PathBuf>,
}

impl ApprovalService {
    /// Create a new in-memory approval service.
    pub fn new() -> Self {
        Self {
            approvals: Arc::new(Mutex::new(HashMap::new())),
            db_path: None,
        }
    }

    /// Create a new persistent approval service backed by SQLite.
    pub fn new_with_db(db_path: std::path::PathBuf) -> Result<Self> {
        let service = Self {
            approvals: Arc::new(Mutex::new(HashMap::new())),
            db_path: Some(db_path),
        };
        service.init_db()?;
        Ok(service)
    }

    /// Initialize the approvals table in SQLite.
    fn init_db(&self) -> Result<()> {
        let Some(path) = &self.db_path else {
            return Ok(());
        };
        let conn = rusqlite::Connection::open(path)?;
        conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS approvals (
                approval_id TEXT PRIMARY KEY,
                action_id TEXT NOT NULL,
                session_id TEXT NOT NULL,
                scope TEXT NOT NULL,
                scope_value TEXT,
                issued_at TEXT NOT NULL,
                expires_at TEXT,
                decision TEXT NOT NULL,
                policy_version TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_approvals_action ON approvals(action_id);
            CREATE INDEX IF NOT EXISTS idx_approvals_session ON approvals(session_id);",
        )?;
        Ok(())
    }

    /// Get the database path if persistent storage is enabled.
    pub fn db_path(&self) -> Option<&std::path::PathBuf> {
        self.db_path.as_ref()
    }

    /// Check if persistent storage is enabled.
    pub fn is_persistent(&self) -> bool {
        self.db_path.is_some()
    }

    /// List all pending (undecided) approvals.
    pub fn list_pending(&self) -> Vec<ApprovalRecord> {
        let approvals = self.approvals.lock().unwrap();
        approvals
            .values()
            .filter(|r| r.decision == Decision::Ask)
            .cloned()
            .collect()
    }

    /// Get approval by action_id (returns first pending match).
    pub fn get_by_action_id(&self, action_id: &str) -> Option<ApprovalRecord> {
        let approvals = self.approvals.lock().unwrap();
        approvals
            .values()
            .find(|r| r.action_id.0 == action_id && r.decision == Decision::Ask)
            .cloned()
    }

    /// Load all approvals from SQLite into memory.
    pub fn load_from_db(&self) -> Result<()> {
        let Some(path) = &self.db_path else {
            return Ok(());
        };
        let conn = rusqlite::Connection::open(path)?;
        let mut stmt = conn.prepare(
            "SELECT approval_id, action_id, session_id, scope, scope_value,
                    issued_at, expires_at, decision, policy_version
             FROM approvals",
        )?;
        let rows = stmt.query_map([], |row| {
            let scope_str: String = row.get(3)?;
            let scope = match scope_str.as_str() {
                "Once" => ApprovalScope::Once,
                "Session" => ApprovalScope::Session,
                "Repository" => ApprovalScope::Repository,
                "Path" => ApprovalScope::Path,
                "Host" => ApprovalScope::Host,
                _ => ApprovalScope::Once,
            };
            let decision_str: String = row.get(7)?;
            let decision = match decision_str.as_str() {
                "Allow" => Decision::Allow,
                "Deny" => Decision::Deny,
                _ => Decision::Ask,
            };
            let issued_at_str: String = row.get(5)?;
            let issued_at = chrono::DateTime::parse_from_rfc3339(&issued_at_str)
                .map(|dt| dt.with_timezone(&chrono::Utc))
                .unwrap_or_else(|_| chrono::Utc::now());
            let expires_at: Option<String> = row.get(6)?;
            let expires_at = expires_at.and_then(|s| {
                chrono::DateTime::parse_from_rfc3339(&s)
                    .ok()
                    .map(|dt| dt.with_timezone(&chrono::Utc))
            });
            Ok(ApprovalRecord {
                approval_id: row.get(0)?,
                action_id: ActionId(row.get(1)?),
                session_id: SessionId::new_from_string(row.get(2)?),
                scope,
                issued_at,
                expires_at,
                decision,
                policy_version: row.get(8)?,
            })
        })?;
        let mut approvals = self.approvals.lock().unwrap();
        for row in rows {
            let record = row?;
            approvals.insert(record.approval_id.clone(), record);
        }
        Ok(())
    }

    /// Save an approval record to SQLite.
    fn save_to_db(&self, record: &ApprovalRecord) -> Result<()> {
        let Some(path) = &self.db_path else {
            return Ok(());
        };
        let conn = rusqlite::Connection::open(path)?;
        let scope_str = match &record.scope {
            ApprovalScope::Once => "Once",
            ApprovalScope::Session => "Session",
            ApprovalScope::Repository => "Repository",
            ApprovalScope::Path => "Path",
            ApprovalScope::Host => "Host",
            ApprovalScope::Expiry(_) => "Once",
        };
        let scope_value = match &record.scope {
            ApprovalScope::Repository | ApprovalScope::Path | ApprovalScope::Host => {
                record.extract_scope_value()
            }
            _ => String::new(),
        };
        let decision_str = match record.decision {
            Decision::Allow => "Allow",
            Decision::Deny => "Deny",
            Decision::Ask => "Ask",
        };
        conn.execute(
            "INSERT OR REPLACE INTO approvals (
                approval_id, action_id, session_id, scope, scope_value,
                issued_at, expires_at, decision, policy_version
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            rusqlite::params![
                record.approval_id,
                record.action_id.0,
                record.session_id.0,
                scope_str,
                scope_value,
                record.issued_at.to_rfc3339(),
                record.expires_at.map(|t| t.to_rfc3339()),
                decision_str,
                record.policy_version,
            ],
        )?;
        Ok(())
    }

    /// Request approval for an action.
    pub fn request_approval(
        &self,
        action_id: ActionId,
        session_id: SessionId,
        scope: ApprovalScope,
        policy_version: impl Into<String>,
    ) -> Result<ApprovalRecord> {
        let approval_id = Uuid::new_v4().to_string();
        let issued_at = Utc::now();

        let expires_at = match &scope {
            ApprovalScope::Expiry(dt) => Some(*dt),
            _ => None,
        };

        let record = ApprovalRecord {
            approval_id,
            action_id,
            session_id,
            scope,
            issued_at,
            expires_at,
            decision: Decision::Ask,
            policy_version: policy_version.into(),
        };

        let mut approvals = self.approvals.lock().unwrap();
        approvals.insert(record.approval_id.clone(), record.clone());
        drop(approvals);

        // Persist to SQLite if enabled
        if let Err(e) = self.save_to_db(&record) {
            warn!("Failed to persist approval to DB: {}", e);
        }

        Ok(record)
    }

    /// Approve an action.
    ///
    /// Returns error if:
    /// - Approval not found
    /// - Approval has expired
    /// - Approval was already decided (replay protection)
    pub fn approve(&self, approval_id: &str) -> Result<ApprovalRecord> {
        let mut approvals = self.approvals.lock().unwrap();

        let record = approvals
            .get_mut(approval_id)
            .ok_or_else(|| AgentFenceError::Approval("Approval not found".to_string()))?;

        if !record.is_valid() {
            return Err(AgentFenceError::Approval(
                "Approval has expired".to_string(),
            ));
        }

        // Replay protection: cannot approve an already-decided approval
        if record.decision != Decision::Ask {
            return Err(AgentFenceError::Approval(
                "Approval already decided".to_string(),
            ));
        }

        record.decision = Decision::Allow;
        let updated = record.clone();
        drop(approvals);

        // Persist decision to SQLite if enabled
        if let Err(e) = self.save_to_db(&updated) {
            warn!("Failed to persist approval decision to DB: {}", e);
        }

        Ok(updated)
    }

    /// Deny an action.
    ///
    /// Returns error if:
    /// - Approval not found
    /// - Approval was already decided (replay protection)
    pub fn deny(&self, approval_id: &str) -> Result<ApprovalRecord> {
        let mut approvals = self.approvals.lock().unwrap();

        let record = approvals
            .get_mut(approval_id)
            .ok_or_else(|| AgentFenceError::Approval("Approval not found".to_string()))?;

        // Replay protection: cannot deny an already-decided approval
        if record.decision != Decision::Ask {
            return Err(AgentFenceError::Approval(
                "Approval already decided".to_string(),
            ));
        }

        record.decision = Decision::Deny;
        let updated = record.clone();
        drop(approvals);

        // Persist decision to SQLite if enabled
        if let Err(e) = self.save_to_db(&updated) {
            warn!("Failed to persist approval decision to DB: {}", e);
        }

        Ok(updated)
    }

    /// Validate an approval for an action.
    pub fn validate(&self, action_id: &ActionId, session_id: &SessionId) -> Option<ApprovalRecord> {
        let approvals = self.approvals.lock().unwrap();

        for record in approvals.values() {
            if record.matches(action_id, session_id) && record.is_valid() {
                return Some(record.clone());
            }
        }

        None
    }
}

impl Default for ApprovalService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_approval_lifecycle() {
        let service = ApprovalService::new();
        let action_id = ActionId::new();
        let session_id = SessionId::new();

        // Request approval
        let record = service
            .request_approval(
                action_id.clone(),
                session_id.clone(),
                ApprovalScope::Once,
                "v1",
            )
            .unwrap();

        assert_eq!(record.decision, Decision::Ask);

        // Approve
        let approved = service.approve(&record.approval_id).unwrap();
        assert_eq!(approved.decision, Decision::Allow);

        // Validate
        let validated = service.validate(&action_id, &session_id);
        assert!(validated.is_some());
    }

    #[test]
    fn test_expired_approval() {
        use chrono::Duration;

        let service = ApprovalService::new();
        let action_id = ActionId::new();
        let session_id = SessionId::new();

        let expired = Utc::now() - Duration::minutes(1);
        let record = service
            .request_approval(
                action_id.clone(),
                session_id.clone(),
                ApprovalScope::Expiry(expired),
                "v1",
            )
            .unwrap();

        assert!(!record.is_valid());

        let result = service.approve(&record.approval_id);
        assert!(result.is_err());
    }

    #[test]
    fn test_session_scope() {
        let service = ApprovalService::new();
        let action_id = ActionId::new();
        let session_id = SessionId::new();

        let record = service
            .request_approval(
                action_id.clone(),
                session_id.clone(),
                ApprovalScope::Session,
                "v1",
            )
            .unwrap();

        service.approve(&record.approval_id).unwrap();

        // Same session should validate
        let validated = service.validate(&action_id, &session_id);
        assert!(validated.is_some());

        // Different session should not validate
        let other_session = SessionId::new();
        let not_validated = service.validate(&action_id, &other_session);
        assert!(not_validated.is_none());
    }

    #[test]
    fn test_path_scope_matching() {
        let service = ApprovalService::new();
        let action_id = ActionId::new();
        let session_id = SessionId::new();

        // Create approval with path scope
        let record = service
            .request_approval(
                action_id.clone(),
                session_id.clone(),
                ApprovalScope::Path,
                "v1",
            )
            .unwrap();

        // Manually set the scope value in approval_id for testing
        let mut record = record;
        record.approval_id = format!("{}:{}", record.approval_id, "/home/user/project");

        // Should match target that starts with the path
        assert!(record.matches_with_context(
            &action_id,
            &session_id,
            "/home/user/project/src/main.rs"
        ));

        // Should NOT match target outside the path
        assert!(!record.matches_with_context(&action_id, &session_id, "/etc/passwd"));
    }

    #[test]
    fn test_host_scope_matching() {
        let service = ApprovalService::new();
        let action_id = ActionId::new();
        let session_id = SessionId::new();

        let record = service
            .request_approval(
                action_id.clone(),
                session_id.clone(),
                ApprovalScope::Host,
                "v1",
            )
            .unwrap();

        let mut record = record;
        record.approval_id = format!("{}:{}", record.approval_id, "github.com");

        // Should match target containing the host
        assert!(record.matches_with_context(&action_id, &session_id, "https://github.com/api/v3"));

        // Should NOT match target without the host
        assert!(!record.matches_with_context(&action_id, &session_id, "https://evil.com/api"));
    }

    #[test]
    fn test_approval_replay_protection() {
        let service = ApprovalService::new();
        let action_id = ActionId::new();
        let session_id = SessionId::new();

        let record = service
            .request_approval(
                action_id.clone(),
                session_id.clone(),
                ApprovalScope::Once,
                "v1",
            )
            .unwrap();

        // First approval should succeed
        let first = service.approve(&record.approval_id);
        assert!(first.is_ok());
        assert_eq!(first.unwrap().decision, Decision::Allow);

        // Second approval (replay) should fail - already approved
        let second = service.approve(&record.approval_id);
        assert!(second.is_err());
    }

    #[test]
    fn test_matches_returns_false_for_scopes_requiring_context() {
        let service = ApprovalService::new();
        let action_id = ActionId::new();
        let session_id = SessionId::new();

        // Repository scope — matches() without context must return false
        let record = service
            .request_approval(
                action_id.clone(),
                session_id.clone(),
                ApprovalScope::Repository,
                "v1",
            )
            .unwrap();
        assert!(!record.matches(&action_id, &session_id));

        // Path scope — matches() without context must return false
        let record = service
            .request_approval(
                action_id.clone(),
                session_id.clone(),
                ApprovalScope::Path,
                "v1",
            )
            .unwrap();
        assert!(!record.matches(&action_id, &session_id));

        // Host scope — matches() without context must return false
        let record = service
            .request_approval(
                action_id.clone(),
                session_id.clone(),
                ApprovalScope::Host,
                "v1",
            )
            .unwrap();
        assert!(!record.matches(&action_id, &session_id));

        // Once scope — matches() should return true
        let record = service
            .request_approval(
                action_id.clone(),
                session_id.clone(),
                ApprovalScope::Once,
                "v1",
            )
            .unwrap();
        assert!(record.matches(&action_id, &session_id));

        // Session scope — matches() should return true
        let record = service
            .request_approval(
                action_id.clone(),
                session_id.clone(),
                ApprovalScope::Session,
                "v1",
            )
            .unwrap();
        assert!(record.matches(&action_id, &session_id));
    }

    #[test]
    fn test_persistent_approval_roundtrip() {
        let db_path = std::env::temp_dir().join(format!("af_approval_{}.db", uuid::Uuid::new_v4()));
        let service = ApprovalService::new_with_db(db_path.clone()).unwrap();
        let action_id = ActionId::new();
        let session_id = SessionId::new();

        // Create and approve
        let record = service
            .request_approval(
                action_id.clone(),
                session_id.clone(),
                ApprovalScope::Once,
                "v1",
            )
            .unwrap();
        service.approve(&record.approval_id).unwrap();

        // Create a new service instance (simulating process restart)
        let service2 = ApprovalService::new_with_db(db_path.clone()).unwrap();
        service2.load_from_db().unwrap();

        // Should find the approved record
        let validated = service2.validate(&action_id, &session_id);
        assert!(validated.is_some());
        assert_eq!(validated.unwrap().decision, Decision::Allow);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_persistent_list_pending() {
        let db_path = std::env::temp_dir().join(format!("af_approval_{}.db", uuid::Uuid::new_v4()));
        let service = ApprovalService::new_with_db(db_path.clone()).unwrap();
        let action_id = ActionId::new();
        let session_id = SessionId::new();

        // Create pending approval
        service
            .request_approval(
                action_id.clone(),
                session_id.clone(),
                ApprovalScope::Once,
                "v1",
            )
            .unwrap();

        // New instance, load from DB
        let service2 = ApprovalService::new_with_db(db_path.clone()).unwrap();
        service2.load_from_db().unwrap();

        let pending = service2.list_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].action_id, action_id);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_wrong_action_id_rejected() {
        let service = ApprovalService::new();
        let action_id = ActionId::new();
        let other_action_id = ActionId::new();
        let session_id = SessionId::new();

        let record = service
            .request_approval(
                action_id.clone(),
                session_id.clone(),
                ApprovalScope::Once,
                "v1",
            )
            .unwrap();

        service.approve(&record.approval_id).unwrap();

        // Should NOT validate for a different action_id
        let not_validated = service.validate(&other_action_id, &session_id);
        assert!(not_validated.is_none());
    }
}
