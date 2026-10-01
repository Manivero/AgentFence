//! Approval records and validation for AgentFence.
//!
//! Approval must happen **outside** the agent process.
//! The agent must never be able to approve its own actions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
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
    pub fn matches(&self, action_id: &ActionId, session_id: &SessionId) -> bool {
        if self.action_id != *action_id {
            return false;
        }

        match &self.scope {
            ApprovalScope::Once => true,
            ApprovalScope::Session => self.session_id == *session_id,
            ApprovalScope::Repository => true, // TODO: implement repository matching
            ApprovalScope::Path => true,       // TODO: implement path matching
            ApprovalScope::Host => true,       // TODO: implement host matching
            ApprovalScope::Expiry(_) => true,
        }
    }
}

/// Approval service.
///
/// Manages approval records and validates them.
/// The agent must never be able to create or forge approvals.
pub struct ApprovalService {
    approvals: Arc<Mutex<HashMap<String, ApprovalRecord>>>,
}

impl ApprovalService {
    /// Create a new approval service.
    pub fn new() -> Self {
        Self {
            approvals: Arc::new(Mutex::new(HashMap::new())),
        }
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

        Ok(record)
    }

    /// Approve an action.
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

        record.decision = Decision::Allow;
        Ok(record.clone())
    }

    /// Deny an action.
    pub fn deny(&self, approval_id: &str) -> Result<ApprovalRecord> {
        let mut approvals = self.approvals.lock().unwrap();

        let record = approvals
            .get_mut(approval_id)
            .ok_or_else(|| AgentFenceError::Approval("Approval not found".to_string()))?;

        record.decision = Decision::Deny;
        Ok(record.clone())
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
}
