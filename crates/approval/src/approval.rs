//! Approval records and validation for AgentFence.
//!
//! Approval must happen **outside** the agent process.
//! The agent must never be able to approve its own actions.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use rusqlite::TransactionBehavior;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use agentfence_core::error::{AgentFenceError, Result};
use agentfence_core::types::{Action, ActionId, ActionType, AgentId, Decision, SessionId};

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

/// Where an approval request is in its lifecycle.
///
/// SECURITY: the status is the authoritative field. `ApprovalRecord::decision`
/// records what the human said; `status` records whether that answer has already
/// been spent. A request that is `Approved` but not yet `Consumed` may still be
/// used exactly once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalStatus {
    Pending,
    Approved,
    Rejected,
    Expired,
    Consumed,
}

impl ApprovalStatus {
    fn as_str(self) -> &'static str {
        match self {
            ApprovalStatus::Pending => "Pending",
            ApprovalStatus::Approved => "Approved",
            ApprovalStatus::Rejected => "Rejected",
            ApprovalStatus::Expired => "Expired",
            ApprovalStatus::Consumed => "Consumed",
        }
    }

    fn from_str(s: &str) -> Self {
        match s {
            "Approved" => ApprovalStatus::Approved,
            "Rejected" => ApprovalStatus::Rejected,
            "Expired" => ApprovalStatus::Expired,
            "Consumed" => ApprovalStatus::Consumed,
            _ => ApprovalStatus::Pending,
        }
    }
}

/// Approval record.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApprovalRecord {
    pub approval_id: String,
    pub action_id: ActionId,
    pub session_id: SessionId,
    /// Agent identity that requested the action, where available.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent_id: Option<AgentId>,
    /// SHA-256 digest of the exact action content being authorized.
    ///
    /// SECURITY: consuming an approval requires the presented action to produce
    /// this digest. An approval therefore cannot authorize a modified command,
    /// target, tool call or network action.
    pub action_digest: String,
    /// Human-readable tool, for operator inspection.
    #[serde(default)]
    pub tool: String,
    /// Human-readable target, for operator inspection.
    #[serde(default)]
    pub target: String,
    /// Why the policy asked (rule id and reason).
    #[serde(default)]
    pub reason: String,
    pub scope: ApprovalScope,
    pub issued_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub decision: Decision,
    /// Lifecycle status. Authoritative over `decision` for replay control.
    pub status: ApprovalStatus,
    /// Set when the approval was consumed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub consumed_at: Option<DateTime<Utc>>,
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

    /// True when the request has not been answered yet.
    pub fn is_pending(&self) -> bool {
        self.status == ApprovalStatus::Pending && self.is_valid()
    }

    /// True when the approval has been granted but not yet spent.
    pub fn is_approved_and_unspent(&self) -> bool {
        self.status == ApprovalStatus::Approved && self.is_valid()
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
    /// Authoritative store for state transitions. Present when the service is
    /// backed by SQLite, so concurrent processes cannot both consume the same
    /// approval.
    conn: Option<Arc<Mutex<rusqlite::Connection>>>,
    db_path: Option<std::path::PathBuf>,
}

impl ApprovalService {
    /// Create a new in-memory approval service.
    pub fn new() -> Self {
        Self {
            approvals: Arc::new(Mutex::new(HashMap::new())),
            conn: None,
            db_path: None,
        }
    }

    /// Create a new persistent approval service backed by SQLite.
    pub fn new_with_db(db_path: std::path::PathBuf) -> Result<Self> {
        // The approval store must be usable from a bare path: a gateway that
        // records a request must not fail because the data directory is missing.
        if let Some(parent) = db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent).map_err(|e| {
                    AgentFenceError::Enforcement(format!(
                        "cannot create approval database directory {}: {}",
                        parent.display(),
                        e
                    ))
                })?;
            }
        }

        let conn = rusqlite::Connection::open(&db_path)?;
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
        migrate(&conn)?;
        conn.execute_batch(
            "CREATE INDEX IF NOT EXISTS idx_approvals_status ON approvals(status);",
        )?;

        let service = Self {
            approvals: Arc::new(Mutex::new(HashMap::new())),
            conn: Some(Arc::new(Mutex::new(conn))),
            db_path: Some(db_path),
        };
        // A persistent service starts in sync with the store, so `list_pending`
        // reflects what another process recorded without an explicit reload.
        service.load_from_db()?;
        Ok(service)
    }

    /// Get the database path if persistent storage is enabled.
    pub fn db_path(&self) -> Option<&std::path::PathBuf> {
        self.db_path.as_ref()
    }

    /// Check if persistent storage is enabled.
    pub fn is_persistent(&self) -> bool {
        self.db_path.is_some()
    }

    /// List all pending (undecided and unexpired) approvals.
    pub fn list_pending(&self) -> Vec<ApprovalRecord> {
        let approvals = self.approvals.lock().unwrap();
        approvals
            .values()
            .filter(|r| r.status == ApprovalStatus::Pending && r.is_valid())
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
            "SELECT approval_id, action_id, session_id, agent_id, action_digest,
                    tool, target, reason, scope, scope_value,
                    issued_at, expires_at, decision, status, consumed_at, policy_version
             FROM approvals",
        )?;
        let rows = stmt.query_map([], record_from_db_row)?;
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
        insert_record(&conn, record)?;
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
        // The legacy API encodes the expiry timestamp in the scope itself.
        let expires_at = match &scope {
            ApprovalScope::Expiry(dt) => Some(*dt),
            _ => None,
        };

        let action = Action {
            id: action_id,
            session_id,
            agent_id: AgentId("legacy".to_string()),
            task_id: None,
            action_type: ActionType::Shell,
            tool: "legacy".to_string(),
            target: String::new(),
            args_hash: String::new(),
            context: Default::default(),
        };

        self.request_pending(&action, "legacy request", policy_version, scope, expires_at)
    }

    /// Approve an action.
    ///
    /// Returns error if:
    /// - Approval not found
    /// - Approval has expired
    /// - Approval was already decided (replay protection)
    pub fn approve(&self, approval_id: &str) -> Result<ApprovalRecord> {
        self.decide(approval_id, true)
    }

    /// Deny an action.
    ///
    /// Returns error if:
    /// - Approval not found
    /// - Approval was already decided (replay protection)
    pub fn deny(&self, approval_id: &str) -> Result<ApprovalRecord> {
        self.decide(approval_id, false)
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
    // ─── Pending-request lifecycle ───────────────────────────────────────────

    /// Record a pending approval request for the exact action being evaluated.
    ///
    /// Called by the policy enforcement point when the PDP returns `Ask`. It
    /// never executes or forwards anything: the request is recorded, the side
    /// effect is prevented, and the caller decides how long to wait.
    pub fn request_pending(
        &self,
        action: &Action,
        reason: impl Into<String>,
        policy_version: impl Into<String>,
        scope: ApprovalScope,
        expires_at: Option<DateTime<Utc>>,
    ) -> Result<ApprovalRecord> {
        let approval_id = Uuid::new_v4().to_string();
        let issued_at = Utc::now();

        let record = ApprovalRecord {
            approval_id,
            action_id: action.id.clone(),
            session_id: action.session_id.clone(),
            agent_id: Some(action.agent_id.clone()),
            action_digest: action.digest(),
            tool: action.tool.clone(),
            target: action.target.clone(),
            reason: reason.into(),
            scope,
            issued_at,
            expires_at,
            decision: Decision::Ask,
            status: ApprovalStatus::Pending,
            consumed_at: None,
            policy_version: policy_version.into(),
        };

        {
            let mut approvals = self.approvals.lock().unwrap();
            approvals.insert(record.approval_id.clone(), record.clone());
        }

        // SECURITY: persistence failure must not silently drop the request.
        self.save_to_db(&record)?;
        Ok(record)
    }

    /// Answer a pending request. `approve = true` grants, `false` rejects.
    ///
    /// Fails closed on an unknown id, an already-decided request, or expiry.
    pub fn decide(&self, approval_id: &str, approve: bool) -> Result<ApprovalRecord> {
        self.transition(approval_id, |record| {
            if record.status != ApprovalStatus::Pending {
                return Err(AgentFenceError::Approval(
                    "Approval already decided".to_string(),
                ));
            }
            record.status = if approve {
                ApprovalStatus::Approved
            } else {
                ApprovalStatus::Rejected
            };
            record.decision = if approve {
                Decision::Allow
            } else {
                Decision::Deny
            };
            Ok(())
        })
    }

    /// Spend an approval on the exact action it was issued for.
    ///
    /// SECURITY: this is the only path that turns an approval into an executed
    /// action. It fails closed unless **all** of the following hold:
    /// - the request exists;
    /// - its status is `Approved` (never `Pending`, `Rejected`, `Expired` or
    ///   `Consumed`);
    /// - it has not expired;
    /// - the presented action produces the stored digest, so a modified command,
    ///   target or tool call can never be authorized.
    ///
    /// The check-and-set happens inside one SQLite `BEGIN IMMEDIATE`
    /// transaction (or one locked section for in-memory storage), so two
    /// concurrent consumers cannot both spend the same approval.
    pub fn consume(&self, approval_id: &str, action: &Action) -> Result<ApprovalRecord> {
        self.transition(approval_id, |record| {
            if record.status == ApprovalStatus::Consumed {
                return Err(AgentFenceError::Approval(
                    "Approval already consumed".to_string(),
                ));
            }
            if record.status != ApprovalStatus::Approved {
                return Err(AgentFenceError::Approval(
                    "Approval is not granted".to_string(),
                ));
            }
            if record.action_digest != action.digest() {
                return Err(AgentFenceError::Approval(
                    "Approval does not match this action".to_string(),
                ));
            }
            record.status = ApprovalStatus::Consumed;
            record.consumed_at = Some(Utc::now());
            Ok(())
        })
    }

    /// Look up a request by id.
    pub fn get(&self, approval_id: &str) -> Option<ApprovalRecord> {
        self.approvals.lock().unwrap().get(approval_id).cloned()
    }

    /// Re-read a request from the authoritative store.
    ///
    /// The enforcement process and `agentfence approve` are separate processes:
    /// the decision is written by the other one. Polling must therefore re-read
    /// the store instead of trusting the local cache.
    pub fn refresh(&self, approval_id: &str) -> Option<ApprovalRecord> {
        if let Some(conn) = &self.conn {
            let conn = conn.lock().unwrap();
            return fetch_record(&conn, approval_id).ok().flatten();
        }
        self.approvals.lock().unwrap().get(approval_id).cloned()
    }

    /// List every request, including decided, expired and consumed ones.
    pub fn list_all(&self) -> Vec<ApprovalRecord> {
        self.approvals.lock().unwrap().values().cloned().collect()
    }

    /// Atomically apply a state transition guarded by `guard`.
    fn transition<F>(&self, approval_id: &str, guard: F) -> Result<ApprovalRecord>
    where
        F: FnOnce(&mut ApprovalRecord) -> Result<()>,
    {
        if let Some(conn) = &self.conn {
            let mut conn = conn.lock().unwrap();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .map_err(|e| {
                    AgentFenceError::Enforcement(format!("approval transaction failed: {}", e))
                })?;

            let mut record = fetch_record(&tx, approval_id)?
                .ok_or_else(|| AgentFenceError::Approval("Approval not found".to_string()))?;

            // Fail closed on expiry, and record it.
            if !record.is_valid()
                && matches!(
                    record.status,
                    ApprovalStatus::Pending | ApprovalStatus::Approved
                )
            {
                record.status = ApprovalStatus::Expired;
                insert_record(&tx, &record)?;
                tx.commit().map_err(|e| {
                    AgentFenceError::Enforcement(format!("approval commit failed: {}", e))
                })?;
                self.remember(&record);
                return Err(AgentFenceError::Approval(
                    "Approval has expired".to_string(),
                ));
            }

            guard(&mut record)?;
            insert_record(&tx, &record)?;
            tx.commit().map_err(|e| {
                AgentFenceError::Enforcement(format!("approval commit failed: {}", e))
            })?;

            self.remember(&record);
            return Ok(record);
        }

        let mut approvals = self.approvals.lock().unwrap();
        let record = approvals
            .get_mut(approval_id)
            .ok_or_else(|| AgentFenceError::Approval("Approval not found".to_string()))?;

        if !record.is_valid()
            && matches!(
                record.status,
                ApprovalStatus::Pending | ApprovalStatus::Approved
            )
        {
            record.status = ApprovalStatus::Expired;
            return Err(AgentFenceError::Approval(
                "Approval has expired".to_string(),
            ));
        }

        guard(record)?;
        Ok(record.clone())
    }

    /// Refresh the in-memory view after a committed transition.
    fn remember(&self, record: &ApprovalRecord) {
        let mut approvals = self.approvals.lock().unwrap();
        approvals.insert(record.approval_id.clone(), record.clone());
    }
}

/// Add columns introduced after the first release. Existing databases keep
/// working; a failed `ALTER` means the column already exists.
fn migrate(conn: &rusqlite::Connection) -> Result<()> {
    for ddl in [
        "ALTER TABLE approvals ADD COLUMN agent_id TEXT",
        "ALTER TABLE approvals ADD COLUMN action_digest TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE approvals ADD COLUMN tool TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE approvals ADD COLUMN target TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE approvals ADD COLUMN reason TEXT NOT NULL DEFAULT ''",
        "ALTER TABLE approvals ADD COLUMN status TEXT NOT NULL DEFAULT 'Pending'",
        "ALTER TABLE approvals ADD COLUMN consumed_at TEXT",
    ] {
        let _ = conn.execute(ddl, []);
    }
    Ok(())
}

fn parse_scope(scope_str: &str, expires_at: Option<DateTime<Utc>>) -> ApprovalScope {
    match scope_str {
        "Session" => ApprovalScope::Session,
        "Repository" => ApprovalScope::Repository,
        "Path" => ApprovalScope::Path,
        "Host" => ApprovalScope::Host,
        "Expiry" => ApprovalScope::Expiry(
            expires_at.unwrap_or_else(|| Utc::now() + chrono::Duration::days(1)),
        ),
        _ => ApprovalScope::Once,
    }
}

fn scope_to_str(scope: &ApprovalScope) -> &'static str {
    match scope {
        ApprovalScope::Once => "Once",
        ApprovalScope::Session => "Session",
        ApprovalScope::Repository => "Repository",
        ApprovalScope::Path => "Path",
        ApprovalScope::Host => "Host",
        ApprovalScope::Expiry(_) => "Expiry",
    }
}

fn decision_to_str(decision: Decision) -> &'static str {
    match decision {
        Decision::Allow => "Allow",
        Decision::Deny => "Deny",
        Decision::Ask => "Ask",
    }
}

fn decision_from_str(s: &str) -> Decision {
    match s {
        "Allow" => Decision::Allow,
        "Deny" => Decision::Deny,
        _ => Decision::Ask,
    }
}

/// Rebuild an approval record from a result-set row.
///
/// SECURITY: `action_digest` and `status` are read with defaults so a row
/// written before those columns existed still loads, but an empty digest can
/// never match a real action digest — the approval fails closed.
fn record_from_db_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ApprovalRecord> {
    let approval_id: String = row.get("approval_id")?;
    let action_id: String = row.get("action_id")?;
    let session_id: String = row.get("session_id")?;
    let agent_id: Option<String> = row.get("agent_id")?;
    let action_digest: String = row.get("action_digest")?;
    let tool: String = row.get("tool")?;
    let target: String = row.get("target")?;
    let reason: String = row.get("reason")?;
    let scope_str: String = row.get("scope")?;
    let issued_at: String = row.get("issued_at")?;
    let expires_at: Option<String> = row.get("expires_at")?;
    let decision_str: String = row.get("decision")?;
    let status_str: String = row.get("status")?;
    let consumed_at: Option<String> = row.get("consumed_at")?;
    let policy_version: String = row.get("policy_version")?;

    let parse_time = |s: &str| {
        chrono::DateTime::parse_from_rfc3339(s)
            .ok()
            .map(|dt| dt.with_timezone(&chrono::Utc))
    };

    let expires_at = expires_at.as_deref().and_then(parse_time);

    Ok(ApprovalRecord {
        approval_id,
        action_id: ActionId(action_id),
        session_id: SessionId::new_from_string(session_id),
        agent_id: agent_id.map(AgentId),
        action_digest,
        tool,
        target,
        reason,
        scope: parse_scope(&scope_str, expires_at),
        issued_at: parse_time(&issued_at).unwrap_or_else(Utc::now),
        expires_at,
        decision: decision_from_str(&decision_str),
        status: ApprovalStatus::from_str(&status_str),
        consumed_at: consumed_at.as_deref().and_then(parse_time),
        policy_version,
    })
}

/// Read one record by id.
fn fetch_record(conn: &rusqlite::Connection, approval_id: &str) -> Result<Option<ApprovalRecord>> {
    let mut stmt = conn.prepare(
        "SELECT approval_id, action_id, session_id, agent_id, action_digest,
                tool, target, reason, scope, scope_value,
                issued_at, expires_at, decision, status, consumed_at, policy_version
         FROM approvals WHERE approval_id = ?1",
    )?;
    let mut rows = stmt.query_map([approval_id], record_from_db_row)?;
    match rows.next() {
        Some(row) => Ok(Some(row?)),
        None => Ok(None),
    }
}

/// Insert or replace a record.
fn insert_record(conn: &rusqlite::Connection, record: &ApprovalRecord) -> Result<()> {
    let scope_value = match &record.scope {
        ApprovalScope::Repository | ApprovalScope::Path | ApprovalScope::Host => {
            record.extract_scope_value()
        }
        _ => String::new(),
    };

    conn.execute(
        "INSERT OR REPLACE INTO approvals (
            approval_id, action_id, session_id, agent_id, action_digest,
            tool, target, reason, scope, scope_value,
            issued_at, expires_at, decision, status, consumed_at, policy_version
        ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16)",
        rusqlite::params![
            record.approval_id,
            record.action_id.0,
            record.session_id.0,
            record.agent_id.as_ref().map(|a| a.0.clone()),
            record.action_digest,
            record.tool,
            record.target,
            record.reason,
            scope_to_str(&record.scope),
            scope_value,
            record.issued_at.to_rfc3339(),
            record.expires_at.map(|t| t.to_rfc3339()),
            decision_to_str(record.decision),
            record.status.as_str(),
            record.consumed_at.map(|t| t.to_rfc3339()),
            record.policy_version,
        ],
    )?;
    Ok(())
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
