//! Enforcement-side approval integration — the boundary a gateway calls.
//!
//! This is the counterpart to `agentfence approve`. When a policy returns `Ask`
//! the enforcement point must **never** execute the action: it calls
//! [`ApprovalBroker::wait_and_consume`], which records a pending request,
//! prevents the side effect, waits up to a bounded timeout for a human, and then
//! spends the approval on the exact action that was authorized.
//!
//! SECURITY: the broker can only ever turn an *approved* request into one
//! execution. It cannot create an approval, cannot decide one, and cannot
//! authorize an action whose digest differs from the stored one.

use std::path::PathBuf;
use std::time::{Duration, Instant};

use chrono::Utc;
use tracing::{info, warn};

use agentfence_core::error::Result;
use agentfence_core::types::{Action, Decision, RiskLevel};

use crate::approval::{ApprovalRecord, ApprovalScope, ApprovalService, ApprovalStatus};

/// Poll interval while waiting for a human decision.
const POLL_INTERVAL: Duration = Duration::from_millis(250);

fn env_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .unwrap_or(default)
}

/// Directory that holds AgentFence runtime state.
pub fn default_db_dir() -> PathBuf {
    if let Ok(dir) = std::env::var("AGENTFENCE_DATA_DIR") {
        return PathBuf::from(dir);
    }
    if let Some(dir) = dirs_next::data_dir() {
        return dir.join("agentfence");
    }
    PathBuf::from(".")
}

/// SQLite path for the approval store. The broker and `agentfence approve` must
/// agree on this, otherwise a decision would never be seen.
pub fn default_approval_db_path() -> PathBuf {
    if let Ok(path) = std::env::var("AGENTFENCE_APPROVAL_DB") {
        return PathBuf::from(path);
    }
    default_db_dir().join("approvals.db")
}

/// SQLite path for the audit store, used to record the approval lifecycle.
pub fn default_audit_db_path() -> PathBuf {
    default_db_dir().join("agentfence.db")
}

/// Operational settings for the approval flow.
#[derive(Debug, Clone)]
pub struct ApprovalConfig {
    /// How long a gateway waits for a human before failing closed.
    /// `0` records the request and returns immediately without waiting.
    pub wait_timeout: Duration,
    /// How long a pending request stays valid before it expires.
    pub request_ttl: Duration,
    /// SQLite path for the shared approval store.
    pub db_path: PathBuf,
}

impl Default for ApprovalConfig {
    fn default() -> Self {
        Self {
            wait_timeout: Duration::from_millis(env_u64("AGENTFENCE_APPROVAL_TIMEOUT_MS", 300_000)),
            request_ttl: Duration::from_secs(env_u64("AGENTFENCE_APPROVAL_TTL_MINUTES", 30) * 60),
            db_path: default_approval_db_path(),
        }
    }
}

impl ApprovalConfig {
    /// Configuration from the environment with safe defaults.
    pub fn from_env() -> Self {
        Self::default()
    }

    /// Build a configuration that never waits (record and block immediately).
    pub fn without_waiting(db_path: PathBuf) -> Self {
        Self {
            wait_timeout: Duration::ZERO,
            db_path,
            ..Self::default()
        }
    }
}

/// The enforcement-side approval boundary.
pub struct ApprovalBroker {
    service: ApprovalService,
    config: ApprovalConfig,
}

impl ApprovalBroker {
    /// Open the broker against the shared approval store.
    pub fn open(config: ApprovalConfig) -> Result<Self> {
        let service = ApprovalService::new_with_db(config.db_path.clone())?;
        Ok(Self { service, config })
    }

    /// The underlying service, for inspection in tests and the CLI.
    pub fn service(&self) -> &ApprovalService {
        &self.service
    }

    pub fn config(&self) -> &ApprovalConfig {
        &self.config
    }

    /// Record a pending request for the exact action being evaluated.
    ///
    /// Never executes anything. The caller must prevent the side effect while
    /// the request is outstanding.
    pub fn request(
        &self,
        action: &Action,
        reason: &str,
        policy_version: &str,
    ) -> Result<ApprovalRecord> {
        let expires_at = if self.config.request_ttl.is_zero() {
            None
        } else {
            Some(
                Utc::now()
                    + chrono::Duration::from_std(self.config.request_ttl).unwrap_or_default(),
            )
        };

        let record = self.service.request_pending(
            action,
            reason,
            policy_version,
            ApprovalScope::Once,
            expires_at,
        )?;

        self.audit_event(
            action,
            "approval.request",
            Decision::Ask,
            &record.approval_id,
        );
        info!(
            "Approval requested: {} for action {} ({})",
            record.approval_id, record.action_id.0, record.target
        );

        Ok(record)
    }

    /// Record a pending request, wait up to `timeout` for a human, and spend the
    /// approval on the exact action.
    ///
    /// Returns `Ok(true)` only when the action was approved **and** consumed.
    /// Denied, expired, timed-out and infrastructure-failed cases all return
    /// `Ok(false)` or `Err` — none of them may execute the action.
    pub fn wait_and_consume(
        &self,
        action: &Action,
        reason: &str,
        policy_version: &str,
        timeout: Option<Duration>,
    ) -> Result<bool> {
        let record = self.request(action, reason, policy_version)?;
        self.wait_for(&record.approval_id, action, timeout)
    }

    /// Wait for a human decision on a request already recorded, then spend it.
    ///
    /// Returns `Ok(true)` only when the action was approved **and** consumed.
    /// Denied, expired, timed-out and infrastructure-failed cases return
    /// `Ok(false)` or `Err` — none of them may execute the action.
    pub fn wait_for(
        &self,
        approval_id: &str,
        action: &Action,
        timeout: Option<Duration>,
    ) -> Result<bool> {
        let timeout = timeout.unwrap_or(self.config.wait_timeout);

        if timeout.is_zero() {
            return Ok(false);
        }

        let deadline = Instant::now() + timeout;
        loop {
            match self.service.refresh(approval_id) {
                Some(r) if r.status == ApprovalStatus::Approved => {
                    // Consume atomically. If a concurrent consumer won, this
                    // returns an error and the action stays blocked.
                    let outcome = self.service.consume(approval_id, action);
                    if outcome.is_ok() {
                        self.audit_event(action, "approval.consumed", Decision::Allow, approval_id);
                    }
                    return outcome.map(|_| true);
                }
                Some(r) if r.status == ApprovalStatus::Rejected => {
                    self.audit_event(action, "approval.decided", Decision::Deny, approval_id);
                    info!("Approval {} rejected by operator", approval_id);
                    return Ok(false);
                }
                Some(r) if r.status == ApprovalStatus::Expired => {
                    warn!("Approval {} expired before it was consumed", approval_id);
                    return Ok(false);
                }
                Some(r) if r.status == ApprovalStatus::Consumed => {
                    warn!("Approval {} was already consumed", approval_id);
                    return Ok(false);
                }
                Some(_) => {}
                None => {
                    // The store lost the request: fail closed.
                    return Err(agentfence_core::error::AgentFenceError::Enforcement(
                        "approval request disappeared from the store".to_string(),
                    ));
                }
            }

            if Instant::now() >= deadline {
                warn!(
                    "Approval {} not answered within {:?}; failing closed",
                    approval_id, timeout
                );
                return Ok(false);
            }

            std::thread::sleep(POLL_INTERVAL);
        }
    }

    /// Spend an existing approval on the exact action it was issued for.
    ///
    /// This is the explicit resume path for callers that recorded a request but
    /// could not wait for a human in the same process.
    pub fn consume(&self, approval_id: &str, action: &Action) -> Result<bool> {
        let record = self.service.refresh(approval_id).ok_or_else(|| {
            agentfence_core::error::AgentFenceError::Approval("Approval not found".to_string())
        })?;

        self.service.consume(approval_id, action)?;
        self.audit_event(action, "approval.consumed", Decision::Allow, approval_id);
        Ok(record.status == ApprovalStatus::Consumed)
    }

    /// Write an audit event for the approval lifecycle.
    ///
    /// Best effort: an audit write failure is logged and does not change the
    /// decision, because the approval record itself is already authoritative.
    fn audit_event(&self, action: &Action, kind: &str, decision: Decision, approval_id: &str) {
        let db_path = default_audit_db_path();
        if let Some(parent) = db_path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let Ok(store) = agentfence_audit::sqlite_store::SqliteStore::new(&db_path) else {
            return;
        };

        let event = agentfence_audit::event::AuditEvent::new(
            action.session_id.clone(),
            action.agent_id.clone(),
            None,
            action.id.clone(),
            None,
            kind,
            action.tool.clone(),
            action.target.clone(),
            action.digest(),
            decision,
            RiskLevel::Medium,
            approval_id,
            "",
            "",
            "",
        );

        if let Err(e) = store.record_event(&event) {
            warn!("Failed to write approval audit event: {}", e);
        }
    }
}
