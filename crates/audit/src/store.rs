//! Audit store for AgentFence.
//!
//! SQLite persistence, JSONL export, hash-chain verification.
//! Must **not** contain policy decisions.

use std::fs::File;
use std::io::Write;
use std::path::Path;

use agentfence_core::error::Result;

use crate::event::AuditEvent;
use crate::hashchain::{verify_chain, VerificationResult};

/// Audit store for persisting and querying audit events.
pub struct AuditStore {
    db_path: std::path::PathBuf,
}

impl AuditStore {
    /// Create a new audit store at the given path.
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let store = Self {
            db_path: db_path.as_ref().to_path_buf(),
        };
        store.init()?;
        Ok(store)
    }

    /// Initialize the database schema.
    fn init(&self) -> Result<()> {
        // For MVP, we use JSONL files instead of SQLite
        // SQLite will be added in a future milestone
        Ok(())
    }

    /// Record an event.
    pub fn record_event(&self, event: &AuditEvent) -> Result<()> {
        let json = serde_json::to_string(event)?;
        let mut file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.db_path)?;
        writeln!(file, "{}", json)?;
        Ok(())
    }

    /// Load all events for a session.
    pub fn load_events(&self, session_id: &str) -> Result<Vec<AuditEvent>> {
        let content = std::fs::read_to_string(&self.db_path)?;
        let mut events = Vec::new();

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let event: AuditEvent = serde_json::from_str(line)?;
            if event.session_id.0 == session_id {
                events.push(event);
            }
        }

        Ok(events)
    }

    /// Verify the hash chain for a session.
    pub fn verify_session(&self, session_id: &str) -> Result<VerificationResult> {
        let events = self.load_events(session_id)?;
        Ok(verify_chain(&events))
    }

    /// Export events as JSONL.
    pub fn export_jsonl<P: AsRef<Path>>(&self, session_id: &str, output_path: P) -> Result<()> {
        let events = self.load_events(session_id)?;
        let mut file = File::create(output_path)?;

        for event in &events {
            let json = serde_json::to_string(event)?;
            writeln!(file, "{}", json)?;
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentfence_core::types::*;

    #[test]
    fn test_record_and_load() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_audit.jsonl");

        let store = AuditStore::new(&db_path).unwrap();

        let event = AuditEvent::new(
            SessionId::new(),
            AgentId::new("test-agent"),
            None,
            ActionId::new(),
            None,
            "shell",
            "shell",
            "git status",
            "hash",
            Decision::Allow,
            RiskLevel::Low,
            "test.rule",
            "v1",
            "policy_hash",
            "",
        );

        store.record_event(&event).unwrap();

        let events = store.load_events(&event.session_id.0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, event.event_id);

        // Cleanup
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_verify_chain() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_audit_verify.jsonl");

        let store = AuditStore::new(&db_path).unwrap();

        let session_id = SessionId::new();
        let event1 = AuditEvent::new(
            session_id.clone(),
            AgentId::new("test-agent"),
            None,
            ActionId::new(),
            None,
            "shell",
            "shell",
            "git status",
            "hash",
            Decision::Allow,
            RiskLevel::Low,
            "test.rule",
            "v1",
            "policy_hash",
            "",
        );

        store.record_event(&event1).unwrap();

        let result = store.verify_session(&session_id.0).unwrap();
        assert_eq!(result, VerificationResult::Valid);

        // Cleanup
        let _ = std::fs::remove_file(&db_path);
    }
}
