//! SQLite persistence for AgentFence audit events.
//!
//! Provides structured storage with hash-chain verification.
//! Supports migration from JSONL files.
//!
//! Schema:
//! - events: stores all audit event fields + hash chain
//! - sessions: stores session metadata
//! - approvals: stores approval records
//! - policies: stores policy versions

use std::io::Write;
use std::path::Path;

use agentfence_core::error::Result;
use rusqlite::{params, Connection};

use crate::event::AuditEvent;
use crate::hashchain::{verify_chain, VerificationResult};
use crate::session::Session;

/// SQLite-backed audit store.
pub struct SqliteStore {
    conn: Connection,
}

impl SqliteStore {
    /// Create a new SQLite store at the given path.
    pub fn new<P: AsRef<Path>>(db_path: P) -> Result<Self> {
        let conn = Connection::open(db_path)?;
        let store = Self { conn };
        store.init()?;
        Ok(store)
    }

    /// Initialize the database schema.
    fn init(&self) -> Result<()> {
        self.conn.execute_batch(
            "CREATE TABLE IF NOT EXISTS events (
                event_id TEXT PRIMARY KEY,
                session_id TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                task_id TEXT,
                action_id TEXT NOT NULL,
                parent_action_id TEXT,
                timestamp TEXT NOT NULL,
                action_type TEXT NOT NULL,
                tool TEXT NOT NULL,
                target TEXT NOT NULL,
                args_hash TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                rule_id TEXT NOT NULL,
                policy_version TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                current_hash TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY,
                agent_id TEXT NOT NULL,
                task_id TEXT,
                started_at TEXT NOT NULL,
                ended_at TEXT,
                policy_version TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                protection_mode TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS approvals (
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

            CREATE TABLE IF NOT EXISTS policies (
                policy_version TEXT PRIMARY KEY,
                policy_hash TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id);
            CREATE INDEX IF NOT EXISTS idx_events_action ON events(action_id);
            CREATE INDEX IF NOT EXISTS idx_events_timestamp ON events(timestamp);
            CREATE INDEX IF NOT EXISTS idx_approvals_action ON approvals(action_id);
            CREATE INDEX IF NOT EXISTS idx_approvals_session ON approvals(session_id);
            ",
        )?;
        Ok(())
    }

    /// Record an event with hash chain.
    ///
    /// Sets `previous_hash` to the actual chain predecessor before computing `current_hash`.
    /// This ensures the stored hash is always derived from the correct chain state.
    pub fn record_event(&self, event: &AuditEvent) -> Result<()> {
        let prev_hash = self.get_last_hash(&event.session_id.0)?;

        // Set previous_hash to the actual chain predecessor BEFORE computing current_hash
        let mut event = event.clone();
        event.previous_hash = prev_hash;
        let current_hash = event.compute_hash();
        event.current_hash = current_hash;

        self.conn.execute(
            "INSERT INTO events (
                event_id, session_id, agent_id, task_id, action_id, parent_action_id,
                timestamp, action_type, tool, target, args_hash, decision, risk_level,
                rule_id, policy_version, policy_hash, prev_hash, current_hash
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, ?15, ?16, ?17, ?18)",
            params![
                event.event_id,
                event.session_id.0,
                event.agent_id.0,
                event.task_id.as_ref().map(|t| t.0.clone()),
                event.action_id.0,
                event.parent_action_id.as_ref().map(|a| a.0.clone()),
                event.timestamp.to_rfc3339(),
                event.action_type,
                event.tool,
                event.target,
                event.args_hash,
                format!("{:?}", event.decision),
                format!("{:?}", event.risk_level),
                event.rule_id,
                event.policy_version,
                event.policy_hash,
                event.previous_hash,
                event.current_hash,
            ],
        )?;

        Ok(())
    }

    /// Get the last hash for a session (for hash chain continuity).
    fn get_last_hash(&self, session_id: &str) -> Result<String> {
        let result: Option<String> = self
            .conn
            .query_row(
                "SELECT current_hash FROM events WHERE session_id = ?1 ORDER BY timestamp DESC LIMIT 1",
                params![session_id],
                |row| row.get(0),
            )
            .ok();

        Ok(result.unwrap_or_else(|| "0".repeat(64)))
    }

    /// Load all events for a session.
    pub fn load_events(&self, session_id: &str) -> Result<Vec<AuditEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id, session_id, agent_id, task_id, action_id, parent_action_id,
                    timestamp, action_type, tool, target, args_hash, decision, risk_level,
                    rule_id, policy_version, policy_hash, prev_hash, current_hash
             FROM events WHERE session_id = ?1 ORDER BY timestamp ASC",
        )?;

        let events = stmt
            .query_map(params![session_id], |row| {
                let decision_str: String = row.get(11)?;
                let risk_str: String = row.get(12)?;

                let decision = match decision_str.as_str() {
                    "Allow" => agentfence_core::types::Decision::Allow,
                    "Deny" => agentfence_core::types::Decision::Deny,
                    "Ask" => agentfence_core::types::Decision::Ask,
                    _ => agentfence_core::types::Decision::Deny,
                };

                let risk_level = match risk_str.as_str() {
                    "Low" => agentfence_core::types::RiskLevel::Low,
                    "Medium" => agentfence_core::types::RiskLevel::Medium,
                    "High" => agentfence_core::types::RiskLevel::High,
                    "Critical" => agentfence_core::types::RiskLevel::Critical,
                    _ => agentfence_core::types::RiskLevel::Low,
                };

                let timestamp_str: String = row.get(6)?;
                let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now());

                let prev_hash: String = row.get(16)?;
                let current_hash: String = row.get(17)?;

                Ok(AuditEvent {
                    event_id: row.get(0)?,
                    schema_version: 1,
                    session_id: agentfence_core::types::SessionId::new_from_string(row.get(1)?),
                    agent_id: agentfence_core::types::AgentId::new_from_string(row.get(2)?),
                    task_id: row
                        .get::<_, Option<String>>(3)?
                        .map(agentfence_core::types::TaskId::new_from_string),
                    action_id: agentfence_core::types::ActionId::new_from_string(row.get(4)?),
                    parent_action_id: row
                        .get::<_, Option<String>>(5)?
                        .map(agentfence_core::types::ActionId::new_from_string),
                    timestamp,
                    action_type: row.get(7)?,
                    tool: row.get(8)?,
                    target: row.get(9)?,
                    args_hash: row.get(10)?,
                    decision,
                    risk_level,
                    rule_id: row.get(13)?,
                    policy_version: row.get(14)?,
                    policy_hash: row.get(15)?,
                    previous_hash: prev_hash,
                    current_hash,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

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
        let mut file = std::fs::File::create(output_path)?;

        for event in &events {
            let json = serde_json::to_string(event)?;
            writeln!(file, "{}", json)?;
        }

        Ok(())
    }

    /// Migrate events from a JSONL file into SQLite.
    pub fn migrate_from_jsonl<P: AsRef<Path>>(&self, jsonl_path: P) -> Result<usize> {
        let content = std::fs::read_to_string(jsonl_path)?;
        let mut count = 0;

        for line in content.lines() {
            if line.trim().is_empty() {
                continue;
            }
            let event: AuditEvent = serde_json::from_str(line)?;
            self.record_event(&event)?;
            count += 1;
        }

        Ok(count)
    }

    /// Record a session.
    pub fn record_session(&self, session: &Session) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO sessions (
                session_id, agent_id, task_id, started_at, ended_at,
                policy_version, policy_hash, protection_mode
            ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![
                session.session_id.0,
                session.agent_id.0,
                session.task_id.as_ref().map(|t| t.0.clone()),
                session.started_at.to_rfc3339(),
                session.ended_at.map(|t| t.to_rfc3339()),
                session.policy_version,
                session.policy_hash,
                format!("{:?}", session.protection_mode),
            ],
        )?;
        Ok(())
    }

    /// Get all events (for debugging/admin).
    pub fn get_all_events(&self) -> Result<Vec<AuditEvent>> {
        let mut stmt = self.conn.prepare(
            "SELECT event_id, session_id, agent_id, task_id, action_id, parent_action_id,
                    timestamp, action_type, tool, target, args_hash, decision, risk_level,
                    rule_id, policy_version, policy_hash
             FROM events ORDER BY timestamp ASC",
        )?;

        let events = stmt
            .query_map([], |row| {
                let decision_str: String = row.get(11)?;
                let risk_str: String = row.get(12)?;

                let decision = match decision_str.as_str() {
                    "Allow" => agentfence_core::types::Decision::Allow,
                    "Deny" => agentfence_core::types::Decision::Deny,
                    "Ask" => agentfence_core::types::Decision::Ask,
                    _ => agentfence_core::types::Decision::Deny,
                };

                let risk_level = match risk_str.as_str() {
                    "Low" => agentfence_core::types::RiskLevel::Low,
                    "Medium" => agentfence_core::types::RiskLevel::Medium,
                    "High" => agentfence_core::types::RiskLevel::High,
                    "Critical" => agentfence_core::types::RiskLevel::Critical,
                    _ => agentfence_core::types::RiskLevel::Low,
                };

                let timestamp_str: String = row.get(6)?;
                let timestamp = chrono::DateTime::parse_from_rfc3339(&timestamp_str)
                    .map(|dt| dt.with_timezone(&chrono::Utc))
                    .unwrap_or_else(|_| chrono::Utc::now());

                let prev_hash: String = row.get(16)?;
                let current_hash: String = row.get(17)?;

                Ok(AuditEvent {
                    event_id: row.get(0)?,
                    schema_version: 1,
                    session_id: agentfence_core::types::SessionId::new_from_string(row.get(1)?),
                    agent_id: agentfence_core::types::AgentId::new_from_string(row.get(2)?),
                    task_id: row
                        .get::<_, Option<String>>(3)?
                        .map(agentfence_core::types::TaskId::new_from_string),
                    action_id: agentfence_core::types::ActionId::new_from_string(row.get(4)?),
                    parent_action_id: row
                        .get::<_, Option<String>>(5)?
                        .map(agentfence_core::types::ActionId::new_from_string),
                    timestamp,
                    action_type: row.get(7)?,
                    tool: row.get(8)?,
                    target: row.get(9)?,
                    args_hash: row.get(10)?,
                    decision,
                    risk_level,
                    rule_id: row.get(13)?,
                    policy_version: row.get(14)?,
                    policy_hash: row.get(15)?,
                    previous_hash: prev_hash,
                    current_hash,
                })
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentfence_core::types::*;

    fn test_event(session_id: SessionId) -> AuditEvent {
        AuditEvent::new(
            session_id,
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
        )
    }

    #[test]
    fn test_sqlite_record_and_load() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_audit.sqlite");

        let store = SqliteStore::new(&db_path).unwrap();
        let session_id = SessionId::new();
        let event = test_event(session_id.clone());

        store.record_event(&event).unwrap();

        let events = store.load_events(&session_id.0).unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_id, event.event_id);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_sqlite_verify_chain() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_audit_verify.sqlite");

        let store = SqliteStore::new(&db_path).unwrap();
        let session_id = SessionId::new();

        let event1 = test_event(session_id.clone());
        store.record_event(&event1).unwrap();

        let result = store.verify_session(&session_id.0).unwrap();
        assert_eq!(result, VerificationResult::Valid);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_sqlite_multiple_events_chain() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_audit_chain.sqlite");

        let store = SqliteStore::new(&db_path).unwrap();
        let session_id = SessionId::new();

        let event1 = test_event(session_id.clone());
        store.record_event(&event1).unwrap();

        let event2 = test_event(session_id.clone());
        store.record_event(&event2).unwrap();

        let event3 = test_event(session_id.clone());
        store.record_event(&event3).unwrap();

        let events = store.load_events(&session_id.0).unwrap();
        assert_eq!(events.len(), 3);

        let result = store.verify_session(&session_id.0).unwrap();
        assert_eq!(result, VerificationResult::Valid);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_sqlite_export_jsonl() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_audit_export.sqlite");
        let export_path = temp_dir.join("test_audit_export.jsonl");

        let store = SqliteStore::new(&db_path).unwrap();
        let session_id = SessionId::new();

        let event1 = test_event(session_id.clone());
        store.record_event(&event1).unwrap();

        let event2 = test_event(session_id.clone());
        store.record_event(&event2).unwrap();

        store.export_jsonl(&session_id.0, &export_path).unwrap();

        let content = std::fs::read_to_string(&export_path).unwrap();
        let lines: Vec<&str> = content.lines().collect();
        assert_eq!(lines.len(), 2);

        let _ = std::fs::remove_file(&db_path);
        let _ = std::fs::remove_file(&export_path);
    }

    #[test]
    fn test_sqlite_migration_from_jsonl() {
        let temp_dir = std::env::temp_dir();
        let jsonl_path = temp_dir.join("test_migrate.jsonl");
        let db_path = temp_dir.join("test_migrate.sqlite");

        // Create a JSONL file
        let session_id = SessionId::new();
        let event1 = test_event(session_id.clone());
        let event2 = test_event(session_id.clone());

        let mut jsonl_content = String::new();
        jsonl_content.push_str(&serde_json::to_string(&event1).unwrap());
        jsonl_content.push('\n');
        jsonl_content.push_str(&serde_json::to_string(&event2).unwrap());
        jsonl_content.push('\n');

        std::fs::write(&jsonl_path, jsonl_content).unwrap();

        // Migrate to SQLite
        let store = SqliteStore::new(&db_path).unwrap();
        let count = store.migrate_from_jsonl(&jsonl_path).unwrap();
        assert_eq!(count, 2);

        // Verify events are in SQLite
        let events = store.load_events(&session_id.0).unwrap();
        assert_eq!(events.len(), 2);

        let _ = std::fs::remove_file(&jsonl_path);
        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_sqlite_corrupted_chain_detection() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_audit_corrupted.sqlite");

        let store = SqliteStore::new(&db_path).unwrap();
        let session_id = SessionId::new();

        let event1 = test_event(session_id.clone());
        store.record_event(&event1).unwrap();

        let event2 = test_event(session_id.clone());
        store.record_event(&event2).unwrap();

        // Manually corrupt the second event's hash
        store
            .conn
            .execute(
                "UPDATE events SET current_hash = 'corrupted' WHERE event_id = ?1",
                params![event2.event_id],
            )
            .unwrap();

        let result = store.verify_session(&session_id.0).unwrap();
        assert!(matches!(result, VerificationResult::Invalid { .. }));

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_sqlite_genesis_hash() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_genesis.sqlite");

        let store = SqliteStore::new(&db_path).unwrap();
        let session_id = SessionId::new();

        let event = test_event(session_id.clone());
        store.record_event(&event).unwrap();

        // First event should use genesis hash
        let stored_hash: String = store
            .conn
            .query_row(
                "SELECT prev_hash FROM events WHERE event_id = ?1",
                params![event.event_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(stored_hash, "0".repeat(64));

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_sqlite_chain_linkage() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_chain_linkage.sqlite");

        let store = SqliteStore::new(&db_path).unwrap();
        let session_id = SessionId::new();

        let event1 = test_event(session_id.clone());
        store.record_event(&event1).unwrap();

        let event2 = test_event(session_id.clone());
        store.record_event(&event2).unwrap();

        // Second event's prev_hash should equal first event's current_hash
        let hash1: String = store
            .conn
            .query_row(
                "SELECT current_hash FROM events WHERE event_id = ?1",
                params![event1.event_id],
                |row| row.get(0),
            )
            .unwrap();
        let prev_hash2: String = store
            .conn
            .query_row(
                "SELECT prev_hash FROM events WHERE event_id = ?1",
                params![event2.event_id],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(prev_hash2, hash1);

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_sqlite_reopen_verify() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_reopen.sqlite");

        let session_id = SessionId::new();

        // Record events in one store instance
        {
            let store = SqliteStore::new(&db_path).unwrap();
            let event1 = test_event(session_id.clone());
            store.record_event(&event1).unwrap();
            let event2 = test_event(session_id.clone());
            store.record_event(&event2).unwrap();
        }

        // Reopen and verify
        {
            let store = SqliteStore::new(&db_path).unwrap();
            let result = store.verify_session(&session_id.0).unwrap();
            assert_eq!(result, VerificationResult::Valid);
        }

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_sqlite_mutate_previous_hash_fails() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_mutate_prev.sqlite");

        let store = SqliteStore::new(&db_path).unwrap();
        let session_id = SessionId::new();

        let event1 = test_event(session_id.clone());
        store.record_event(&event1).unwrap();

        let event2 = test_event(session_id.clone());
        store.record_event(&event2).unwrap();

        // Mutate previous_hash of second event
        store
            .conn
            .execute(
                "UPDATE events SET prev_hash = 'mutated' WHERE event_id = ?1",
                params![event2.event_id],
            )
            .unwrap();

        let result = store.verify_session(&session_id.0).unwrap();
        assert!(matches!(result, VerificationResult::Invalid { .. }));

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_sqlite_mutate_current_hash_fails() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_mutate_curr.sqlite");

        let store = SqliteStore::new(&db_path).unwrap();
        let session_id = SessionId::new();

        let event1 = test_event(session_id.clone());
        store.record_event(&event1).unwrap();

        // Mutate current_hash of first event
        store
            .conn
            .execute(
                "UPDATE events SET current_hash = 'mutated' WHERE event_id = ?1",
                params![event1.event_id],
            )
            .unwrap();

        let result = store.verify_session(&session_id.0).unwrap();
        assert!(matches!(result, VerificationResult::Invalid { .. }));

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_sqlite_mutate_event_field_fails() {
        let temp_dir = std::env::temp_dir();
        let db_path = temp_dir.join("test_mutate_field.sqlite");

        let store = SqliteStore::new(&db_path).unwrap();
        let session_id = SessionId::new();

        let event1 = test_event(session_id.clone());
        store.record_event(&event1).unwrap();

        // Mutate target field (used in hash computation)
        store
            .conn
            .execute(
                "UPDATE events SET target = 'mutated' WHERE event_id = ?1",
                params![event1.event_id],
            )
            .unwrap();

        let result = store.verify_session(&session_id.0).unwrap();
        assert!(matches!(result, VerificationResult::Invalid { .. }));

        let _ = std::fs::remove_file(&db_path);
    }

    #[test]
    fn test_compute_chain_hash_equals_compute_hash() {
        let event = test_event(SessionId::new());
        let prev = "test_prev_hash_123";

        // When self.previous_hash == prev, both methods must return identical values
        let mut event_with_prev = event.clone();
        event_with_prev.previous_hash = prev.to_string();

        let chain_hash = event_with_prev.compute_chain_hash(prev);
        let compute_hash = event_with_prev.compute_hash();
        assert_eq!(chain_hash, compute_hash);
    }
}
