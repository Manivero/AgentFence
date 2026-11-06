//! Audit secrecy and tamper-evidence regression tests.
//!
//! The audit trail is a first-class security artifact: it must not carry raw
//! credentials, and redacting a target must not weaken the hash chain.

use agentfence_audit::event::AuditEvent;
use agentfence_audit::hashchain::VerificationResult;
use agentfence_audit::session::Session;
use agentfence_audit::sqlite_store::SqliteStore;
use agentfence_core::types::{
    ActionId, AgentId, Decision, ProtectionMode, RiskLevel, SessionId, TaskId,
};

const TOKEN: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";
const SESSION: &str = "session-1";

fn session() -> Session {
    Session {
        session_id: SessionId(SESSION.into()),
        agent_id: AgentId("agent-1".into()),
        task_id: None,
        started_at: chrono::Utc::now(),
        ended_at: None,
        policy_version: "1".into(),
        policy_hash: "policy-hash".into(),
        protection_mode: ProtectionMode::Cooperative,
    }
}

fn event(target: &str, action_id: &str) -> AuditEvent {
    AuditEvent::new(
        SessionId(SESSION.into()),
        AgentId("agent-1".into()),
        Some(TaskId("task-1".into())),
        ActionId(action_id.into()),
        None,
        "shell",
        "shell",
        target.to_string(),
        "deadbeef",
        Decision::Allow,
        RiskLevel::Low,
        "shell.allow",
        "1",
        "policy-hash",
        "0",
    )
}

fn temp_db(label: &str) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!(
        "af-audit-redact-{}-{}",
        label,
        uuid::Uuid::new_v4()
    ));
    let _ = std::fs::remove_file(&p);
    p
}

#[test]
fn a_credential_in_the_target_is_not_persisted() {
    let db = temp_db("secret");
    let store = SqliteStore::new(&db).expect("store");
    store.record_session(&session()).expect("session");

    let target = format!("curl -H \"Authorization: Bearer {TOKEN}\" https://example.com");
    store
        .record_event(&event(&target, "action-1"))
        .expect("record");

    let events = store.load_events("session-1").expect("load");
    assert_eq!(events.len(), 1);
    assert!(
        !events[0].target.contains(TOKEN),
        "raw credential leaked into the audit store: {}",
        events[0].target
    );
    assert!(
        events[0].target.contains("[REDACTED]"),
        "{}",
        events[0].target
    );
    // Decision-relevant context survives.
    assert!(events[0].target.contains("https://example.com"));

    let _ = std::fs::remove_file(&db);
}

#[test]
fn redaction_does_not_break_the_hash_chain() {
    let db = temp_db("chain");
    let store = SqliteStore::new(&db).expect("store");
    store.record_session(&session()).expect("session");

    store
        .record_event(&event(&format!("cmd --token {TOKEN}"), "action-1"))
        .unwrap();
    store
        .record_event(&event("cmd --other", "action-2"))
        .unwrap();

    let result = store.verify_session("session-1").expect("verify");
    assert_eq!(
        result,
        VerificationResult::Valid,
        "hash chain must verify after redaction"
    );

    let _ = std::fs::remove_file(&db);
}

#[test]
fn an_ordinary_target_is_stored_verbatim() {
    let db = temp_db("plain");
    let store = SqliteStore::new(&db).expect("store");
    store.record_session(&session()).expect("session");

    store
        .record_event(&event("git push origin main", "action-1"))
        .unwrap();

    let events = store.load_events("session-1").expect("load");
    assert_eq!(events[0].target, "git push origin main");

    let _ = std::fs::remove_file(&db);
}

#[test]
fn a_new_audit_directory_is_restricted_to_the_current_user() {
    let dir = std::env::temp_dir().join(format!("af-audit-redact-perms-{}", uuid::Uuid::new_v4()));
    let report =
        agentfence_core::secure_fs::prepare_db_path(&dir.join("agentfence.db")).expect("prepare");
    assert!(report.is_secure(), "issues: {:?}", report.issues);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_pre_existing_audit_directory_is_reported_not_rewritten() {
    // SECURITY: `/inheritance:r` on a directory strips inherited ACEs from its
    // children, leaving them with an empty DACL. A pre-existing directory must
    // therefore be reported, never rewritten.
    let dir =
        std::env::temp_dir().join(format!("af-audit-redact-existing-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir_all(&dir).unwrap();
    let file = dir.join("operator.txt");
    std::fs::write(&file, b"operator data").unwrap();

    let report =
        agentfence_core::secure_fs::prepare_db_path(&dir.join("agentfence.db")).expect("prepare");
    assert!(
        !report.is_secure(),
        "a pre-existing directory must be reported"
    );
    assert!(!report.issues.is_empty());
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "operator data");

    let _ = std::fs::remove_dir_all(&dir);
}
