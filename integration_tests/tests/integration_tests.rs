//! Integration tests for AgentFence.
//!
//! Tests the full chain: policy → PEP → PDP → audit.

use agentfence_audit::event::AuditEvent;
use agentfence_audit::sqlite_store::SqliteStore;
use agentfence_core::types::*;
use agentfence_policy::parser::parse_policy;
use agentfence_policy::pdp::Pdp;
use agentfence_shell::command::ShellCommand;
use agentfence_shell::gateway::ShellGateway;

#[test]
fn test_full_chain_allow() {
    // 1. Create policy
    let yaml = r#"
version: 1
defaults:
  shell: deny
  network: deny
  mcp: deny
  filesystem: deny
shell:
  allow:
    - git
    - cargo
"#;
    let policy = parse_policy(yaml).unwrap();
    let pdp = Pdp::new(policy);

    // 2. Create session
    let session_id = SessionId::new();
    let agent_id = AgentId::new("test-agent");

    // 3. Create command
    let cmd = ShellCommand::parse("git status").unwrap();

    // 4. Evaluate through ShellGateway
    let gateway = ShellGateway::new(pdp);
    let record = gateway.evaluate(&cmd, &session_id, &agent_id);

    // 5. Verify decision
    assert!(matches!(record.decision, Decision::Allow));
    assert!(!record.rule_id.is_empty());

    // 6. Record audit event
    let db_path = std::env::temp_dir().join(format!("agentfence_test_{}.db", uuid::Uuid::new_v4()));
    let store = SqliteStore::new(&db_path).unwrap();

    let event = AuditEvent::new(
        session_id.clone(),
        agent_id.clone(),
        None,
        ActionId::new(),
        None,
        "shell",
        "git",
        "status",
        "hash123",
        record.decision,
        record.risk_level,
        &record.rule_id,
        &record.policy_version,
        "",
        "",
    );

    store.record_event(&event).unwrap();

    // 7. Verify audit trail
    let events = store.load_events(&session_id.0).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].tool, "git");
    assert_eq!(events[0].decision, Decision::Allow);

    // 8. Verify hash chain
    let result = store.verify_session(&session_id.0).unwrap();
    assert!(matches!(
        result,
        agentfence_audit::hashchain::VerificationResult::Valid
    ));

    // Cleanup
    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn test_full_chain_deny() {
    let yaml = r#"
version: 1
defaults:
  shell: deny
  network: deny
  mcp: deny
  filesystem: deny
shell:
  allow:
    - git
"#;
    let policy = parse_policy(yaml).unwrap();
    let pdp = Pdp::new(policy);

    let session_id = SessionId::new();
    let agent_id = AgentId::new("test-agent");

    // Try to run a denied command
    let cmd = ShellCommand::parse("rm -rf /").unwrap();
    let gateway = ShellGateway::new(pdp);
    let record = gateway.evaluate(&cmd, &session_id, &agent_id);

    assert!(matches!(record.decision, Decision::Deny));
    assert!(!record.rule_id.is_empty());
}

#[test]
fn test_full_chain_ask() {
    let yaml = r#"
version: 1
defaults:
  shell: deny
  network: deny
  mcp: deny
  filesystem: deny
shell:
  allow:
    - git
  ask:
    - npm
"#;
    let policy = parse_policy(yaml).unwrap();
    let pdp = Pdp::new(policy);

    let session_id = SessionId::new();
    let agent_id = AgentId::new("test-agent");

    // Try to run a command that requires approval
    let cmd = ShellCommand::parse("npm install").unwrap();
    let gateway = ShellGateway::new(pdp);
    let record = gateway.evaluate(&cmd, &session_id, &agent_id);

    assert!(matches!(record.decision, Decision::Ask));
    assert!(!record.rule_id.is_empty());
}

#[test]
fn test_audit_chain_integrity() {
    let db_path = std::env::temp_dir().join(format!("agentfence_test_{}.db", uuid::Uuid::new_v4()));
    let store = SqliteStore::new(&db_path).unwrap();

    let session_id = SessionId::new();
    let agent_id = AgentId::new("test-agent");

    // Record multiple events
    for i in 0..5 {
        let event = AuditEvent::new(
            session_id.clone(),
            agent_id.clone(),
            None,
            ActionId::new(),
            None,
            "shell",
            &format!("cmd{}", i),
            "arg",
            &format!("hash{}", i),
            Decision::Allow,
            RiskLevel::Low,
            "rule1",
            "1.0",
            "",
            "",
        );
        store.record_event(&event).unwrap();
    }

    // Verify chain
    let result = store.verify_session(&session_id.0).unwrap();
    assert!(matches!(
        result,
        agentfence_audit::hashchain::VerificationResult::Valid
    ));

    // Load and verify all events
    let events = store.load_events(&session_id.0).unwrap();
    assert_eq!(events.len(), 5);

    // Verify chain linkage
    for i in 1..events.len() {
        assert_eq!(events[i].previous_hash, events[i - 1].current_hash);
    }

    // Cleanup
    let _ = std::fs::remove_file(&db_path);
}

#[test]
fn test_audit_tamper_detection() {
    let db_path = std::env::temp_dir().join(format!("agentfence_test_{}.db", uuid::Uuid::new_v4()));
    let store = SqliteStore::new(&db_path).unwrap();

    let session_id = SessionId::new();
    let agent_id = AgentId::new("test-agent");

    // Record events
    for i in 0..3 {
        let event = AuditEvent::new(
            session_id.clone(),
            agent_id.clone(),
            None,
            ActionId::new(),
            None,
            "shell",
            &format!("cmd{}", i),
            "arg",
            &format!("hash{}", i),
            Decision::Allow,
            RiskLevel::Low,
            "rule1",
            "1.0",
            "",
            "",
        );
        store.record_event(&event).unwrap();
    }

    // Tamper with the database directly
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute(
        "UPDATE events SET target = 'tampered' WHERE event_id = (SELECT event_id FROM events LIMIT 1)",
        [],
    ).unwrap();
    drop(conn);

    // Verify should fail
    let result = store.verify_session(&session_id.0).unwrap();
    assert!(matches!(
        result,
        agentfence_audit::hashchain::VerificationResult::Invalid { .. }
    ));

    // Cleanup
    let _ = std::fs::remove_file(&db_path);
}
