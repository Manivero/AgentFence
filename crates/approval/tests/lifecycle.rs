//! Phase 9 — approval lifecycle tests.
//!
//! These tests exercise the security-critical behaviour of the approval
//! boundary: binding, expiry, replay prevention and atomic consumption.

use std::sync::Arc;
use std::time::Duration;

use agentfence_approval::approval::{ApprovalScope, ApprovalService, ApprovalStatus};
use agentfence_approval::broker::{ApprovalBroker, ApprovalConfig};
use agentfence_core::types::{Action, ActionId, ActionType, AgentId, SessionId};

fn action(session: &str, agent: &str, target: &str) -> Action {
    Action {
        id: ActionId::new(),
        session_id: SessionId(session.to_string()),
        agent_id: AgentId(agent.to_string()),
        task_id: None,
        action_type: ActionType::Shell,
        tool: "shell".to_string(),
        target: target.to_string(),
        args_hash: format!("h:{}", target),
        context: Default::default(),
    }
}

fn request(
    service: &ApprovalService,
    action: &Action,
) -> agentfence_approval::approval::ApprovalRecord {
    service
        .request_pending(
            action,
            "policy requires approval",
            "v1",
            ApprovalScope::Once,
            None,
        )
        .expect("request should be recorded")
}

#[test]
fn pending_request_is_recorded_and_not_executable() {
    let service = ApprovalService::new();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");

    let record = request(&service, &a);

    assert_eq!(record.status, ApprovalStatus::Pending);
    assert_eq!(record.action_id, a.id);
    assert_eq!(record.session_id, a.session_id);
    assert_eq!(
        record.agent_id.as_ref().map(|x| x.0.as_str()),
        Some("agent-a")
    );
    assert_eq!(record.tool, "shell");
    assert_eq!(record.target, "rm -rf /tmp/x");
    assert_eq!(record.reason, "policy requires approval");
    assert_eq!(record.policy_version, "v1");
    assert!(record.consumed_at.is_none());
    assert_eq!(service.list_pending().len(), 1);

    // Nothing was approved, so consuming must fail.
    assert!(service.consume(&record.approval_id, &a).is_err());
}

#[test]
fn approved_request_consumes_exactly_once() {
    let service = ApprovalService::new();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");
    let record = request(&service, &a);

    service.decide(&record.approval_id, true).expect("approve");
    assert_eq!(
        service.get(&record.approval_id).unwrap().status,
        ApprovalStatus::Approved
    );

    let consumed = service
        .consume(&record.approval_id, &a)
        .expect("first consumption succeeds");
    assert_eq!(consumed.status, ApprovalStatus::Consumed);
    assert!(consumed.consumed_at.is_some());

    // Replay must fail.
    assert!(service.consume(&record.approval_id, &a).is_err());
    // And the record is no longer pending.
    assert!(service.list_pending().is_empty());
}

#[test]
fn rejected_request_never_consumes() {
    let service = ApprovalService::new();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");
    let record = request(&service, &a);

    service.decide(&record.approval_id, false).expect("deny");
    assert_eq!(
        service.get(&record.approval_id).unwrap().status,
        ApprovalStatus::Rejected
    );

    assert!(service.consume(&record.approval_id, &a).is_err());
}

#[test]
fn expired_request_cannot_be_decided_or_consumed() {
    let service = ApprovalService::new();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");

    let record = service
        .request_pending(
            &a,
            "reason",
            "v1",
            ApprovalScope::Once,
            Some(chrono::Utc::now() - chrono::Duration::minutes(1)),
        )
        .unwrap();

    // It must not even be possible to *approve* an already expired request.
    assert!(
        service.decide(&record.approval_id, true).is_err(),
        "an expired request cannot be approved"
    );
    assert!(
        service.consume(&record.approval_id, &a).is_err(),
        "an expired approval must not be consumable"
    );
    assert!(service.list_pending().is_empty());
}

#[test]
fn approval_cannot_authorize_a_modified_action() {
    let service = ApprovalService::new();
    let original = action("s1", "agent-a", "rm -rf /tmp/x");
    let record = request(&service, &original);
    service.decide(&record.approval_id, true).unwrap();

    // Same session/agent, different command.
    let modified = action("s1", "agent-a", "rm -rf /tmp/y");
    assert!(
        service.consume(&record.approval_id, &modified).is_err(),
        "an approval must not authorize a different command"
    );

    // The original is still unconsumed, so it can still be spent on itself.
    assert!(service.consume(&record.approval_id, &original).is_ok());
}

#[test]
fn cross_session_and_cross_agent_approvals_are_rejected() {
    let service = ApprovalService::new();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");
    let record = request(&service, &a);
    service.decide(&record.approval_id, true).unwrap();

    let other_session = action("s2", "agent-a", "rm -rf /tmp/x");
    assert!(
        service
            .consume(&record.approval_id, &other_session)
            .is_err(),
        "an approval must not cross sessions"
    );

    let other_agent = action("s1", "agent-b", "rm -rf /tmp/x");
    assert!(
        service.consume(&record.approval_id, &other_agent).is_err(),
        "an approval must not cross agents"
    );

    // The approved session/agent still owns it.
    assert!(service.consume(&record.approval_id, &a).is_ok());
}

#[test]
fn unknown_malformed_and_already_consumed_ids_fail_closed() {
    let service = ApprovalService::new();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");

    assert!(service.consume("does-not-exist", &a).is_err());
    assert!(service.consume("", &a).is_err());
    assert!(service.consume("../../etc/passwd", &a).is_err());
    assert!(service.decide("does-not-exist", true).is_err());

    let record = request(&service, &a);
    service.decide(&record.approval_id, true).unwrap();
    service.consume(&record.approval_id, &a).unwrap();

    // Already consumed.
    assert!(service.consume(&record.approval_id, &a).is_err());
    // Duplicate decision on a consumed request.
    assert!(service.decide(&record.approval_id, true).is_err());
    // Duplicate decision on a rejected request.
    let second = request(&service, &a);
    service.decide(&second.approval_id, false).unwrap();
    assert!(service.decide(&second.approval_id, true).is_err());
}

#[test]
fn concurrent_consumption_executes_once() {
    let service = ApprovalService::new();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");
    let record = request(&service, &a);
    service.decide(&record.approval_id, true).unwrap();

    let service = Arc::new(service);
    let id = record.approval_id.clone();

    let successes = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..8)
            .map(|_| {
                let service = Arc::clone(&service);
                let id = id.clone();
                let a = a.clone();
                scope.spawn(move || service.consume(&id, &a).is_ok())
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count()
    });

    assert_eq!(successes, 1, "exactly one consumer may win the approval");
    assert_eq!(service.get(&id).unwrap().status, ApprovalStatus::Consumed);
}

#[test]
fn persistent_store_roundtrips_across_processes() {
    let dir = std::env::temp_dir().join(format!("af-approval-{}", uuid::Uuid::new_v4()));
    let db = dir.join("approvals.db");

    // "Process A": the enforcement path records the request.
    {
        let service = ApprovalService::new_with_db(db.clone()).unwrap();
        let a = action("s1", "agent-a", "rm -rf /tmp/x");
        let record = request(&service, &a);
        assert_eq!(record.status, ApprovalStatus::Pending);
        // The record must be visible to a fresh connection.
        let fresh = ApprovalService::new_with_db(db.clone()).unwrap();
        assert!(fresh.refresh(&record.approval_id).is_some());
    }

    // "Process B": the operator approves it.
    {
        let service = ApprovalService::new_with_db(db.clone()).unwrap();
        let pending = service.list_pending();
        assert_eq!(pending.len(), 1);
        let id = pending[0].approval_id.clone();
        service.decide(&id, true).unwrap();
    }

    // "Process C": the gateway consumes it, exactly once.
    {
        let service = ApprovalService::new_with_db(db.clone()).unwrap();
        let approved = service
            .list_all()
            .into_iter()
            .find(|r| r.status == ApprovalStatus::Approved)
            .expect("approved record");
        let a = action("s1", "agent-a", "rm -rf /tmp/x");
        assert!(service.consume(&approved.approval_id, &a).is_ok());
        assert!(service.consume(&approved.approval_id, &a).is_err());
    }

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn concurrent_consumption_is_atomic_across_the_persistent_store() {
    let dir = std::env::temp_dir().join(format!("af-approval-{}", uuid::Uuid::new_v4()));
    let db = dir.join("approvals.db");

    let service = ApprovalService::new_with_db(db.clone()).unwrap();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");
    let record = request(&service, &a);
    service.decide(&record.approval_id, true).unwrap();

    let id = record.approval_id.clone();
    let a2 = a.clone();

    let successes = std::thread::scope(|scope| {
        let handles: Vec<_> = (0..6)
            .map(|_| {
                let db = db.clone();
                let id = id.clone();
                let a = a2.clone();
                scope.spawn(move || {
                    // Each thread is its own process-equivalent connection.
                    let svc = ApprovalService::new_with_db(db).unwrap();
                    svc.consume(&id, &a).is_ok()
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .filter(|ok| *ok)
            .count()
    });

    assert_eq!(
        successes, 1,
        "the BEGIN IMMEDIATE transaction must allow exactly one consumer"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn broker_waits_for_a_decision_and_consumes_once() {
    let dir = std::env::temp_dir().join(format!("af-approval-{}", uuid::Uuid::new_v4()));
    let db = dir.join("approvals.db");
    let config = ApprovalConfig {
        wait_timeout: Duration::from_secs(20),
        request_ttl: Duration::from_secs(60),
        db_path: db.clone(),
    };

    let broker = ApprovalBroker::open(config).unwrap();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");

    let record = broker.request(&a, "reason", "v1").unwrap();

    // A second, independent service plays the operator.
    let operator = ApprovalService::new_with_db(db.clone()).unwrap();
    let pending = operator.list_pending();
    assert_eq!(pending.len(), 1);
    operator
        .decide(&pending[0].approval_id, true)
        .expect("operator approves");

    let granted = broker
        .wait_for(&record.approval_id, &a, Some(Duration::from_secs(20)))
        .expect("wait succeeds");
    assert!(granted, "the approved action must be permitted once");

    // A second call must not be permitted.
    let again = broker
        .wait_for(&record.approval_id, &a, Some(Duration::from_millis(50)))
        .expect("wait succeeds");
    assert!(!again, "the approval was already consumed");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn broker_without_waiting_blocks_and_reports_pending() {
    let dir = std::env::temp_dir().join(format!("af-approval-{}", uuid::Uuid::new_v4()));
    let db = dir.join("approvals.db");
    let config = ApprovalConfig::without_waiting(db.clone());

    let broker = ApprovalBroker::open(config).unwrap();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");
    let record = broker.request(&a, "reason", "v1").unwrap();

    // The request is recorded and visible, but nothing is permitted.
    assert_eq!(
        broker.service().get(&record.approval_id).unwrap().status,
        ApprovalStatus::Pending
    );
    assert!(!broker.wait_for(&record.approval_id, &a, None).unwrap());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn broker_rejection_blocks_the_action() {
    let dir = std::env::temp_dir().join(format!("af-approval-{}", uuid::Uuid::new_v4()));
    let db = dir.join("approvals.db");
    let config = ApprovalConfig {
        wait_timeout: Duration::from_secs(20),
        request_ttl: Duration::from_secs(60),
        db_path: db.clone(),
    };

    let broker = ApprovalBroker::open(config).unwrap();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");
    let record = broker.request(&a, "reason", "v1").unwrap();

    let operator = ApprovalService::new_with_db(db.clone()).unwrap();
    let pending = operator.list_pending();
    operator.decide(&pending[0].approval_id, false).unwrap();

    let granted = broker
        .wait_for(&record.approval_id, &a, Some(Duration::from_secs(20)))
        .unwrap();
    assert!(!granted, "a rejected request must not permit the action");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn broker_timeout_blocks_the_action() {
    let dir = std::env::temp_dir().join(format!("af-approval-{}", uuid::Uuid::new_v4()));
    let db = dir.join("approvals.db");
    let config = ApprovalConfig {
        wait_timeout: Duration::from_millis(300),
        request_ttl: Duration::from_secs(60),
        db_path: db.clone(),
    };

    let broker = ApprovalBroker::open(config).unwrap();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");
    let record = broker.request(&a, "reason", "v1").unwrap();

    let granted = broker
        .wait_for(&record.approval_id, &a, Some(Duration::from_millis(400)))
        .unwrap();
    assert!(!granted, "a timeout must fail closed");

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn broker_open_fails_closed_on_unusable_storage() {
    // A path whose parent is a regular file can never be opened.
    let dir = std::env::temp_dir().join(format!("af-approval-{}", uuid::Uuid::new_v4()));
    let _ = std::fs::create_dir_all(&dir);
    let blocker = dir.join("blocker");
    std::fs::write(&blocker, "not a directory").unwrap();

    let config = ApprovalConfig {
        db_path: blocker.join("approvals.db"),
        ..ApprovalConfig::default()
    };

    // SECURITY: an approval infrastructure failure must surface as an error,
    // never as a silent permission.
    assert!(ApprovalBroker::open(config).is_err());

    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn digest_is_stable_and_action_specific() {
    let a = action("s1", "agent-a", "rm -rf /tmp/x");
    let same = action("s1", "agent-a", "rm -rf /tmp/x");
    let other = action("s1", "agent-a", "rm -rf /tmp/y");

    assert_eq!(a.digest(), same.digest(), "digest must be deterministic");
    assert_ne!(
        a.digest(),
        other.digest(),
        "digest must change with the action"
    );
    assert_eq!(a.digest().len(), 64);
}

// ─── Phase 10: context binding ───────────────────────────────────────────────

// ─── Phase 10: expiry boundaries ─────────────────────────────────────────────

// ─── Phase 10: concurrent decisions ──────────────────────────────────────────

// ─── Phase 10: true multi-process replay ─────────────────────────────────────

