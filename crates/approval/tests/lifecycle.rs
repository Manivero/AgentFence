//! Phase 9 — approval lifecycle tests.
//!
//! These tests exercise the security-critical behaviour of the approval
//! boundary: binding, expiry, replay prevention and atomic consumption.

use std::sync::Arc;
use std::time::Duration;

use agentfence_approval::approval::{ApprovalScope, ApprovalService, ApprovalStatus};
use agentfence_approval::broker::{ApprovalBroker, ApprovalConfig};
use agentfence_core::types::{Action, ActionId, ActionType, AgentId, Context, SessionId, TaskId};

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

fn action_with_context(session: &str, agent: &str, target: &str, ctx: Context) -> Action {
    Action {
        id: ActionId::new(),
        session_id: SessionId(session.to_string()),
        agent_id: AgentId(agent.to_string()),
        task_id: ctx.task_id.clone(),
        action_type: ActionType::Shell,
        tool: "shell".to_string(),
        target: target.to_string(),
        args_hash: format!("h:{}", target),
        context: ctx,
    }
}

#[test]
fn approval_cannot_be_consumed_in_a_different_directory() {
    // SECURITY: `git push` in /srv/production and in /tmp are different
    // operations. An approval issued for one must not authorise the other.
    let service = ApprovalService::new();

    let prod_ctx = Context {
        cwd: Some("/srv/production".to_string()),
        ..Default::default()
    };
    let original = action_with_context("s1", "agent-a", "git push", prod_ctx);
    let record = request(&service, &original);
    service.decide(&record.approval_id, true).unwrap();

    let tmp_ctx = Context {
        cwd: Some("/tmp".to_string()),
        ..Default::default()
    };
    let elsewhere = action_with_context("s1", "agent-a", "git push", tmp_ctx);
    assert!(
        service.consume(&record.approval_id, &elsewhere).is_err(),
        "an approval must not be consumed from a different directory"
    );

    // The original context still owns it.
    assert!(service.consume(&record.approval_id, &original).is_ok());
}

#[test]
fn approval_cannot_be_consumed_from_a_different_location() {
    // SECURITY: location conditions read `client_ip` and `host`.
    let service = ApprovalService::new();

    let allowed_ctx = Context {
        client_ip: Some("10.0.0.5".to_string()),
        host: Some("prod.internal".to_string()),
        ..Default::default()
    };
    let original = action_with_context("s1", "agent-a", "deploy", allowed_ctx);
    let record = request(&service, &original);
    service.decide(&record.approval_id, true).unwrap();

    let other_ip = action_with_context(
        "s1",
        "agent-a",
        "deploy",
        Context {
            client_ip: Some("203.0.113.9".to_string()),
            host: Some("prod.internal".to_string()),
            ..Default::default()
        },
    );
    assert!(service.consume(&record.approval_id, &other_ip).is_err());

    let other_host = action_with_context(
        "s1",
        "agent-a",
        "deploy",
        Context {
            client_ip: Some("10.0.0.5".to_string()),
            host: Some("dev.internal".to_string()),
            ..Default::default()
        },
    );
    assert!(service.consume(&record.approval_id, &other_host).is_err());

    assert!(service.consume(&record.approval_id, &original).is_ok());
}

#[test]
fn approval_cannot_be_consumed_in_a_different_repository_or_branch() {
    // SECURITY: plugins receive repository/branch/task_id and can change their
    // decision based on them.
    let service = ApprovalService::new();

    let prod = Context {
        repository: Some("acme/prod".to_string()),
        branch: Some("main".to_string()),
        task_id: Some(TaskId("task-1".to_string())),
        ..Default::default()
    };
    let original = action_with_context("s1", "agent-a", "publish", prod);
    let record = request(&service, &original);
    service.decide(&record.approval_id, true).unwrap();

    let dev = Context {
        repository: Some("acme/dev".to_string()),
        branch: Some("main".to_string()),
        task_id: Some(TaskId("task-1".to_string())),
        ..Default::default()
    };
    assert!(service
        .consume(
            &record.approval_id,
            &action_with_context("s1", "agent-a", "publish", dev)
        )
        .is_err());

    assert!(service.consume(&record.approval_id, &original).is_ok());
}

#[test]
fn env_metadata_does_not_weaken_the_binding() {
    // Documented exclusion: env_metadata is untrusted and consulted by neither
    // the PDP nor the plugins, so it must not affect the binding.
    let service = ApprovalService::new();

    let ctx = Context::default();
    let original = action_with_context("s1", "agent-a", "git push", ctx.clone());
    let record = request(&service, &original);
    service.decide(&record.approval_id, true).unwrap();

    let spoofed = action_with_context(
        "s1",
        "agent-a",
        "git push",
        Context {
            env_metadata: Some(serde_json::json!({"host": "evil.example.com"})),
            ..ctx
        },
    );
    assert!(service.consume(&record.approval_id, &spoofed).is_ok());
}

// ─── Phase 10: expiry boundaries ─────────────────────────────────────────────

#[test]
fn expiry_boundary_is_inclusive_and_enforced() {
    let service = ApprovalService::new();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");

    // A request that expires one second from now is still valid.
    let alive = service
        .request_pending(
            &a,
            "reason",
            "v1",
            ApprovalScope::Once,
            Some(chrono::Utc::now() + chrono::Duration::seconds(1)),
        )
        .unwrap();
    assert!(alive.is_valid(), "a future expiry must be valid");

    // A request that expired one second ago is not.
    let dead = service
        .request_pending(
            &a,
            "reason",
            "v1",
            ApprovalScope::Once,
            Some(chrono::Utc::now() - chrono::Duration::seconds(1)),
        )
        .unwrap();
    assert!(!dead.is_valid(), "a past expiry must be invalid");
    assert!(service.decide(&dead.approval_id, true).is_err());
    assert!(service.consume(&dead.approval_id, &a).is_err());
}

#[test]
fn an_approved_request_cannot_be_consumed_after_it_expires() {
    // SECURITY: the validity check happens inside the same atomic transition as
    // the consumption, so there is no window between "still valid" and "spent".
    let service = ApprovalService::new();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");

    let record = service
        .request_pending(
            &a,
            "reason",
            "v1",
            ApprovalScope::Once,
            Some(chrono::Utc::now() + chrono::Duration::milliseconds(200)),
        )
        .unwrap();
    service.decide(&record.approval_id, true).unwrap();

    // Wait past the expiry, then try to consume.
    std::thread::sleep(std::time::Duration::from_millis(400));
    assert!(
        service.consume(&record.approval_id, &a).is_err(),
        "an expired approval must not be consumable"
    );
    assert_eq!(
        service.get(&record.approval_id).unwrap().status,
        ApprovalStatus::Expired,
        "the expired request must be recorded as Expired"
    );
}

#[test]
fn restarting_the_service_does_not_reset_approval_state() {
    // SECURITY: approval state lives in SQLite, not in process memory.
    let dir = std::env::temp_dir().join(format!("af-approval-{}", uuid::Uuid::new_v4()));
    let db = dir.join("approvals.db");

    let a = action("s1", "agent-a", "rm -rf /tmp/x");
    let approval_id = {
        let service = ApprovalService::new_with_db(db.clone()).unwrap();
        let record = request(&service, &a);
        service.decide(&record.approval_id, true).unwrap();
        record.approval_id
    };

    // Simulate a restart: a brand new service over the same store.
    let restarted = ApprovalService::new_with_db(db.clone()).unwrap();
    let record = restarted.get(&approval_id).expect("state must survive");
    assert_eq!(record.status, ApprovalStatus::Approved);
    assert!(restarted.consume(&approval_id, &a).is_ok());

    let _ = std::fs::remove_dir_all(&dir);
}

// ─── Phase 10: concurrent decisions ──────────────────────────────────────────

#[test]
fn concurrent_approve_and_reject_produces_exactly_one_decision() {
    let service = ApprovalService::new();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");
    let record = request(&service, &a);
    let id = record.approval_id.clone();

    let service = Arc::new(service);
    let outcomes = std::thread::scope(|scope| {
        let mut handles = Vec::new();
        for i in 0..8 {
            let service = Arc::clone(&service);
            let id = id.clone();
            handles.push(scope.spawn(move || {
                let approve = i % 2 == 0;
                service.decide(&id, approve).map(|r| r.decision)
            }));
        }
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });

    let decided = outcomes.iter().filter(|o| o.is_ok()).count();
    assert_eq!(decided, 1, "exactly one decision may succeed");

    // The recorded decision matches the winner.
    let final_record = service.get(&id).unwrap();
    assert!(matches!(
        final_record.status,
        ApprovalStatus::Approved | ApprovalStatus::Rejected
    ));
    assert!(outcomes.iter().any(|o| o
        .as_ref()
        .ok()
        .map(|d| *d == final_record.decision)
        .unwrap_or(false)));
}

// ─── Phase 10: true multi-process replay ─────────────────────────────────────

#[test]
fn two_separate_processes_cannot_both_consume_the_same_approval() {
    // Worker mode: this test binary re-executes itself as a consumer process.
    if let (Ok(db), Ok(id), Ok(action_json)) = (
        std::env::var("AF_WORKER_DB"),
        std::env::var("AF_WORKER_ID"),
        std::env::var("AF_WORKER_ACTION"),
    ) {
        let action: Action = serde_json::from_str(&action_json).expect("worker action");
        let service = ApprovalService::new_with_db(std::path::PathBuf::from(db)).unwrap();
        let ok = service.consume(&id, &action).is_ok();
        std::process::exit(if ok { 0 } else { 1 });
    }

    let dir = std::env::temp_dir().join(format!("af-approval-{}", uuid::Uuid::new_v4()));
    let db = dir.join("approvals.db");

    let service = ApprovalService::new_with_db(db.clone()).unwrap();
    let a = action("s1", "agent-a", "rm -rf /tmp/x");
    let record = request(&service, &a);
    service.decide(&record.approval_id, true).unwrap();
    drop(service);

    // Two genuinely separate OS processes race for the same approval.
    let exe = std::env::current_exe().unwrap();
    let test_name = "two_separate_processes_cannot_both_consume_the_same_approval";
    let action_json = serde_json::to_string(&a).unwrap();

    let mut children = Vec::new();
    for _ in 0..2 {
        children.push(
            std::process::Command::new(&exe)
                .args(["--exact", test_name])
                .env("AF_WORKER_DB", &db)
                .env("AF_WORKER_ID", &record.approval_id)
                .env("AF_WORKER_ACTION", &action_json)
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn()
                .expect("worker process"),
        );
    }

    let successes = children
        .into_iter()
        .map(|mut c| c.wait().expect("worker wait").success())
        .filter(|ok| *ok)
        .count();

    assert_eq!(
        successes, 1,
        "exactly one process must consume the approval; the other must be refused"
    );

    // Database state is consistent: one Consumed record, no duplicates.
    let after = ApprovalService::new_with_db(db.clone()).unwrap();
    let all = after.list_all();
    assert_eq!(all.len(), 1, "no duplicate records may be created");
    assert_eq!(all[0].status, ApprovalStatus::Consumed);
    assert!(all[0].consumed_at.is_some());

    let _ = std::fs::remove_dir_all(&dir);
}
