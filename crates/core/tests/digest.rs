//! Phase 10 — `Action::digest()` correctness and binding tests.
//!
//! The digest is what an approval is bound to. These tests pin down two things:
//! every authorization-relevant field is covered, and the encoding cannot
//! produce collisions.

use agentfence_core::types::{Action, ActionId, ActionType, AgentId, Context, SessionId, TaskId};

fn base() -> Action {
    Action {
        id: ActionId::new(),
        session_id: SessionId("session-1".to_string()),
        agent_id: AgentId("agent-1".to_string()),
        task_id: None,
        action_type: ActionType::Shell,
        tool: "shell".to_string(),
        target: "git push".to_string(),
        args_hash: "h:git push".to_string(),
        context: Context::default(),
    }
}

fn differs(a: &Action, b: &Action) {
    assert_ne!(
        a.digest(),
        b.digest(),
        "a change to an authorization-relevant field must change the digest\na: {:?}\nb: {:?}",
        a,
        b
    );
}

#[test]
fn digest_is_deterministic_and_well_formed() {
    let a = base();
    assert_eq!(a.digest(), a.digest());
    assert_eq!(a.digest().len(), 64, "SHA-256 hex must be 64 chars");
    assert!(
        a.digest().chars().all(|c| c.is_ascii_hexdigit()),
        "digest must be lowercase hex"
    );
}

// ─── Scalar action fields ────────────────────────────────────────────────────

#[test]
fn digest_covers_action_type_tool_target_and_args() {
    let a = base();
    differs(
        &a,
        &Action {
            action_type: ActionType::Mcp,
            ..a.clone()
        },
    );
    differs(
        &a,
        &Action {
            tool: "network".to_string(),
            ..a.clone()
        },
    );
    differs(
        &a,
        &Action {
            target: "git push --force".to_string(),
            ..a.clone()
        },
    );
    differs(
        &a,
        &Action {
            args_hash: "h:other".to_string(),
            ..a.clone()
        },
    );
}

#[test]
fn digest_covers_session_and_agent() {
    let a = base();
    differs(
        &a,
        &Action {
            session_id: SessionId("session-2".to_string()),
            ..a.clone()
        },
    );
    differs(
        &a,
        &Action {
            agent_id: AgentId("agent-2".to_string()),
            ..a.clone()
        },
    );
}

// ─── Authorization-relevant context ──────────────────────────────────────────

#[test]
fn digest_covers_cwd() {
    // SECURITY: `git push` means something different per directory. An approval
    // issued for one directory must not authorize the same command elsewhere.
    let a = base();
    let mut b = a.clone();
    b.context.cwd = Some("/srv/production".to_string());
    differs(&a, &b);

    let mut c = a.clone();
    c.context.cwd = Some("/tmp".to_string());
    differs(&b, &c);
}

#[test]
fn digest_covers_location_context() {
    // SECURITY: location conditions read exactly `client_ip` and `host`. A
    // request approved from an allowed location must not be consumed from
    // another one.
    let a = base();

    let mut allowed = a.clone();
    allowed.context.client_ip = Some("10.0.0.5".to_string());
    differs(&a, &allowed);

    let mut other = a.clone();
    other.context.client_ip = Some("203.0.113.9".to_string());
    differs(&allowed, &other);

    let mut host_a = a.clone();
    host_a.context.host = Some("prod.internal".to_string());
    let mut host_b = a.clone();
    host_b.context.host = Some("dev.internal".to_string());
    differs(&host_a, &host_b);
    differs(&a, &host_a);
}

#[test]
fn digest_covers_plugin_relevant_context() {
    // SECURITY: plugins receive cwd/repository/branch/task_id and can change
    // their decision based on them.
    let a = base();

    let mut repo = a.clone();
    repo.context.repository = Some("acme/prod".to_string());
    differs(&a, &repo);

    let mut other_repo = a.clone();
    other_repo.context.repository = Some("acme/dev".to_string());
    differs(&repo, &other_repo);

    let mut branch = a.clone();
    branch.context.branch = Some("main".to_string());
    differs(&a, &branch);

    let mut task = a.clone();
    task.task_id = Some(TaskId("task-1".to_string()));
    differs(&a, &task);

    let mut other_task = a.clone();
    other_task.task_id = Some(TaskId("task-2".to_string()));
    differs(&task, &other_task);
}

#[test]
fn digest_excludes_env_metadata_by_design() {
    // Documented exclusion: `env_metadata` is untyped and untrusted, and is
    // consulted by neither the PDP nor the plugins.
    let a = base();
    let mut b = a.clone();
    b.context.env_metadata = Some(serde_json::json!({"host": "evil.example.com"}));
    assert_eq!(
        a.digest(),
        b.digest(),
        "env_metadata must not affect the binding (it is not a trusted source)"
    );
}

// ─── Encoding correctness ────────────────────────────────────────────────────

#[test]
fn encoding_has_no_concatenation_collision() {
    // Two different field splits must not produce the same digest.
    let mut a = base();
    a.tool = "ab".to_string();
    a.target = "c".to_string();

    let mut b = base();
    b.tool = "a".to_string();
    b.target = "bc".to_string();

    assert_ne!(
        a.digest(),
        b.digest(),
        "length-prefixing must prevent collisions"
    );
}

#[test]
fn absent_and_empty_are_different() {
    let a = base();
    let mut b = a.clone();
    b.context.cwd = Some(String::new());
    assert_ne!(
        a.digest(),
        b.digest(),
        "`None` and `Some(\"\")` must not be interchangeable"
    );
}

#[test]
fn unicode_is_encoded_as_bytes_not_chars() {
    // Byte-length prefixing means a multi-byte value cannot be confused with an
    // ASCII value of the same character count.
    let mut a = base();
    a.target = "héllo".to_string();

    let mut b = base();
    b.target = "hxxxx".to_string();

    assert_eq!(a.target.chars().count(), b.target.chars().count());
    assert_ne!(a.digest(), b.digest());
}

#[test]
fn empty_action_is_stable() {
    let a = Action {
        id: ActionId::new(),
        session_id: SessionId(String::new()),
        agent_id: AgentId(String::new()),
        task_id: None,
        action_type: ActionType::Shell,
        tool: String::new(),
        target: String::new(),
        args_hash: String::new(),
        context: Context::default(),
    };
    assert_eq!(a.digest(), a.digest());
    assert_eq!(a.digest().len(), 64);
}

#[test]
fn digest_does_not_contain_plaintext_values() {
    let mut a = base();
    a.target = "ghp_supersecrettoken123".to_string();
    let digest = a.digest();
    assert!(
        !digest.contains("ghp_supersecrettoken123"),
        "the digest must never embed plaintext values"
    );
}
