//! CLI secrecy tests: a credential that appears in a command must never reach
//! stdout, stderr, the approval store, or the audit store.

use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

use agentfence_approval::approval::{ApprovalScope, ApprovalService};
use agentfence_core::types::{
    Action, ActionId, ActionType, AgentId, Context, Decision, RiskLevel, SessionId,
};

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let n = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "agentfence-secrecy-{}-{}-{}",
            label,
            std::process::id(),
            n
        ));
        std::fs::create_dir_all(&path).unwrap();
        Self { path }
    }

    fn join(&self, name: &str) -> PathBuf {
        self.path.join(name)
    }

    fn data_dir(&self) -> PathBuf {
        self.path.join("data")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

const TOKEN: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

fn runner() -> &'static str {
    if cfg!(windows) {
        "cmd"
    } else {
        "sh"
    }
}

fn write_allow_policy(dir: &TempDir) -> PathBuf {
    let yaml = format!(
        "version: 1\ndefaults:\n  shell: deny\n  network: deny\n  mcp: deny\n  filesystem: deny\nshell:\n  allow:\n    - {}\n",
        runner()
    );
    let path = dir.join("allow.yaml");
    std::fs::write(&path, yaml).unwrap();
    path
}

fn run_agentfence(args: &[&str], data_dir: &std::path::Path) -> Output {
    let agentfence = env!("CARGO_BIN_EXE_agentfence");
    Command::new(agentfence)
        .args(args)
        .env("AGENTFENCE_DATA_DIR", data_dir)
        .output()
        .expect("spawn agentfence")
}

fn stdout_plus_stderr(out: &Output) -> String {
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    s
}

#[test]
fn exec_never_prints_a_credential_from_the_command() {
    let dir = TempDir::new("exec");
    let policy = write_allow_policy(&dir);

    // The command writes the token to the null device, so the token can only
    // appear in the output if AgentFence itself prints it.
    let sink = if cfg!(windows) { "nul" } else { "/dev/null" };
    let script = format!("echo {TOKEN} > {sink}");
    let out = run_agentfence(
        &[
            "exec",
            "--policy",
            &policy.to_string_lossy(),
            "--",
            runner(),
            "/C",
            &script,
        ],
        &dir.data_dir(),
    );

    let combined = stdout_plus_stderr(&out);
    assert!(
        !combined.contains(TOKEN),
        "credential leaked to the CLI output:\n{}",
        combined
    );
    assert!(
        combined.contains("[REDACTED]"),
        "the credential should be masked, not silently dropped:\n{}",
        combined
    );
}

#[test]
fn the_approval_store_keeps_a_redacted_target() {
    let dir = TempDir::new("approval-store");
    let db = dir.data_dir().join("approvals.db");
    let service = ApprovalService::new_with_db(db.clone()).unwrap();

    let action = Action {
        id: ActionId("action-secret".into()),
        action_type: ActionType::Shell,
        tool: "shell".into(),
        target: format!("echo {TOKEN}"),
        args_hash: "hash".into(),
        session_id: SessionId("s1".into()),
        agent_id: AgentId("a1".into()),
        task_id: None,
        context: Context::default(),
    };

    let record = service
        .request_pending(&action, "needs approval", "v1", ApprovalScope::Once, None)
        .unwrap();

    // Read the row back through a fresh connection: what is on disk must be
    // redacted, not merely redacted in memory.
    let conn = rusqlite::Connection::open(&db).unwrap();
    let target: String = conn
        .query_row(
            "SELECT target FROM approvals WHERE approval_id = ?1",
            [&record.approval_id],
            |r| r.get(0),
        )
        .unwrap();
    assert!(
        !target.contains(TOKEN),
        "approval store holds the raw credential: {target}"
    );
    assert!(target.contains("[REDACTED]"), "{target}");
}

#[test]
fn approve_list_and_show_never_print_a_credential() {
    let dir = TempDir::new("approve-display");
    let db = dir.data_dir().join("approvals.db");
    let service = ApprovalService::new_with_db(db).unwrap();

    let action = Action {
        id: ActionId("action-secret-2".into()),
        action_type: ActionType::Shell,
        tool: "shell".into(),
        target: format!("curl -H \"Authorization: Bearer {TOKEN}\" https://example.com"),
        args_hash: "hash".into(),
        session_id: SessionId("s1".into()),
        agent_id: AgentId("a1".into()),
        task_id: None,
        context: Context::default(),
    };

    let record = service
        .request_pending(&action, "needs approval", "v1", ApprovalScope::Once, None)
        .unwrap();

    let list = run_agentfence(&["approve", "list", "--all"], &dir.data_dir());
    let list_out = stdout_plus_stderr(&list);
    assert!(
        !list_out.contains(TOKEN),
        "approve list leaked a credential:\n{list_out}"
    );

    let show = run_agentfence(
        &["approve", record.approval_id.as_str(), "--decision", "show"],
        &dir.data_dir(),
    );
    let show_out = stdout_plus_stderr(&show);
    assert!(
        !show_out.contains(TOKEN),
        "approve show leaked a credential:\n{show_out}"
    );
    assert!(show_out.contains("[REDACTED]"), "{show_out}");

    // The interactive prompt path shows the same redacted record.
    let prompt = run_agentfence(&["approve", record.approval_id.as_str()], &dir.data_dir());
    let prompt_out = stdout_plus_stderr(&prompt);
    assert!(
        !prompt_out.contains(TOKEN),
        "approval prompt leaked a credential:\n{prompt_out}"
    );
}

#[test]
fn the_audit_store_keeps_a_redacted_target() {
    let dir = TempDir::new("audit-store");
    let db = dir.data_dir().join("agentfence.db");
    let store = agentfence_audit::sqlite_store::SqliteStore::new(&db).unwrap();

    let session = agentfence_audit::session::Session {
        session_id: SessionId("s1".into()),
        agent_id: AgentId("a1".into()),
        task_id: None,
        started_at: chrono::Utc::now(),
        ended_at: None,
        policy_version: "1".into(),
        policy_hash: "hash".into(),
        protection_mode: agentfence_core::types::ProtectionMode::Cooperative,
    };
    store.record_session(&session).unwrap();

    let event = agentfence_audit::event::AuditEvent::new(
        SessionId("s1".into()),
        AgentId("a1".into()),
        None,
        ActionId("action-1".into()),
        None,
        "shell",
        "shell",
        format!("echo {TOKEN}"),
        "hash",
        Decision::Allow,
        RiskLevel::Low,
        "shell.allow",
        "1",
        "hash",
        "0",
    );
    store.record_event(&event).unwrap();

    let events = store.load_events("s1").unwrap();
    assert!(!events[0].target.contains(TOKEN), "{}", events[0].target);
    assert!(
        events[0].target.contains("[REDACTED]"),
        "{}",
        events[0].target
    );
}

#[test]
fn redaction_does_not_change_the_action_digest_binding() {
    let dir = TempDir::new("digest");
    let db = dir.data_dir().join("approvals.db");
    let service = ApprovalService::new_with_db(db).unwrap();

    let action = Action {
        id: ActionId("action-3".into()),
        action_type: ActionType::Shell,
        tool: "shell".into(),
        target: format!("echo {TOKEN}"),
        args_hash: "hash".into(),
        session_id: SessionId("s1".into()),
        agent_id: AgentId("a1".into()),
        task_id: None,
        context: Context::default(),
    };

    let before = action.digest();
    let record = service
        .request_pending(&action, "needs approval", "v1", ApprovalScope::Once, None)
        .unwrap();
    // The stored display target is redacted; the approval binding still commits
    // to the exact original action.
    assert_ne!(record.target, format!("echo {TOKEN}"));
    assert_eq!(record.action_digest, before);
}
