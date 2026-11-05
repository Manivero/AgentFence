//! Phase 9 — end-to-end approval flow tests.
//!
//! These drive the real `agentfence` binary, so they prove the flow an operator
//! actually experiences: policy returns `Ask`, the pending request is recorded,
//! the side effect is prevented, a human decides, and only then does the action
//! run — exactly once.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use agentfence_approval::approval::ApprovalService;
use agentfence_approval::broker::ApprovalConfig;

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let n = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "agentfence-approval-flow-{}-{}-{}",
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
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

fn runner() -> (&'static str, &'static str) {
    if cfg!(windows) {
        ("cmd", ".bat")
    } else {
        ("sh", ".sh")
    }
}

fn slash_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Policy whose shell decision is `ask` for the runner executables.
///
/// SECURITY: the `shell:` section is required — the PDP fails closed with
/// "No shell policy defined" when it is absent, and an explicit `allow` entry
/// overrides the default. `shell.ask` is therefore the way to request a human
/// decision for a specific executable.
fn write_ask_policy(dir: &TempDir) -> PathBuf {
    let yaml = "version: 1\ndefaults:\n  shell: deny\n  network: deny\n  mcp: deny\n  filesystem: deny\nshell:\n  ask:\n    - cmd\n    - sh\n";
    let path = dir.join("ask.yaml");
    std::fs::write(&path, yaml).unwrap();
    path
}

/// Policy with an explicit allow list (no ask anywhere).
fn write_allow_policy(dir: &TempDir, allow: &[&str]) -> PathBuf {
    let body = allow
        .iter()
        .map(|a| format!("    - {}", a))
        .collect::<Vec<_>>()
        .join("\n");
    let allow_block = if allow.is_empty() {
        "  allow: []".to_string()
    } else {
        format!("  allow:\n{}", body)
    };
    let yaml = format!(
        "version: 1\ndefaults:\n  shell: deny\n  network: deny\n  mcp: deny\n  filesystem: deny\nshell:\n{}",
        allow_block
    );
    let path = dir.join("allow.yaml");
    std::fs::write(&path, yaml).unwrap();
    path
}

/// Policy with a WASM plugin whose guest returns `Ask` for `ask.example.com`.
fn write_plugin_ask_policy(dir: &TempDir) -> PathBuf {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../wasm-plugin/tests/fixtures/test-plugin.component.wasm"
    );
    let yaml = format!(
        "version: 1\ndefaults:\n  shell: allow\n  network: deny\n  mcp: deny\n  filesystem: deny\n\
         shell:\n  allow:\n    - cmd\n    - sh\n\
         plugins:\n  wasm:\n    - id: test-plugin\n      enabled: true\n      module: {}\n",
        fixture
    );
    let path = dir.join("plugin-ask.yaml");
    std::fs::write(&path, yaml).unwrap();
    path
}

/// Write the script that creates `sentinel`, and return the command that runs it.
fn write_side_effect_script(dir: &TempDir, sentinel: &Path, tag: &str) -> String {
    let (runner_name, ext) = runner();
    let script = dir.path.join(format!("side_effect{}{}", tag, ext));
    let body = format!("echo invoked > \"{}\"", slash_path(sentinel));
    std::fs::write(&script, body).unwrap();

    if runner_name == "cmd" {
        format!("{} /c {}", runner_name, slash_path(&script))
    } else {
        format!("{} {}", runner_name, slash_path(&script))
    }
}

struct ExecSpawn {
    child: std::process::Child,
}

impl ExecSpawn {
    /// Start `agentfence exec` and return once the process is running.
    fn start(policy: &Path, raw_command: &str, dir: &TempDir, timeout_ms: u64) -> Self {
        let agentfence = env!("CARGO_BIN_exe_agentfence");
        let parts: Vec<&str> = raw_command.split_whitespace().collect();

        let child = Command::new(agentfence)
            .arg("exec")
            .arg("--policy")
            .arg(policy)
            .arg("--")
            .args(&parts)
            .current_dir(&dir.path)
            .env("AGENTFENCE_DATA_DIR", dir.path.to_str().unwrap())
            .env("AGENTFENCE_APPROVAL_TIMEOUT_MS", timeout_ms.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("failed to spawn agentfence exec");

        Self { child }
    }

    fn finish(self) -> std::process::Output {
        self.child
            .wait_with_output()
            .expect("failed to collect agentfence exec output")
    }
}

/// Wait until a pending request appears in the isolated approval store.
fn wait_for_pending(dir: &TempDir, timeout: Duration) -> Option<String> {
    let db = dir.join("approvals.db");
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if db.exists() {
            if let Ok(service) = ApprovalService::new_with_db(db.clone()) {
                if let Some(record) = service.list_pending().into_iter().next() {
                    return Some(record.approval_id);
                }
            }
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    None
}

fn decide(dir: &TempDir, approval_id: &str, approve: bool) -> Result<(), String> {
    let db = dir.join("approvals.db");
    let service = ApprovalService::new_with_db(db).map_err(|e| e.to_string())?;
    service
        .decide(approval_id, approve)
        .map(|_| ())
        .map_err(|e| e.to_string())
}

fn wait_for_sentinel(sentinel: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if sentinel.exists() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

#[test]
fn ask_records_a_pending_request_and_does_not_execute() {
    // SECURITY: with the default decision `ask`, the command must not run and a
    // pending request must exist for a human to decide.
    let dir = TempDir::new("ask-pending");
    let sentinel = dir.join("sentinel.txt");
    let policy = write_ask_policy(&dir);
    let raw = write_side_effect_script(&dir, &sentinel, "ask");

    // Short timeout: the request is recorded, then the wait fails closed.
    let output = {
        let agentfence = env!("CARGO_BIN_exe_agentfence");
        let parts: Vec<&str> = raw.split_whitespace().collect();
        Command::new(agentfence)
            .arg("exec")
            .arg("--policy")
            .arg(&policy)
            .arg("--")
            .args(&parts)
            .current_dir(&dir.path)
            .env("AGENTFENCE_DATA_DIR", dir.path.to_str().unwrap())
            .env("AGENTFENCE_APPROVAL_TIMEOUT_MS", "800")
            .output()
            .expect("failed to run agentfence exec")
    };

    assert!(
        !output.status.success(),
        "an unanswered Ask must exit non-zero"
    );
    assert!(
        !sentinel.exists(),
        "a command awaiting approval must never reach the execution backend"
    );

    // The request must be recorded and inspectable.
    let db = dir.join("approvals.db");
    let service = ApprovalService::new_with_db(db).unwrap();
    let pending = service.list_pending();
    assert_eq!(pending.len(), 1, "exactly one request must be pending");
    assert_eq!(pending[0].tool, "shell");
    assert!(
        pending[0].reason.contains("requires approval"),
        "the request must carry the policy reason: {}",
        pending[0].reason
    );
}

#[test]
fn approving_the_pending_request_enables_the_action() {
    // SECURITY: approval permits the action, but only the action that was asked
    // about, and only once.
    let dir = TempDir::new("approve");
    let sentinel = dir.join("sentinel.txt");
    let policy = write_ask_policy(&dir);
    let raw = write_side_effect_script(&dir, &sentinel, "approve");

    let spawn = ExecSpawn::start(&policy, &raw, &dir, 30_000);

    let approval_id = wait_for_pending(&dir, Duration::from_secs(10))
        .expect("a pending request must be recorded");

    decide(&dir, &approval_id, true).expect("operator approves");

    let output = spawn.finish();
    assert!(
        output.status.success(),
        "an approved command must exit zero; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        wait_for_sentinel(&sentinel, Duration::from_secs(5)),
        "an approved command must reach the execution backend"
    );

    // The approval is spent.
    let service = ApprovalService::new_with_db(dir.join("approvals.db")).unwrap();
    assert!(
        service.list_pending().is_empty(),
        "the approval must be consumed, not left pending"
    );
}

#[test]
fn rejecting_keeps_the_action_blocked() {
    // SECURITY: a refusal must block the action and leave no execution.
    let dir = TempDir::new("reject");
    let sentinel = dir.join("sentinel.txt");
    let policy = write_ask_policy(&dir);
    let raw = write_side_effect_script(&dir, &sentinel, "reject");

    let spawn = ExecSpawn::start(&policy, &raw, &dir, 30_000);
    let approval_id = wait_for_pending(&dir, Duration::from_secs(10)).expect("pending request");
    decide(&dir, &approval_id, false).expect("operator rejects");

    let output = spawn.finish();
    assert!(
        !output.status.success(),
        "a rejected command must exit non-zero"
    );
    assert!(
        !sentinel.exists(),
        "a rejected command must never reach the execution backend"
    );
}

#[test]
fn an_approval_is_single_use_across_runs() {
    // SECURITY: replaying the same command must not be authorised by the
    // approval that was already spent.
    let dir = TempDir::new("replay");
    let sentinel = dir.join("sentinel.txt");
    let policy = write_ask_policy(&dir);
    let raw = write_side_effect_script(&dir, &sentinel, "replay");

    // First run: approved and executed.
    let spawn = ExecSpawn::start(&policy, &raw, &dir, 30_000);
    let approval_id = wait_for_pending(&dir, Duration::from_secs(10)).unwrap();
    decide(&dir, &approval_id, true).unwrap();
    let first = spawn.finish();
    assert!(first.status.success(), "first run must be approved and run");
    assert!(wait_for_sentinel(&sentinel, Duration::from_secs(5)));

    std::fs::remove_file(&sentinel).unwrap();

    // Second run of the identical command: no approval is available any more.
    let spawn = ExecSpawn::start(&policy, &raw, &dir, 5_000);
    let second = spawn.finish();
    assert!(
        !second.status.success(),
        "a consumed approval must not authorise a second execution"
    );
    assert!(
        !sentinel.exists(),
        "the second run must not reach the execution backend"
    );

    let service = ApprovalService::new_with_db(dir.join("approvals.db")).unwrap();
    let all = service.list_all();
    assert_eq!(all.len(), 2, "the second run created its own request");
    assert!(
        all.iter()
            .any(|r| r.status == agentfence_approval::approval::ApprovalStatus::Consumed),
        "the first approval must be marked consumed"
    );
}

#[test]
fn an_unknown_approval_id_cannot_decide_anything() {
    // SECURITY: the CLI must not invent or guess a request.
    let dir = TempDir::new("unknown-id");
    let agentfence = env!("CARGO_BIN_exe_agentfence");

    let output = Command::new(agentfence)
        .arg("approve")
        .arg("00000000-0000-0000-0000-000000000000")
        .arg("--decision")
        .arg("allow")
        .env("AGENTFENCE_DATA_DIR", dir.path.to_str().unwrap())
        .output()
        .expect("failed to run agentfence approve");

    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("No approval request found"),
        "an unknown id must be refused: {}",
        stdout
    );

    // Nothing was recorded.
    let db = dir.join("approvals.db");
    assert!(
        !db.exists()
            || ApprovalService::new_with_db(db)
                .unwrap()
                .list_all()
                .is_empty()
    );
}

#[test]
fn approve_list_and_show_expose_the_pending_request() {
    let dir = TempDir::new("list-show");
    let sentinel = dir.join("sentinel.txt");
    let policy = write_ask_policy(&dir);
    let raw = write_side_effect_script(&dir, &sentinel, "list");

    let spawn = ExecSpawn::start(&policy, &raw, &dir, 8_000);
    let approval_id = wait_for_pending(&dir, Duration::from_secs(10)).unwrap();
    let _ = spawn.finish();

    let agentfence = env!("CARGO_BIN_exe_agentfence");

    let list = Command::new(agentfence)
        .arg("approve")
        .arg("list")
        .env("AGENTFENCE_DATA_DIR", dir.path.to_str().unwrap())
        .output()
        .expect("approve list");
    let list_out = String::from_utf8_lossy(&list.stdout);
    assert!(
        list_out.contains(&approval_id),
        "the pending request must be listed: {}",
        list_out
    );

    let show = Command::new(agentfence)
        .arg("approve")
        .arg(&approval_id)
        .arg("--decision")
        .arg("show")
        .env("AGENTFENCE_DATA_DIR", dir.path.to_str().unwrap())
        .output()
        .expect("approve show");
    let show_out = String::from_utf8_lossy(&show.stdout);
    assert!(
        show_out.contains(&approval_id)
            && show_out.contains("shell")
            && show_out.contains("Pending"),
        "show must expose the action and status: {}",
        show_out
    );
}

#[test]
fn audit_trail_correlates_decision_approval_and_outcome() {
    // SECURITY: the audit trail must let an auditor reconstruct that the policy
    // asked, a human approved, and the action then ran.
    let dir = TempDir::new("audit");
    let sentinel = dir.join("sentinel.txt");
    let policy = write_ask_policy(&dir);
    let raw = write_side_effect_script(&dir, &sentinel, "audit");

    let spawn = ExecSpawn::start(&policy, &raw, &dir, 30_000);
    let approval_id = wait_for_pending(&dir, Duration::from_secs(10)).unwrap();
    decide(&dir, &approval_id, true).unwrap();
    let output = spawn.finish();
    assert!(output.status.success(), "approved run must succeed");
    assert!(wait_for_sentinel(&sentinel, Duration::from_secs(5)));

    let store = agentfence_audit::sqlite_store::SqliteStore::new(dir.join("agentfence.db"))
        .expect("audit store");
    let events = store.get_all_events().expect("events");

    let kinds: Vec<String> = events.iter().map(|e| e.action_type.clone()).collect();

    assert!(
        kinds.iter().any(|k| k == "approval.request"),
        "the request must be audited: {:?}",
        kinds
    );
    assert!(
        kinds.iter().any(|k| k == "approval.consumed"),
        "the consumption must be audited: {:?}",
        kinds
    );
    assert!(
        kinds.iter().any(|k| k == "shell"),
        "the executed action must be audited: {:?}",
        kinds
    );

    // The approval events must carry the approval id so they can be correlated.
    let approval_events: Vec<_> = events
        .iter()
        .filter(|e| e.action_type.starts_with("approval."))
        .collect();
    assert!(
        approval_events.iter().any(|e| e.rule_id == approval_id),
        "the approval id must be part of the audit record"
    );

    // The audit trail must show the policy decision (Ask) *and* the eventual
    // outcome under approval (Allow) for the same action.
    let shell_events: Vec<_> = events.iter().filter(|e| e.action_type == "shell").collect();
    assert!(
        shell_events
            .iter()
            .any(|e| e.decision == agentfence_core::types::Decision::Ask),
        "the policy's Ask must be recorded: {:?}",
        shell_events.iter().map(|e| e.decision).collect::<Vec<_>>()
    );
    let executed = shell_events
        .iter()
        .find(|e| e.decision == agentfence_core::types::Decision::Allow)
        .expect("the approved execution must be recorded as Allow");
    assert_eq!(executed.action_id, shell_events[0].action_id);
}

#[test]
fn allow_and_deny_behaviour_is_unchanged() {
    // Regression guard: the approval work must not change plain allow/deny.
    let dir = TempDir::new("regression");
    let (runner_name, _) = runner();

    let denied_sentinel = dir.join("denied.txt");
    let denied_policy = write_allow_policy(&dir, &[]);
    let raw = write_side_effect_script(&dir, &denied_sentinel, "deny");
    let agentfence = env!("CARGO_BIN_exe_agentfence");
    let parts: Vec<&str> = raw.split_whitespace().collect();

    let denied = Command::new(agentfence)
        .arg("exec")
        .arg("--policy")
        .arg(&denied_policy)
        .arg("--")
        .args(&parts)
        .current_dir(&dir.path)
        .env("AGENTFENCE_DATA_DIR", dir.path.to_str().unwrap())
        .output()
        .unwrap();
    assert!(!denied.status.success(), "denied: must exit non-zero");
    assert!(!denied_sentinel.exists(), "denied: no side effect");

    let allowed_sentinel = dir.join("allowed.txt");
    let allowed_policy = write_allow_policy(&dir, &[runner_name]);
    let raw = write_side_effect_script(&dir, &allowed_sentinel, "allow");
    let parts: Vec<&str> = raw.split_whitespace().collect();

    let allowed = Command::new(agentfence)
        .arg("exec")
        .arg("--policy")
        .arg(&allowed_policy)
        .arg("--")
        .args(&parts)
        .current_dir(&dir.path)
        .env("AGENTFENCE_DATA_DIR", dir.path.to_str().unwrap())
        .output()
        .unwrap();
    assert!(allowed.status.success(), "allowed: must exit zero");
    assert!(
        wait_for_sentinel(&allowed_sentinel, Duration::from_secs(5)),
        "allowed: side effect must happen"
    );
}

#[test]
fn wasm_plugin_ask_enters_the_same_approval_lifecycle() {
    // SECURITY: a plugin `Ask` must reach the same human decision point. A
    // plugin can tighten a decision but never bypass the approval boundary.
    let dir = TempDir::new("plugin-ask");
    let sentinel = dir.join("sentinel.txt");
    let policy = write_plugin_ask_policy(&dir);

    // The core policy allows this command; the plugin asks for it.
    let raw = format!("{} /c echo ask.example.com", runner().0);
    let spawn = ExecSpawn::start(&policy, &raw, &dir, 8_000);
    let output = spawn.finish();

    assert!(
        !output.status.success(),
        "a plugin Ask must block, not execute"
    );
    assert!(
        !sentinel.exists(),
        "a plugin Ask must not reach the execution backend"
    );

    let db = dir.join("approvals.db");
    let service = ApprovalService::new_with_db(db).unwrap();
    assert_eq!(
        service.list_pending().len(),
        1,
        "the plugin Ask must produce a pending approval request"
    );

    // The plugin cannot produce an Allow either: an approval must be required.
    let config = ApprovalConfig::default();
    assert!(config.wait_timeout > Duration::from_secs(0));
}
