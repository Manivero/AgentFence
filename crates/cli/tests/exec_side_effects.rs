//! End-to-end enforcement tests for `agentfence exec`.
//!
//! These tests assert the **observable side effect**, not the PDP decision:
//! a denied command must never reach the execution backend, and an allowed one
//! must. The tests drive the real CLI binary, so they exercise the same path an
//! agent would (PEP -> PDP -> execute-or-block -> audit).

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let n = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "agentfence-exec-side-effect-{}-{}-{}",
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

/// The interpreter used to run the sentinel-producing script.
fn runner() -> (&'static str, &'static str) {
    if cfg!(windows) {
        ("cmd", ".bat")
    } else {
        ("sh", ".sh")
    }
}

fn write_policy(dir: &TempDir, allow: &[&str]) -> PathBuf {
    let allow_yaml = allow
        .iter()
        .map(|a| format!("    - {}", a))
        .collect::<Vec<_>>()
        .join("\n");
    let allow_block = if allow.is_empty() {
        "  allow: []".to_string()
    } else {
        format!("  allow:\n{}", allow_yaml)
    };
    let yaml = format!(
        "version: 1\ndefaults:\n  shell: deny\n  network: deny\n  mcp: deny\n  filesystem: deny\nshell:\n{}",
        allow_block
    );
    let path = dir.join("policy.yaml");
    std::fs::write(&path, yaml).unwrap();
    path
}

/// A path in the form `ShellCommand::parse` preserves.
///
/// The shell parser is POSIX-compliant (`shell-words`), so a `\` is an escape
/// character and `C:\Users\x` becomes `C:Usersx`. Windows accepts forward
/// slashes, so the tests always emit `/`-separated paths.
fn slash_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Write the script that creates `sentinel`, and return the command that runs it.
fn write_side_effect_script(dir: &TempDir, sentinel: &Path) -> String {
    let (runner_name, ext) = runner();
    let script = dir.path.join(format!("side_effect{}", ext));
    let body = format!("echo invoked > \"{}\"", slash_path(sentinel));
    std::fs::write(&script, body).unwrap();

    if runner_name == "cmd" {
        format!("{} /c {}", runner_name, slash_path(&script))
    } else {
        format!("{} {}", runner_name, slash_path(&script))
    }
}

fn run_exec(policy: &Path, raw_command: &str, dir: &TempDir) -> std::process::Output {
    let agentfence = env!("CARGO_BIN_exe_agentfence");
    let parts: Vec<&str> = raw_command.split_whitespace().collect();

    // Isolate the audit database so the test never touches the real one.
    Command::new(agentfence)
        .arg("exec")
        .arg("--policy")
        .arg(policy)
        .arg("--")
        .args(&parts)
        .current_dir(&dir.path)
        .env("AGENTFENCE_DATA_DIR", dir.path.to_str().unwrap())
        .output()
        .expect("failed to run agentfence exec")
}

#[test]
fn test_denied_command_never_reaches_the_execution_backend() {
    // SECURITY: observable side effect. With the command not in the allow list
    // the sentinel file must never be created.
    let dir = TempDir::new("deny");
    let sentinel = dir.join("sentinel.txt");
    let policy = write_policy(&dir, &[]);
    let raw = write_side_effect_script(&dir, &sentinel);

    let output = run_exec(&policy, &raw, &dir);

    assert!(
        !output.status.success(),
        "a denied command must exit non-zero, got {:?}",
        output.status.code()
    );
    assert!(
        !sentinel.exists(),
        "a denied command must never reach the execution backend"
    );
}

#[test]
fn test_allowed_command_does_reach_the_execution_backend() {
    // Control: the identical command, with the runner in the allow list, must
    // actually execute and produce the sentinel.
    let dir = TempDir::new("allow");
    let sentinel = dir.join("sentinel.txt");
    let (runner_name, _) = runner();
    let policy = write_policy(&dir, &[runner_name]);
    let raw = write_side_effect_script(&dir, &sentinel);

    let output = run_exec(&policy, &raw, &dir);

    assert!(
        output.status.success(),
        "an allowed command must exit zero; stderr: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !sentinel.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(
        sentinel.exists(),
        "an allowed command must reach the execution backend"
    );
}

#[test]
fn test_same_command_is_allowed_or_denied_by_policy_alone() {
    // SECURITY: the *only* difference between these two runs is the policy.
    // This rules out "the command failed for an unrelated reason" as an
    // explanation for the side effect.
    let dir = TempDir::new("paired");
    let (runner_name, _) = runner();

    let denied_sentinel = dir.join("denied.txt");
    let denied_policy = write_policy(&dir, &[]);
    let raw = write_side_effect_script(&dir, &denied_sentinel);
    run_exec(&denied_policy, &raw, &dir);
    assert!(!denied_sentinel.exists(), "denied: sentinel must not exist");

    let allowed_sentinel = dir.join("allowed.txt");
    let allowed_policy = write_policy(&dir, &[runner_name]);
    let raw = write_side_effect_script(&dir, &allowed_sentinel);
    run_exec(&allowed_policy, &raw, &dir);

    let deadline = Instant::now() + Duration::from_secs(5);
    while !allowed_sentinel.exists() && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    assert!(allowed_sentinel.exists(), "allowed: sentinel must exist");
    assert!(
        !denied_sentinel.exists(),
        "denied: sentinel must still not exist"
    );
}

#[test]
fn test_audit_event_carries_a_real_action_id_and_argument_hash() {
    // SECURITY: audit integrity. The recorded event must reference the action
    // that was evaluated, and `args_hash` must be a real digest rather than a
    // placeholder. A constant hash cannot reconstruct what was decided.
    let dir = TempDir::new("audit");
    let sentinel = dir.join("audit-sentinel.txt");
    let (runner_name, _) = runner();
    let policy = write_policy(&dir, &[runner_name]);
    let raw = write_side_effect_script(&dir, &sentinel);

    let output = run_exec(&policy, &raw, &dir);
    assert!(output.status.success());

    // The audit database lives directly under AGENTFENCE_DATA_DIR
    // (see `cli::commands::db::get_db_path`).
    let db = dir.path.join("agentfence.db");
    assert!(
        db.exists(),
        "expected an audit database at {}",
        db.display()
    );

    let store = agentfence_audit::sqlite_store::SqliteStore::new(db.to_string_lossy().to_string())
        .expect("open audit db");
    let events = store.get_all_events().expect("read audit events");
    assert!(
        events.iter().any(|e| e.target == raw),
        "expected an audit event for the executed command; events: {:?}",
        events
            .iter()
            .map(|e| (&e.target, &e.args_hash))
            .collect::<Vec<_>>()
    );

    let event = events.iter().find(|e| e.target == raw).unwrap();

    // The recorded hash must be the digest of the command that was evaluated,
    // not a constant placeholder.
    let expected = agentfence_shell::hash::hash_args(&raw);
    assert_eq!(
        event.args_hash, expected,
        "args_hash must be the digest of the evaluated command"
    );
    assert_ne!(
        event.args_hash, "hash",
        "args_hash must not be a placeholder"
    );
    assert_eq!(
        event.args_hash.len(),
        64,
        "args_hash must be a SHA-256 digest"
    );

    // The event must reference a real action id, not an empty one.
    assert!(
        !event.action_id.0.is_empty(),
        "audit action_id must not be empty"
    );
}
