//! End-to-end enforcement tests for the container execution backend.
//!
//! These drive the real `agentfence` binary with a **fake** runtime. They prove
//! the enforcement invariants (denied and pending actions never reach the
//! runtime; approved actions reach it exactly once) but they do **not** prove
//! container isolation.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let n = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "agentfence-container-enforce-{}-{}-{}",
            label,
            std::process::id(),
            n
        ));
        let _ = std::fs::remove_dir_all(&path);
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

/// A fake Docker-compatible runtime that records every invocation.
fn make_fake_runtime(dir: &Path) -> PathBuf {
    std::fs::write(dir.join("exit_code"), "0").unwrap();

    #[cfg(windows)]
    {
        let p = dir.join("docker.bat");
        let mut script = String::new();
        script.push_str("@echo off\r\n");
        script.push_str("set DIR=%~dp0\r\n");
        script.push_str("echo %* >> \"%DIR%runtime.log\"\r\n");
        script.push_str("if \"%1\"==\"--version\" exit /b 0\r\n");
        script.push_str("if \"%1\"==\"kill\" exit /b 0\r\n");
        script.push_str("if \"%1\"==\"rm\" exit /b 0\r\n");
        script.push_str("echo fake stdout\r\n");
        script.push_str("exit /b 0\r\n");
        std::fs::write(&p, script).unwrap();
        p
    }

    #[cfg(unix)]
    {
        let p = dir.join("docker");
        let mut script = String::new();
        script.push_str("#!/bin/sh\n");
        script.push_str("DIR=\"$(dirname \"$0\")\"\n");
        script.push_str("printf '%s\\n' \"$*\" >> \"$DIR/runtime.log\"\n");
        script.push_str("if [ \"$1\" = \"--version\" ]; then exit 0; fi\n");
        script.push_str("if [ \"$1\" = \"kill\" ] || [ \"$1\" = \"rm\" ]; then exit 0; fi\n");
        script.push_str("echo 'fake stdout'\n");
        script.push_str("exit 0\n");
        std::fs::write(&p, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }
}

fn write_policy(dir: &TempDir, shell: &str) -> PathBuf {
    let yaml = format!(
        "version: 1\ndefaults:\n  shell: {shell}\n  network: deny\n  mcp: deny\n  filesystem: deny\n"
    );
    let path = dir.path.join(format!("{shell}.yaml"));
    std::fs::write(&path, yaml).unwrap();
    path
}

fn write_allow_policy(dir: &TempDir) -> PathBuf {
    let yaml = "version: 1\ndefaults:\n  shell: deny\n  network: deny\n  mcp: deny\n  filesystem: deny\nshell:\n  allow:\n    - sh\n";
    let path = dir.join("allow.yaml");
    std::fs::write(&path, yaml).unwrap();
    path
}

fn run_agentfence(args: &[&str], data_dir: &Path, runtime: &Path) -> Output {
    let agentfence = env!("CARGO_BIN_EXE_agentfence");
    Command::new(agentfence)
        .args(args)
        .env("AGENTFENCE_DATA_DIR", data_dir)
        .env("AGENTFENCE_EXECUTION_BACKEND", "container")
        .env(
            "AGENTFENCE_CONTAINER_RUNTIME_PATH",
            runtime.to_string_lossy().into_owned(),
        )
        .env("AGENTFENCE_CONTAINER_IMAGE", "alpine:latest")
        .env("AGENTFENCE_CONTAINER_TIMEOUT_SECS", "20")
        .output()
        .expect("spawn agentfence")
}

fn stdout_plus_stderr(out: &Output) -> String {
    let mut s = String::from_utf8_lossy(&out.stdout).into_owned();
    s.push_str(&String::from_utf8_lossy(&out.stderr));
    s
}

/// Container `run` invocations only. The runtime availability probe
/// (`--version`) is not command execution.
fn run_invocations(dir: &TempDir) -> Vec<String> {
    let log = dir.join("runtime.log");
    if !log.exists() {
        return vec![];
    }
    std::fs::read_to_string(&log)
        .unwrap()
        .lines()
        .filter(|l| l.starts_with("run "))
        .map(str::to_string)
        .collect()
}

#[test]
fn denied_commands_never_invoke_the_runtime() {
    let dir = TempDir::new("deny");
    let runtime = make_fake_runtime(&dir.path);
    let policy = write_policy(&dir, "deny");

    let out = run_agentfence(
        &[
            "exec",
            "--policy",
            &policy.to_string_lossy(),
            "--",
            "sh",
            "-c",
            "echo should-not-run",
        ],
        &dir.data_dir(),
        &runtime,
    );

    let combined = stdout_plus_stderr(&out);
    assert!(
        combined.to_lowercase().contains("denied") || !out.status.success(),
        "expected a denial, got: {combined}"
    );
    assert!(
        run_invocations(&dir).is_empty(),
        "a denied command must never reach the container runtime: {:?}",
        run_invocations(&dir)
    );
}

#[test]
fn pending_approvals_never_invoke_the_runtime() {
    let dir = TempDir::new("ask");
    let runtime = make_fake_runtime(&dir.path);
    let policy = write_policy(&dir, "ask");

    // No approval is issued, so the action must stop at ASK.
    let out = run_agentfence(
        &[
            "exec",
            "--policy",
            &policy.to_string_lossy(),
            "--",
            "sh",
            "-c",
            "echo should-not-run",
        ],
        &dir.data_dir(),
        &runtime,
    );

    let combined = stdout_plus_stderr(&out);
    assert!(
        combined.to_lowercase().contains("approval")
            || combined.to_lowercase().contains("pending")
            || !out.status.success(),
        "expected an approval request, got: {combined}"
    );
    assert!(
        run_invocations(&dir).is_empty(),
        "a pending approval must never reach the container runtime: {:?}",
        run_invocations(&dir)
    );
}

#[test]
fn approved_commands_execute_exactly_once() {
    let dir = TempDir::new("allow");
    let runtime = make_fake_runtime(&dir.path);
    let policy = write_allow_policy(&dir);

    let out = run_agentfence(
        &[
            "exec",
            "--policy",
            &policy.to_string_lossy(),
            "--",
            "sh",
            "-c",
            "echo hello",
        ],
        &dir.data_dir(),
        &runtime,
    );

    let combined = stdout_plus_stderr(&out);
    assert!(
        combined.contains("fake stdout"),
        "expected the container output, got: {combined}"
    );

    let runs: Vec<_> = run_invocations(&dir)
        .into_iter()
        .filter(|c| c.starts_with("run "))
        .collect();
    assert_eq!(
        runs.len(),
        1,
        "an approved command must execute exactly once, saw: {runs:?}"
    );
}

#[test]
fn the_runtime_receives_the_safety_configuration() {
    let dir = TempDir::new("flags");
    let runtime = make_fake_runtime(&dir.path);
    let policy = write_allow_policy(&dir);

    let out = run_agentfence(
        &[
            "exec",
            "--policy",
            &policy.to_string_lossy(),
            "--",
            "sh",
            "-c",
            "echo hello",
        ],
        &dir.data_dir(),
        &runtime,
    );
    assert!(
        out.status.success(),
        "exec failed: {}",
        stdout_plus_stderr(&out)
    );

    let run = run_invocations(&dir)
        .into_iter()
        .find(|c| c.starts_with("run "))
        .expect("run invocation");

    for expected in [
        "--read-only",
        "--network none",
        "--cap-drop ALL",
        "--security-opt no-new-privileges:true",
        "--pids-limit",
        "--cpus",
        "--memory",
        "--user 1000:1000",
    ] {
        assert!(run.contains(expected), "missing {expected:?} in: {run}");
    }
    assert!(
        !run.contains("--privileged"),
        "privileged mode must never be requested: {run}"
    );
    assert!(
        !run.contains("docker.sock"),
        "the Docker socket must never be mounted: {run}"
    );
}

#[test]
fn a_missing_runtime_fails_closed_instead_of_running_on_the_host() {
    let dir = TempDir::new("noruntime");
    let policy = write_allow_policy(&dir);
    let absent = dir.join("absent-runtime");

    let out = run_agentfence(
        &[
            "exec",
            "--policy",
            &policy.to_string_lossy(),
            "--",
            "sh",
            "-c",
            "echo hello",
        ],
        &dir.data_dir(),
        &absent,
    );

    let combined = stdout_plus_stderr(&out);
    assert!(
        !out.status.success(),
        "a missing runtime must fail closed, got success: {combined}"
    );
    assert!(
        combined.to_lowercase().contains("runtime") || combined.to_lowercase().contains("backend"),
        "expected an explicit runtime failure, got: {combined}"
    );
}

#[test]
fn credentials_in_the_command_are_not_printed_by_the_cli() {
    let dir = TempDir::new("secrets");
    let runtime = make_fake_runtime(&dir.path);
    let policy = write_allow_policy(&dir);
    let token = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

    let out = run_agentfence(
        &[
            "exec",
            "--policy",
            &policy.to_string_lossy(),
            "--",
            "sh",
            "-c",
            &format!(
                "echo {token} > {}",
                if cfg!(windows) { "nul" } else { "/dev/null" }
            ),
        ],
        &dir.data_dir(),
        &runtime,
    );

    let combined = stdout_plus_stderr(&out);
    assert!(
        !combined.contains(token),
        "the credential reached the CLI output:\n{combined}"
    );
}
