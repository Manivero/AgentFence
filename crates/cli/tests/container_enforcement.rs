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
        // Argument count. Echoing arguments directly is not safe here: a `>` or
        // `|` inside an argument would be reinterpreted by cmd as a redirection
        // or a pipe, so the count is the reliable signal.
        script.push_str("set COUNT=0\r\n");
        script.push_str(":countloop\r\n");
        script.push_str("if \"%~1\"==\"\" goto countdone\r\n");
        script.push_str("set /a COUNT+=1\r\n");
        script.push_str("shift\r\n");
        script.push_str("goto countloop\r\n");
        script.push_str(":countdone\r\n");
        script.push_str("echo argc=%COUNT% >> \"%DIR%runtime.log\"\r\n");
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
        // Argument count.
        script.push_str("COUNT=0\n");
        script.push_str("for a in \"$@\"; do COUNT=$((COUNT+1)); done\n");
        script.push_str("printf 'argc=%s\\n' \"$COUNT\" >> \"$DIR/runtime.log\"\n");
        script.push_str("echo 'fake stdout'\n");
        script.push_str("exit 0\n");
        std::fs::write(&p, script).unwrap();
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }
}

/// A fake runtime whose cleanup commands always fail. The execution itself
/// succeeds, so cleanup failure must not turn a successful run into a failure.
fn make_failing_cleanup_runtime(dir: &Path) -> PathBuf {
    std::fs::write(dir.join("exit_code"), "0").unwrap();

    #[cfg(windows)]
    {
        let p = dir.join("docker.bat");
        let mut script = String::new();
        script.push_str("@echo off\r\n");
        script.push_str("set DIR=%~dp0\r\n");
        script.push_str("echo %* >> \"%DIR%runtime.log\"\r\n");
        script.push_str("if \"%1\"==\"--version\" exit /b 0\r\n");
        script.push_str("if \"%1\"==\"kill\" exit /b 1\r\n");
        script.push_str("if \"%1\"==\"rm\" exit /b 1\r\n");
        script.push_str("echo 'fake stdout'\r\n");
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
        script.push_str("if [ \"$1\" = \"kill\" ]; then exit 1; fi\n");
        script.push_str("if [ \"$1\" = \"rm\" ]; then exit 1; fi\n");
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

#[test]
fn a_quoted_payload_reaches_the_runtime_as_one_argument() {
    let dir = TempDir::new("quoting");
    let runtime_dir = dir.path.join("runtime");
    std::fs::create_dir_all(&runtime_dir).unwrap();
    let runtime = make_fake_runtime(&runtime_dir);
    let policy = write_allow_policy(&dir);

    let payload = "echo ran > /data/sentinel";
    let out = run_agentfence(
        &[
            "exec",
            "--policy",
            policy.to_str().unwrap(),
            "--",
            "sh",
            "-c",
            payload,
        ],
        &dir.path,
        &runtime,
    );

    assert_eq!(
        out.status.code(),
        Some(0),
        "output: {}",
        stdout_plus_stderr(&out)
    );

    let log = std::fs::read_to_string(runtime_dir.join("runtime.log")).unwrap();
    // The `-c` payload contains spaces and shell metacharacters. It must arrive
    // as exactly one argument; joining the argv and re-tokenizing it would
    // split it and silently change the executed command.
    //
    // The invocation is:
    //   docker run --rm --name <n> --init --user 1000:1000 --cpus 1.00
    //     --memory 512m --memory-swap 512m --pids-limit 256 --read-only
    //     --tmpfs /tmp:... --network none --cap-drop ALL
    //     --security-opt no-new-privileges:true --workdir /workspace
    //     alpine:latest sh -c "<payload>"
    // = 29 arguments before the payload plus the payload itself.
    let argc = log
        .lines()
        .find_map(|l| l.strip_prefix("argc="))
        .and_then(|v| v.trim().parse::<usize>().ok())
        .expect("argc line");
    assert_eq!(
        argc, 30,
        "the -c payload must be a single argument; it was split: {log}"
    );
}

#[test]
fn concurrent_executions_get_distinct_container_names() {
    // Each thread gets its own fake runtime and log: a single shared log loses
    // concurrent appends on Windows, which would make the test flaky rather than
    // wrong.
    let dir = TempDir::new("concurrent");
    let policy = write_allow_policy(&dir);

    let mut handles = Vec::new();
    for i in 0..4 {
        let policy = policy.clone();
        let base = dir.path.clone();
        handles.push(std::thread::spawn(move || {
            let runtime_dir = base.join(format!("runtime-{i}"));
            std::fs::create_dir_all(&runtime_dir).unwrap();
            let runtime = make_fake_runtime(&runtime_dir);
            let data = base.join(format!("data-{i}"));
            let out = run_agentfence(
                &[
                    "exec",
                    "--policy",
                    &policy.to_string_lossy(),
                    "--",
                    "sh",
                    "-c",
                    "echo ok",
                ],
                &data,
                &runtime,
            );
            (
                i,
                out.status.success(),
                stdout_plus_stderr(&out),
                runtime_dir,
            )
        }));
    }

    let mut all_names: Vec<String> = Vec::new();
    for (i, ok, combined, runtime_dir) in handles
        .into_iter()
        .map(|h| h.join().expect("thread panicked"))
    {
        assert!(ok, "thread {i} failed: {combined}");
        let log = std::fs::read_to_string(runtime_dir.join("runtime.log")).unwrap_or_default();
        let runs: Vec<&str> = log.lines().filter(|l| l.starts_with("run ")).collect();
        assert_eq!(
            runs.len(),
            1,
            "thread {i} must invoke the runtime exactly once: {runs:?}"
        );
        for name in runs
            .iter()
            .filter_map(|l| l.split("--name ").nth(1))
            .map(|rest| rest.split_whitespace().next().unwrap_or(""))
        {
            all_names.push(name.to_string());
        }
    }

    assert_eq!(all_names.len(), 4, "missing names: {all_names:?}");
    let unique: std::collections::HashSet<&str> = all_names.iter().map(|s| s.as_str()).collect();
    assert_eq!(
        unique.len(),
        4,
        "container names must be unique: {all_names:?}"
    );
}

#[test]
fn cleanup_failure_does_not_turn_a_successful_run_into_a_failure() {
    let dir = TempDir::new("cleanup-fail");
    let runtime = make_failing_cleanup_runtime(&dir.path);
    let policy = write_allow_policy(&dir);

    let out = run_agentfence(
        &[
            "exec",
            "--policy",
            &policy.to_string_lossy(),
            "--",
            "sh",
            "-c",
            "echo survived",
        ],
        &dir.data_dir(),
        &runtime,
    );

    assert!(
        out.status.success(),
        "cleanup failure must not fail the run: {}",
        stdout_plus_stderr(&out)
    );
    let combined = stdout_plus_stderr(&out);
    assert!(combined.contains("survived"), "{combined}");
}
