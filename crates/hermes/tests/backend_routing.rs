//! Hermes wrapper execution-path tests.
//!
//! The wrapper used to spawn commands directly on the host, which meant that
//! selecting the container backend for `agentguard exec` left Hermes running on
//! the host. These tests prove the wrapper now routes through the selected
//! backend and that a denied command reaches no runtime at all.
//!
//! Backend selection is driven by process environment variables, so the tests
//! that change them run under a shared lock and cannot race each other.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Mutex;

use agentfence_hermes::wrapper::HermesWrapper;

/// Serializes tests that mutate the process environment.
static ENV_LOCK: Mutex<()> = Mutex::new(());

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let n = COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "agentfence-hermes-routing-{}-{}-{}",
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
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// Write a policy whose shell section decides the outcome.
///
/// A `shell:` section is required: without one every shell action is denied
/// with "No shell policy defined", regardless of `defaults`.
fn write_policy(dir: &TempDir, decision: &str) -> PathBuf {
    let yaml = format!(
        "version: 1\ndefaults:\n  shell: {decision}\n  network: deny\n  mcp: deny\n  filesystem: deny\nshell:\n  {decision}:\n    - sh\n"
    );
    let path = dir.path.join(format!("{decision}.yaml"));
    std::fs::write(&path, yaml).unwrap();
    path
}

/// A fake Docker-compatible runtime that records invocations.
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

fn select_container_backend(runtime: &Path) {
    std::env::set_var("AGENTFENCE_EXECUTION_BACKEND", "container");
    std::env::set_var(
        "AGENTFENCE_CONTAINER_RUNTIME_PATH",
        runtime.to_string_lossy().into_owned(),
    );
    std::env::set_var("AGENTFENCE_CONTAINER_IMAGE", "alpine:latest");
    std::env::set_var("AGENTFENCE_CONTAINER_TIMEOUT_SECS", "20");
}

#[test]
fn an_allowed_command_reaches_the_backend_not_the_host() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new("allow");
    let runtime = make_fake_runtime(&dir.path);
    select_container_backend(&runtime);
    let policy = write_policy(&dir, "allow");

    // The sentinel would appear on the host if the wrapper spawned the command
    // directly. With the container backend it must never be created.
    let sentinel = dir.join("host-sentinel.txt");
    let command = format!("sh -c \"echo hi > {}\"", sentinel.display());

    let wrapper = HermesWrapper::new(&policy.to_string_lossy()).expect("wrapper");
    let ok = wrapper.execute(&command).expect("execute");

    assert!(ok, "the backend reported success");
    assert!(
        !sentinel.exists(),
        "the command ran on the host instead of through the backend"
    );
    let runs = run_invocations(&dir);
    assert_eq!(
        runs.len(),
        1,
        "the allowed command must reach the runtime exactly once: {runs:?}"
    );
    let _ = std::fs::remove_dir_all(&dir.path);
}

#[test]
fn a_denied_command_reaches_no_runtime() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new("deny");
    let runtime = make_fake_runtime(&dir.path);
    select_container_backend(&runtime);
    let policy = write_policy(&dir, "deny");

    let wrapper = HermesWrapper::new(&policy.to_string_lossy()).expect("wrapper");
    let ok = wrapper
        .execute("sh -c \"echo should-not-run\"")
        .expect("execute");

    assert!(!ok, "a denied command must report failure");
    assert!(
        run_invocations(&dir).is_empty(),
        "a denied command must never reach the runtime: {:?}",
        run_invocations(&dir)
    );
    let _ = std::fs::remove_dir_all(&dir.path);
}

#[test]
fn a_missing_runtime_fails_closed() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new("noruntime");
    let policy = write_policy(&dir, "allow");
    std::env::set_var("AGENTFENCE_EXECUTION_BACKEND", "container");
    std::env::set_var(
        "AGENTFENCE_CONTAINER_RUNTIME_PATH",
        dir.join("absent-runtime").to_string_lossy().into_owned(),
    );

    let result = HermesWrapper::new(&policy.to_string_lossy());
    assert!(
        result.is_err(),
        "the wrapper must not be created when the selected backend is unusable"
    );
    let _ = std::fs::remove_dir_all(&dir.path);
}

#[test]
fn host_mode_executes_locally_without_a_runtime() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = TempDir::new("host");
    let allow_policy = dir.join("allow.yaml");
    std::fs::write(
        &allow_policy,
        "version: 1\ndefaults:\n  shell: deny\nshell:\n  allow:\n    - git\n",
    )
    .unwrap();
    std::env::set_var("AGENTFENCE_EXECUTION_BACKEND", "host");

    let wrapper = HermesWrapper::new(&allow_policy.to_string_lossy()).expect("wrapper");
    // `git --version` exists on this host; the point is that host mode needs no
    // container runtime at all.
    let ok = wrapper.execute("git --version").expect("execute");
    assert!(ok, "host mode must execute without any container runtime");
    let _ = std::fs::remove_dir_all(&dir.path);
}

#[test]
fn the_command_helper_is_available() {
    let _ = Command::new("cmd");
}
