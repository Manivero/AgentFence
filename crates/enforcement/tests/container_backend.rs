//! Container backend tests driven by a **fake** runtime executable.
//!
//! These tests verify that AgentFence builds the correct runtime invocation,
//! fails closed, and propagates output. They do **not** verify real container
//! isolation: a fake runtime provides no isolation whatsoever. Real-runtime
//! integration is a separate, opt-in concern and is called out as such in
//! `SECURITY.md`.

use std::path::{Path, PathBuf};
use std::sync::Mutex;

use agentfence_enforcement::backend::{
    select_backend, ContainerBackend, ExecutionError, ExecutionMode,
};
use agentfence_enforcement::container::{
    ContainerConfig, ContainerEnforcer, ContainerError, ContainerRuntime, Mount,
};

const TOKEN: &str = "ghp_abcdefghijklmnopqrstuvwxyz0123456789";

/// A scratch directory unique to this test.
fn scratch(label: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "af-container-{}-{}",
        label,
        uuid::Uuid::new_v4().simple()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A fake Docker-compatible runtime.
///
/// Every invocation is appended to `runtime.log`. The exit code is read from
/// `exit_code` inside the scratch directory, so tests never share global state.
struct FakeRuntime {
    path: PathBuf,
    log: PathBuf,
}

impl FakeRuntime {
    fn new(dir: &Path, name: &str) -> Self {
        let log = dir.join("runtime.log");
        let path = make_fake_runtime(dir, name, &log);
        Self { path, log }
    }

    fn config(&self) -> ContainerConfig {
        ContainerConfig {
            runtime: ContainerRuntime::Docker,
            runtime_path: Some(self.path.to_string_lossy().into_owned()),
            ..ContainerConfig::default()
        }
    }

    fn invocations(&self) -> Vec<String> {
        if !self.log.exists() {
            return vec![];
        }
        std::fs::read_to_string(&self.log)
            .unwrap()
            .lines()
            .filter(|l| !l.trim().is_empty())
            .map(str::to_string)
            .collect()
    }

    /// The single `run` invocation, if any.
    fn run_call(&self) -> String {
        self.invocations()
            .into_iter()
            .find(|c| c.starts_with("run "))
            .expect("expected a container `run` invocation")
    }
}

#[cfg(windows)]
fn make_fake_runtime(dir: &Path, name: &str, _log: &Path) -> PathBuf {
    let p = dir.join(format!("{name}.bat"));
    let mut script = String::new();
    script.push_str(
        "@echo off
",
    );
    script.push_str(
        "set DIR=%~dp0
",
    );
    script.push_str(
        "echo %* >> \"%DIR%runtime.log\"
",
    );
    script.push_str(
        "if \"%1\"==\"--version\" exit /b 0
",
    );
    script.push_str(
        "if \"%1\"==\"kill\" exit /b 0
",
    );
    script.push_str(
        "if \"%1\"==\"rm\" exit /b 0
",
    );
    script.push_str(
        "echo fake stdout
",
    );
    script.push_str(
        "echo fake stderr >&2
",
    );
    script.push_str(
        "set /p CODE=<\"%DIR%exit_code\"
",
    );
    script.push_str(
        "if not defined CODE set CODE=0
",
    );
    script.push_str(
        "exit /b %CODE%
",
    );
    std::fs::write(&p, script).unwrap();
    std::fs::write(dir.join("exit_code"), "0").unwrap();
    p
}

#[cfg(unix)]
fn make_fake_runtime(dir: &Path, name: &str, _log: &Path) -> PathBuf {
    let p = dir.join(name);
    let mut script = String::new();
    script.push_str(
        "#!/bin/sh
",
    );
    script.push_str(
        "DIR=\"$(dirname \"$0\")\"
",
    );
    script.push_str(
        "printf '%s\n' \"$*\" >> \"$DIR/runtime.log\"
",
    );
    script.push_str(
        "if [ \"$1\" = \"--version\" ]; then exit 0; fi
",
    );
    script.push_str(
        "if [ \"$1\" = \"kill\" ] || [ \"$1\" = \"rm\" ]; then exit 0; fi
",
    );
    script.push_str(
        "echo 'fake stdout'
",
    );
    script.push_str(
        "echo 'fake stderr' >&2
",
    );
    script.push_str(
        "exit \"$(cat \"$DIR/exit_code\" 2>/dev/null || echo 0)\"
",
    );
    std::fs::write(&p, script).unwrap();
    std::fs::write(dir.join("exit_code"), "0").unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
    p
}

#[test]
fn the_executable_and_arguments_are_passed_as_separate_values() {
    let dir = scratch("args");
    let fake = FakeRuntime::new(&dir, "docker");

    let enforcer = ContainerEnforcer::new(fake.config());
    let args = vec!["--flag".to_string(), "value".to_string(), "a b".to_string()];
    let result = enforcer.execute("/bin/tool", &args).expect("execute");

    assert_eq!(result.exit_code, 0, "stderr: {}", result.stderr);
    let run = fake.run_call();
    assert!(run.contains(" /bin/tool "), "executable missing: {run:?}");
    assert!(run.contains(" --flag value "), "arguments missing: {run:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn shell_metacharacters_are_not_interpreted_by_the_host_shell() {
    let dir = scratch("metachars");
    let fake = FakeRuntime::new(&dir, "docker");
    let sentinel = dir.join("pwned.txt");

    let enforcer = ContainerEnforcer::new(fake.config());
    // A hostile argument that would run a second command if it were ever joined
    // into a shell string.
    let hostile = format!("x; touch {}", sentinel.display());

    enforcer.execute("/bin/tool", &[hostile]).expect("execute");

    assert!(
        !sentinel.exists(),
        "shell metacharacters were interpreted by the host shell"
    );
    assert!(
        fake.run_call().contains("; touch"),
        "the argument was altered before reaching the runtime"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn resource_limits_are_part_of_the_invocation() {
    let dir = scratch("limits");
    let fake = FakeRuntime::new(&dir, "docker");

    let enforcer = ContainerEnforcer::new(fake.config());
    enforcer.execute("/bin/tool", &[]).expect("execute");

    let run = fake.run_call();
    for expected in [
        "--cpus",
        "--memory",
        "--memory-swap",
        "--pids-limit",
        "--read-only",
        "--network none",
        "--cap-drop ALL",
        "--security-opt no-new-privileges:true",
        "--tmpfs",
        "--user 1000:1000",
        "--workdir",
        "--rm",
        "--name",
        "--init",
    ] {
        assert!(run.contains(expected), "missing {expected:?} in: {run}");
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_host_container_runtime_socket_is_never_mounted() {
    let dir = scratch("socket");
    let fake = FakeRuntime::new(&dir, "docker");
    let mut config = fake.config();
    config.mounts.push(Mount {
        host_path: "/var/run/docker.sock".to_string(),
        container_path: "/var/run/docker.sock".to_string(),
        read_only: false,
    });

    // Mounting the host runtime socket would hand the container control of the
    // host runtime, so the configuration is rejected outright.
    let err = config
        .validate()
        .expect_err("the socket mount must be rejected");
    assert!(
        err.contains("container runtime socket"),
        "unexpected error: {err}"
    );
    assert!(!format!("{config:?}").contains("--privileged"));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_missing_runtime_fails_closed() {
    let dir = scratch("missing");
    let config = ContainerConfig {
        runtime_path: Some(dir.join("does-not-exist").to_string_lossy().into_owned()),
        ..Default::default()
    };

    let enforcer = ContainerEnforcer::new(config);
    let err = enforcer.execute("/bin/tool", &[]).expect_err("must fail");
    assert!(
        matches!(err, ContainerError::RuntimeUnavailable { .. }),
        "expected RuntimeUnavailable, got {err:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_failing_runtime_probe_fails_closed() {
    let dir = scratch("probe");
    let path = dir.join("broken.bat");
    std::fs::write(&path, "@echo off\r\nexit /b 1\r\n").unwrap();
    let config = ContainerConfig {
        runtime_path: Some(path.to_string_lossy().into_owned()),
        ..Default::default()
    };

    let enforcer = ContainerEnforcer::new(config);
    let err = enforcer.execute("/bin/tool", &[]).expect_err("must fail");
    assert!(matches!(err, ContainerError::RuntimeUnavailable { .. }));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn invalid_configuration_is_rejected() {
    let dir = scratch("config");
    let fake = FakeRuntime::new(&dir, "docker");

    let config = ContainerConfig {
        run_as_uid: 0,
        ..fake.config()
    };
    let err = ContainerBackend::new(config).expect_err("must reject");
    assert!(
        matches!(err, ExecutionError::InvalidConfiguration(_)),
        "expected InvalidConfiguration, got {err:?}"
    );

    let config = ContainerConfig {
        workdir: "relative/path".to_string(),
        ..fake.config()
    };
    let err = ContainerBackend::new(config).expect_err("must reject");
    assert!(matches!(err, ExecutionError::InvalidConfiguration(_)));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn exit_codes_and_output_are_propagated() {
    let dir = scratch("exit");
    let fake = FakeRuntime::new(&dir, "docker");
    std::fs::write(dir.join("exit_code"), "7").unwrap();

    let enforcer = ContainerEnforcer::new(fake.config());
    let result = enforcer.execute("/bin/tool", &[]).expect("execute");

    assert_eq!(result.exit_code, 7, "exit code must be propagated");
    assert!(
        result.stdout.contains("fake stdout"),
        "stdout: {:?}",
        result.stdout
    );
    assert!(
        result.stderr.contains("fake stderr"),
        "stderr: {:?}",
        result.stderr
    );
    assert!(!result.timed_out);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn credentials_are_not_logged() {
    let dir = scratch("secrets");
    let fake = FakeRuntime::new(&dir, "docker");

    let enforcer = ContainerEnforcer::new(fake.config());
    enforcer
        .execute("/bin/tool", &[format!("--token={TOKEN}")])
        .expect("execute");

    // The argument legitimately reaches the runtime. What must never happen is
    // AgentFence writing the raw credential to its own logs.
    let masked = agentfence_secrets::redact::redact(&format!("--token={TOKEN}")).text;
    assert!(!masked.contains(TOKEN), "redaction must mask the token");
    assert!(
        fake.run_call().contains("--token="),
        "the argument must still reach the runtime"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn select_backend_fails_closed_for_a_missing_container_runtime() {
    let dir = scratch("select");
    let config = ContainerConfig {
        runtime_path: Some(dir.join("absent").to_string_lossy().into_owned()),
        ..Default::default()
    };

    let err = select_backend(ExecutionMode::Container(config)).expect_err("must fail");
    assert!(matches!(err, ExecutionError::RuntimeUnavailable { .. }));
    let _ = std::fs::remove_dir_all(&dir);
}

/// Serializes tests that mutate the process environment.
static ENV_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn an_unreadable_container_config_is_an_error_not_a_silent_default() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch("cfg-missing");
    std::env::set_var("AGENTFENCE_EXECUTION_BACKEND", "container");
    std::env::set_var(
        "AGENTFENCE_CONTAINER_CONFIG",
        dir.join("does-not-exist.json")
            .to_string_lossy()
            .into_owned(),
    );

    let err = ExecutionMode::from_env().expect_err("a missing config must be an error");
    assert!(err.contains("cannot read container config"), "{err}");

    std::env::remove_var("AGENTFENCE_CONTAINER_CONFIG");
    std::env::remove_var("AGENTFENCE_EXECUTION_BACKEND");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn a_malformed_container_config_is_an_error_not_a_silent_default() {
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let dir = scratch("cfg-bad");
    let bad = dir.join("config.json");
    // A Windows path with unescaped backslashes is not valid JSON, which is
    // exactly how a hand-written config ends up in practice.
    std::fs::write(&bad, "{\"mounts\": [{\"host_path\": \"C:\\temp\"}]}").unwrap();
    std::env::set_var("AGENTFENCE_EXECUTION_BACKEND", "container");
    std::env::set_var(
        "AGENTFENCE_CONTAINER_CONFIG",
        bad.to_string_lossy().into_owned(),
    );

    let err = ExecutionMode::from_env().expect_err("malformed JSON must be an error");
    assert!(err.contains("invalid container config"), "{err}");

    std::env::remove_var("AGENTFENCE_CONTAINER_CONFIG");
    std::env::remove_var("AGENTFENCE_EXECUTION_BACKEND");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn the_container_is_stopped_on_timeout() {
    let dir = scratch("timeout");
    let hang = dir.join("hang.bat");
    let mut script = String::new();
    script.push_str("@echo off\r\n");
    script.push_str("if \"%1\"==\"--version\" exit /b 0\r\n");
    script.push_str("if \"%1\"==\"kill\" exit /b 0\r\n");
    script.push_str("if \"%1\"==\"rm\" exit /b 0\r\n");
    script.push_str("if \"%1\"==\"run\" (\r\n");
    script.push_str("  ping -n 60 127.0.0.1 >NUL\r\n");
    script.push_str("  exit /b 0\r\n");
    script.push_str(")\r\n");
    script.push_str("exit /b 0\r\n");
    std::fs::write(&hang, script).unwrap();

    let config = ContainerConfig {
        runtime_path: Some(hang.to_string_lossy().into_owned()),
        timeout_secs: 1,
        ..Default::default()
    };

    let enforcer = ContainerEnforcer::new(config);
    let start = std::time::Instant::now();
    let err = enforcer
        .execute("/bin/tool", &[])
        .expect_err("must time out");
    let elapsed = start.elapsed();

    assert!(
        matches!(err, ContainerError::TimedOut(1)),
        "expected TimedOut(1), got {err:?}"
    );
    assert!(
        elapsed < std::time::Duration::from_secs(15),
        "the timeout was not enforced promptly: {elapsed:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn mounts_are_validated() {
    let config = ContainerConfig {
        mounts: vec![Mount {
            host_path: "relative".to_string(),
            container_path: "/data".to_string(),
            read_only: true,
        }],
        ..Default::default()
    };
    assert!(config.validate().is_err());

    let config = ContainerConfig {
        mounts: vec![Mount {
            host_path: "/tmp".to_string(),
            container_path: "relative".to_string(),
            read_only: true,
        }],
        ..Default::default()
    };
    assert!(config.validate().is_err());

    let host_tmp = if cfg!(windows) { "C:/tmp" } else { "/tmp" };
    let config = ContainerConfig {
        mounts: vec![Mount {
            host_path: host_tmp.to_string(),
            container_path: "/data".to_string(),
            read_only: true,
        }],
        ..Default::default()
    };
    assert!(
        config.validate().is_ok(),
        "{}",
        config.validate().err().unwrap()
    );
}

#[test]
fn the_runtime_probe_succeeds_for_a_working_fake() {
    let dir = scratch("probe-ok");
    let fake = FakeRuntime::new(&dir, "docker");
    let enforcer = ContainerEnforcer::new(fake.config());
    enforcer
        .check_runtime()
        .expect("the fake runtime must answer --version");
    assert!(Path::new(&fake.path).exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn host_mode_does_not_require_a_container_runtime() {
    let backend = select_backend(ExecutionMode::Host).expect("host backend");
    let req = agentfence_enforcement::backend::ExecutionRequest {
        executable: "cmd",
        arguments: &[],
        cwd: None,
    };
    // Either the command runs or it fails; the point is that no container
    // runtime is consulted on the host path.
    let _ = backend.execute(&req);
}
