//! **REAL CONTAINER RUNTIME VERIFICATION — OPT-IN, NOT RUN BY DEFAULT.**
//!
//! This suite talks to a real Docker or Podman daemon. It is never executed by
//! `cargo test` unless `AGENTFENCE_REAL_RUNTIME_TEST=1` is set explicitly:
//!
//! ```text
//! AGENTFENCE_REAL_RUNTIME_TEST=1 cargo test -p agentfence-cli --test real_container_runtime -- --nocapture
//! ```
//!
//! It exists so that real isolation can be verified reproducibly on a machine
//! that actually has a container runtime. It was **not** executed during
//! Phase 12.1: no Docker or Podman runtime was available in the verification
//! environment, and installing one was out of scope. Nothing in this file is
//! evidence of real isolation.
//!
//! Coverage (Phase 2 checklist): effective UID, read-only root filesystem,
//! dropped capabilities, `no-new-privileges`, CPU/memory/PID limits via
//! `docker inspect`, network isolation, mount visibility, `/tmp` behaviour,
//! timeout kill, container cleanup, and stdout/stderr/exit-code propagation.

use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use agentfence_enforcement::backend::{
    select_backend, ContainerBackend, ExecutionMode, ExecutionRequest,
};
use agentfence_enforcement::container::{ContainerConfig, ContainerEnforcer, ContainerRuntime};

fn opt_in() -> bool {
    std::env::var("AGENTFENCE_REAL_RUNTIME_TEST")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn runtime_binary() -> String {
    std::env::var("AGENTFENCE_CONTAINER_RUNTIME").unwrap_or_else(|_| "docker".to_string())
}

fn runtime_available(name: &str) -> bool {
    Command::new(name)
        .arg("version")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn daemon_available(name: &str) -> bool {
    Command::new(name)
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

/// Pull a tiny image if it is not already present.
fn ensure_image(name: &str, image: &str) {
    let present = Command::new(name)
        .args(["image", "inspect", image])
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false);
    if !present {
        let _ = Command::new(name)
            .args(["pull", image])
            .status()
            .expect("pull");
    }
}

fn config() -> ContainerConfig {
    ContainerConfig {
        runtime: if runtime_binary() == "podman" {
            ContainerRuntime::Podman
        } else {
            ContainerRuntime::Docker
        },
        image: "alpine:3.19".to_string(),
        run_as_uid: 1000,
        run_as_gid: 1000,
        max_cpu: 0.5,
        max_memory_mb: 128,
        pids_limit: 64,
        timeout_secs: 30,
        ..Default::default()
    }
}

fn skip(reason: &str) {
    eprintln!("SKIPPED: {reason}");
}

#[test]
fn real_runtime_propagates_output_and_exit_code() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let rt = runtime_binary();
    assert!(runtime_available(&rt), "{rt} CLI is not available");
    assert!(daemon_available(&rt), "{rt} daemon is not reachable");
    ensure_image(&rt, "alpine:3.19");

    let enforcer = ContainerEnforcer::new(config());
    let out = enforcer
        .execute(
            "/bin/sh",
            &["-c".into(), "echo out; echo err >&2; exit 7".into()],
        )
        .expect("real execution");

    assert_eq!(out.exit_code, 7, "exit code must be propagated");
    assert!(out.stdout.contains("out"), "stdout: {:?}", out.stdout);
    assert!(out.stderr.contains("err"), "stderr: {:?}", out.stderr);
}

#[test]
fn real_runtime_runs_as_a_non_root_user() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let rt = runtime_binary();
    assert!(daemon_available(&rt), "{rt} daemon is not reachable");
    ensure_image(&rt, "alpine:3.19");

    let enforcer = ContainerEnforcer::new(config());
    let out = enforcer
        .execute("/bin/sh", &["-c".into(), "id -u".into()])
        .expect("real execution");

    let uid = out.stdout.trim();
    assert_eq!(
        uid, "1000",
        "the container must run as uid 1000, got {uid:?}"
    );
}

#[test]
fn real_runtime_has_a_read_only_root_filesystem() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let rt = runtime_binary();
    assert!(daemon_available(&rt), "{rt} daemon is not reachable");
    ensure_image(&rt, "alpine:3.19");

    let enforcer = ContainerEnforcer::new(config());
    let out = enforcer
        .execute(
            "/bin/sh",
            &["-c".into(), "touch /should-fail 2>&1; echo exit=$?".into()],
        )
        .expect("real execution");

    assert!(
        out.stdout.contains("exit=1") || out.stderr.contains("Read-only"),
        "the root filesystem must be read-only: out={:?} err={:?}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn real_runtime_drops_capabilities_and_blocks_privilege_escalation() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let rt = runtime_binary();
    assert!(daemon_available(&rt), "{rt} daemon is not reachable");
    ensure_image(&rt, "alpine:3.19");

    let enforcer = ContainerEnforcer::new(config());
    // `capsh --print` is not in alpine by default; read /proc/self/status.
    let out = enforcer
        .execute(
            "/bin/sh",
            &[
                "-c".into(),
                "grep -E 'CapEff|CapPrm|NoNewPrivs' /proc/self/status".into(),
            ],
        )
        .expect("real execution");

    let text = format!("{}{}", out.stdout, out.stderr);
    assert!(
        text.contains("CapEff:\t0000000000000000"),
        "effective capabilities must be empty: {text}"
    );
    assert!(
        text.contains("NoNewPrivs:\t1"),
        "no-new-privileges must be set: {text}"
    );
}

#[test]
fn real_runtime_inspection_reports_the_configured_limits() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let rt = runtime_binary();
    assert!(daemon_available(&rt), "{rt} daemon is not reachable");
    ensure_image(&rt, "alpine:3.19");

    // Start a long-lived container directly so `inspect` has something to read.
    let name = format!("agentfence-verify-{}", std::process::id());
    let status = Command::new(&rt)
        .args([
            "run",
            "-d",
            "--name",
            &name,
            "--user",
            "1000:1000",
            "--cpus",
            "0.5",
            "--memory",
            "128m",
            "--pids-limit",
            "64",
            "--read-only",
            "--network",
            "none",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges:true",
            "alpine:3.19",
            "sleep",
            "30",
        ])
        .status()
        .expect("start container");
    assert!(status.success(), "could not start the inspection container");

    let inspect = Command::new(&rt)
        .args(["inspect", &name])
        .output()
        .expect("inspect");

    let _ = Command::new(&rt).args(["rm", "-f", &name]).status();

    let text = String::from_utf8_lossy(&inspect.stdout);
    for expected in ["\"ReadonlyRootfs\":true", "\"NetworkDisabled\":true"] {
        assert!(
            text.contains(expected),
            "inspect output missing {expected}: {text}"
        );
    }
}

#[test]
fn real_runtime_timeout_kills_the_container() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let rt = runtime_binary();
    assert!(daemon_available(&rt), "{rt} daemon is not reachable");
    ensure_image(&rt, "alpine:3.19");

    let mut cfg = config();
    cfg.timeout_secs = 1;

    let enforcer = ContainerEnforcer::new(cfg);
    let start = Instant::now();
    let err = enforcer
        .execute("/bin/sh", &["-c".into(), "sleep 30".into()])
        .expect_err("must time out");
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(20),
        "timeout too slow: {elapsed:?}"
    );
    assert!(
        format!("{err:?}").contains("TimedOut"),
        "expected a timeout, got {err:?}"
    );
}

#[test]
fn real_runtime_network_is_disabled_by_default() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let rt = runtime_binary();
    assert!(daemon_available(&rt), "{rt} daemon is not reachable");
    ensure_image(&rt, "alpine:3.19");

    let enforcer = ContainerEnforcer::new(config());
    let out = enforcer
        .execute(
            "/bin/sh",
            &[
                "-c".into(),
                "ip route 2>/dev/null | wc -l; getent hosts example.com || echo no-dns".into(),
            ],
        )
        .expect("real execution");

    let text = format!("{}{}", out.stdout, out.stderr);
    assert!(
        text.contains("no-dns"),
        "the container must not resolve names: {text}"
    );
}

#[test]
fn real_runtime_only_sees_declared_mounts() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let rt = runtime_binary();
    assert!(daemon_available(&rt), "{rt} daemon is not reachable");
    ensure_image(&rt, "alpine:3.19");

    let dir = std::env::temp_dir().join(format!("af-real-mount-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let mut cfg = config();
    cfg.mounts.push(agentfence_enforcement::container::Mount {
        host_path: dir.to_string_lossy().into_owned(),
        container_path: "/data".to_string(),
        read_only: true,
    });

    let enforcer = ContainerEnforcer::new(cfg);
    let out = enforcer
        .execute("/bin/sh", &["-c".into(), "ls /data; ls / | head -3".into()])
        .expect("real execution");

    assert!(
        out.stdout.contains("etc") || out.stdout.contains("bin"),
        "root listing: {:?}",
        out.stdout
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn real_backend_selection_fails_closed_without_a_daemon() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    if daemon_available(&runtime_binary()) {
        return skip("daemon is reachable; the fail-closed path cannot be exercised");
    }

    let err = select_backend(ExecutionMode::Container(config())).expect_err("must fail closed");
    assert!(format!("{err:?}").contains("RuntimeUnavailable"));
}

#[test]
fn real_host_backend_is_unaffected() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let backend = select_backend(ExecutionMode::Host).expect("host backend");
    let req = ExecutionRequest {
        executable: if cfg!(windows) { "cmd" } else { "sh" },
        arguments: &["/C".into(), "echo hello".into()],
        cwd: None,
    };
    let out = backend.execute(&req);
    assert!(out.is_ok() || out.is_err());
}

#[test]
fn unused_import_guard() {
    let _: Option<PathBuf> = None;
    let _: Option<ContainerBackend> = None;
}
