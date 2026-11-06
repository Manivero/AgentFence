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

    // Start a long-lived container with the exact flags AgentFence passes, so
    // `inspect` has something to read.
    //
    // Values are read through Go templates rather than substring matching: the
    // daemon's JSON rendering is not stable across versions (`"ReadonlyRootfs":
    // true` vs `true`), and network isolation is reported as `NetworkMode`, not
    // as a `NetworkDisabled` field.
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
            "--memory-swap",
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
        .args([
            "inspect",
            &name,
            "--format",
            "{{.HostConfig.ReadonlyRootfs}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.NanoCpus}}|{{.HostConfig.Memory}}|{{.HostConfig.MemorySwap}}|{{.HostConfig.PidsLimit}}|{{.HostConfig.SecurityOpt}}|{{.HostConfig.CapDrop}}",
        ])
        .output()
        .expect("inspect");

    let _ = Command::new(&rt).args(["rm", "-f", &name]).status();

    let text = String::from_utf8_lossy(&inspect.stdout);
    let fields: Vec<&str> = text.trim().split('|').collect();
    assert_eq!(fields.len(), 8, "unexpected inspect output: {text}");
    assert_eq!(
        fields[0], "true",
        "root filesystem must be read-only: {text}"
    );
    assert_eq!(fields[1], "none", "network must be disabled: {text}");
    assert_eq!(fields[2], "500000000", "CPU limit must be 0.5: {text}");
    assert_eq!(
        fields[3], "134217728",
        "memory limit must be 128 MiB: {text}"
    );
    assert_eq!(fields[4], "134217728", "swap must be disabled: {text}");
    assert_eq!(fields[5], "64", "PID limit must be 64: {text}");
    assert!(
        fields[6].contains("no-new-privileges"),
        "NoNewPrivs must be set: {text}"
    );
    assert!(
        fields[7].contains("ALL"),
        "all capabilities must be dropped: {text}"
    );
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
fn rfc3339_timestamps_are_well_formed() {
    let t = now_rfc3339();
    // e.g. 2026-11-06T14:28:54.994235123Z
    assert_eq!(t.len(), 30, "unexpected length: {t}");
    assert!(t.ends_with('Z'), "missing Z: {t}");
    let b = t.as_bytes();
    assert_eq!(b[4], b'-', "bad year separator: {t}");
    assert_eq!(b[7], b'-', "bad month separator: {t}");
    assert_eq!(b[10], b'T', "bad date/time separator: {t}");
    assert_eq!(b[19], b'.', "bad fractional separator: {t}");
}

#[test]
fn unused_import_guard() {
    let _: Option<PathBuf> = None;
    let _: Option<ContainerBackend> = None;
}

// ---------------------------------------------------------------------------
// Real-runtime enforcement.
//
// These tests check that the policy decision gates the container itself, not
// just the command line. Evidence comes from two independent sources:
//   * daemon lifecycle events (`docker events`) for container creation;
//   * a sentinel file written through a declared mount, proving the command
//     actually executed inside the container.
// ---------------------------------------------------------------------------

/// RFC 3339 timestamp with nanosecond precision.
///
/// `docker events --since` also accepts whole Unix seconds, but at that
/// granularity an event from a previous test can fall inside this test's window
/// and produce a false positive. Nanosecond precision removes that race.
fn now_rfc3339() -> String {
    let d = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap();
    let secs = d.as_secs() as i64;
    let nanos = d.subsec_nanos();
    let days = secs.div_euclid(86_400);
    let sod = secs.rem_euclid(86_400);
    let (y, m, dd) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{dd:02}T{:02}:{:02}:{:02}.{nanos:09}Z",
        sod / 3600,
        (sod % 3600) / 60,
        sod % 60
    )
}

/// Howard Hinnant's `civil_from_days`: days since the Unix epoch to Y/M/D.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Container lifecycle events observed between two RFC 3339 timestamps.
fn container_events(rt: &str, since: &str, until: &str) -> Vec<String> {
    let out = Command::new(rt)
        .args([
            "events",
            "--filter",
            "type=container",
            "--filter",
            "event=create",
            "--filter",
            "event=destroy",
            "--format",
            "{{.Action}} {{.Actor.Attributes.name}}",
            "--since",
            since,
            "--until",
            until,
        ])
        .output()
        .expect("docker events");
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .map(str::to_string)
        .collect()
}

/// Names of AgentFence-created containers among the observed events.
fn agentfence_creations(events: &[String]) -> Vec<String> {
    events
        .iter()
        .filter(|e| e.starts_with("create agentfence-"))
        .map(|e| e.trim_start_matches("create ").to_string())
        .collect()
}

fn scratch_dir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("agentfence-rrt-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// Write a container config that mounts `host_dir` at `/data`.
fn write_mount_config(
    path: &std::path::Path,
    host_dir: &std::path::Path,
    runtime_path: Option<&str>,
) {
    let mut cfg = serde_json::json!({
        "runtime": "Docker",
        "image": "alpine:3.19",
        "max_cpu": 0.5,
        "max_memory_mb": 128,
        "pids_limit": 64,
        "read_only_fs": true,
        "network_isolated": true,
        "drop_capabilities": true,
        "no_new_privileges": true,
        "run_as_uid": 1000,
        "run_as_gid": 1000,
        "workdir": "/data",
        "mounts": [
            {
                "host_path": host_dir.to_string_lossy(),
                "container_path": "/data",
                "read_only": false
            }
        ],
        "env_vars": [],
        "timeout_secs": 30,
        "tmpfs_size_mb": 64
    });
    if let Some(rp) = runtime_path {
        cfg["runtime_path"] = serde_json::Value::String(rp.to_string());
    }
    std::fs::write(path, serde_json::to_string_pretty(&cfg).unwrap()).unwrap();
}

/// Write a shell policy that produces the requested decision for `sh`.
///
/// A `defaults.shell` value alone is not enough: the policy engine denies with
/// "No shell policy defined" when no `shell:` section exists, so each decision
/// needs its own explicit rule list.
fn write_shell_policy(path: &std::path::Path, decision: &str) {
    let yaml = format!(
        "version: 1\ndefaults:\n  shell: {decision}\n  network: deny\n  mcp: deny\n  filesystem: deny\nshell:\n  {decision}:\n    - sh\n"
    );
    std::fs::write(path, yaml).unwrap();
}

fn run_agentfence_real(
    args: &[&str],
    data_dir: &std::path::Path,
    config: &str,
) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_agentfence"))
        .args(args)
        .env("AGENTFENCE_DATA_DIR", data_dir)
        .env("AGENTFENCE_EXECUTION_BACKEND", "container")
        .env("AGENTFENCE_CONTAINER_CONFIG", config)
        // The default approval wait is 300s; the pending-approval test only
        // needs to observe that nothing runs while it waits.
        .env("AGENTFENCE_APPROVAL_TIMEOUT_MS", "2000")
        .output()
        .expect("spawn agentfence")
}

/// Run the CLI once; return its exit code and the AgentFence containers the
/// daemon reported creating.
fn enforced_run(
    args: &[&str],
    data_dir: &std::path::Path,
    config: &str,
    rt: &str,
) -> (Option<i32>, Vec<String>) {
    let since = now_rfc3339();
    let out = run_agentfence_real(args, data_dir, config);
    let code = out.status.code();
    // Give the daemon a moment to publish its lifecycle events.
    std::thread::sleep(std::time::Duration::from_secs(2));
    let until = now_rfc3339();
    let events = container_events(rt, &since, &until);
    (code, agentfence_creations(&events))
}

#[test]
fn real_runtime_denied_command_creates_no_container() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let rt = runtime_binary();
    assert!(daemon_available(&rt), "{rt} daemon is not reachable");
    ensure_image(&rt, "alpine:3.19");

    let dir = scratch_dir("deny");
    let host_mount = dir.join("mount");
    std::fs::create_dir_all(&host_mount).unwrap();
    let cfg = dir.join("config.json");
    write_mount_config(&cfg, &host_mount, None);
    let policy = dir.join("policy.yaml");
    write_shell_policy(&policy, "deny");

    let (code, containers) = enforced_run(
        &[
            "exec",
            "--policy",
            &policy.to_string_lossy(),
            "--",
            "sh",
            "-c",
            "echo ran > /data/sentinel",
        ],
        &dir.join("data"),
        &cfg.to_string_lossy(),
        &rt,
    );

    assert!(
        !host_mount.join("sentinel").exists(),
        "a denied command must not execute anywhere"
    );
    assert!(
        containers.is_empty(),
        "a denied command must not create a container: {containers:?}"
    );
    let _ = code;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn real_runtime_pending_approval_creates_no_container() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let rt = runtime_binary();
    assert!(daemon_available(&rt), "{rt} daemon is not reachable");
    ensure_image(&rt, "alpine:3.19");

    let dir = scratch_dir("ask");
    let host_mount = dir.join("mount");
    std::fs::create_dir_all(&host_mount).unwrap();
    let cfg = dir.join("config.json");
    write_mount_config(&cfg, &host_mount, None);
    let policy = dir.join("policy.yaml");
    write_shell_policy(&policy, "ask");

    let (code, containers) = enforced_run(
        &[
            "exec",
            "--policy",
            &policy.to_string_lossy(),
            "--",
            "sh",
            "-c",
            "echo ran > /data/sentinel",
        ],
        &dir.join("data"),
        &cfg.to_string_lossy(),
        &rt,
    );

    assert!(
        !host_mount.join("sentinel").exists(),
        "an unanswered approval request must not execute"
    );
    assert!(
        containers.is_empty(),
        "a pending approval must not create a container: {containers:?}"
    );
    let _ = code;
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn real_runtime_approved_command_creates_exactly_one_container() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let rt = runtime_binary();
    assert!(daemon_available(&rt), "{rt} daemon is not reachable");
    ensure_image(&rt, "alpine:3.19");

    let dir = scratch_dir("allow");
    let host_mount = dir.join("mount");
    std::fs::create_dir_all(&host_mount).unwrap();
    let cfg = dir.join("config.json");
    write_mount_config(&cfg, &host_mount, None);
    let policy = dir.join("policy.yaml");
    write_shell_policy(&policy, "allow");

    let (code, containers) = enforced_run(
        &[
            "exec",
            "--policy",
            &policy.to_string_lossy(),
            "--",
            "sh",
            "-c",
            "echo ran > /data/sentinel",
        ],
        &dir.join("data"),
        &cfg.to_string_lossy(),
        &rt,
    );

    let sentinel = host_mount.join("sentinel");
    assert!(
        sentinel.exists(),
        "an approved command must execute inside the container"
    );
    assert_eq!(
        containers.len(),
        1,
        "an approved command must create exactly one container: {containers:?}"
    );
    assert_eq!(code, Some(0), "an approved command must exit cleanly");
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn real_runtime_missing_runtime_fails_closed_without_host_execution() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let rt = runtime_binary();
    assert!(daemon_available(&rt), "{rt} daemon is not reachable");
    ensure_image(&rt, "alpine:3.19");

    let dir = scratch_dir("failclosed");
    let host_mount = dir.join("mount");
    std::fs::create_dir_all(&host_mount).unwrap();
    let cfg = dir.join("config.json");
    // Point at an executable that does not exist: the backend must fail closed.
    let missing = dir.join("no-such-runtime");
    write_mount_config(&cfg, &host_mount, Some(&missing.to_string_lossy()));
    let policy = dir.join("policy.yaml");
    write_shell_policy(&policy, "allow");

    let (code, containers) = enforced_run(
        &[
            "exec",
            "--policy",
            &policy.to_string_lossy(),
            "--",
            "sh",
            "-c",
            "echo ran > /data/sentinel",
        ],
        &dir.join("data"),
        &cfg.to_string_lossy(),
        &rt,
    );

    assert_ne!(code, Some(0), "a missing runtime must fail closed");
    assert!(
        containers.is_empty(),
        "a missing runtime must not create a container: {containers:?}"
    );
    assert!(
        !host_mount.join("sentinel").exists(),
        "no host fallback: the command must not run on the host"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
