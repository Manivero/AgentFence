//! Opt-in real-runtime tests for the Hermes wrapper.
//!
//! These run only when `AGENTFENCE_REAL_RUNTIME_TEST=1` is set **and** a
//! container daemon is reachable. They exist to prove on a real runtime — not a
//! fake one — that the wrapper routes through the selected container backend and
//! that a denied command reaches no runtime at all.
//!
//! Run single-threaded: the tests mutate process environment variables.
//!
//! ```sh
//! AGENTFENCE_REAL_RUNTIME_TEST=1 cargo test -p agentfence-hermes \
//!   --test real_container_backend -- --test-threads=1 --nocapture
//! ```

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;

use agentfence_hermes::wrapper::HermesWrapper;

/// Serializes tests that mutate the process environment.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn opt_in() -> bool {
    std::env::var("AGENTFENCE_REAL_RUNTIME_TEST").is_ok()
}

fn skip(msg: &str) {
    eprintln!("SKIPPED: {msg}");
}

fn daemon_available(rt: &str) -> bool {
    Command::new(rt)
        .arg("info")
        .output()
        .map(|o| o.status.success())
        .unwrap_or(false)
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "agentfence-hermes-rrt-{tag}-{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

fn write_config(path: &Path, host_dir: &Path, runtime_path: Option<&str>) {
    // JSON requires backslashes to be escaped; a raw Windows path would make the
    // whole config unreadable.
    fn json_escape(s: &str) -> String {
        s.replace('\\', "\\\\")
    }
    let runtime_path_line = match runtime_path {
        Some(p) => format!("  \"runtime_path\": \"{}\",\n", json_escape(p)),
        None => String::new(),
    };
    let json = format!(
        r#"{{
  "runtime": "Docker",
  "image": "alpine:3.19",
{runtime_path_line}  "max_cpu": 0.5,
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
    {{ "host_path": "{}", "container_path": "/data", "read_only": false }}
  ],
  "env_vars": [],
  "timeout_secs": 30,
  "tmpfs_size_mb": 64
}}"#,
        json_escape(&host_dir.to_string_lossy())
    );
    std::fs::write(path, json).unwrap();
}

fn write_policy(path: &Path, decision: &str) {
    let yaml = format!(
        "version: 1\ndefaults:\n  shell: {decision}\n  network: deny\n  mcp: deny\n  filesystem: deny\nshell:\n  {decision}:\n    - sh\n"
    );
    std::fs::write(path, yaml).unwrap();
}

#[test]
fn hermes_wrapper_executes_through_the_container_backend() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let rt = std::env::var("AGENTFENCE_CONTAINER_RUNTIME").unwrap_or_else(|_| "docker".into());
    if !daemon_available(&rt) {
        return skip("no container daemon is reachable");
    }

    let dir = scratch("allow");
    let mount = dir.join("mount");
    std::fs::create_dir_all(&mount).unwrap();
    let cfg = dir.join("config.json");
    write_config(&cfg, &mount, None);
    let policy = dir.join("policy.yaml");
    write_policy(&policy, "allow");

    std::env::set_var("AGENTFENCE_EXECUTION_BACKEND", "container");
    std::env::set_var("AGENTFENCE_CONTAINER_CONFIG", &cfg);
    std::env::set_var("AGENTFENCE_DATA_DIR", dir.join("data"));

    let wrapper = HermesWrapper::new(policy.to_str().unwrap()).expect("wrapper must build");
    let executed = wrapper
        .execute("sh -c 'echo ran > /data/sentinel'")
        .expect("execute must not error");

    assert!(executed, "an allowed command must be reported as executed");
    assert!(
        mount.join("sentinel").exists(),
        "the command must have run inside the container, not on the host"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hermes_wrapper_denied_command_reaches_no_container() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let rt = std::env::var("AGENTFENCE_CONTAINER_RUNTIME").unwrap_or_else(|_| "docker".into());
    if !daemon_available(&rt) {
        return skip("no container daemon is reachable");
    }

    let dir = scratch("deny");
    let mount = dir.join("mount");
    std::fs::create_dir_all(&mount).unwrap();
    let cfg = dir.join("config.json");
    write_config(&cfg, &mount, None);
    let policy = dir.join("policy.yaml");
    write_policy(&policy, "deny");

    std::env::set_var("AGENTFENCE_EXECUTION_BACKEND", "container");
    std::env::set_var("AGENTFENCE_CONTAINER_CONFIG", &cfg);
    std::env::set_var("AGENTFENCE_DATA_DIR", dir.join("data"));

    let wrapper = HermesWrapper::new(policy.to_str().unwrap()).expect("wrapper must build");
    let executed = wrapper
        .execute("sh -c 'echo ran > /data/sentinel'")
        .expect("execute must not error");

    assert!(
        !executed,
        "a denied command must not be reported as executed"
    );
    assert!(
        !mount.join("sentinel").exists(),
        "a denied command must not run anywhere"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hermes_wrapper_fails_closed_without_a_runtime() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let rt = std::env::var("AGENTFENCE_CONTAINER_RUNTIME").unwrap_or_else(|_| "docker".into());
    if !daemon_available(&rt) {
        return skip("no container daemon is reachable");
    }

    let dir = scratch("failclosed");
    let mount = dir.join("mount");
    std::fs::create_dir_all(&mount).unwrap();
    let cfg = dir.join("config.json");
    let missing = dir.join("no-such-runtime");
    write_config(&cfg, &mount, Some(&missing.to_string_lossy()));
    let policy = dir.join("policy.yaml");
    write_policy(&policy, "allow");

    std::env::set_var("AGENTFENCE_EXECUTION_BACKEND", "container");
    std::env::set_var("AGENTFENCE_CONTAINER_CONFIG", &cfg);
    std::env::set_var("AGENTFENCE_DATA_DIR", dir.join("data"));

    // Either the wrapper refuses to build, or the execution fails — both are
    // fail-closed. What must never happen is the command running on the host.
    let outcome = match HermesWrapper::new(policy.to_str().unwrap()) {
        Ok(wrapper) => wrapper
            .execute("sh -c 'echo ran > /data/sentinel'")
            .map_err(|e| e.to_string()),
        Err(e) => Err(e.to_string()),
    };

    assert!(
        !mount.join("sentinel").exists(),
        "no host fallback: the command must not run on the host (outcome: {outcome:?})"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn hermes_wrapper_supports_concurrent_executions() {
    if !opt_in() {
        return skip("set AGENTFENCE_REAL_RUNTIME_TEST=1 to run real-runtime tests");
    }
    let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());

    let rt = std::env::var("AGENTFENCE_CONTAINER_RUNTIME").unwrap_or_else(|_| "docker".into());
    if !daemon_available(&rt) {
        return skip("no container daemon is reachable");
    }

    let dir = scratch("concurrent");
    let mount = dir.join("mount");
    std::fs::create_dir_all(&mount).unwrap();
    let cfg = dir.join("config.json");
    write_config(&cfg, &mount, None);
    let policy = dir.join("policy.yaml");
    write_policy(&policy, "allow");

    std::env::set_var("AGENTFENCE_EXECUTION_BACKEND", "container");
    std::env::set_var("AGENTFENCE_CONTAINER_CONFIG", &cfg);
    std::env::set_var("AGENTFENCE_DATA_DIR", dir.join("data"));

    let mut handles = Vec::new();
    for i in 0..3 {
        let policy = policy.clone();
        handles.push(std::thread::spawn(move || {
            let wrapper = HermesWrapper::new(policy.to_str().unwrap()).expect("wrapper must build");
            let executed = wrapper
                .execute(&format!("sh -c 'echo marker-{i} > /data/file-{i}'"))
                .expect("execute must not error");
            (i, executed)
        }));
    }
    for (i, executed) in handles
        .into_iter()
        .map(|h| h.join().expect("thread panicked"))
    {
        assert!(executed, "thread {i} must report execution");
    }

    // Every concurrent execution must have produced its own artifact. A shared
    // container name, or one execution cleaning up another's container, would
    // lose files here.
    for i in 0..3 {
        let path = mount.join(format!("file-{i}"));
        let content =
            std::fs::read_to_string(&path).unwrap_or_else(|e| panic!("missing {path:?}: {e}"));
        assert_eq!(
            content.trim(),
            format!("marker-{i}"),
            "wrong content in {path:?}"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}
