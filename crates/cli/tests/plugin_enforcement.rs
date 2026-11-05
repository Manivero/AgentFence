//! End-to-end tests for configured policy plugins through the real CLI.
//!
//! These drive the `agentfence exec` binary, so they exercise the path an agent
//! actually takes: policy file -> `plugin_loader::build_pdp` -> `Pdp::evaluate`
//! -> execute-or-block. The plugin is the genuine WebAssembly component fixture,
//! compiled and executed inside the sandbox.
//!
//! The observable assertion is always a **side effect**: a configured plugin that
//! denies must prevent the command from running at all.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicUsize, Ordering};

/// The real compiled WebAssembly component fixture.
const FIXTURE: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../wasm-plugin/tests/fixtures/test-plugin.component.wasm"
);

static TEMP_COUNTER: AtomicUsize = AtomicUsize::new(0);

struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(label: &str) -> Self {
        let n = TEMP_COUNTER.fetch_add(1, Ordering::SeqCst);
        let mut path = std::env::temp_dir();
        path.push(format!(
            "agentfence-plugin-e2e-{}-{}-{}",
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

fn slash_path(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/")
}

/// Write the trigger script and return the command that runs it.
///
/// The script name deliberately contains `deny.example.com`, which is the string
/// the WebAssembly guest matches on. The *whole raw command line* is what the
/// plugin receives as `action.target`, so the plugin sees it.
fn write_trigger_script(dir: &TempDir, sentinel: &Path) -> String {
    let (runner_name, ext) = runner();
    let script = dir.path.join(format!("deny.example.com{}", ext));
    let body = format!("echo invoked > \"{}\"", slash_path(sentinel));
    std::fs::write(&script, body).unwrap();

    if runner_name == "cmd" {
        format!("{} /c {}", runner_name, slash_path(&script))
    } else {
        format!("{} {}", runner_name, slash_path(&script))
    }
}

fn write_policy(dir: &TempDir, plugin_yaml: &str) -> PathBuf {
    let yaml = format!(
        "version: 1\n\
         defaults:\n  \
         shell: deny\n  \
         network: deny\n  \
         mcp: deny\n  \
         filesystem: deny\n\
         shell:\n  \
         allow:\n    \
         - {}\n\
         {}",
        runner().0,
        plugin_yaml
    );
    let path = dir.join("policy.yaml");
    std::fs::write(&path, yaml).unwrap();
    path
}

fn wasm_plugin_yaml(id: &str, enabled: bool, module: &str, fingerprint: &str) -> String {
    format!(
        "plugins:\n  \
         wasm:\n    \
         - id: {id}\n      \
         enabled: {enabled}\n      \
         module: {module}\n      \
         expected_fingerprint: \"{fingerprint}\"\n"
    )
}

fn run_exec(policy: &Path, raw_command: &str, dir: &TempDir) -> std::process::Output {
    let agentfence = env!("CARGO_BIN_EXE_agentfence");
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

fn setup(enabled: bool) -> (TempDir, PathBuf, String, PathBuf) {
    let dir = TempDir::new(if enabled { "enabled" } else { "disabled" });
    let sentinel = dir.join("sentinel.txt");
    let policy = write_policy(&dir, &wasm_plugin_yaml("test-plugin", enabled, FIXTURE, ""));
    let raw = write_trigger_script(&dir, &sentinel);
    (dir, policy, raw, sentinel)
}

// ─── A configured plugin controls a real command ─────────────────────────────

#[test]
fn test_configured_plugin_denies_a_command_the_core_policy_allows() {
    // Core policy allows the interpreter; the configured WebAssembly plugin
    // denies because the raw command line contains `deny.example.com`.
    let (dir, policy, raw, sentinel) = setup(true);

    let output = run_exec(&policy, &raw, &dir);

    assert!(
        !output.status.success(),
        "a plugin denial must fail the command, got {:?}",
        output.status.code()
    );
    assert!(
        !sentinel.exists(),
        "SECURITY: a plugin-denied command must never reach the execution backend"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("deny.example.com") || stderr.contains("Denied"),
        "the denial must be explained, got stderr: {}",
        stderr
    );
}

#[test]
fn test_disabled_plugin_does_not_block_the_command() {
    let (dir, policy, raw, sentinel) = setup(false);

    let output = run_exec(&policy, &raw, &dir);

    assert!(
        sentinel.exists(),
        "a disabled plugin must not deny; the command should have run"
    );
    assert!(
        output.status.success(),
        "an allowed command must exit zero, got {:?}: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn test_policy_without_plugin_section_still_runs_the_command() {
    // Backward compatibility at the gateway level: no `plugins:` section means
    // the plugin never participates and the core allow applies.
    let dir = TempDir::new("no-plugins");
    let sentinel = dir.join("sentinel.txt");
    let policy = write_policy(&dir, "");
    let raw = write_trigger_script(&dir, &sentinel);

    let output = run_exec(&policy, &raw, &dir);

    assert!(
        sentinel.exists(),
        "a policy without a plugins section must behave as before"
    );
    assert!(output.status.success());
}

// ─── Configuration failures are visible, not silent ──────────────────────────

#[test]
fn test_invalid_plugin_configuration_is_reported_and_nothing_runs() {
    let dir = TempDir::new("invalid");
    let sentinel = dir.join("sentinel.txt");
    let policy = write_policy(
        &dir,
        &wasm_plugin_yaml(
            "test-plugin",
            true,
            FIXTURE,
            "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
        ),
    );
    let raw = write_trigger_script(&dir, &sentinel);

    let output = run_exec(&policy, &raw, &dir);

    assert!(!output.status.success(), "invalid configuration must fail");
    assert!(
        !sentinel.exists(),
        "SECURITY: a command must not run when the policy failed to load"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("fingerprint mismatch"),
        "the error must name the fingerprint mismatch, got: {}",
        stderr
    );
}

#[test]
fn test_missing_plugin_module_is_reported_and_nothing_runs() {
    let dir = TempDir::new("missing-module");
    let sentinel = dir.join("sentinel.txt");
    let policy = write_policy(
        &dir,
        &wasm_plugin_yaml(
            "test-plugin",
            true,
            "/nonexistent/plugin.component.wasm",
            "",
        ),
    );
    let raw = write_trigger_script(&dir, &sentinel);

    let output = run_exec(&policy, &raw, &dir);

    assert!(!output.status.success());
    assert!(
        !sentinel.exists(),
        "SECURITY: a command must not run when the configured plugin is missing"
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to read wasm module"),
        "the error must name the missing module, got: {}",
        stderr
    );
}

#[test]
fn test_unknown_native_plugin_is_rejected_at_the_gateway() {
    // The CLI never supplies native plugins, so a `native:` entry must fail
    // closed rather than being ignored.
    let dir = TempDir::new("unknown-native");
    let sentinel = dir.join("sentinel.txt");
    let policy = write_policy(
        &dir,
        "plugins:\n  \
         native:\n    \
         - id: not-registered-by-anyone\n",
    );
    let raw = write_trigger_script(&dir, &sentinel);

    let output = run_exec(&policy, &raw, &dir);

    assert!(!output.status.success());
    assert!(!sentinel.exists());

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not registered by the host application"),
        "the error must explain the native trust boundary, got: {}",
        stderr
    );
}
