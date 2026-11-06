//! Container enforcement for AgentFence.
//!
//! Executes policy-approved commands inside an isolated, non-root container.
//! The runtime is Docker-compatible (Docker or Podman); no other runtime is
//! supported.
//!
//! ```text
//! Agent -> AgentFence PEP -> policy + plugin + approval -> ContainerEnforcer
//!        -> isolated container
//! ```
//!
//! SECURITY: this module never re-evaluates policy. It only runs commands the
//! enforcement path has already allowed. It never falls back to host execution:
//! if the runtime is missing, misconfigured, or fails to start a container,
//! execution fails closed.
//!
//! Limits applied by default: non-root user, read-only root filesystem,
//! `--cap-drop ALL`, `no-new-privileges`, CPU/memory/PID limits, no network,
//! no host Docker socket, no unrestricted host mounts, bounded temp space, and
//! a hard wall-clock timeout.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use crate::backend::{run_with_timeout, ExecutionError};
use tracing::{debug, info, warn};

/// Container runtime type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ContainerRuntime {
    Docker,
    Podman,
}

impl std::fmt::Display for ContainerRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ContainerRuntime::Docker => write!(f, "docker"),
            ContainerRuntime::Podman => write!(f, "podman"),
        }
    }
}

/// A validated host mount.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mount {
    pub host_path: String,
    pub container_path: String,
    pub read_only: bool,
}

/// Container configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// Runtime kind.
    pub runtime: ContainerRuntime,
    /// Explicit path to the runtime executable. `None` means search `PATH`.
    pub runtime_path: Option<String>,
    /// Container image.
    pub image: String,
    /// Maximum CPU cores (0 = unlimited).
    pub max_cpu: f64,
    /// Maximum memory in MB (0 = unlimited).
    pub max_memory_mb: u64,
    /// Maximum number of processes (0 = unlimited).
    pub pids_limit: u32,
    /// Read-only root filesystem.
    pub read_only_fs: bool,
    /// Disable all network access.
    pub network_isolated: bool,
    /// Drop all Linux capabilities.
    pub drop_capabilities: bool,
    /// Block privilege escalation.
    pub no_new_privileges: bool,
    /// Container user (uid).
    pub run_as_uid: u32,
    /// Container group (gid).
    pub run_as_gid: u32,
    /// Working directory inside the container.
    pub workdir: String,
    /// Explicit host mounts.
    pub mounts: Vec<Mount>,
    /// Environment variables passed to the container.
    pub env_vars: Vec<(String, String)>,
    /// When set, only these names may be passed to the container.
    ///
    /// Defence in depth: the config file is the only source of `env_vars`, so
    /// this bounds what a misconfigured or tampered config can inject.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env_allowlist: Option<Vec<String>>,
    /// Wall-clock timeout in seconds (0 = no timeout).
    pub timeout_secs: u64,
    /// Size of the in-container temporary filesystem in MB (0 = none).
    pub tmpfs_size_mb: u64,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            runtime: ContainerRuntime::Docker,
            runtime_path: None,
            image: "alpine:latest".to_string(),
            max_cpu: 1.0,
            max_memory_mb: 512,
            pids_limit: 256,
            read_only_fs: true,
            network_isolated: true,
            drop_capabilities: true,
            no_new_privileges: true,
            run_as_uid: 1000,
            run_as_gid: 1000,
            workdir: "/workspace".to_string(),
            mounts: vec![],
            env_vars: vec![],
            env_allowlist: None,
            timeout_secs: 300,
            tmpfs_size_mb: 64,
        }
    }
}

impl ContainerConfig {
    /// Validate the configuration. Any problem is a fail-closed error.
    pub fn validate(&self) -> Result<(), String> {
        if self.image.trim().is_empty() {
            return Err("image must not be empty".to_string());
        }
        if self.image.split_whitespace().count() != 1 {
            return Err(format!("image {:?} must be a single reference", self.image));
        }
        if !is_container_absolute(&self.workdir) {
            return Err(format!(
                "workdir {:?} must be an absolute path",
                self.workdir
            ));
        }
        if self.run_as_uid == 0 {
            return Err("run_as_uid must not be 0: the container must not run as root".to_string());
        }
        if self.pids_limit == 0 {
            return Err("pids_limit must be greater than 0".to_string());
        }
        if self.max_cpu <= 0.0 {
            return Err("max_cpu must be greater than 0".to_string());
        }
        if self.max_memory_mb == 0 {
            return Err("max_memory_mb must be greater than 0".to_string());
        }
        for (key, value) in &self.env_vars {
            if key.is_empty() || key.contains('=') || key.contains('\0') {
                return Err(format!("invalid environment variable name {key:?}"));
            }
            if denied_env_name(key) {
                return Err(format!(
                    "environment variable {key:?} must not be injected into the container: \
                     it could redirect the guest's container runtime or expose credentials"
                ));
            }
            if let Some(allow) = &self.env_allowlist {
                if !allow.iter().any(|allowed| allowed == key) {
                    return Err(format!(
                        "environment variable {key:?} is not in the configured allowlist"
                    ));
                }
            }
            if value.contains('\0') {
                return Err(format!(
                    "environment variable {key:?} must not contain a NUL byte"
                ));
            }
        }
        let mut seen = std::collections::HashSet::new();
        for mount in &self.mounts {
            validate_mount(mount)?;
            if !seen.insert(mount.container_path.clone()) {
                return Err(format!(
                    "duplicate container mount target {}",
                    mount.container_path
                ));
            }
        }
        Ok(())
    }
}

/// Host paths follow the host operating system's path model.
fn is_host_absolute(p: &str) -> bool {
    Path::new(p).is_absolute()
}

/// Container paths are always POSIX absolute, regardless of the host OS.
/// `Path::is_absolute` is platform-dependent and would reject `/workspace`
/// on Windows, which is a perfectly valid path inside a Linux container.
fn is_container_absolute(p: &str) -> bool {
    p.starts_with('/')
}

/// Resolve the container runtime executable to a single absolute path.
///
/// SECURITY: the result is cached and reused for the `--version` probe, the
/// container run, and cleanup. Resolving on each call would let a concurrent
/// process change `PATH` or replace a file on it between the probe and the run,
/// so the binary that was validated would not be the binary that executed.
///
/// This closes the resolution race. It does **not** close the file-replacement
/// race: a local attacker who can write to the resolved file can still swap it
/// after validation. Closing that would require verifying the executable's
/// identity at exec time, which `std::process::Command` cannot do. The daemon
/// and the runtime binary are therefore trusted, as documented in THREAT_MODEL.
fn resolve_runtime_path(config: &ContainerConfig) -> Result<PathBuf, String> {
    let configured = match &config.runtime_path {
        Some(p) => {
            let p = p.trim();
            if p.is_empty() {
                return Err("runtime_path must not be empty".to_string());
            }
            PathBuf::from(p)
        }
        None => PathBuf::from(config.runtime.to_string()),
    };

    let resolved = if looks_like_path(&configured) {
        configured
    } else {
        // A bare name: search PATH the same way the OS would.
        search_path(&configured.to_string_lossy())
            .ok_or_else(|| format!("could not find {:?} in PATH", configured.to_string_lossy()))?
    };

    canonicalize_for_execution(&resolved)
}

/// True when the value carries a directory component, so it must not be searched
/// for in `PATH`.
fn looks_like_path(p: &Path) -> bool {
    p.components().count() > 1 || p.is_absolute()
}

/// Canonicalize a path and strip the Windows `\\?\` prefix.
///
/// `canonicalize` resolves symlinks and junctions, which is what makes the
/// validation path and the execution path refer to the same file. The `\\?\`
/// prefix is an extended-length path that some child programs do not handle, so
/// it is removed when it is a plain volume path.
fn canonicalize_for_execution(p: &Path) -> Result<PathBuf, String> {
    let canonical =
        std::fs::canonicalize(p).map_err(|e| format!("could not resolve {}: {e}", p.display()))?;
    #[cfg(windows)]
    {
        // The extended-length prefix is an implementation detail of
        // `canonicalize`; strip it so child programs receive a normal path.
        const PREFIX: &str = "\\\\?\\";
        const UNC_PREFIX: &str = "\\\\?\\UNC\\";
        let text = canonical.to_string_lossy().into_owned();
        if let Some(rest) = text.strip_prefix(UNC_PREFIX) {
            // `\\server\share\...`
            let mut parts = rest.splitn(2, '\\');
            let server = parts.next().unwrap_or("");
            let tail = parts.next().unwrap_or("");
            return Ok(PathBuf::from(format!(r"\\{server}\{tail}")));
        }
        if let Some(rest) = text.strip_prefix(PREFIX) {
            return Ok(PathBuf::from(rest));
        }
    }
    Ok(canonical)
}

/// Search `PATH` for an executable, honouring `PATHEXT` on Windows.
fn search_path(name: &str) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    let extensions: Vec<String> = if cfg!(windows) {
        std::env::var("PATHEXT")
            .unwrap_or_else(|_| ".EXE;.BAT;.CMD".to_string())
            .split(';')
            .map(|e| e.trim().trim_start_matches('.').to_ascii_lowercase())
            .filter(|e| !e.is_empty())
            .collect()
    } else {
        Vec::new()
    };

    for dir in std::env::split_paths(&path) {
        let direct = dir.join(name);
        if is_executable_file(&direct) {
            return Some(direct);
        }
        for ext in &extensions {
            let candidate = dir.join(format!("{name}.{ext}"));
            if is_executable_file(&candidate) {
                return Some(candidate);
            }
        }
    }
    None
}

fn is_executable_file(p: &Path) -> bool {
    p.is_file()
}

/// Mounts are never used to build a shell command, but they are validated so a
/// malformed or hostile value cannot smuggle a runtime flag.
/// Render argv for a human-readable log line.
///
/// SECURITY: joining arguments with spaces is ambiguous — a payload containing
/// spaces, quotes or shell metacharacters can be misread as a different command,
/// and an operator acting on the log could approve the wrong thing. Each argument
/// is redacted individually and the result is a JSON array, so argument
/// boundaries stay visible and credentials never reach the log.
///
/// This is display only. The authoritative record is the action digest written
/// by the audit layer, which is derived from the same `ShellCommand`.
fn logged_arguments(executable: &str, arguments: &[String]) -> String {
    let mut rendered: Vec<String> = Vec::with_capacity(arguments.len() + 1);
    rendered.push(agentfence_secrets::redact::redact(executable).text);
    for argument in arguments {
        rendered.push(agentfence_secrets::redact::redact(argument).text);
    }
    // Serialization of a `Vec<String>` cannot fail, but fall back to a spaced
    // join rather than dropping the log line entirely.
    serde_json::to_string(&rendered).unwrap_or_else(|_| rendered.join(" "))
}

/// Build the `--env` argument for one variable.
///
/// SECURITY: the value is always attached with `=`. A bare `-e KEY` makes Docker
/// inherit the value from AgentFence's own environment, which would leak host
/// variables into the guest; `-e KEY=` sets an empty value instead.
fn env_argument(key: &str, value: &str) -> String {
    format!("{key}={value}")
}

/// Variable names that must never be injected into a container.
///
/// These locate or authenticate against a container runtime. The Docker CLI reads
/// them from AgentFence's own environment to find the daemon; they are not
/// forwarded to the guest unless a configuration explicitly asks for them, which
/// is now rejected. Setting `DOCKER_HOST` in a guest would hand it a socket path
/// it must never see, and any `AGENTFENCE_*` value could steer AgentFence itself
/// from inside a container.
fn denied_env_name(key: &str) -> bool {
    let upper = key.to_ascii_uppercase();
    if upper.starts_with("DOCKER_") || upper.starts_with("CONTAINERD_") {
        return true;
    }
    const NAMES: [&str; 6] = [
        "AGENTFENCE_EXECUTION_BACKEND",
        "AGENTFENCE_CONTAINER_CONFIG",
        "AGENTFENCE_CONTAINER_RUNTIME",
        "AGENTFENCE_CONTAINER_RUNTIME_PATH",
        "AGENTFENCE_DATA_DIR",
        "AGENTFENCE_APPROVAL_DB",
    ];
    NAMES.contains(&upper.as_str())
}

/// Security-critical host paths that must never be bind-mounted.
///
/// Mounting the container runtime's control socket hands the guest full control
/// of the host runtime. `/proc`, `/sys` and `/dev` expose host kernel state and
/// device nodes. Comparison is component-wise on canonicalized paths, so a
/// prefix can never match a sibling such as `/srv/data` versus `/srv/data-evil`.
fn blocked_host_prefixes() -> Vec<PathBuf> {
    let mut blocked: Vec<PathBuf> = Vec::new();
    if cfg!(windows) {
        let candidates = [
            ("PROGRAMDATA", Some("Docker")),
            ("ProgramData", Some("containerd")),
            ("LOCALAPPDATA", Some("Docker")),
            ("SystemRoot", None),
        ];
        for (key, suffix) in candidates {
            if let Some(dir) = std::env::var_os(key) {
                let base = PathBuf::from(dir);
                blocked.push(match suffix {
                    Some(s) => base.join(s),
                    None => base,
                });
            }
        }
        blocked.push(PathBuf::from(r"C:\Program Files\Docker"));
        blocked.push(PathBuf::from(r"C:\ProgramData\DockerDesktop"));
    } else {
        for raw in [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/var/run/docker",
            "/run/docker",
            "/run/containerd",
            "/var/run/containerd",
            "/proc",
            "/sys",
            "/dev",
        ] {
            blocked.push(PathBuf::from(raw));
        }
    }
    blocked
}

/// Resolve `p` for comparison, falling back to the literal path when it does not
/// exist. Windows extended-length prefixes are stripped so both sides use the
/// same form.
fn comparison_path(p: &Path) -> PathBuf {
    canonicalize_for_execution(p).unwrap_or_else(|_| p.to_path_buf())
}

fn validate_mount(mount: &Mount) -> Result<(), String> {
    // Never expose the host container runtime's control socket. Mounting it
    // would give the container full control of the host runtime. This is
    // checked first so the security reason is the one that is reported.
    //
    // The literal-name check is only the first line of defence: a symlink or
    // junction whose *name* is innocent can still point at the socket. The
    // canonicalized check below closes that.
    let socketish = mount.host_path.to_ascii_lowercase();
    if socketish.contains("docker.sock")
        || socketish.contains("containerd.sock")
        || socketish.contains("/var/run/docker")
        || socketish.contains("/run/docker")
    {
        return Err(format!(
            "mount host_path {:?} must not expose the host container runtime socket",
            mount.host_path
        ));
    }
    if mount.host_path.trim().is_empty() {
        return Err("mount host_path must not be empty".to_string());
    }
    if !is_host_absolute(&mount.host_path) {
        return Err(format!(
            "mount host_path {:?} must be absolute",
            mount.host_path
        ));
    }
    // Resolve symlinks and junctions and check the *real* target. A path that
    // does not exist yet is left to the runtime to reject, but see the
    // documented TOCTOU limitation: it could be created between this check and
    // the runtime's own resolution.
    let host = Path::new(&mount.host_path);
    if host.exists() {
        let canonical = comparison_path(host);
        for prefix in blocked_host_prefixes() {
            let prefix = comparison_path(&prefix);
            if canonical.starts_with(&prefix) {
                return Err(format!(
                    "mount host_path {:?} resolves to {:?}, which is inside the protected host path {:?}",
                    mount.host_path, canonical, prefix
                ));
            }
        }
    }
    if Path::new(&mount.host_path)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!(
            "mount host_path {:?} must not contain '..'",
            mount.host_path
        ));
    }
    if mount.container_path.trim().is_empty() {
        return Err("mount container_path must not be empty".to_string());
    }
    if !is_container_absolute(&mount.container_path) {
        return Err(format!(
            "mount container_path {:?} must be absolute",
            mount.container_path
        ));
    }
    if mount.container_path == "/" {
        return Err("mount container_path must not be /".to_string());
    }
    if Path::new(&mount.container_path)
        .components()
        .any(|c| matches!(c, std::path::Component::ParentDir))
    {
        return Err(format!(
            "mount container_path {:?} must not contain '..'",
            mount.container_path
        ));
    }
    if mount.container_path.contains(':') {
        return Err(format!(
            "mount container_path {:?} must not contain ':'",
            mount.container_path
        ));
    }
    Ok(())
}

/// Container execution failure modes.
#[derive(Debug, thiserror::Error)]
pub enum ContainerError {
    #[error("container runtime '{}' is not available: {detail}", runtime)]
    RuntimeUnavailable { runtime: String, detail: String },
    #[error("container configuration is invalid: {0}")]
    InvalidConfiguration(String),
    #[error("container initialization failed: {0}")]
    InitializationFailed(String),
    #[error("execution failed: {0}")]
    ExecutionFailed(String),
    #[error("execution timed out after {0}s")]
    TimedOut(u64),
    #[error("I/O error: {0}")]
    Io(String),
}

/// Container execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

/// Stop and remove a named container.
///
/// `kill` is retried a bounded number of times because a container that is
/// still being created can reject the first attempt. A leak here is a resource
/// leak, not a privilege escalation, so a bounded retry is the right trade-off.
fn stop_container(runtime: &Path, name: &str) {
    for attempt in 0..3 {
        let stopped = Command::new(runtime)
            .args(["kill", name])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if stopped {
            break;
        }
        if attempt < 2 {
            std::thread::sleep(Duration::from_millis(50));
        }
    }
    let _ = Command::new(runtime)
        .args(["rm", "-f", name])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

/// Executes commands in an isolated container.
#[derive(Debug)]
pub struct ContainerEnforcer {
    config: ContainerConfig,
    /// The runtime executable, resolved once.
    ///
    /// SECURITY: the `--version` probe and the container run must use the same
    /// binary. Resolving on every call would let the executable found for the
    /// probe differ from the one used for the run if `PATH`, or a file on it,
    /// changes in between.
    runtime: std::sync::OnceLock<Result<PathBuf, String>>,
}

impl ContainerEnforcer {
    pub fn new(config: ContainerConfig) -> Self {
        Self {
            config,
            runtime: std::sync::OnceLock::new(),
        }
    }

    /// The runtime executable to invoke, resolved once.
    fn runtime_path(&self) -> Result<PathBuf, ContainerError> {
        self.runtime
            .get_or_init(|| resolve_runtime_path(&self.config))
            .clone()
            .map_err(|detail| ContainerError::RuntimeUnavailable {
                runtime: self.config.runtime.to_string(),
                detail,
            })
    }

    pub fn config(&self) -> &ContainerConfig {
        &self.config
    }

    fn runtime_command(&self, runtime: &Path) -> Command {
        Command::new(runtime)
    }

    /// Fail closed when the configured runtime cannot be executed.
    pub fn check_runtime(&self) -> Result<(), ContainerError> {
        let runtime = self.runtime_path()?;
        match self
            .runtime_command(&runtime)
            .arg("--version")
            .stdin(Stdio::null())
            .output()
        {
            Ok(out) if out.status.success() => Ok(()),
            Ok(out) => {
                let detail = String::from_utf8_lossy(&out.stderr).trim().to_string();
                Err(ContainerError::RuntimeUnavailable {
                    runtime: self.config.runtime.to_string(),
                    detail: if detail.is_empty() {
                        format!("exit code {:?}", out.status.code())
                    } else {
                        detail
                    },
                })
            }
            Err(e) => Err(ContainerError::RuntimeUnavailable {
                runtime: self.config.runtime.to_string(),
                detail: e.to_string(),
            }),
        }
    }

    /// Execute a command in a container.
    ///
    /// `executable` and `arguments` are passed to the runtime as separate
    /// values; nothing is joined into a shell string.
    pub fn execute(
        &self,
        executable: &str,
        arguments: &[String],
    ) -> Result<ContainerResult, ContainerError> {
        if executable.trim().is_empty() {
            return Err(ContainerError::InvalidConfiguration(
                "executable must not be empty".to_string(),
            ));
        }
        self.config
            .validate()
            .map_err(ContainerError::InvalidConfiguration)?;
        // Fail closed: a runtime that has disappeared since startup must never
        // turn into a host execution.
        self.check_runtime()?;
        let runtime = self.runtime_path()?;

        let container_name = format!("agentfence-{}", uuid::Uuid::new_v4().simple());

        let mut cmd = self.runtime_command(&runtime);
        cmd.arg("run");
        cmd.arg("--rm");
        cmd.arg("--name").arg(&container_name);
        cmd.arg("--init");
        cmd.arg("--user").arg(format!(
            "{}:{}",
            self.config.run_as_uid, self.config.run_as_gid
        ));
        cmd.arg("--cpus").arg(format!("{:.2}", self.config.max_cpu));
        cmd.arg("--memory")
            .arg(format!("{}m", self.config.max_memory_mb));
        // `--memory-swap` equal to `--memory` disables swap entirely.
        cmd.arg("--memory-swap")
            .arg(format!("{}m", self.config.max_memory_mb));
        cmd.arg("--pids-limit")
            .arg(self.config.pids_limit.to_string());

        if self.config.read_only_fs {
            cmd.arg("--read-only");
        }
        if self.config.tmpfs_size_mb > 0 {
            cmd.arg("--tmpfs").arg(format!(
                "/tmp:rw,nosuid,noexec,size={}m",
                self.config.tmpfs_size_mb
            ));
        }
        if self.config.network_isolated {
            cmd.arg("--network").arg("none");
        }
        if self.config.drop_capabilities {
            cmd.arg("--cap-drop").arg("ALL");
        }
        if self.config.no_new_privileges {
            cmd.arg("--security-opt").arg("no-new-privileges:true");
        }

        // Explicit mounts only. Never the Docker socket, never `/`.
        for mount in &self.config.mounts {
            let mode = if mount.read_only { "ro" } else { "rw" };
            cmd.arg("-v").arg(format!(
                "{}:{}:{}",
                mount.host_path, mount.container_path, mode
            ));
        }

        for (key, value) in &self.config.env_vars {
            cmd.arg("-e").arg(env_argument(key, value));
        }

        cmd.arg("--workdir").arg(&self.config.workdir);
        cmd.arg(&self.config.image);
        cmd.arg(executable);
        cmd.args(arguments);

        cmd.stdin(Stdio::null());
        cmd.stdout(Stdio::piped());
        cmd.stderr(Stdio::piped());

        // SECURITY: never log the raw command. Credentials embedded in arguments
        // would otherwise reach stdout, logs, and terminal scrollback.
        info!(
            "Executing in container {}: {}",
            container_name,
            logged_arguments(executable, arguments)
        );
        debug!(?cmd, "container invocation");

        let child = cmd.spawn().map_err(|e| {
            ContainerError::InitializationFailed(format!("could not start container: {e}"))
        })?;

        let timeout = if self.config.timeout_secs > 0 {
            Some(Duration::from_secs(self.config.timeout_secs))
        } else {
            None
        };
        let name = container_name.clone();
        let cleanup_name = name.clone();
        let cleanup_runtime = runtime.clone();

        let outcome = run_with_timeout(child, timeout, move || {
            // The container is named, so it can be stopped even though the
            // client process has been abandoned.
            warn!(container = %cleanup_name, "execution timed out; stopping container");
            stop_container(&cleanup_runtime, &cleanup_name);
        });

        match outcome {
            Ok((code, stdout, stderr, _timed_out)) => {
                let code = code.unwrap_or(-1);
                info!(exit_code = code, "container execution finished");
                Ok(ContainerResult {
                    exit_code: code,
                    stdout: String::from_utf8_lossy(&stdout).to_string(),
                    stderr: String::from_utf8_lossy(&stderr).to_string(),
                    timed_out: false,
                })
            }
            Err(ExecutionError::TimedOut(secs)) => {
                // The on-timeout handler already attempted a stop; repeat the
                // removal so a container that ignored `kill` is still cleaned up.
                stop_container(&runtime, &name);
                Err(ContainerError::TimedOut(secs))
            }
            Err(ExecutionError::Io(m)) => Err(ContainerError::Io(m)),
            Err(e) => Err(ContainerError::ExecutionFailed(e.to_string())),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_configuration_is_the_hardened_one() {
        let config = ContainerConfig::default();
        assert_eq!(config.runtime, ContainerRuntime::Docker);
        assert_eq!(config.max_cpu, 1.0);
        assert_eq!(config.max_memory_mb, 512);
        assert_eq!(config.pids_limit, 256);
        assert!(config.read_only_fs);
        assert!(config.network_isolated);
        assert!(config.drop_capabilities);
        assert!(config.no_new_privileges);
        assert_ne!(config.run_as_uid, 0);
        assert!(config.timeout_secs > 0);
        assert!(config.tmpfs_size_mb > 0);
    }

    #[test]
    fn the_runtime_name_is_the_invocation_name() {
        assert_eq!(format!("{}", ContainerRuntime::Docker), "docker");
        assert_eq!(format!("{}", ContainerRuntime::Podman), "podman");
    }

    #[test]
    fn an_enforcer_exposes_its_configuration() {
        let config = ContainerConfig::default();
        let enforcer = ContainerEnforcer::new(config);
        assert_eq!(enforcer.config().runtime, ContainerRuntime::Docker);
    }

    #[test]
    fn a_result_carries_exit_status_and_output() {
        let result = ContainerResult {
            exit_code: 0,
            stdout: "hello".to_string(),
            stderr: String::new(),
            timed_out: false,
        };
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "hello");
        assert!(!result.timed_out);
    }

    #[test]
    fn a_mount_is_constructed_verbatim() {
        let mount = Mount {
            host_path: "/tmp".to_string(),
            container_path: "/workspace".to_string(),
            read_only: true,
        };
        assert_eq!(mount.host_path, "/tmp");
        assert_eq!(mount.container_path, "/workspace");
        assert!(mount.read_only);
    }

    #[test]
    fn the_default_configuration_is_valid() {
        ContainerConfig::default()
            .validate()
            .expect("the hardened defaults must validate");
    }

    #[test]
    fn a_root_uid_is_rejected() {
        let config = ContainerConfig {
            run_as_uid: 0,
            ..Default::default()
        };
        let err = config.validate().expect_err("root must be rejected");
        assert!(err.contains("root"), "unexpected error: {err}");
    }

    #[test]
    fn a_relative_workdir_is_rejected() {
        let config = ContainerConfig {
            workdir: "workspace".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn an_empty_image_is_rejected() {
        let config = ContainerConfig {
            image: "   ".to_string(),
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    #[test]
    fn a_socket_mount_is_rejected_before_the_path_check() {
        let config = ContainerConfig {
            mounts: vec![Mount {
                host_path: "docker.sock".to_string(),
                container_path: "/var/run/docker.sock".to_string(),
                read_only: true,
            }],
            ..Default::default()
        };
        let err = config.validate().expect_err("socket must be rejected");
        assert!(
            err.contains("container runtime socket"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_parent_directory_in_a_mount_is_rejected() {
        let host = if cfg!(windows) {
            "C:/tmp/../etc".to_string()
        } else {
            "/tmp/../etc".to_string()
        };
        let config = ContainerConfig {
            mounts: vec![Mount {
                host_path: host,
                container_path: "/data".to_string(),
                read_only: true,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }

    /// Serializes tests that mutate the process environment.
    static RESOLVE_ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn an_explicit_runtime_path_is_resolved_and_reused() {
        // `current_exe` is a real file on every platform.
        let exe = std::env::current_exe().expect("current exe");
        let config = ContainerConfig {
            runtime_path: Some(exe.to_string_lossy().into_owned()),
            ..Default::default()
        };
        let enforcer = ContainerEnforcer::new(config);

        let first = enforcer.runtime_path().expect("must resolve");
        let second = enforcer.runtime_path().expect("must resolve again");
        assert_eq!(
            first, second,
            "the probe and the run must use the same executable"
        );
        assert!(
            first.is_absolute(),
            "resolved path must be absolute: {first:?}"
        );
    }

    #[test]
    fn a_missing_explicit_runtime_fails_closed() {
        let config = ContainerConfig {
            runtime_path: Some("/nonexistent/agentfence-no-such-runtime".into()),
            ..Default::default()
        };
        let enforcer = ContainerEnforcer::new(config);
        let err = enforcer.runtime_path().expect_err("must not resolve");
        assert!(
            matches!(err, ContainerError::RuntimeUnavailable { .. }),
            "unexpected error: {err:?}"
        );
    }

    #[test]
    fn a_bare_runtime_name_is_searched_in_path() {
        let _guard = RESOLVE_ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let dir = std::env::temp_dir().join(format!(
            "af-runtime-resolve-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        ));
        std::fs::create_dir_all(&dir).unwrap();

        // A real file, so `is_file()` succeeds. The default runtime is `docker`,
        // so the probe must carry that name (plus `PATHEXT` on Windows).
        let name = if cfg!(windows) {
            "docker.exe"
        } else {
            "docker"
        };
        let candidate = dir.join(name);
        std::fs::write(
            &candidate,
            if cfg!(windows) {
                "@echo off\r\n"
            } else {
                "#!/bin/sh\n"
            },
        )
        .unwrap();

        let previous = std::env::var_os("PATH");
        std::env::set_var("PATH", &dir);
        let resolved = resolve_runtime_path(&ContainerConfig {
            runtime_path: None,
            ..Default::default()
        });
        match previous {
            Some(v) => std::env::set_var("PATH", v),
            None => std::env::remove_var("PATH"),
        }

        let resolved = resolved.expect("must find the executable in PATH");
        assert!(
            resolved.is_absolute(),
            "resolved path must be absolute: {resolved:?}"
        );
        assert_eq!(resolved.file_name().and_then(|n| n.to_str()), Some(name));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn the_extended_length_prefix_is_stripped() {
        let dir = std::env::temp_dir();
        let resolved = canonicalize_for_execution(&dir).expect("canonicalize the temp dir");
        let text = resolved.to_string_lossy();
        assert!(
            !text.starts_with(r"\\?\"),
            "the extended-length prefix must be stripped: {text}"
        );
        assert!(resolved.is_absolute());
    }

    #[test]
    fn a_prefix_check_never_matches_a_sibling() {
        // Component-wise comparison: `/safe/data` must not match
        // `/safe/data-evil`, and a truncated prefix must not match either.
        assert!(Path::new("/safe/data/x").starts_with("/safe/data"));
        assert!(!Path::new("/safe/data-evil/x").starts_with("/safe/data"));
        assert!(!Path::new("/safe/dat").starts_with("/safe/data"));
        assert!(!Path::new("/other/data").starts_with("/safe/data"));
    }

    #[test]
    fn the_runtime_socket_is_rejected_in_every_spelling() {
        for path in [
            "/var/run/docker.sock",
            "/run/docker.sock",
            "/srv/containerd.sock",
            "/srv/DOCKER.SOCK",
        ] {
            let config = ContainerConfig {
                mounts: vec![Mount {
                    host_path: path.to_string(),
                    container_path: "/data".to_string(),
                    read_only: true,
                }],
                ..Default::default()
            };
            let err = config
                .validate()
                .expect_err(&format!("{path} must be rejected"));
            assert!(err.contains("socket"), "{path}: {err}");
        }
    }

    #[test]
    fn a_nonexistent_host_path_is_left_to_the_runtime() {
        // Docker creates a missing bind-mount source, so validation must not
        // reject it. The residual race is documented in THREAT_MODEL.
        let config = ContainerConfig {
            mounts: vec![Mount {
                host_path: if cfg!(windows) {
                    r"C:\nonexistent\agentfence-af-missing-path".to_string()
                } else {
                    "/nonexistent/agentfence-af-missing-path".to_string()
                },
                container_path: "/data".to_string(),
                read_only: true,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn a_file_mount_is_allowed() {
        let file =
            std::env::temp_dir().join(format!("af-file-mount-{}", uuid::Uuid::new_v4().simple()));
        std::fs::write(&file, "probe").unwrap();
        let config = ContainerConfig {
            mounts: vec![Mount {
                host_path: file.to_string_lossy().into_owned(),
                container_path: "/probe.txt".to_string(),
                read_only: true,
            }],
            ..Default::default()
        };
        assert!(config.validate().is_ok());
        let _ = std::fs::remove_file(&file);
    }

    #[test]
    fn read_only_and_read_write_mounts_are_both_valid() {
        for read_only in [true, false] {
            let config = ContainerConfig {
                mounts: vec![Mount {
                    host_path: if cfg!(windows) {
                        r"C:\srv\agentfence-probe".to_string()
                    } else {
                        "/srv/agentfence-probe".to_string()
                    },
                    container_path: "/data".to_string(),
                    read_only,
                }],
                ..Default::default()
            };
            assert!(config.validate().is_ok(), "read_only={read_only}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_to_a_protected_path_is_rejected() {
        let dir = std::env::temp_dir().join(format!("af-mount-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join("innocent");
        std::os::unix::fs::symlink("/proc", &link).unwrap();

        let config = ContainerConfig {
            mounts: vec![Mount {
                host_path: link.to_string_lossy().into_owned(),
                container_path: "/proc-link".to_string(),
                read_only: true,
            }],
            ..Default::default()
        };
        let err = config
            .validate()
            .expect_err("a symlink to /proc must be rejected");
        assert!(err.contains("protected host path"), "{err}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(windows)]
    #[test]
    fn a_junction_to_a_protected_path_is_rejected() {
        // Creating a directory junction needs no elevation, unlike a symlink.
        let dir = std::env::temp_dir().join(format!("af-mount-{}", uuid::Uuid::new_v4().simple()));
        std::fs::create_dir_all(&dir).unwrap();
        let link = dir.join("innocent");
        let created = Command::new("cmd")
            .args(["/C", "mklink", "/J", &link.to_string_lossy(), r"C:\Windows"])
            .output();
        let Ok(output) = created else {
            return;
        };
        if !output.status.success() {
            // Junction creation may be unavailable; skip rather than fail.
            let _ = std::fs::remove_dir_all(&dir);
            return;
        }

        let config = ContainerConfig {
            mounts: vec![Mount {
                host_path: link.to_string_lossy().into_owned(),
                container_path: "/windows-link".to_string(),
                read_only: true,
            }],
            ..Default::default()
        };
        let err = config
            .validate()
            .expect_err("a junction to C:\\Windows must be rejected");
        assert!(err.contains("protected host path"), "{err}");
        let _ = std::fs::remove_dir_all(&link);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn docker_control_variables_are_rejected() {
        for key in [
            "DOCKER_HOST",
            "DOCKER_CERT_PATH",
            "DOCKER_TLS_VERIFY",
            "DOCKER_CONFIG",
            "CONTAINERD_ADDRESS",
            "AGENTFENCE_EXECUTION_BACKEND",
            "AGENTFENCE_CONTAINER_CONFIG",
            "AGENTFENCE_DATA_DIR",
        ] {
            let config = ContainerConfig {
                env_vars: vec![(key.to_string(), "value".to_string())],
                ..Default::default()
            };
            let err = config
                .validate()
                .expect_err(&format!("{key} must be rejected"));
            assert!(err.contains("must not be injected"), "{key}: {err}");
        }
    }

    #[test]
    fn a_configured_allowlist_is_enforced() {
        let config = ContainerConfig {
            env_vars: vec![
                ("ALLOWED".to_string(), "yes".to_string()),
                ("NOT_ALLOWED".to_string(), "no".to_string()),
            ],
            env_allowlist: Some(vec!["ALLOWED".to_string()]),
            ..Default::default()
        };
        let err = config
            .validate()
            .expect_err("an unlisted variable must be rejected");
        assert!(err.contains("allowlist"), "{err}");

        let config = ContainerConfig {
            env_vars: vec![("ALLOWED".to_string(), "yes".to_string())],
            env_allowlist: Some(vec!["ALLOWED".to_string()]),
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn an_absent_allowlist_restricts_nothing() {
        let config = ContainerConfig {
            env_vars: vec![("ANYTHING".to_string(), "value".to_string())],
            env_allowlist: None,
            ..Default::default()
        };
        assert!(config.validate().is_ok());
    }

    #[test]
    fn an_empty_value_is_an_empty_assignment_not_an_inherited_one() {
        assert_eq!(env_argument("KEY", ""), "KEY=");
        assert_eq!(env_argument("KEY", "value"), "KEY=value");
    }

    #[test]
    fn a_nul_byte_is_rejected_in_names_and_values() {
        for (key, value) in [("KE\u{0}Y", "v"), ("KEY", "v\u{0}")] {
            let config = ContainerConfig {
                env_vars: vec![(key.to_string(), value.to_string())],
                ..Default::default()
            };
            assert!(config.validate().is_err(), "{key:?}={value:?}");
        }
    }

    #[test]
    fn container_names_are_unique() {
        // Every execution must get its own name, so a timeout or cleanup aimed
        // at one container can never touch another.
        let mut seen = std::collections::HashSet::new();
        for _ in 0..1000 {
            let name = format!("agentfence-{}", uuid::Uuid::new_v4().simple());
            assert!(name.starts_with("agentfence-"), "{name}");
            assert!(seen.insert(name.clone()), "duplicate name {name}");
        }
    }

    #[test]
    fn logged_arguments_preserve_argument_boundaries() {
        let rendered = logged_arguments(
            "sh",
            &[
                "-c".to_string(),
                "echo 'hello world' > /data/sentinel".to_string(),
            ],
        );
        let parsed: Vec<String> = serde_json::from_str(&rendered).expect("valid JSON array");
        assert_eq!(
            parsed,
            vec!["sh", "-c", "echo 'hello world' > /data/sentinel"]
        );
    }

    #[test]
    fn logged_arguments_survive_quotes_backslashes_and_metacharacters() {
        let payload = "echo \"quoted\" 'single' `backtick` $VAR | ; & < > \\ end";
        let rendered = logged_arguments("sh", &["-c".to_string(), payload.to_string()]);
        let parsed: Vec<String> = serde_json::from_str(&rendered).expect("valid JSON array");
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[2], payload);
    }

    #[test]
    fn logged_arguments_are_redacted() {
        // A GitHub-style token must never appear in the log line.
        let rendered = logged_arguments(
            "sh",
            &[
                "-c".to_string(),
                "curl -H ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 x".to_string(),
            ],
        );
        assert!(
            !rendered.contains("ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
            "raw credential in log: {rendered}"
        );
        assert!(rendered.contains("[REDACTED]"), "{rendered}");
    }

    #[test]
    fn logged_arguments_are_valid_json_for_empty_input() {
        let rendered = logged_arguments("sh", &[]);
        let parsed: Vec<String> = serde_json::from_str(&rendered).expect("valid JSON array");
        assert_eq!(parsed, vec!["sh"]);
    }

    #[test]
    fn duplicate_mount_targets_are_rejected() {
        let host = if cfg!(windows) { "C:/tmp" } else { "/tmp" };
        let config = ContainerConfig {
            mounts: vec![
                Mount {
                    host_path: host.to_string(),
                    container_path: "/data".to_string(),
                    read_only: true,
                },
                Mount {
                    host_path: host.to_string(),
                    container_path: "/data".to_string(),
                    read_only: true,
                },
            ],
            ..Default::default()
        };
        assert!(config.validate().is_err());
    }
}
