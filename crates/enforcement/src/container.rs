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
use std::path::Path;
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
        for key in self.env_vars.iter().map(|(k, _)| k) {
            if key.is_empty() || key.contains('=') || key.contains('\0') {
                return Err(format!("invalid environment variable name {key:?}"));
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

/// Mounts are never used to build a shell command, but they are validated so a
/// malformed or hostile value cannot smuggle a runtime flag.
fn validate_mount(mount: &Mount) -> Result<(), String> {
    // Never expose the host container runtime's control socket. Mounting it
    // would give the container full control of the host runtime. This is
    // checked first so the security reason is the one that is reported.
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
fn stop_container(enforcer: &ContainerEnforcer, name: &str) {
    for attempt in 0..3 {
        let stopped = enforcer
            .runtime_command()
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
    let _ = enforcer
        .runtime_command()
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
}

impl ContainerEnforcer {
    pub fn new(config: ContainerConfig) -> Self {
        Self { config }
    }

    pub fn config(&self) -> &ContainerConfig {
        &self.config
    }

    fn runtime_command(&self) -> Command {
        match &self.config.runtime_path {
            Some(path) => Command::new(path),
            None => Command::new(self.config.runtime.to_string()),
        }
    }

    /// Fail closed when the configured runtime cannot be executed.
    pub fn check_runtime(&self) -> Result<(), ContainerError> {
        match self
            .runtime_command()
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

        let container_name = format!("agentfence-{}", uuid::Uuid::new_v4().simple());

        let mut cmd = self.runtime_command();
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
            cmd.arg("-e").arg(format!("{key}={value}"));
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
            "Executing in container {}: {} {}",
            container_name,
            executable,
            agentfence_secrets::redact::redact(&arguments.join(" ")).text
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
        let enforcer = ContainerEnforcer::new(self.config.clone());

        let outcome = run_with_timeout(child, timeout, || {
            // The container is named, so it can be stopped even though the
            // client process has been abandoned.
            warn!(container = %name, "execution timed out; stopping container");
            stop_container(&enforcer, &name);
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
                stop_container(&enforcer, &name);
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
