//! Execution backend abstraction for AgentFence.
//!
//! The enforcement flow is always:
//!
//! ```text
//! policy evaluation -> plugin evaluation -> approval (if required) -> backend
//! ```
//!
//! The backend is selected **once**, from explicit configuration, and there is
//! no per-invocation fallback: if the container backend is selected and the
//! runtime is unavailable, execution fails closed. Nothing here re-evaluates
//! policy and nothing here can turn a `DENY` into an execution.

use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use crate::container::{ContainerConfig, ContainerEnforcer, ContainerError, ContainerResult};

/// A command to execute, in structured form.
///
/// The executable and its arguments are passed to the backend as separate
/// values. No backend may join them into a shell string.
pub struct ExecutionRequest<'a> {
    pub executable: &'a str,
    pub arguments: &'a [String],
    pub cwd: Option<&'a Path>,
}

/// Outcome of an execution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExecutionResult {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub timed_out: bool,
}

/// Backend failure modes.
#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
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

impl From<ContainerError> for ExecutionError {
    fn from(e: ContainerError) -> Self {
        match e {
            ContainerError::RuntimeUnavailable { runtime, detail } => {
                ExecutionError::RuntimeUnavailable { runtime, detail }
            }
            ContainerError::InvalidConfiguration(m) => ExecutionError::InvalidConfiguration(m),
            ContainerError::InitializationFailed(m) => ExecutionError::InitializationFailed(m),
            ContainerError::ExecutionFailed(m) => ExecutionError::ExecutionFailed(m),
            ContainerError::TimedOut(s) => ExecutionError::TimedOut(s),
            ContainerError::Io(m) => ExecutionError::Io(m),
        }
    }
}

/// A process execution backend.
pub trait ExecutionBackend: Send + Sync + std::fmt::Debug {
    fn execute(&self, req: &ExecutionRequest<'_>) -> Result<ExecutionResult, ExecutionError>;
}

/// Executes the command directly on the host, with no isolation.
///
/// This is the cooperative-mode backend. It exists so that the enforcement
/// path has exactly one call site, and so that selecting the container backend
/// removes the host path rather than adding a second one.
#[derive(Debug)]
pub struct HostBackend;

impl ExecutionBackend for HostBackend {
    fn execute(&self, req: &ExecutionRequest<'_>) -> Result<ExecutionResult, ExecutionError> {
        let mut cmd = Command::new(req.executable);
        cmd.args(req.arguments);
        if let Some(cwd) = req.cwd {
            cmd.current_dir(cwd);
        }
        // A backend must not block forever waiting for input the caller cannot
        // provide.
        cmd.stdin(Stdio::null());

        let out = cmd.output().map_err(|e| {
            ExecutionError::ExecutionFailed(format!("spawn {}: {e}", req.executable))
        })?;

        Ok(ExecutionResult {
            exit_code: out.status.code().unwrap_or(-1),
            stdout: out.stdout,
            stderr: out.stderr,
            timed_out: false,
        })
    }
}

/// Executes the command inside a policy-approved container.
#[derive(Debug)]
pub struct ContainerBackend {
    enforcer: ContainerEnforcer,
}

impl ContainerBackend {
    pub fn new(config: ContainerConfig) -> Result<Self, ExecutionError> {
        config
            .validate()
            .map_err(ExecutionError::InvalidConfiguration)?;
        Ok(Self {
            enforcer: ContainerEnforcer::new(config),
        })
    }

    /// Fail closed if the configured runtime is not reachable.
    pub fn check_runtime(&self) -> Result<(), ExecutionError> {
        self.enforcer.check_runtime().map_err(ExecutionError::from)
    }
}

impl ExecutionBackend for ContainerBackend {
    fn execute(&self, req: &ExecutionRequest<'_>) -> Result<ExecutionResult, ExecutionError> {
        // Checked on every execution: the runtime may have disappeared since
        // startup, and a missing runtime must never become a host execution.
        self.enforcer.check_runtime()?;

        let args: Vec<String> = req.arguments.to_vec();
        let result: ContainerResult = self.enforcer.execute(req.executable, &args)?;

        Ok(ExecutionResult {
            exit_code: result.exit_code,
            stdout: result.stdout.into_bytes(),
            stderr: result.stderr.into_bytes(),
            timed_out: result.timed_out,
        })
    }
}

/// Explicitly selected execution mode.
#[derive(Debug, Clone)]
pub enum ExecutionMode {
    /// Host execution (cooperative mode).
    Host,
    /// Container execution with the given configuration.
    Container(ContainerConfig),
}

impl ExecutionMode {
    /// Read the mode from the environment.
    ///
    /// `AGENTFENCE_EXECUTION_BACKEND` selects the backend. Unset or `host` means
    /// cooperative mode; `container` means the container backend, configured by
    /// the `AGENTFENCE_CONTAINER_*` variables documented in `SECURITY.md`.
    pub fn from_env() -> Result<Self, String> {
        match std::env::var("AGENTFENCE_EXECUTION_BACKEND")
            .ok()
            .as_deref()
            .map(str::trim)
            .map(str::to_ascii_lowercase)
            .as_deref()
        {
            Some("container") | Some("docker") | Some("podman") => {
                Ok(Self::Container(container_config_from_env()?))
            }
            _ => Ok(Self::Host),
        }
    }
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key)
        .ok()
        .map(|v| v.trim().to_string())
        .filter(|v| !v.is_empty())
}

fn container_config_from_env() -> Result<ContainerConfig, String> {
    // An explicitly supplied config that cannot be read or parsed is an error.
    // Falling back to the defaults here would silently discard the operator's
    // declared mounts and other settings, changing what the fence allows
    // without telling anyone.
    let mut cfg = match env_nonempty("AGENTFENCE_CONTAINER_CONFIG") {
        Some(path) => {
            let text = std::fs::read_to_string(&path)
                .map_err(|e| format!("cannot read container config {path}: {e}"))?;
            serde_json::from_str::<ContainerConfig>(&text)
                .map_err(|e| format!("invalid container config {path}: {e}"))?
        }
        None => ContainerConfig::default(),
    };

    if let Some(runtime) = env_nonempty("AGENTFENCE_CONTAINER_RUNTIME") {
        cfg.runtime = match runtime.to_ascii_lowercase().as_str() {
            "podman" => crate::container::ContainerRuntime::Podman,
            _ => crate::container::ContainerRuntime::Docker,
        };
    }
    if let Some(path) = env_nonempty("AGENTFENCE_CONTAINER_RUNTIME_PATH") {
        cfg.runtime_path = Some(path);
    }
    if let Some(image) = env_nonempty("AGENTFENCE_CONTAINER_IMAGE") {
        cfg.image = image;
    }
    if let Some(v) = env_nonempty("AGENTFENCE_CONTAINER_MAX_CPU").and_then(|v| v.parse().ok()) {
        cfg.max_cpu = v;
    }
    if let Some(v) = env_nonempty("AGENTFENCE_CONTAINER_MAX_MEMORY_MB").and_then(|v| v.parse().ok())
    {
        cfg.max_memory_mb = v;
    }
    if let Some(v) = env_nonempty("AGENTFENCE_CONTAINER_PIDS_LIMIT").and_then(|v| v.parse().ok()) {
        cfg.pids_limit = v;
    }
    if let Some(v) = env_nonempty("AGENTFENCE_CONTAINER_TIMEOUT_SECS").and_then(|v| v.parse().ok())
    {
        cfg.timeout_secs = v;
    }
    if let Some(v) = env_nonempty("AGENTFENCE_CONTAINER_RUN_AS_UID").and_then(|v| v.parse().ok()) {
        cfg.run_as_uid = v;
    }
    if let Some(v) = env_nonempty("AGENTFENCE_CONTAINER_RUN_AS_GID").and_then(|v| v.parse().ok()) {
        cfg.run_as_gid = v;
    }
    if let Some(v) = env_nonempty("AGENTFENCE_CONTAINER_NETWORK").map(|v| v == "none") {
        cfg.network_isolated = v;
    }
    if let Some(v) = env_nonempty("AGENTFENCE_CONTAINER_READ_ONLY").map(|v| v == "true") {
        cfg.read_only_fs = v;
    }
    Ok(cfg)
}

/// Select the backend once. Invalid configuration fails closed.
pub fn select_backend(mode: ExecutionMode) -> Result<Box<dyn ExecutionBackend>, ExecutionError> {
    match mode {
        ExecutionMode::Host => Ok(Box::new(HostBackend)),
        ExecutionMode::Container(config) => {
            let backend = ContainerBackend::new(config)?;
            backend.check_runtime()?;
            Ok(Box::new(backend))
        }
    }
}

/// What a finished execution produced: exit code, stdout, stderr, timed out.
type Completed = (Option<i32>, Vec<u8>, Vec<u8>, bool);

/// Run a command with a hard wall-clock limit, returning whether it timed out.
///
/// The child is waited on in a worker thread so the timeout is real; on timeout
/// the caller is responsible for stopping the underlying resource.
pub(crate) fn run_with_timeout(
    mut child: std::process::Child,
    timeout: Option<Duration>,
    mut on_timeout: impl FnMut(),
) -> Result<Completed, ExecutionError> {
    let mut stdout = child
        .stdout
        .take()
        .ok_or_else(|| ExecutionError::Io("child stdout was not captured".to_string()))?;
    let mut stderr = child
        .stderr
        .take()
        .ok_or_else(|| ExecutionError::Io("child stderr was not captured".to_string()))?;

    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut out = Vec::new();
        let mut err = Vec::new();
        let _ = stdout.read_to_end(&mut out);
        let _ = stderr.read_to_end(&mut err);
        let status = child.wait();
        let _ = tx.send((status, out, err));
    });

    match timeout {
        None => {
            let (status, out, err) = rx
                .recv()
                .map_err(|_| ExecutionError::Io("execution worker thread died".to_string()))?;
            let code = status.ok().and_then(|s| s.code());
            Ok((code, out, err, false))
        }
        Some(limit) => match rx.recv_timeout(limit) {
            Ok((status, out, err)) => {
                let code = status.ok().and_then(|s| s.code());
                Ok((code, out, err, false))
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {
                on_timeout();
                Err(ExecutionError::TimedOut(limit.as_secs()))
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => Err(ExecutionError::Io(
                "execution worker thread died".to_string(),
            )),
        },
    }
}
