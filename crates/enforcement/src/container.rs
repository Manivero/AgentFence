//! Container enforcement for AgentFence.
//!
//! Provides isolated execution environments for agent actions.
//! Uses Docker/Podman containers for process isolation.
//!
//! Architecture:
//! Agent -> AgentFence PEP -> Container Enforcement -> Isolated Container
//!
//! Security guarantees:
//! - Process isolation via containers
//! - Resource limits (CPU, memory, disk)
//! - Read-only filesystem (optional)
//! - Network isolation (optional)
//! - No privilege escalation

use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{debug, info};

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

/// Container configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// Container runtime (Docker or Podman)
    pub runtime: ContainerRuntime,
    /// Container image to use
    pub image: String,
    /// Maximum CPU cores (0 = unlimited)
    pub max_cpu: f64,
    /// Maximum memory in MB (0 = unlimited)
    pub max_memory_mb: u64,
    /// Read-only filesystem
    pub read_only_fs: bool,
    /// Network isolation (no network access)
    pub network_isolated: bool,
    /// Drop all capabilities
    pub drop_capabilities: bool,
    /// No new privileges
    pub no_new_privileges: bool,
    /// Working directory inside container
    pub workdir: String,
    /// Mount points (host_path:container_path)
    pub mounts: Vec<Mount>,
    /// Environment variables
    pub env_vars: Vec<(String, String)>,
    /// Timeout in seconds (0 = no timeout)
    pub timeout_secs: u64,
}

/// Mount point configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Mount {
    pub host_path: String,
    pub container_path: String,
    pub read_only: bool,
}

impl Default for ContainerConfig {
    fn default() -> Self {
        Self {
            runtime: ContainerRuntime::Docker,
            image: "alpine:latest".to_string(),
            max_cpu: 1.0,
            max_memory_mb: 512,
            read_only_fs: true,
            network_isolated: true,
            drop_capabilities: true,
            no_new_privileges: true,
            workdir: "/workspace".to_string(),
            mounts: vec![],
            env_vars: vec![],
            timeout_secs: 300,
        }
    }
}

/// Container execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContainerResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

/// Container enforcer.
///
/// Executes commands in isolated containers.
/// Provides process isolation, resource limits, and filesystem isolation.
pub struct ContainerEnforcer {
    config: ContainerConfig,
}

impl ContainerEnforcer {
    /// Create a new container enforcer.
    pub fn new(config: ContainerConfig) -> Self {
        Self { config }
    }

    /// Check if the container runtime is available.
    pub fn is_runtime_available(&self) -> bool {
        let output = Command::new(self.config.runtime.to_string())
            .arg("--version")
            .output();

        match output {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    /// Execute a command in a container.
    ///
    /// Returns the execution result with stdout, stderr, and exit code.
    pub fn execute(&self, command: &[String]) -> Result<ContainerResult, String> {
        if !self.is_runtime_available() {
            return Err(format!(
                "Container runtime '{}' is not available",
                self.config.runtime
            ));
        }

        info!("Executing command in container: {:?}", command.join(" "));

        let mut cmd = Command::new(self.config.runtime.to_string());
        cmd.arg("run");

        // Add resource limits
        if self.config.max_cpu > 0.0 {
            cmd.arg("--cpus").arg(self.config.max_cpu.to_string());
        }
        if self.config.max_memory_mb > 0 {
            cmd.arg("--memory")
                .arg(format!("{}m", self.config.max_memory_mb));
        }

        // Add security options
        if self.config.read_only_fs {
            cmd.arg("--read-only");
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

        // Add mounts
        for mount in &self.config.mounts {
            let mode = if mount.read_only { "ro" } else { "rw" };
            cmd.arg("-v").arg(format!(
                "{}:{}:{}",
                mount.host_path, mount.container_path, mode
            ));
        }

        // Add environment variables
        for (key, value) in &self.config.env_vars {
            cmd.arg("-e").arg(format!("{}={}", key, value));
        }

        // Add working directory
        cmd.arg("--workdir").arg(&self.config.workdir);

        // Add image and command
        cmd.arg(&self.config.image);
        cmd.args(command);

        // Set timeout
        if self.config.timeout_secs > 0 {
            cmd.arg("--timeout")
                .arg(self.config.timeout_secs.to_string());
        }

        debug!("Container command: {:?}", cmd);

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to execute container command: {}", e))?;

        let result = ContainerResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            timed_out: !output.status.success() && output.status.code().is_none(),
        };

        info!(
            "Container execution completed with exit code: {}",
            result.exit_code
        );

        Ok(result)
    }

    /// Get the container configuration.
    pub fn config(&self) -> &ContainerConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_container_config_default() {
        let config = ContainerConfig::default();
        assert_eq!(config.runtime, ContainerRuntime::Docker);
        assert_eq!(config.max_cpu, 1.0);
        assert_eq!(config.max_memory_mb, 512);
        assert!(config.read_only_fs);
        assert!(config.network_isolated);
        assert!(config.drop_capabilities);
        assert!(config.no_new_privileges);
    }

    #[test]
    fn test_container_runtime_display() {
        assert_eq!(format!("{}", ContainerRuntime::Docker), "docker");
        assert_eq!(format!("{}", ContainerRuntime::Podman), "podman");
    }

    #[test]
    fn test_container_enforcer_creation() {
        let config = ContainerConfig::default();
        let enforcer = ContainerEnforcer::new(config);
        assert_eq!(enforcer.config().runtime, ContainerRuntime::Docker);
    }

    #[test]
    fn test_container_result_creation() {
        let result = ContainerResult {
            exit_code: 0,
            stdout: "hello".to_string(),
            stderr: "".to_string(),
            timed_out: false,
        };
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "hello");
        assert!(!result.timed_out);
    }

    #[test]
    fn test_mount_creation() {
        let mount = Mount {
            host_path: "/tmp".to_string(),
            container_path: "/workspace".to_string(),
            read_only: true,
        };
        assert_eq!(mount.host_path, "/tmp");
        assert_eq!(mount.container_path, "/workspace");
        assert!(mount.read_only);
    }
}
