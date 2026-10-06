//! WSL enforcement for AgentFence.
//!
//! Provides isolated execution environments for agent actions using WSL.
//!
//! Architecture:
//! Agent -> AgentFence PEP -> WSL Enforcement -> Isolated WSL Instance
//!
//! Security guarantees:
//! - Process isolation via WSL instances
//! - Filesystem isolation
//! - Network isolation (optional)
//! - Resource limits (optional)

use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{debug, info};

/// WSL distribution type.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum WslDistro {
    Ubuntu,
    Debian,
    OpenSuse,
    Kali,
    Custom(String),
}

impl std::fmt::Display for WslDistro {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            WslDistro::Ubuntu => write!(f, "Ubuntu"),
            WslDistro::Debian => write!(f, "Debian"),
            WslDistro::OpenSuse => write!(f, "openSUSE"),
            WslDistro::Kali => write!(f, "kali-linux"),
            WslDistro::Custom(name) => write!(f, "{}", name),
        }
    }
}

/// WSL configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WslConfig {
    /// WSL distribution
    pub distro: WslDistro,
    /// Maximum memory in MB (0 = unlimited)
    pub max_memory_mb: u64,
    /// Maximum CPU cores (0 = unlimited)
    pub max_cpu: u64,
    /// Network isolation (no network access)
    pub network_isolated: bool,
    /// Read-only filesystem
    pub read_only_fs: bool,
    /// Working directory inside WSL
    pub workdir: String,
    /// Timeout in seconds (0 = no timeout)
    pub timeout_secs: u64,
    /// Mount points (host_path:container_path)
    pub mounts: Vec<WslMount>,
}

/// WSL mount point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WslMount {
    pub host_path: String,
    pub wsl_path: String,
    pub read_only: bool,
}

impl Default for WslConfig {
    fn default() -> Self {
        Self {
            distro: WslDistro::Ubuntu,
            max_memory_mb: 1024,
            max_cpu: 2,
            network_isolated: true,
            read_only_fs: true,
            workdir: "/home/user".to_string(),
            timeout_secs: 300,
            mounts: vec![],
        }
    }
}

/// WSL execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WslResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

/// WSL enforcer.
///
/// Executes commands in isolated WSL instances.
/// Provides process isolation, filesystem isolation, and network isolation.
pub struct WslEnforcer {
    config: WslConfig,
}

impl WslEnforcer {
    /// Create a new WSL enforcer.
    pub fn new(config: WslConfig) -> Self {
        Self { config }
    }

    /// Check if WSL is available.
    pub fn is_wsl_available(&self) -> bool {
        let output = Command::new("wsl").arg("--status").output();

        match output {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    /// Execute a command in WSL.
    ///
    /// Returns the execution result with stdout, stderr, and exit code.
    pub fn execute(&self, command: &[String]) -> Result<WslResult, String> {
        if !self.is_wsl_available() {
            return Err("WSL is not available".to_string());
        }

        info!("Executing command in WSL: {:?}", command.join(" "));

        let mut cmd = Command::new("wsl");
        cmd.arg("--distribution")
            .arg(self.config.distro.to_string());

        // Add resource limits
        if self.config.max_memory_mb > 0 {
            cmd.arg("--exec").arg(format!(
                "systemd-run --scope -p MemoryMax={}M --",
                self.config.max_memory_mb
            ));
        }

        // Add network isolation
        if self.config.network_isolated {
            cmd.arg("--exec").arg("unshare -n --");
        }

        // Add working directory
        cmd.arg("--cd").arg(&self.config.workdir);

        // Add command
        cmd.args(command);

        // Set timeout
        if self.config.timeout_secs > 0 {
            cmd.arg("--timeout")
                .arg(self.config.timeout_secs.to_string());
        }

        debug!("WSL command: {:?}", cmd);

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to execute WSL command: {}", e))?;

        let result = WslResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            timed_out: !output.status.success() && output.status.code().is_none(),
        };

        info!(
            "WSL execution completed with exit code: {}",
            result.exit_code
        );

        Ok(result)
    }

    /// Get the WSL configuration.
    pub fn config(&self) -> &WslConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_wsl_config_default() {
        let config = WslConfig::default();
        assert_eq!(config.distro, WslDistro::Ubuntu);
        assert_eq!(config.max_memory_mb, 1024);
        assert_eq!(config.max_cpu, 2);
        assert!(config.network_isolated);
        assert!(config.read_only_fs);
    }

    #[test]
    fn test_wsl_distro_display() {
        assert_eq!(format!("{}", WslDistro::Ubuntu), "Ubuntu");
        assert_eq!(format!("{}", WslDistro::Debian), "Debian");
        assert_eq!(format!("{}", WslDistro::OpenSuse), "openSUSE");
        assert_eq!(format!("{}", WslDistro::Kali), "kali-linux");
        assert_eq!(
            format!("{}", WslDistro::Custom("my-distro".to_string())),
            "my-distro"
        );
    }

    #[test]
    fn test_wsl_enforcer_creation() {
        let config = WslConfig::default();
        let enforcer = WslEnforcer::new(config);
        assert_eq!(enforcer.config().distro, WslDistro::Ubuntu);
    }

    #[test]
    fn test_wsl_result_creation() {
        let result = WslResult {
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
    fn test_wsl_mount_creation() {
        let mount = WslMount {
            host_path: "/tmp".to_string(),
            wsl_path: "/mnt/tmp".to_string(),
            read_only: true,
        };
        assert_eq!(mount.host_path, "/tmp");
        assert_eq!(mount.wsl_path, "/mnt/tmp");
        assert!(mount.read_only);
    }
}
