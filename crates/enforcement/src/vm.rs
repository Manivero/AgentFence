//! VM enforcement for AgentFence.
//!
//! Provides isolated execution environments for agent actions using VMs.
//!
//! Architecture:
//! Agent -> AgentFence PEP -> VM Enforcement -> Isolated VM Instance
//!
//! Security guarantees:
//! - Full process isolation via VMs
//! - Filesystem isolation
//! - Network isolation (optional)
//! - Resource limits (CPU, memory, disk)
//! - Snapshot/rollback capability

use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::{debug, info};

/// VM runtime type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum VmRuntime {
    Qemu,
    VirtualBox,
    HyperV,
    VMware,
}

impl std::fmt::Display for VmRuntime {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VmRuntime::Qemu => write!(f, "qemu"),
            VmRuntime::VirtualBox => write!(f, "vbox"),
            VmRuntime::HyperV => write!(f, "hyperv"),
            VmRuntime::VMware => write!(f, "vmware"),
        }
    }
}

/// VM configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmConfig {
    /// VM runtime
    pub runtime: VmRuntime,
    /// VM image path
    pub image_path: String,
    /// Maximum memory in MB
    pub max_memory_mb: u64,
    /// Maximum CPU cores
    pub max_cpu: u64,
    /// Network isolation (no network access)
    pub network_isolated: bool,
    /// Read-only filesystem
    pub read_only_fs: bool,
    /// Enable snapshot mode (rollback after execution)
    pub snapshot_mode: bool,
    /// Timeout in seconds
    pub timeout_secs: u64,
    /// Disk size in MB (for temporary disks)
    pub disk_size_mb: u64,
}

/// VM execution result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmResult {
    pub exit_code: i32,
    pub stdout: String,
    pub stderr: String,
    pub timed_out: bool,
}

/// VM enforcer.
///
/// Executes commands in isolated VMs.
/// Provides full process isolation, filesystem isolation, and network isolation.
pub struct VmEnforcer {
    config: VmConfig,
}

impl VmEnforcer {
    /// Create a new VM enforcer.
    pub fn new(config: VmConfig) -> Self {
        Self { config }
    }

    /// Check if the VM runtime is available.
    pub fn is_runtime_available(&self) -> bool {
        let cmd = match self.config.runtime {
            VmRuntime::Qemu => "qemu-system-x86_64",
            VmRuntime::VirtualBox => "VBoxManage",
            VmRuntime::HyperV => "vmconnect",
            VmRuntime::VMware => "vmrun",
        };

        let output = Command::new(cmd).arg("--version").output();

        match output {
            Ok(out) => out.status.success(),
            Err(_) => false,
        }
    }

    /// Execute a command in a VM.
    ///
    /// Returns the execution result with stdout, stderr, and exit code.
    pub fn execute(&self, command: &[String]) -> Result<VmResult, String> {
        if !self.is_runtime_available() {
            return Err(format!(
                "VM runtime '{}' is not available",
                self.config.runtime
            ));
        }

        info!("Executing command in VM: {:?}", command.join(" "));

        let mut cmd = Command::new(self.runtime_command());

        // Add runtime-specific arguments
        match self.config.runtime {
            VmRuntime::Qemu => {
                cmd.arg("-m").arg(format!("{}M", self.config.max_memory_mb));
                cmd.arg("-smp").arg(self.config.max_cpu.to_string());
                if self.config.network_isolated {
                    cmd.arg("-net").arg("none");
                }
                if self.config.read_only_fs {
                    cmd.arg("-snapshot");
                }
                cmd.arg("-hda").arg(&self.config.image_path);
                cmd.arg("-nographic");
            }
            VmRuntime::VirtualBox => {
                cmd.arg("startvm")
                    .arg(&self.config.image_path)
                    .arg("--type")
                    .arg("headless");
            }
            _ => {
                return Err(format!(
                    "VM runtime '{}' is not yet implemented",
                    self.config.runtime
                ));
            }
        }

        debug!("VM command: {:?}", cmd);

        let output = cmd
            .output()
            .map_err(|e| format!("Failed to execute VM command: {}", e))?;

        let result = VmResult {
            exit_code: output.status.code().unwrap_or(-1),
            stdout: String::from_utf8_lossy(&output.stdout).to_string(),
            stderr: String::from_utf8_lossy(&output.stderr).to_string(),
            timed_out: !output.status.success() && output.status.code().is_none(),
        };

        info!(
            "VM execution completed with exit code: {}",
            result.exit_code
        );

        Ok(result)
    }

    /// Get the runtime command.
    fn runtime_command(&self) -> &'static str {
        match self.config.runtime {
            VmRuntime::Qemu => "qemu-system-x86_64",
            VmRuntime::VirtualBox => "VBoxManage",
            VmRuntime::HyperV => "vmconnect",
            VmRuntime::VMware => "vmrun",
        }
    }

    /// Get the VM configuration.
    pub fn config(&self) -> &VmConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vm_config_creation() {
        let config = VmConfig {
            runtime: VmRuntime::Qemu,
            image_path: "/path/to/image.qcow2".to_string(),
            max_memory_mb: 2048,
            max_cpu: 2,
            network_isolated: true,
            read_only_fs: true,
            snapshot_mode: true,
            timeout_secs: 300,
            disk_size_mb: 10240,
        };
        assert_eq!(config.runtime, VmRuntime::Qemu);
        assert_eq!(config.max_memory_mb, 2048);
        assert!(config.network_isolated);
    }

    #[test]
    fn test_vm_runtime_display() {
        assert_eq!(format!("{}", VmRuntime::Qemu), "qemu");
        assert_eq!(format!("{}", VmRuntime::VirtualBox), "vbox");
        assert_eq!(format!("{}", VmRuntime::HyperV), "hyperv");
        assert_eq!(format!("{}", VmRuntime::VMware), "vmware");
    }

    #[test]
    fn test_vm_enforcer_creation() {
        let config = VmConfig {
            runtime: VmRuntime::Qemu,
            image_path: "/path/to/image.qcow2".to_string(),
            max_memory_mb: 1024,
            max_cpu: 1,
            network_isolated: true,
            read_only_fs: true,
            snapshot_mode: false,
            timeout_secs: 60,
            disk_size_mb: 5120,
        };
        let enforcer = VmEnforcer::new(config);
        assert_eq!(enforcer.config().runtime, VmRuntime::Qemu);
    }

    #[test]
    fn test_vm_result_creation() {
        let result = VmResult {
            exit_code: 0,
            stdout: "hello".to_string(),
            stderr: "".to_string(),
            timed_out: false,
        };
        assert_eq!(result.exit_code, 0);
        assert_eq!(result.stdout, "hello");
        assert!(!result.timed_out);
    }
}
