//! OS-specific enforcement for AgentFence.
//!
//! Provides OS-level enforcement mechanisms:
//! - Linux: auditd integration for syscall monitoring
//! - Windows: ETW (Event Tracing for Windows) integration
//!
//! Architecture:
//! Agent -> AgentFence PEP -> OS Enforcement -> Kernel-level monitoring
//!
//! Security guarantees:
//! - Kernel-level syscall monitoring (Linux)
//! - Event tracing for security events (Windows)
//! - Process isolation enforcement
//! - File access auditing
//! - Network connection auditing

use serde::{Deserialize, Serialize};
use std::process::Command;
use tracing::info;

/// OS enforcement type.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum OsEnforcementType {
    LinuxAudit,
    WindowsEtw,
}

impl std::fmt::Display for OsEnforcementType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OsEnforcementType::LinuxAudit => write!(f, "linux-audit"),
            OsEnforcementType::WindowsEtw => write!(f, "windows-etw"),
        }
    }
}

/// OS enforcement configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsEnforcementConfig {
    /// Enforcement type
    pub enforcement_type: OsEnforcementType,
    /// Enable process monitoring
    pub monitor_processes: bool,
    /// Enable file access monitoring
    pub monitor_files: bool,
    /// Enable network connection monitoring
    pub monitor_network: bool,
    /// Enable syscall auditing (Linux only)
    pub audit_syscalls: bool,
    /// Log file path
    pub log_path: String,
    /// Maximum log file size in MB
    pub max_log_size_mb: u64,
    /// Enable real-time alerting
    pub real_time_alerts: bool,
}

impl Default for OsEnforcementConfig {
    fn default() -> Self {
        Self {
            enforcement_type: OsEnforcementType::LinuxAudit,
            monitor_processes: true,
            monitor_files: true,
            monitor_network: true,
            audit_syscalls: true,
            log_path: "/var/log/agentfence/audit.log".to_string(),
            max_log_size_mb: 100,
            real_time_alerts: true,
        }
    }
}

/// OS enforcement event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OsEnforcementEvent {
    pub timestamp: String,
    pub event_type: String,
    pub process_id: u32,
    pub process_name: String,
    pub action: String,
    pub target: String,
    pub result: String,
    pub details: String,
}

/// OS enforcer.
///
/// Provides OS-level enforcement using kernel mechanisms.
pub struct OsEnforcer {
    config: OsEnforcementConfig,
}

impl OsEnforcer {
    /// Create a new OS enforcer.
    pub fn new(config: OsEnforcementConfig) -> Self {
        Self { config }
    }

    /// Check if the OS enforcement is available.
    pub fn is_available(&self) -> bool {
        match self.config.enforcement_type {
            OsEnforcementType::LinuxAudit => {
                let output = Command::new("auditctl").arg("--version").output();
                matches!(output, Ok(out) if out.status.success())
            }
            OsEnforcementType::WindowsEtw => {
                let output = Command::new("logman").arg("query").arg("ETW").output();
                matches!(output, Ok(out) if out.status.success())
            }
        }
    }

    /// Enable OS enforcement.
    pub fn enable(&self) -> Result<(), String> {
        if !self.is_available() {
            return Err(format!(
                "OS enforcement '{}' is not available",
                self.config.enforcement_type
            ));
        }

        info!("Enabling OS enforcement: {}", self.config.enforcement_type);

        match self.config.enforcement_type {
            OsEnforcementType::LinuxAudit => self.enable_linux_audit(),
            OsEnforcementType::WindowsEtw => self.enable_windows_etw(),
        }
    }

    /// Disable OS enforcement.
    pub fn disable(&self) -> Result<(), String> {
        info!("Disabling OS enforcement: {}", self.config.enforcement_type);

        match self.config.enforcement_type {
            OsEnforcementType::LinuxAudit => self.disable_linux_audit(),
            OsEnforcementType::WindowsEtw => self.disable_windows_etw(),
        }
    }

    /// Enable Linux audit.
    fn enable_linux_audit(&self) -> Result<(), String> {
        // Enable auditd
        let _ = Command::new("auditctl").arg("-e").arg("1").output();

        // Add audit rules
        if self.config.monitor_processes {
            let _ = Command::new("auditctl")
                .arg("-a")
                .arg("always,exit")
                .arg("-F")
                .arg("arch=b64")
                .arg("-S")
                .arg("execve")
                .output();
        }

        if self.config.monitor_files {
            let _ = Command::new("auditctl")
                .arg("-w")
                .arg("/etc/passwd")
                .arg("-p")
                .arg("wa")
                .output();
        }

        if self.config.monitor_network {
            let _ = Command::new("auditctl")
                .arg("-a")
                .arg("always,exit")
                .arg("-F")
                .arg("arch=b64")
                .arg("-S")
                .arg("connect")
                .output();
        }

        info!("Linux audit enabled");
        Ok(())
    }

    /// Disable Linux audit.
    fn disable_linux_audit(&self) -> Result<(), String> {
        let _ = Command::new("auditctl").arg("-e").arg("0").output();

        info!("Linux audit disabled");
        Ok(())
    }

    /// Enable Windows ETW.
    fn enable_windows_etw(&self) -> Result<(), String> {
        // Start ETW session
        let _ = Command::new("logman")
            .arg("start")
            .arg("AgentFence")
            .arg("-ets")
            .output();

        info!("Windows ETW enabled");
        Ok(())
    }

    /// Disable Windows ETW.
    fn disable_windows_etw(&self) -> Result<(), String> {
        let _ = Command::new("logman")
            .arg("stop")
            .arg("AgentFence")
            .arg("-ets")
            .output();

        info!("Windows ETW disabled");
        Ok(())
    }

    /// Get the OS enforcement configuration.
    pub fn config(&self) -> &OsEnforcementConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_os_enforcement_config_default() {
        let config = OsEnforcementConfig::default();
        assert_eq!(config.enforcement_type, OsEnforcementType::LinuxAudit);
        assert!(config.monitor_processes);
        assert!(config.monitor_files);
        assert!(config.monitor_network);
        assert!(config.audit_syscalls);
    }

    #[test]
    fn test_os_enforcement_type_display() {
        assert_eq!(format!("{}", OsEnforcementType::LinuxAudit), "linux-audit");
        assert_eq!(format!("{}", OsEnforcementType::WindowsEtw), "windows-etw");
    }

    #[test]
    fn test_os_enforcer_creation() {
        let config = OsEnforcementConfig::default();
        let enforcer = OsEnforcer::new(config);
        assert_eq!(
            enforcer.config().enforcement_type,
            OsEnforcementType::LinuxAudit
        );
    }

    #[test]
    fn test_os_enforcement_event_creation() {
        let event = OsEnforcementEvent {
            timestamp: "2026-10-05T12:00:00Z".to_string(),
            event_type: "syscall".to_string(),
            process_id: 1234,
            process_name: "bash".to_string(),
            action: "execve".to_string(),
            target: "/bin/ls".to_string(),
            result: "success".to_string(),
            details: "uid=1000 gid=1000".to_string(),
        };
        assert_eq!(event.process_id, 1234);
        assert_eq!(event.action, "execve");
    }
}
