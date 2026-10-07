//! Policy Enforcement Point (PEP) for AgentFence.
//!
//! PEP interfaces, enforcement abstractions, backend interfaces,
//! decision application. Future backends: cooperative, container,
//! OpenShell, WSL, VM, Windows, Linux.

pub mod anomaly;
pub mod container;
pub mod ml_anomaly;
pub mod multi_agent;
pub mod os_enforcement;
pub mod pep;
pub mod vm;
pub mod wsl;
