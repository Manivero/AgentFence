//! Hermes integration for AgentFence.
//!
//! Hermes is the first real integration target.
//!
//! Architecture:
//! Hermes -> AgentFence -> Resources
//!
//! Integration points:
//! - MCP: AgentFence MCP proxy sits between Hermes and MCP servers
//! - Shell: AgentFence shell gateway wraps terminal tool calls
//! - Network: AgentFence network proxy controls HTTP requests
//!
//! ## Hermes Configuration
//!
//! To integrate with AgentFence, configure Hermes to use AgentFence as:
//!
//! 1. **MCP Proxy**: Point Hermes MCP servers to AgentFence proxy
//! 2. **Shell Wrapper**: Configure Hermes to use `agentfence exec` for shell commands
//! 3. **Network Proxy**: Set HTTP_PROXY to AgentFence network proxy
//!
//! See `examples/hermes-config.yaml` for a complete example.

pub mod config;
pub mod wrapper;
