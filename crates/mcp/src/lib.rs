//! MCP gateway for AgentFence.
//!
//! MCP transport, proxy, request parsing, tool-call extraction,
//! request normalization, forwarding. Policy evaluation belongs to PDP.

pub mod http_transport;
pub mod proxy;
pub mod types;
