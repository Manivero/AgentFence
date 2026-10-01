//! Shell gateway for AgentFence.
//!
//! Command representation, command parsing, execution,
//! environment metadata, result capture.
//! Never use naive substring checks as the security model.

pub mod command;
pub mod gateway;
