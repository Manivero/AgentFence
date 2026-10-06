//! Policy engine for AgentFence.
//!
//! YAML parsing, validation, typed policy model, rule matching,
//! priority resolution, PDP, decision explanation.
//! Must **not** execute actions. Only decides.

pub mod federated_policy;
pub mod model;
pub mod parser;
pub mod pdp;
pub mod plugin;
