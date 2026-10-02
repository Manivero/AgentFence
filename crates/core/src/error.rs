//! Core error types for AgentFence.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum AgentFenceError {
    #[error("policy error: {0}")]
    Policy(String),

    #[error("validation error: {0}")]
    Validation(String),

    #[error("audit error: {0}")]
    Audit(String),

    #[error("approval error: {0}")]
    Approval(String),

    #[error("enforcement error: {0}")]
    Enforcement(String),

    #[error("secret error: {0}")]
    Secret(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("YAML error: {0}")]
    Yaml(#[from] serde_yaml::Error),
    #[error("Database error: {0}")]
    Database(#[from] rusqlite::Error),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("unauthorized: {0}")]
    Unauthorized(String),

    #[error("internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, AgentFenceError>;
