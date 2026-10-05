//! SIEM integration for AgentFence.
//!
//! Sends audit events to external SIEM systems via HTTP webhook.
//! Never sends raw secrets — only fingerprints and metadata.

use serde_json::json;
use tracing::{debug, error, warn};

use crate::event::AuditEvent;

/// SIEM webhook configuration.
#[derive(Debug, Clone)]
pub struct SiemConfig {
    /// Webhook URL
    pub url: String,
    /// Authentication header (optional)
    pub auth_header: Option<String>,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Timeout in seconds
    pub timeout_secs: u64,
}

/// SIEM webhook sender.
pub struct SiemSender {
    config: SiemConfig,
}

impl SiemSender {
    /// Create a new SIEM sender.
    pub fn new(config: SiemConfig) -> Self {
        Self { config }
    }

    /// Send an audit event to the SIEM webhook.
    ///
    /// Returns true if the event was sent successfully.
    /// Never sends raw secrets — only fingerprints and metadata.
    pub fn send_event(&self, event: &AuditEvent) -> bool {
        let payload = self.build_payload(event);

        for attempt in 0..self.config.max_retries {
            match self.send_webhook(&payload) {
                Ok(_) => {
                    debug!("SIEM event sent successfully on attempt {}", attempt + 1);
                    return true;
                }
                Err(e) => {
                    warn!("SIEM webhook attempt {} failed: {}", attempt + 1, e);
                    if attempt < self.config.max_retries - 1 {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                }
            }
        }

        error!(
            "Failed to send SIEM event after {} attempts",
            self.config.max_retries
        );
        false
    }

    /// Build JSON payload for SIEM webhook.
    ///
    /// Never includes raw secrets — only fingerprints and metadata.
    fn build_payload(&self, event: &AuditEvent) -> serde_json::Value {
        json!({
            "event_id": event.event_id,
            "session_id": event.session_id.0,
            "agent_id": event.agent_id.0,
            "task_id": event.task_id.as_ref().map(|t| t.0.clone()),
            "action_id": event.action_id.0,
            "parent_action_id": event.parent_action_id.as_ref().map(|a| a.0.clone()),
            "timestamp": event.timestamp.to_rfc3339(),
            "action_type": event.action_type,
            "tool": event.tool,
            "args_hash": event.args_hash,
            "decision": format!("{:?}", event.decision),
            "risk_level": format!("{:?}", event.risk_level),
            "rule_id": event.rule_id,
            "policy_version": event.policy_version,
            "previous_hash": event.previous_hash,
            "current_hash": event.current_hash,
        })
    }

    /// Send webhook request.
    fn send_webhook(&self, payload: &serde_json::Value) -> Result<(), String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(self.config.timeout_secs))
            .build()
            .map_err(|e| format!("Failed to build client: {}", e))?;

        let mut request = client
            .post(&self.config.url)
            .header("Content-Type", "application/json")
            .json(payload);

        if let Some(ref auth) = self.config.auth_header {
            request = request.header("Authorization", auth);
        }

        let response = request
            .send()
            .map_err(|e| format!("Request failed: {}", e))?;

        if response.status().is_success() {
            Ok(())
        } else {
            Err(format!("HTTP {}", response.status()))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentfence_core::types::*;

    #[test]
    fn test_siem_payload_no_raw_secrets() {
        let config = SiemConfig {
            url: "http://localhost:9999".to_string(),
            auth_header: None,
            max_retries: 1,
            timeout_secs: 1,
        };
        let sender = SiemSender::new(config);

        let event = AuditEvent::new(
            SessionId::new(),
            AgentId::new("test-agent"),
            None,
            ActionId::new(),
            None,
            "shell",
            "echo",
            "ghp_1234567890abcdef",
            "hash123",
            Decision::Allow,
            RiskLevel::Low,
            "rule1",
            "1.0",
            "",
            "",
        );

        let payload = sender.build_payload(&event);
        let payload_str = payload.to_string();

        // Verify raw secret is not in payload
        assert!(!payload_str.contains("ghp_1234567890abcdef"));
        // Verify hash is in payload
        assert!(payload_str.contains("hash123"));
    }

    #[test]
    fn test_siem_config_creation() {
        let config = SiemConfig {
            url: "https://siem.example.com/webhook".to_string(),
            auth_header: Some("Bearer token123".to_string()),
            max_retries: 3,
            timeout_secs: 10,
        };
        let sender = SiemSender::new(config);
        assert_eq!(sender.config.max_retries, 3);
        assert_eq!(sender.config.timeout_secs, 10);
    }
}
