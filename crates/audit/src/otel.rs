//! OpenTelemetry export for AgentFence audit events.
//!
//! Sends audit events to OpenTelemetry collectors via OTLP/HTTP.
//! Never sends raw secrets — only fingerprints and metadata.

use serde_json::json;
use tracing::{debug, error, warn};

use crate::event::AuditEvent;

/// OpenTelemetry exporter configuration.
#[derive(Debug, Clone)]
pub struct OtelConfig {
    /// OTLP HTTP endpoint (e.g., "http://localhost:4318/v1/traces")
    pub endpoint: String,
    /// Maximum retry attempts
    pub max_retries: u32,
    /// Timeout in seconds
    pub timeout_secs: u64,
    /// Service name for telemetry
    pub service_name: String,
}

/// OpenTelemetry exporter for audit events.
pub struct OtelExporter {
    config: OtelConfig,
}

impl OtelExporter {
    /// Create a new OpenTelemetry exporter.
    pub fn new(config: OtelConfig) -> Self {
        Self { config }
    }

    /// Export an audit event to OpenTelemetry.
    ///
    /// Returns true if the event was exported successfully.
    /// Never sends raw secrets — only fingerprints and metadata.
    pub fn export_event(&self, event: &AuditEvent) -> bool {
        let payload = self.build_otlp_payload(event);

        for attempt in 0..self.config.max_retries {
            match self.send_otlp(&payload) {
                Ok(_) => {
                    debug!(
                        "OTLP event exported successfully on attempt {}",
                        attempt + 1
                    );
                    return true;
                }
                Err(e) => {
                    warn!("OTLP export attempt {} failed: {}", attempt + 1, e);
                    if attempt < self.config.max_retries - 1 {
                        std::thread::sleep(std::time::Duration::from_secs(1));
                    }
                }
            }
        }

        error!(
            "Failed to export OTLP event after {} attempts",
            self.config.max_retries
        );
        false
    }

    /// Build OTLP/HTTP JSON payload.
    ///
    /// Never includes raw secrets — only fingerprints and metadata.
    fn build_otlp_payload(&self, event: &AuditEvent) -> serde_json::Value {
        json!({
            "resourceSpans": [{
                "resource": {
                    "attributes": [
                        {
                            "key": "service.name",
                            "value": { "stringValue": self.config.service_name }
                        }
                    ]
                },
                "scopeSpans": [{
                    "scope": {
                        "name": "agentfence.audit",
                        "version": "1.0.0"
                    },
                    "spans": [{
                        "traceId": event.session_id.0,
                        "spanId": event.event_id,
                        "name": format!("{}.{}", event.action_type, event.tool),
                        "startTimeUnixNano": event.timestamp.timestamp_nanos_opt().unwrap_or(0),
                        "endTimeUnixNano": event.timestamp.timestamp_nanos_opt().unwrap_or(0),
                        "attributes": [
                            {
                                "key": "agentfence.session_id",
                                "value": { "stringValue": event.session_id.0 }
                            },
                            {
                                "key": "agentfence.agent_id",
                                "value": { "stringValue": event.agent_id.0 }
                            },
                            {
                                "key": "agentfence.action_type",
                                "value": { "stringValue": event.action_type }
                            },
                            {
                                "key": "agentfence.tool",
                                "value": { "stringValue": event.tool }
                            },
                            {
                                "key": "agentfence.decision",
                                "value": { "stringValue": format!("{:?}", event.decision) }
                            },
                            {
                                "key": "agentfence.risk_level",
                                "value": { "stringValue": format!("{:?}", event.risk_level) }
                            },
                            {
                                "key": "agentfence.rule_id",
                                "value": { "stringValue": event.rule_id }
                            },
                            {
                                "key": "agentfence.policy_version",
                                "value": { "stringValue": event.policy_version }
                            },
                            {
                                "key": "agentfence.args_hash",
                                "value": { "stringValue": event.args_hash }
                            }
                        ]
                    }]
                }]
            }]
        })
    }

    /// Send OTLP payload via HTTP.
    fn send_otlp(&self, payload: &serde_json::Value) -> Result<(), String> {
        let client = reqwest::blocking::Client::builder()
            .timeout(std::time::Duration::from_secs(self.config.timeout_secs))
            .build()
            .map_err(|e| format!("Failed to build client: {}", e))?;

        let response = client
            .post(&self.config.endpoint)
            .header("Content-Type", "application/json")
            .json(payload)
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
    fn test_otel_payload_no_raw_secrets() {
        let config = OtelConfig {
            endpoint: "http://localhost:4318/v1/traces".to_string(),
            max_retries: 1,
            timeout_secs: 1,
            service_name: "agentfence".to_string(),
        };
        let exporter = OtelExporter::new(config);

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

        let payload = exporter.build_otlp_payload(&event);
        let payload_str = payload.to_string();

        // Verify raw secret is not in payload
        assert!(!payload_str.contains("ghp_1234567890abcdef"));
        // Verify hash is in payload
        assert!(payload_str.contains("hash123"));
    }

    #[test]
    fn test_otel_config_creation() {
        let config = OtelConfig {
            endpoint: "http://otel-collector:4318/v1/traces".to_string(),
            max_retries: 3,
            timeout_secs: 10,
            service_name: "agentfence-prod".to_string(),
        };
        let exporter = OtelExporter::new(config);
        assert_eq!(exporter.config.max_retries, 3);
        assert_eq!(exporter.config.timeout_secs, 10);
        assert_eq!(exporter.config.service_name, "agentfence-prod");
    }
}
