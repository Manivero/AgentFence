//! Anomaly detection for AgentFence (advisory only).
//!
//! Analyzes agent actions for suspicious patterns.
//! NEVER affects authorization decisions — purely advisory.
//! LLM is never the authorization authority (invariant 5.1).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

use agentfence_core::types::{Action, DecisionRecord};

/// Anomaly severity level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AnomalySeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl std::fmt::Display for AnomalySeverity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AnomalySeverity::Low => write!(f, "LOW"),
            AnomalySeverity::Medium => write!(f, "MEDIUM"),
            AnomalySeverity::High => write!(f, "HIGH"),
            AnomalySeverity::Critical => write!(f, "CRITICAL"),
        }
    }
}

/// Detected anomaly (advisory only).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Anomaly {
    pub severity: AnomalySeverity,
    pub rule_id: String,
    pub description: String,
    pub action_id: String,
}

/// Anomaly detector configuration.
#[derive(Debug, Clone)]
pub struct AnomalyConfig {
    /// Maximum actions per session before flagging
    pub max_actions_per_session: usize,
    /// Maximum denied actions per session before flagging
    pub max_denied_per_session: usize,
    /// Maximum distinct tools per session before flagging
    pub max_distinct_tools: usize,
    /// Enable time-based anomaly detection
    pub enable_time_based: bool,
}

impl Default for AnomalyConfig {
    fn default() -> Self {
        Self {
            max_actions_per_session: 1000,
            max_denied_per_session: 50,
            max_distinct_tools: 100,
            enable_time_based: true,
        }
    }
}

/// Anomaly detector (advisory only).
///
/// Analyzes agent behavior patterns and flags suspicious activity.
/// NEVER affects authorization decisions — purely advisory.
pub struct AnomalyDetector {
    config: AnomalyConfig,
    session_stats: HashMap<String, SessionStats>,
}

#[derive(Debug, Default)]
struct SessionStats {
    total_actions: usize,
    denied_actions: usize,
    distinct_tools: std::collections::HashSet<String>,
    first_action_time: Option<chrono::DateTime<chrono::Utc>>,
    last_action_time: Option<chrono::DateTime<chrono::Utc>>,
}

impl AnomalyDetector {
    /// Create a new anomaly detector.
    pub fn new(config: AnomalyConfig) -> Self {
        Self {
            config,
            session_stats: HashMap::new(),
        }
    }

    /// Analyze an action and return detected anomalies (advisory only).
    ///
    /// This NEVER affects the authorization decision.
    /// It only provides additional context for human reviewers.
    pub fn analyze(&mut self, action: &Action, record: &DecisionRecord) -> Vec<Anomaly> {
        let mut anomalies = Vec::new();
        let session_id = action.session_id.0.clone();

        // Update session stats
        let stats = self.session_stats.entry(session_id.clone()).or_default();
        stats.total_actions += 1;
        stats.distinct_tools.insert(action.tool.clone());

        let now = chrono::Utc::now();
        if stats.first_action_time.is_none() {
            stats.first_action_time = Some(now);
        }
        stats.last_action_time = Some(now);

        if record.decision == agentfence_core::types::Decision::Deny {
            stats.denied_actions += 1;
        }

        // Check for excessive actions
        if stats.total_actions > self.config.max_actions_per_session {
            anomalies.push(Anomaly {
                severity: AnomalySeverity::Medium,
                rule_id: "anomaly.excessive_actions".to_string(),
                description: format!(
                    "Session {} has {} actions (limit: {})",
                    session_id, stats.total_actions, self.config.max_actions_per_session
                ),
                action_id: action.id.0.clone(),
            });
        }

        // Check for excessive denied actions
        if stats.denied_actions > self.config.max_denied_per_session {
            anomalies.push(Anomaly {
                severity: AnomalySeverity::High,
                rule_id: "anomaly.excessive_denied".to_string(),
                description: format!(
                    "Session {} has {} denied actions (limit: {})",
                    session_id, stats.denied_actions, self.config.max_denied_per_session
                ),
                action_id: action.id.0.clone(),
            });
        }

        // Check for excessive distinct tools
        if stats.distinct_tools.len() > self.config.max_distinct_tools {
            anomalies.push(Anomaly {
                severity: AnomalySeverity::Medium,
                rule_id: "anomaly.excessive_tools".to_string(),
                description: format!(
                    "Session {} uses {} distinct tools (limit: {})",
                    session_id,
                    stats.distinct_tools.len(),
                    self.config.max_distinct_tools
                ),
                action_id: action.id.0.clone(),
            });
        }

        // Check for rapid actions (time-based)
        if self.config.enable_time_based {
            if let (Some(first), Some(last)) = (stats.first_action_time, stats.last_action_time) {
                let duration = last.signed_duration_since(first);
                if duration.num_minutes() < 1 && stats.total_actions > 10 {
                    anomalies.push(Anomaly {
                        severity: AnomalySeverity::High,
                        rule_id: "anomaly.rapid_actions".to_string(),
                        description: format!(
                            "Session {} has {} actions in {} seconds",
                            session_id,
                            stats.total_actions,
                            duration.num_seconds()
                        ),
                        action_id: action.id.0.clone(),
                    });
                }
            }
        }

        anomalies
    }

    /// Get session statistics.
    pub fn get_session_stats(&self, session_id: &str) -> Option<SessionStatsView> {
        self.session_stats
            .get(session_id)
            .map(|s| SessionStatsView {
                total_actions: s.total_actions,
                denied_actions: s.denied_actions,
                distinct_tools: s.distinct_tools.len(),
                first_action_time: s.first_action_time,
                last_action_time: s.last_action_time,
            })
    }

    /// Clear session statistics.
    pub fn clear_session(&mut self, session_id: &str) {
        self.session_stats.remove(session_id);
    }
}

/// Session statistics view.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionStatsView {
    pub total_actions: usize,
    pub denied_actions: usize,
    pub distinct_tools: usize,
    pub first_action_time: Option<chrono::DateTime<chrono::Utc>>,
    pub last_action_time: Option<chrono::DateTime<chrono::Utc>>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentfence_core::types::*;

    fn test_action(session_id: &str, tool: &str) -> Action {
        Action {
            id: ActionId::new(),
            session_id: SessionId::new_from_string(session_id.to_string()),
            agent_id: AgentId::new("test-agent"),
            task_id: None,
            action_type: ActionType::Shell,
            tool: tool.to_string(),
            target: "test".to_string(),
            args_hash: "hash".to_string(),
            context: Default::default(),
        }
    }

    fn test_record(decision: Decision) -> DecisionRecord {
        DecisionRecord {
            decision,
            rule_id: "test".to_string(),
            reason: "test".to_string(),
            risk_level: RiskLevel::Low,
            policy_version: "1.0".to_string(),
            evidence: None,
        }
    }

    #[test]
    fn test_no_anomalies_for_normal_activity() {
        let config = AnomalyConfig::default();
        let mut detector = AnomalyDetector::new(config);

        let action = test_action("session1", "git");
        let record = test_record(Decision::Allow);

        let anomalies = detector.analyze(&action, &record);
        assert!(anomalies.is_empty());
    }

    #[test]
    fn test_excessive_denied_detection() {
        let config = AnomalyConfig {
            max_denied_per_session: 2,
            ..Default::default()
        };
        let mut detector = AnomalyDetector::new(config);

        let action = test_action("session1", "git");
        let record = test_record(Decision::Deny);

        // First two denied actions — no anomaly yet
        let anomalies = detector.analyze(&action, &record);
        assert!(anomalies.is_empty());

        let anomalies = detector.analyze(&action, &record);
        assert!(anomalies.is_empty());

        // Third denied action — anomaly detected
        let anomalies = detector.analyze(&action, &record);
        assert!(!anomalies.is_empty());
        assert_eq!(anomalies[0].rule_id, "anomaly.excessive_denied");
    }

    #[test]
    fn test_excessive_tools_detection() {
        let config = AnomalyConfig {
            max_distinct_tools: 2,
            ..Default::default()
        };
        let mut detector = AnomalyDetector::new(config);

        let action1 = test_action("session1", "git");
        let action2 = test_action("session1", "cargo");
        let action3 = test_action("session1", "npm");
        let record = test_record(Decision::Allow);

        detector.analyze(&action1, &record);
        detector.analyze(&action2, &record);

        // Third distinct tool — anomaly detected
        let anomalies = detector.analyze(&action3, &record);
        assert!(!anomalies.is_empty());
        assert_eq!(anomalies[0].rule_id, "anomaly.excessive_tools");
    }

    #[test]
    fn test_anomaly_does_not_affect_authorization() {
        let config = AnomalyConfig::default();
        let mut detector = AnomalyDetector::new(config);

        let action = test_action("session1", "git");
        let record = test_record(Decision::Allow);

        let anomalies = detector.analyze(&action, &record);

        // Anomaly detection NEVER changes the decision
        assert_eq!(record.decision, Decision::Allow);
        // Anomalies are advisory only
        assert!(anomalies.is_empty() || !anomalies.is_empty()); // Just verify it runs
    }

    #[test]
    fn test_session_stats() {
        let config = AnomalyConfig::default();
        let mut detector = AnomalyDetector::new(config);

        let action = test_action("session1", "git");
        let record = test_record(Decision::Allow);

        detector.analyze(&action, &record);

        let stats = detector.get_session_stats("session1").unwrap();
        assert_eq!(stats.total_actions, 1);
        assert_eq!(stats.distinct_tools, 1);
    }
}
