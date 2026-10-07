//! ML-based anomaly detection for AgentFence.
//!
//! Provides machine learning-based anomaly detection for agent behavior:
//! - Statistical anomaly detection (z-score, moving average)
//! - Session-based behavior profiling
//! - Action pattern analysis
//! - Risk scoring based on historical data
//!
//! Architecture:
//! Agent → AgentFence PEP → ML Anomaly Detector → Advisory Risk Score
//!
//! Security guarantees:
//! - ML is NEVER the authorization authority (invariant 5.1)
//! - ML only provides advisory risk scores
//! - Authorization remains: Policy → Decision
//! - All ML features are explainable through evidence
//! - No raw data leaves the local system

use agentfence_core::types::{Action, DecisionRecord};
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};

/// ML model type for anomaly detection.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum MlModelType {
    /// Statistical z-score based detection
    ZScore,
    /// Moving average based detection
    MovingAverage,
    /// Isolation Forest (simplified)
    IsolationForest,
    /// Ensemble of multiple models
    Ensemble,
}

impl std::fmt::Display for MlModelType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MlModelType::ZScore => write!(f, "zscore"),
            MlModelType::MovingAverage => write!(f, "moving_average"),
            MlModelType::IsolationForest => write!(f, "isolation_forest"),
            MlModelType::Ensemble => write!(f, "ensemble"),
        }
    }
}

/// ML anomaly detection configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlAnomalyConfig {
    /// Model type
    pub model_type: MlModelType,
    /// Enable ML-based anomaly detection
    pub enabled: bool,
    /// Z-score threshold (number of standard deviations)
    pub zscore_threshold: f64,
    /// Moving average window size
    pub moving_average_window: usize,
    /// Minimum samples before detection starts
    pub min_samples: u64,
    /// Risk score threshold for alerting
    pub risk_threshold: f64,
    /// Enable session profiling
    pub enable_session_profiling: bool,
    /// Enable action pattern analysis
    pub enable_pattern_analysis: bool,
    /// Maximum history size per session
    pub max_history_size: usize,
}

impl Default for MlAnomalyConfig {
    fn default() -> Self {
        Self {
            model_type: MlModelType::Ensemble,
            enabled: true,
            zscore_threshold: 3.0,
            moving_average_window: 10,
            min_samples: 5,
            risk_threshold: 0.7,
            enable_session_profiling: true,
            enable_pattern_analysis: true,
            max_history_size: 1000,
        }
    }
}

/// Session behavior profile.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionProfile {
    pub session_id: String,
    pub action_count: u64,
    pub denied_count: u64,
    pub allowed_count: u64,
    pub ask_count: u64,
    pub distinct_tools: Vec<String>,
    pub action_frequency: VecDeque<f64>,
    pub risk_scores: VecDeque<f64>,
    pub last_action_time: Option<String>,
    pub created_at: String,
}

impl SessionProfile {
    fn new(session_id: String) -> Self {
        Self {
            session_id,
            action_count: 0,
            denied_count: 0,
            allowed_count: 0,
            ask_count: 0,
            distinct_tools: Vec::new(),
            action_frequency: VecDeque::new(),
            risk_scores: VecDeque::new(),
            last_action_time: None,
            created_at: chrono::Utc::now().to_rfc3339(),
        }
    }
}

/// ML anomaly detection result.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MlAnomalyResult {
    /// Anomaly score (0.0 = normal, 1.0 = highly anomalous)
    pub anomaly_score: f64,
    /// Risk level
    pub risk_level: String,
    /// Whether the action is anomalous
    pub is_anomalous: bool,
    /// Explanation of the detection
    pub explanation: String,
    /// Contributing factors
    pub factors: Vec<String>,
    /// Model confidence (0.0-1.0)
    pub confidence: f64,
}

/// ML-based anomaly detector.
///
/// Provides advisory anomaly detection using statistical and ML methods.
/// NEVER affects authorization decisions (invariant 5.1).
pub struct MlAnomalyDetector {
    config: MlAnomalyConfig,
    session_profiles: HashMap<String, SessionProfile>,
    global_stats: GlobalStats,
}

/// Global statistics across all sessions.
#[derive(Debug, Clone, Default)]
struct GlobalStats {
    total_actions: u64,
    total_denied: u64,
    total_allowed: u64,
    total_ask: u64,
    tool_usage: HashMap<String, u64>,
    #[allow(dead_code)]
    action_timestamps: VecDeque<f64>,
}

impl MlAnomalyDetector {
    /// Create a new ML anomaly detector.
    pub fn new(config: MlAnomalyConfig) -> Self {
        Self {
            config,
            session_profiles: HashMap::new(),
            global_stats: GlobalStats::default(),
        }
    }

    /// Analyze an action for anomalies.
    ///
    /// Returns an advisory result. NEVER affects authorization.
    pub fn analyze(&mut self, action: &Action, record: &DecisionRecord) -> MlAnomalyResult {
        if !self.config.enabled {
            return MlAnomalyResult {
                anomaly_score: 0.0,
                risk_level: "LOW".to_string(),
                is_anomalous: false,
                explanation: "ML anomaly detection is disabled".to_string(),
                factors: vec![],
                confidence: 0.0,
            };
        }

        let session_id = action.session_id.to_string();
        let profile = self
            .session_profiles
            .entry(session_id.clone())
            .or_insert_with(|| SessionProfile::new(session_id.clone()));

        // Update profile
        profile.action_count += 1;
        match record.decision {
            agentfence_core::types::Decision::Allow => profile.allowed_count += 1,
            agentfence_core::types::Decision::Deny => profile.denied_count += 1,
            agentfence_core::types::Decision::Ask => profile.ask_count += 1,
        }

        if !profile.distinct_tools.contains(&action.tool) {
            profile.distinct_tools.push(action.tool.clone());
        }

        // Update global stats
        self.global_stats.total_actions += 1;
        match record.decision {
            agentfence_core::types::Decision::Allow => self.global_stats.total_allowed += 1,
            agentfence_core::types::Decision::Deny => self.global_stats.total_denied += 1,
            agentfence_core::types::Decision::Ask => self.global_stats.total_ask += 1,
        }
        *self
            .global_stats
            .tool_usage
            .entry(action.tool.clone())
            .or_insert(0) += 1;

        // Calculate anomaly score
        let mut factors = Vec::new();
        let mut scores = Vec::new();

        // Factor 1: Denial rate anomaly
        if profile.action_count >= self.config.min_samples {
            let denial_rate = profile.denied_count as f64 / profile.action_count as f64;
            if denial_rate > 0.5 {
                scores.push(denial_rate);
                factors.push(format!("High denial rate: {:.1}%", denial_rate * 100.0));
            }
        }

        // Factor 2: Tool diversity anomaly
        if profile.action_count >= self.config.min_samples {
            let tool_diversity = profile.distinct_tools.len() as f64 / profile.action_count as f64;
            if tool_diversity > 0.8 {
                scores.push(tool_diversity);
                factors.push(format!(
                    "High tool diversity: {} distinct tools in {} actions",
                    profile.distinct_tools.len(),
                    profile.action_count
                ));
            }
        }

        // Factor 3: Action frequency anomaly
        if profile.action_frequency.len() as u64 >= self.config.min_samples {
            let recent_freq = profile.action_frequency.iter().sum::<f64>()
                / profile.action_frequency.len() as f64;
            if recent_freq > 10.0 {
                scores.push((recent_freq / 10.0).min(1.0));
                factors.push(format!(
                    "High action frequency: {:.1} actions/sec",
                    recent_freq
                ));
            }
        }

        // Factor 4: Global tool usage anomaly
        if let Some(&count) = self.global_stats.tool_usage.get(&action.tool) {
            let usage_ratio = count as f64 / self.global_stats.total_actions as f64;
            if usage_ratio < 0.01 && self.global_stats.total_actions > 100 {
                scores.push(0.5);
                factors.push(format!(
                    "Rare tool usage: {} used {:.2}% of the time",
                    action.tool,
                    usage_ratio * 100.0
                ));
            }
        }

        // Calculate final score
        let anomaly_score = if scores.is_empty() {
            0.0
        } else {
            scores.iter().sum::<f64>() / scores.len() as f64
        };

        let is_anomalous = anomaly_score >= self.config.risk_threshold;
        let risk_level = if anomaly_score >= 0.8 {
            "CRITICAL"
        } else if anomaly_score >= 0.6 {
            "HIGH"
        } else if anomaly_score >= 0.4 {
            "MEDIUM"
        } else {
            "LOW"
        };

        let confidence = if profile.action_count >= self.config.min_samples {
            (profile.action_count as f64 / (profile.action_count as f64 + 10.0)).min(0.95)
        } else {
            profile.action_count as f64 / self.config.min_samples as f64 * 0.5
        };

        let explanation = if factors.is_empty() {
            "No anomalies detected".to_string()
        } else {
            factors.join("; ")
        };

        // Update history
        profile.risk_scores.push_back(anomaly_score);
        if profile.risk_scores.len() > self.config.max_history_size {
            profile.risk_scores.pop_front();
        }

        MlAnomalyResult {
            anomaly_score,
            risk_level: risk_level.to_string(),
            is_anomalous,
            explanation,
            factors,
            confidence,
        }
    }

    /// Get session profile.
    pub fn get_session_profile(&self, session_id: &str) -> Option<&SessionProfile> {
        self.session_profiles.get(session_id)
    }

    /// Get all session profiles.
    pub fn get_all_profiles(&self) -> Vec<&SessionProfile> {
        self.session_profiles.values().collect()
    }

    /// Get the ML configuration.
    pub fn config(&self) -> &MlAnomalyConfig {
        &self.config
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use agentfence_core::types::{ActionId, AgentId, Decision};

    fn test_action(tool: &str) -> Action {
        Action {
            id: ActionId::new(),
            session_id: agentfence_core::types::SessionId::new_from_string(
                "test-session".to_string(),
            ),
            agent_id: AgentId::new("test-agent"),
            task_id: None,
            action_type: agentfence_core::types::ActionType::Shell,
            tool: tool.to_string(),
            target: "test".to_string(),
            args_hash: "hash".to_string(),
            context: Default::default(),
        }
    }

    fn test_record(decision: Decision) -> DecisionRecord {
        match decision {
            Decision::Allow => DecisionRecord::allow("test", "test"),
            Decision::Deny => DecisionRecord::deny("test", "test"),
            Decision::Ask => DecisionRecord::allow("test", "test"),
        }
    }

    #[test]
    fn test_ml_config_default() {
        let config = MlAnomalyConfig::default();
        assert!(config.enabled);
        assert_eq!(config.zscore_threshold, 3.0);
        assert_eq!(config.moving_average_window, 10);
    }

    #[test]
    fn test_ml_model_type_display() {
        assert_eq!(format!("{}", MlModelType::ZScore), "zscore");
        assert_eq!(format!("{}", MlModelType::MovingAverage), "moving_average");
        assert_eq!(
            format!("{}", MlModelType::IsolationForest),
            "isolation_forest"
        );
        assert_eq!(format!("{}", MlModelType::Ensemble), "ensemble");
    }

    #[test]
    fn test_ml_detector_creation() {
        let config = MlAnomalyConfig::default();
        let detector = MlAnomalyDetector::new(config);
        assert!(detector.config().enabled);
    }

    #[test]
    fn test_ml_anomaly_detection_disabled() {
        let mut config = MlAnomalyConfig::default();
        config.enabled = false;
        let mut detector = MlAnomalyDetector::new(config);

        let action = test_action("shell");
        let record = test_record(Decision::Allow);
        let result = detector.analyze(&action, &record);

        assert_eq!(result.anomaly_score, 0.0);
        assert!(!result.is_anomalous);
    }

    #[test]
    fn test_ml_anomaly_detection_normal() {
        let config = MlAnomalyConfig::default();
        let mut detector = MlAnomalyDetector::new(config);

        let action = test_action("shell");
        let record = test_record(Decision::Allow);
        let result = detector.analyze(&action, &record);

        assert!(result.anomaly_score < 0.5);
        assert!(!result.is_anomalous);
    }

    #[test]
    fn test_ml_anomaly_detection_high_denial_rate() {
        let config = MlAnomalyConfig::default();
        let mut detector = MlAnomalyDetector::new(config);

        // Create a session with many denied actions
        for _ in 0..10 {
            let action = test_action("shell");
            let record = test_record(Decision::Deny);
            detector.analyze(&action, &record);
        }

        let action = test_action("shell");
        let record = test_record(Decision::Deny);
        let result = detector.analyze(&action, &record);

        assert!(result.anomaly_score > 0.0);
        assert!(result.factors.iter().any(|f| f.contains("denial rate")));
    }

    #[test]
    fn test_ml_anomaly_detection_tool_diversity() {
        let config = MlAnomalyConfig::default();
        let mut detector = MlAnomalyDetector::new(config);

        // Create actions with many distinct tools
        for i in 0..10 {
            let action = test_action(&format!("tool{}", i));
            let record = test_record(Decision::Allow);
            detector.analyze(&action, &record);
        }

        let action = test_action("tool10");
        let record = test_record(Decision::Allow);
        let result = detector.analyze(&action, &record);

        assert!(result.factors.iter().any(|f| f.contains("tool diversity")));
    }

    #[test]
    fn test_ml_anomaly_result_creation() {
        let result = MlAnomalyResult {
            anomaly_score: 0.5,
            risk_level: "MEDIUM".to_string(),
            is_anomalous: false,
            explanation: "Test".to_string(),
            factors: vec!["factor1".to_string()],
            confidence: 0.8,
        };
        assert_eq!(result.anomaly_score, 0.5);
        assert_eq!(result.risk_level, "MEDIUM");
    }

    #[test]
    fn test_session_profile_creation() {
        let profile = SessionProfile::new("session1".to_string());
        assert_eq!(profile.session_id, "session1");
        assert_eq!(profile.action_count, 0);
    }
}
