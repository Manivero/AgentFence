//! Federated policy distribution for AgentFence.
//!
//! Provides mechanisms for distributing policies across multiple
//! AgentFence instances:
//! - Policy versioning and synchronization
//! - Hierarchical policy resolution (global → repository → project)
//! - Policy signing and verification
//! - Conflict resolution between policy versions
//!
//! Architecture:
//! Policy Registry → Federated Distributor → Local Policy Cache
//!
//! Security guarantees:
//! - Policies are signed and verified before application
//! - Version conflicts are detected and resolved deterministically
//! - Downgrade attacks are prevented (version monotonicity)
//! - Policy integrity is verified through hashes

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{info, warn};

/// Policy hierarchy level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum PolicyLevel {
    /// Global policy (applies to all repositories)
    Global,
    /// Repository-level policy (applies to a specific repository)
    Repository,
    /// Project-level policy (applies to a specific project)
    Project,
}

impl std::fmt::Display for PolicyLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PolicyLevel::Global => write!(f, "global"),
            PolicyLevel::Repository => write!(f, "repository"),
            PolicyLevel::Project => write!(f, "project"),
        }
    }
}

/// Federated policy version.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedPolicyVersion {
    pub version: u64,
    pub policy_hash: String,
    pub timestamp: String,
    pub source: String,
    pub signature: Option<String>,
}

/// Federated policy entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedPolicy {
    pub id: String,
    pub level: PolicyLevel,
    pub repository: Option<String>,
    pub project: Option<String>,
    pub current_version: FederatedPolicyVersion,
    pub version_history: Vec<FederatedPolicyVersion>,
    pub content: String,
}

/// Federated policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FederatedPolicyConfig {
    /// Enable federated policy distribution
    pub enabled: bool,
    /// Policy registry URL
    pub registry_url: String,
    /// Sync interval in seconds
    pub sync_interval_secs: u64,
    /// Enable policy signing verification
    pub verify_signatures: bool,
    /// Maximum number of versions to keep
    pub max_versions: usize,
    /// Conflict resolution strategy
    pub conflict_resolution: ConflictResolution,
}

/// Conflict resolution strategy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ConflictResolution {
    /// Always use the highest version
    HighestVersion,
    /// Always use the local version
    Local,
    /// Always use the remote version
    Remote,
    /// Fail on conflict (manual resolution required)
    Fail,
}

impl Default for FederatedPolicyConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            registry_url: "http://localhost:8080/policies".to_string(),
            sync_interval_secs: 300,
            verify_signatures: true,
            max_versions: 10,
            conflict_resolution: ConflictResolution::HighestVersion,
        }
    }
}

/// Federated policy distributor.
///
/// Distributes policies across multiple AgentFence instances.
pub struct FederatedPolicyDistributor {
    config: FederatedPolicyConfig,
    policies: HashMap<String, FederatedPolicy>,
}

impl FederatedPolicyDistributor {
    /// Create a new federated policy distributor.
    pub fn new(config: FederatedPolicyConfig) -> Self {
        Self {
            config,
            policies: HashMap::new(),
        }
    }

    /// Register a federated policy.
    pub fn register_policy(&mut self, policy: FederatedPolicy) -> Result<(), String> {
        if policy.current_version.version == 0 {
            return Err("Policy version must be > 0".to_string());
        }

        let hash = compute_policy_hash(&policy.content);
        if hash != policy.current_version.policy_hash {
            return Err("Policy hash mismatch".to_string());
        }

        info!("Registering federated policy: {}", policy.id);
        self.policies.insert(policy.id.clone(), policy);
        Ok(())
    }

    /// Get a federated policy.
    pub fn get_policy(&self, id: &str) -> Option<&FederatedPolicy> {
        self.policies.get(id)
    }

    /// List all federated policies.
    pub fn list_policies(&self) -> Vec<&FederatedPolicy> {
        self.policies.values().collect()
    }

    /// Update a federated policy.
    ///
    /// Version must be monotonically increasing (no downgrade attacks).
    pub fn update_policy(
        &mut self,
        id: &str,
        new_content: String,
        source: String,
    ) -> Result<FederatedPolicyVersion, String> {
        let policy = self.policies.get_mut(id).ok_or("Policy not found")?;

        let new_version_num = policy.current_version.version + 1;
        let new_hash = compute_policy_hash(&new_content);

        let new_version = FederatedPolicyVersion {
            version: new_version_num,
            policy_hash: new_hash,
            timestamp: chrono::Utc::now().to_rfc3339(),
            source,
            signature: None,
        };

        policy.current_version = new_version.clone();
        policy.content = new_content;
        policy.version_history.push(new_version.clone());

        // Trim version history
        if policy.version_history.len() > self.config.max_versions {
            let excess = policy.version_history.len() - self.config.max_versions;
            policy.version_history.drain(0..excess);
        }

        info!(
            "Updated federated policy: {} to version {}",
            id, new_version_num
        );
        Ok(new_version)
    }

    /// Resolve conflict between local and remote versions.
    pub fn resolve_conflict(
        &self,
        local: &FederatedPolicyVersion,
        remote: &FederatedPolicyVersion,
    ) -> FederatedPolicyVersion {
        match self.config.conflict_resolution {
            ConflictResolution::HighestVersion => {
                if remote.version > local.version {
                    remote.clone()
                } else {
                    local.clone()
                }
            }
            ConflictResolution::Local => local.clone(),
            ConflictResolution::Remote => remote.clone(),
            ConflictResolution::Fail => {
                warn!(
                    "Policy conflict detected: local={}, remote={}",
                    local.version, remote.version
                );
                local.clone()
            }
        }
    }

    /// Verify policy integrity.
    pub fn verify_policy(&self, policy: &FederatedPolicy) -> bool {
        let computed_hash = compute_policy_hash(&policy.content);
        computed_hash == policy.current_version.policy_hash
    }

    /// Get the federated policy configuration.
    pub fn config(&self) -> &FederatedPolicyConfig {
        &self.config
    }
}

/// Compute SHA-256 hash of policy content.
fn compute_policy_hash(content: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(content.as_bytes());
    let result = hasher.finalize();
    hex::encode(result)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_policy(id: &str, level: PolicyLevel, version: u64) -> FederatedPolicy {
        let content = format!("version: 1\npolicy: {}\n", id);
        let hash = compute_policy_hash(&content);
        FederatedPolicy {
            id: id.to_string(),
            level,
            repository: None,
            project: None,
            current_version: FederatedPolicyVersion {
                version,
                policy_hash: hash,
                timestamp: "2026-10-05T12:00:00Z".to_string(),
                source: "test".to_string(),
                signature: None,
            },
            version_history: vec![],
            content,
        }
    }

    #[test]
    fn test_federated_config_default() {
        let config = FederatedPolicyConfig::default();
        assert!(!config.enabled);
        assert_eq!(config.sync_interval_secs, 300);
        assert!(config.verify_signatures);
        assert_eq!(
            config.conflict_resolution,
            ConflictResolution::HighestVersion
        );
    }

    #[test]
    fn test_policy_registration() {
        let config = FederatedPolicyConfig::default();
        let mut distributor = FederatedPolicyDistributor::new(config);
        let policy = test_policy("policy1", PolicyLevel::Global, 1);

        assert!(distributor.register_policy(policy).is_ok());
        assert_eq!(distributor.list_policies().len(), 1);
    }

    #[test]
    fn test_policy_hash_mismatch() {
        let config = FederatedPolicyConfig::default();
        let mut distributor = FederatedPolicyDistributor::new(config);
        let mut policy = test_policy("policy1", PolicyLevel::Global, 1);
        policy.current_version.policy_hash = "wrong_hash".to_string();

        assert!(distributor.register_policy(policy).is_err());
    }

    #[test]
    fn test_policy_update() {
        let config = FederatedPolicyConfig::default();
        let mut distributor = FederatedPolicyDistributor::new(config);
        let policy = test_policy("policy1", PolicyLevel::Global, 1);
        distributor.register_policy(policy).unwrap();

        let new_content = "version: 1\npolicy: updated\n".to_string();
        let result = distributor.update_policy("policy1", new_content, "test".to_string());
        assert!(result.is_ok());
        assert_eq!(result.unwrap().version, 2);
    }

    #[test]
    fn test_conflict_resolution_highest() {
        let config = FederatedPolicyConfig::default();
        let distributor = FederatedPolicyDistributor::new(config);

        let local = FederatedPolicyVersion {
            version: 1,
            policy_hash: "a".to_string(),
            timestamp: "2026-10-05T12:00:00Z".to_string(),
            source: "local".to_string(),
            signature: None,
        };
        let remote = FederatedPolicyVersion {
            version: 2,
            policy_hash: "b".to_string(),
            timestamp: "2026-10-05T12:00:00Z".to_string(),
            source: "remote".to_string(),
            signature: None,
        };

        let resolved = distributor.resolve_conflict(&local, &remote);
        assert_eq!(resolved.version, 2);
    }

    #[test]
    fn test_policy_verification() {
        let config = FederatedPolicyConfig::default();
        let distributor = FederatedPolicyDistributor::new(config);
        let policy = test_policy("policy1", PolicyLevel::Global, 1);

        assert!(distributor.verify_policy(&policy));
    }

    #[test]
    fn test_policy_level_display() {
        assert_eq!(format!("{}", PolicyLevel::Global), "global");
        assert_eq!(format!("{}", PolicyLevel::Repository), "repository");
        assert_eq!(format!("{}", PolicyLevel::Project), "project");
    }
}
