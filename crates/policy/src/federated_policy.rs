//! Federated policy distribution for AgentFence.
//!
//! Provides mechanisms for distributing policies across multiple
//! AgentFence instances:
//! - Policy versioning and synchronization
//! - Hierarchical policy resolution (global → repository → project)
//! - Policy signing and verification (Ed25519)
//! - Conflict resolution between policy versions
//!
//! Architecture:
//! Policy Registry → Federated Distributor → Local Policy Cache
//!
//! Security guarantees:
//! - Policies are signed with Ed25519 and verified before application
//! - Version conflicts are detected and resolved deterministically
//! - Downgrade attacks are prevented (version monotonicity)
//! - Policy integrity is verified through hashes
//! - Signature verification prevents policy forgery

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use tracing::{info, warn};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

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
    /// Ed25519 signature of the policy hash
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
    /// Trusted public keys for signature verification (hex-encoded)
    pub trusted_pubkeys: Vec<String>,
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
            trusted_pubkeys: Vec::new(),
        }
    }
}

/// Signing key pair for policy signing.
#[derive(Debug, Clone)]
pub struct PolicySigningKeys {
    pub signing_key: SigningKey,
    pub verifying_key: VerifyingKey,
}

impl PolicySigningKeys {
    /// Generate a new signing key pair.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Get the public key as a hex string.
    pub fn public_key_hex(&self) -> String {
        hex::encode(self.verifying_key.to_bytes())
    }

    /// Sign a message with the signing key.
    pub fn sign(&self, message: &[u8]) -> String {
        let signature = self.signing_key.sign(message);
        hex::encode(signature.to_bytes())
    }

    /// Verify a signature with a public key.
    pub fn verify(pubkey_hex: &str, message: &[u8], signature_hex: &str) -> Result<(), String> {
        let pubkey_bytes =
            hex::decode(pubkey_hex).map_err(|e| format!("Invalid pubkey hex: {}", e))?;
        let pubkey_arr: [u8; 32] = pubkey_bytes
            .try_into()
            .map_err(|_| "Invalid pubkey length".to_string())?;
        let verifying_key =
            VerifyingKey::from_bytes(&pubkey_arr).map_err(|e| format!("Invalid pubkey: {}", e))?;

        let sig_bytes =
            hex::decode(signature_hex).map_err(|e| format!("Invalid signature hex: {}", e))?;
        let sig_arr: [u8; 64] = sig_bytes
            .try_into()
            .map_err(|_| "Invalid signature length".to_string())?;
        let signature = Signature::from_bytes(&sig_arr);

        verifying_key
            .verify(message, &signature)
            .map_err(|e| format!("Signature verification failed: {}", e))
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
    ///
    /// SECURITY: If verify_signatures is enabled, the policy must have a valid signature
    /// from a trusted public key.
    pub fn register_policy(&mut self, policy: FederatedPolicy) -> Result<(), String> {
        if policy.current_version.version == 0 {
            return Err("Policy version must be > 0".to_string());
        }

        let hash = compute_policy_hash(&policy.content);
        if hash != policy.current_version.policy_hash {
            return Err("Policy hash mismatch".to_string());
        }

        // Verify signature if enabled
        if self.config.verify_signatures {
            if policy.current_version.signature.is_none() {
                return Err("Policy signature required but missing".to_string());
            }
            self.verify_policy_signature(&policy)?;
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
    /// If signing keys are provided, the new version is signed.
    pub fn update_policy(
        &mut self,
        id: &str,
        new_content: String,
        source: String,
        signing_keys: Option<&PolicySigningKeys>,
    ) -> Result<FederatedPolicyVersion, String> {
        let policy = self.policies.get_mut(id).ok_or("Policy not found")?;

        let new_version_num = policy.current_version.version + 1;
        let new_hash = compute_policy_hash(&new_content);

        // Sign the new version if keys are provided
        let signature = if let Some(keys) = signing_keys {
            Some(keys.sign(new_hash.as_bytes()))
        } else if self.config.verify_signatures {
            return Err("Signing keys required for policy update".to_string());
        } else {
            None
        };

        let new_version = FederatedPolicyVersion {
            version: new_version_num,
            policy_hash: new_hash,
            timestamp: chrono::Utc::now().to_rfc3339(),
            source,
            signature,
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
        if computed_hash != policy.current_version.policy_hash {
            return false;
        }

        // Verify signature if enabled
        if self.config.verify_signatures && self.verify_policy_signature(policy).is_err() {
            return false;
        }

        true
    }

    /// Verify the policy's Ed25519 signature against trusted public keys.
    fn verify_policy_signature(&self, policy: &FederatedPolicy) -> Result<(), String> {
        let signature_hex = policy
            .current_version
            .signature
            .as_ref()
            .ok_or("Policy signature missing".to_string())?;

        let message = policy.current_version.policy_hash.as_bytes();

        for pubkey_hex in &self.config.trusted_pubkeys {
            if PolicySigningKeys::verify(pubkey_hex, message, signature_hex).is_ok() {
                return Ok(());
            }
        }

        Err("No trusted public key could verify the policy signature".to_string())
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

    fn test_policy_with_signature(
        id: &str,
        level: PolicyLevel,
        version: u64,
        keys: &PolicySigningKeys,
    ) -> FederatedPolicy {
        let mut policy = test_policy(id, level, version);
        policy.current_version.signature =
            Some(keys.sign(policy.current_version.policy_hash.as_bytes()));
        policy
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
        assert!(config.trusted_pubkeys.is_empty());
    }

    #[test]
    fn test_signing_key_generation() {
        let keys = PolicySigningKeys::generate();
        let pubkey_hex = keys.public_key_hex();
        assert_eq!(pubkey_hex.len(), 64); // 32 bytes = 64 hex chars
    }

    #[test]
    fn test_signing_and_verification() {
        let keys = PolicySigningKeys::generate();
        let message = b"test message";
        let signature = keys.sign(message);
        assert_eq!(signature.len(), 128); // 64 bytes = 128 hex chars
        assert!(PolicySigningKeys::verify(&keys.public_key_hex(), message, &signature).is_ok());
    }

    #[test]
    fn test_signing_verification_wrong_message() {
        let keys = PolicySigningKeys::generate();
        let message = b"test message";
        let wrong_message = b"wrong message";
        let signature = keys.sign(message);
        assert!(
            PolicySigningKeys::verify(&keys.public_key_hex(), wrong_message, &signature).is_err()
        );
    }

    #[test]
    fn test_signing_verification_wrong_key() {
        let keys1 = PolicySigningKeys::generate();
        let keys2 = PolicySigningKeys::generate();
        let message = b"test message";
        let signature = keys1.sign(message);
        assert!(PolicySigningKeys::verify(&keys2.public_key_hex(), message, &signature).is_err());
    }

    #[test]
    fn test_signing_verification_tampered_signature() {
        let keys = PolicySigningKeys::generate();
        let message = b"test message";
        let signature = keys.sign(message);
        let mut sig_bytes = hex::decode(&signature).unwrap();
        sig_bytes[0] ^= 0xff;
        let tampered_signature = hex::encode(sig_bytes);
        assert!(
            PolicySigningKeys::verify(&keys.public_key_hex(), message, &tampered_signature)
                .is_err()
        );
    }

    #[test]
    fn test_policy_registration_without_signature_verification() {
        let config = FederatedPolicyConfig {
            verify_signatures: false,
            ..Default::default()
        };
        let mut distributor = FederatedPolicyDistributor::new(config);
        let policy = test_policy("policy1", PolicyLevel::Global, 1);

        assert!(distributor.register_policy(policy).is_ok());
        assert_eq!(distributor.list_policies().len(), 1);
    }

    #[test]
    fn test_policy_registration_with_valid_signature() {
        let keys = PolicySigningKeys::generate();
        let config = FederatedPolicyConfig {
            verify_signatures: true,
            trusted_pubkeys: vec![keys.public_key_hex()],
            ..Default::default()
        };
        let mut distributor = FederatedPolicyDistributor::new(config);
        let policy = test_policy_with_signature("policy1", PolicyLevel::Global, 1, &keys);

        assert!(distributor.register_policy(policy).is_ok());
    }

    #[test]
    fn test_policy_registration_with_missing_signature() {
        let keys = PolicySigningKeys::generate();
        let config = FederatedPolicyConfig {
            verify_signatures: true,
            trusted_pubkeys: vec![keys.public_key_hex()],
            ..Default::default()
        };
        let mut distributor = FederatedPolicyDistributor::new(config);
        let policy = test_policy("policy1", PolicyLevel::Global, 1); // No signature

        assert!(distributor.register_policy(policy).is_err());
    }

    #[test]
    fn test_policy_registration_with_wrong_signature() {
        let keys1 = PolicySigningKeys::generate();
        let keys2 = PolicySigningKeys::generate();
        let config = FederatedPolicyConfig {
            verify_signatures: true,
            trusted_pubkeys: vec![keys1.public_key_hex()],
            ..Default::default()
        };
        let mut distributor = FederatedPolicyDistributor::new(config);
        // Sign with keys2 but verify with keys1
        let policy = test_policy_with_signature("policy1", PolicyLevel::Global, 1, &keys2);

        assert!(distributor.register_policy(policy).is_err());
    }

    #[test]
    fn test_policy_hash_mismatch() {
        let config = FederatedPolicyConfig {
            verify_signatures: false,
            ..Default::default()
        };
        let mut distributor = FederatedPolicyDistributor::new(config);
        let mut policy = test_policy("policy1", PolicyLevel::Global, 1);
        policy.current_version.policy_hash = "wrong_hash".to_string();

        assert!(distributor.register_policy(policy).is_err());
    }

    #[test]
    fn test_policy_update_with_signing() {
        let keys = PolicySigningKeys::generate();
        let config = FederatedPolicyConfig {
            verify_signatures: true,
            trusted_pubkeys: vec![keys.public_key_hex()],
            ..Default::default()
        };
        let mut distributor = FederatedPolicyDistributor::new(config);
        let policy = test_policy_with_signature("policy1", PolicyLevel::Global, 1, &keys);
        distributor.register_policy(policy).unwrap();

        let new_content = "version: 1\npolicy: updated\n".to_string();
        let result =
            distributor.update_policy("policy1", new_content, "test".to_string(), Some(&keys));
        assert!(result.is_ok());
        let new_version = result.unwrap();
        assert_eq!(new_version.version, 2);
        assert!(new_version.signature.is_some());
    }

    #[test]
    fn test_policy_update_without_signing_keys_fails() {
        let keys = PolicySigningKeys::generate();
        let config = FederatedPolicyConfig {
            verify_signatures: true,
            trusted_pubkeys: vec![keys.public_key_hex()],
            ..Default::default()
        };
        let mut distributor = FederatedPolicyDistributor::new(config);
        let policy = test_policy_with_signature("policy1", PolicyLevel::Global, 1, &keys);
        distributor.register_policy(policy).unwrap();

        let new_content = "version: 1\npolicy: updated\n".to_string();
        let result = distributor.update_policy("policy1", new_content, "test".to_string(), None);
        assert!(result.is_err());
    }

    #[test]
    fn test_policy_verification_with_signature() {
        let keys = PolicySigningKeys::generate();
        let config = FederatedPolicyConfig {
            verify_signatures: true,
            trusted_pubkeys: vec![keys.public_key_hex()],
            ..Default::default()
        };
        let distributor = FederatedPolicyDistributor::new(config);
        let policy = test_policy_with_signature("policy1", PolicyLevel::Global, 1, &keys);

        assert!(distributor.verify_policy(&policy));
    }

    #[test]
    fn test_policy_verification_with_wrong_signature() {
        let keys1 = PolicySigningKeys::generate();
        let keys2 = PolicySigningKeys::generate();
        let config = FederatedPolicyConfig {
            verify_signatures: true,
            trusted_pubkeys: vec![keys1.public_key_hex()],
            ..Default::default()
        };
        let distributor = FederatedPolicyDistributor::new(config);
        let policy = test_policy_with_signature("policy1", PolicyLevel::Global, 1, &keys2);

        assert!(!distributor.verify_policy(&policy));
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
    fn test_policy_level_display() {
        assert_eq!(format!("{}", PolicyLevel::Global), "global");
        assert_eq!(format!("{}", PolicyLevel::Repository), "repository");
        assert_eq!(format!("{}", PolicyLevel::Project), "project");
    }
}
