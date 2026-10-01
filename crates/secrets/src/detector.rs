//! Secret detection for AgentFence.
//!
//! Deterministic secret detector. Never logs raw secrets.
//! Stores fingerprints/hashes instead.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Secret category.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecretCategory {
    ApiKey,
    AccessToken,
    BearerToken,
    Jwt,
    PrivateKey,
    Password,
    CloudCredential,
    GitHubToken,
    EnvFile,
}

impl std::fmt::Display for SecretCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SecretCategory::ApiKey => write!(f, "API_KEY"),
            SecretCategory::AccessToken => write!(f, "ACCESS_TOKEN"),
            SecretCategory::BearerToken => write!(f, "BEARER_TOKEN"),
            SecretCategory::Jwt => write!(f, "JWT"),
            SecretCategory::PrivateKey => write!(f, "PRIVATE_KEY"),
            SecretCategory::Password => write!(f, "PASSWORD"),
            SecretCategory::CloudCredential => write!(f, "CLOUD_CREDENTIAL"),
            SecretCategory::GitHubToken => write!(f, "GITHUB_TOKEN"),
            SecretCategory::EnvFile => write!(f, "ENV_FILE"),
        }
    }
}

/// Detected secret (without raw value).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedSecret {
    pub category: SecretCategory,
    pub fingerprint: String,
    pub location: String,
}

/// Secret detector.
///
/// Detects common secret patterns in text.
/// Never stores or logs raw secrets.
pub struct SecretDetector;

impl SecretDetector {
    /// Create a new secret detector.
    pub fn new() -> Self {
        Self
    }

    /// Detect secrets in text.
    pub fn detect(&self, text: &str, location: &str) -> Vec<DetectedSecret> {
        let mut secrets = Vec::new();

        // Check for JWT
        if let Some(fp) = self.detect_jwt(text) {
            secrets.push(DetectedSecret {
                category: SecretCategory::Jwt,
                fingerprint: fp,
                location: location.to_string(),
            });
        }

        // Check for GitHub tokens
        if let Some(fp) = self.detect_github_token(text) {
            secrets.push(DetectedSecret {
                category: SecretCategory::GitHubToken,
                fingerprint: fp,
                location: location.to_string(),
            });
        }

        // Check for private keys
        if let Some(fp) = self.detect_private_key(text) {
            secrets.push(DetectedSecret {
                category: SecretCategory::PrivateKey,
                fingerprint: fp,
                location: location.to_string(),
            });
        }

        // Check for API keys
        if let Some(fp) = self.detect_api_key(text) {
            secrets.push(DetectedSecret {
                category: SecretCategory::ApiKey,
                fingerprint: fp,
                location: location.to_string(),
            });
        }

        // Check for bearer tokens
        if let Some(fp) = self.detect_bearer_token(text) {
            secrets.push(DetectedSecret {
                category: SecretCategory::BearerToken,
                fingerprint: fp,
                location: location.to_string(),
            });
        }

        // Check for .env access
        if let Some(fp) = self.detect_env_access(text) {
            secrets.push(DetectedSecret {
                category: SecretCategory::EnvFile,
                fingerprint: fp,
                location: location.to_string(),
            });
        }

        secrets
    }

    fn detect_jwt(&self, text: &str) -> Option<String> {
        // JWT pattern: eyJ... (base64url encoded)
        if text.contains("eyJ") && text.split('.').count() == 3 {
            Some(self.fingerprint(text))
        } else {
            None
        }
    }

    fn detect_github_token(&self, text: &str) -> Option<String> {
        // GitHub token patterns: ghp_, gho_, ghu_, ghs_, ghr_
        if text.contains("ghp_")
            || text.contains("gho_")
            || text.contains("ghu_")
            || text.contains("ghs_")
            || text.contains("ghr_")
        {
            Some(self.fingerprint(text))
        } else {
            None
        }
    }

    fn detect_private_key(&self, text: &str) -> Option<String> {
        // Private key patterns
        if text.contains("-----BEGIN RSA PRIVATE KEY-----")
            || text.contains("-----BEGIN EC PRIVATE KEY-----")
            || text.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
            || text.contains("-----BEGIN PGP PRIVATE KEY BLOCK-----")
        {
            Some(self.fingerprint(text))
        } else {
            None
        }
    }

    fn detect_api_key(&self, text: &str) -> Option<String> {
        // Common API key patterns
        if text.contains("api_key")
            || text.contains("apikey")
            || text.contains("API_KEY")
            || text.contains("api-key")
        {
            Some(self.fingerprint(text))
        } else {
            None
        }
    }

    fn detect_bearer_token(&self, text: &str) -> Option<String> {
        // Bearer token pattern
        if text.contains("Bearer ") || text.contains("bearer ") {
            Some(self.fingerprint(text))
        } else {
            None
        }
    }

    fn detect_env_access(&self, text: &str) -> Option<String> {
        // .env file access
        if text.contains(".env") || text.contains("dotenv") {
            Some(self.fingerprint(text))
        } else {
            None
        }
    }

    fn fingerprint(&self, text: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(text.as_bytes());
        let hash = hex::encode(hasher.finalize());
        format!("sha256:{}", &hash[..16])
    }
}

impl Default for SecretDetector {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_jwt() {
        let detector = SecretDetector::new();
        let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U";
        let secrets = detector.detect(jwt, "test");
        assert!(secrets.iter().any(|s| s.category == SecretCategory::Jwt));
    }

    #[test]
    fn test_detect_github_token() {
        let detector = SecretDetector::new();
        let token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz";
        let secrets = detector.detect(token, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::GitHubToken));
    }

    #[test]
    fn test_detect_private_key() {
        let detector = SecretDetector::new();
        let key = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...";
        let secrets = detector.detect(key, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::PrivateKey));
    }

    #[test]
    fn test_detect_api_key() {
        let detector = SecretDetector::new();
        let text = "api_key = \"sk-1234567890\"";
        let secrets = detector.detect(text, "test");
        assert!(secrets.iter().any(|s| s.category == SecretCategory::ApiKey));
    }

    #[test]
    fn test_detect_bearer_token() {
        let detector = SecretDetector::new();
        let text = "Authorization: Bearer abc123";
        let secrets = detector.detect(text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::BearerToken));
    }

    #[test]
    fn test_detect_env_access() {
        let detector = SecretDetector::new();
        let text = "Loading .env file";
        let secrets = detector.detect(text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::EnvFile));
    }

    #[test]
    fn test_no_secrets() {
        let detector = SecretDetector::new();
        let text = "This is a normal string with no secrets";
        let secrets = detector.detect(text, "test");
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_fingerprint_not_raw() {
        let detector = SecretDetector::new();
        let text = "super_secret_value_12345";
        let secrets = detector.detect(text, "test");
        for secret in &secrets {
            assert!(!secret.fingerprint.contains("super_secret_value_12345"));
        }
    }
}
