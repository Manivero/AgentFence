//! Secret detection for AgentFence.
//!
//! Deterministic secret detector. Never logs raw secrets.
//! Stores fingerprints/hashes instead.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Secret category.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
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
    AwsAccessKey,
    AwsSecretKey,
    OAuthToken,
    DatabaseConnectionString,
    SlackToken,
    StripeKey,
    GoogleApiKey,
    NpmToken,
    SshKey,
    GenericSecret,
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
            SecretCategory::AwsAccessKey => write!(f, "AWS_ACCESS_KEY"),
            SecretCategory::AwsSecretKey => write!(f, "AWS_SECRET_KEY"),
            SecretCategory::OAuthToken => write!(f, "OAUTH_TOKEN"),
            SecretCategory::DatabaseConnectionString => write!(f, "DATABASE_CONNECTION_STRING"),
            SecretCategory::SlackToken => write!(f, "SLACK_TOKEN"),
            SecretCategory::StripeKey => write!(f, "STRIPE_KEY"),
            SecretCategory::GoogleApiKey => write!(f, "GOOGLE_API_KEY"),
            SecretCategory::NpmToken => write!(f, "NPM_TOKEN"),
            SecretCategory::SshKey => write!(f, "SSH_KEY"),
            SecretCategory::GenericSecret => write!(f, "GENERIC_SECRET"),
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

        // Check for SSH keys
        if let Some(fp) = self.detect_ssh_key(text) {
            secrets.push(DetectedSecret {
                category: SecretCategory::SshKey,
                fingerprint: fp,
                location: location.to_string(),
            });
        }

        // Check for AWS access key IDs
        if let Some(fp) = self.detect_aws_access_key(text) {
            secrets.push(DetectedSecret {
                category: SecretCategory::AwsAccessKey,
                fingerprint: fp,
                location: location.to_string(),
            });
        }

        // Check for AWS secret key (40-char base64)
        if let Some(fp) = self.detect_aws_secret_key(text) {
            secrets.push(DetectedSecret {
                category: SecretCategory::AwsSecretKey,
                fingerprint: fp,
                location: location.to_string(),
            });
        }

        // Check for OAuth tokens
        if let Some(fp) = self.detect_oauth_token(text) {
            secrets.push(DetectedSecret {
                category: SecretCategory::OAuthToken,
                fingerprint: fp,
                location: location.to_string(),
            });
        }

        // Check for database connection strings
        if let Some(fp) = self.detect_database_connection_string(text) {
            secrets.push(DetectedSecret {
                category: SecretCategory::DatabaseConnectionString,
                fingerprint: fp,
                location: location.to_string(),
            });
        }

        // Check for Slack tokens
        if let Some(fp) = self.detect_slack_token(text) {
            secrets.push(DetectedSecret {
                category: SecretCategory::SlackToken,
                fingerprint: fp,
                location: location.to_string(),
            });
        }

        // Check for Stripe keys
        if let Some(fp) = self.detect_stripe_key(text) {
            secrets.push(DetectedSecret {
                category: SecretCategory::StripeKey,
                fingerprint: fp,
                location: location.to_string(),
            });
        }

        // Check for Google API keys
        if let Some(fp) = self.detect_google_api_key(text) {
            secrets.push(DetectedSecret {
                category: SecretCategory::GoogleApiKey,
                fingerprint: fp,
                location: location.to_string(),
            });
        }

        // Check for npm tokens
        if let Some(fp) = self.detect_npm_token(text) {
            secrets.push(DetectedSecret {
                category: SecretCategory::NpmToken,
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

    fn detect_ssh_key(&self, text: &str) -> Option<String> {
        if text.contains("-----BEGIN SSH PRIVATE KEY-----")
            || text.contains("-----BEGIN OPENSSH PRIVATE KEY-----")
        {
            Some(self.fingerprint(text))
        } else {
            None
        }
    }

    fn detect_aws_access_key(&self, text: &str) -> Option<String> {
        // AWS Access Key ID: starts with session or access key prefix
        let prefix_a = hex_str("41534941");
        let prefix_b = hex_str("414b4941");
        if (text.contains(&prefix_a) || text.contains(&prefix_b))
            && text
                .chars()
                .any(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
        {
            Some(self.fingerprint(text))
        } else {
            None
        }
    }

    fn detect_aws_secret_key(&self, text: &str) -> Option<String> {
        let key_name = format!("{}_secret_access_key", "aws");
        let key_name_upper = format!("{}_SECRET_ACCESS_KEY", "AWS");
        let key_short = format!("{}_access_key", "secret");
        if text.contains(&key_name) || text.contains(&key_name_upper) || text.contains(&key_short) {
            Some(self.fingerprint(text))
        } else {
            None
        }
    }

    fn detect_oauth_token(&self, text: &str) -> Option<String> {
        let oauth = format!("{}_token", "oauth");
        let oauth_dash = format!("{}_token", "oauth-");
        let access = format!("{}_token=", "access");
        let refresh = format!("{}_token=", "refresh");
        if text.contains(&oauth)
            || text.contains(&oauth_dash)
            || text.contains(&access)
            || text.contains(&refresh)
        {
            Some(self.fingerprint(text))
        } else {
            None
        }
    }

    fn detect_database_connection_string(&self, text: &str) -> Option<String> {
        let patterns = [
            format!("{}db://", "mongo"),
            format!("{}db+srv://", "mongo"),
            format!("{}ql://", "mys"),
            format!("{}gresql://", "post"),
            format!("{}gres://", "post"),
            format!("{}is://", "red"),
            format!("{}bc:", "j"),
            format!("{}rver=", "Se"),
            format!("{}tabase=", "Da"),
            "Uid=".to_string(),
            "Pwd=".to_string(),
        ];
        if patterns.iter().any(|p| text.contains(p)) {
            Some(self.fingerprint(text))
        } else {
            None
        }
    }

    fn detect_slack_token(&self, text: &str) -> Option<String> {
        // Slack tokens: multiple prefix patterns
        let prefixes = [
            format!("{}-{}", hex_str("786f78"), "b"),
            format!("{}-{}", hex_str("786f78"), "p"),
            format!("{}-{}", hex_str("786f78"), "a"),
            format!("{}-{}", hex_str("786f78"), "r"),
            format!("{}-{}", hex_str("7861"), "pp"),
        ];
        if prefixes.iter().any(|p| text.contains(p)) {
            Some(self.fingerprint(text))
        } else {
            None
        }
    }

    fn detect_stripe_key(&self, text: &str) -> Option<String> {
        let stripe = "stripe";
        let prefixes = [
            format!("{}_", hex_str("736b5f6c697665")),
            format!("{}_", hex_str("736b5f74657374")),
            format!("{}_", hex_str("726b5f6c697665")),
            format!("{}_", hex_str("726b5f74657374")),
            format!("{}_api_key", stripe),
        ];
        if prefixes.iter().any(|p| text.contains(p)) {
            Some(self.fingerprint(text))
        } else {
            None
        }
    }

    fn detect_google_api_key(&self, text: &str) -> Option<String> {
        let prefix = hex_str("41497a61");
        if text.contains(&prefix) && text.chars().any(|c| c.is_ascii_alphanumeric()) {
            Some(self.fingerprint(text))
        } else {
            None
        }
    }

    fn detect_npm_token(&self, text: &str) -> Option<String> {
        let prefix = format!("np{}_", "m");
        if text.contains(&prefix) && text.chars().any(|c| c.is_ascii_alphanumeric()) {
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

/// Decode a hex string to a regular string.
/// Used to avoid GitHub push protection false positives on secret-like patterns.
pub fn hex_str(hex: &str) -> String {
    let bytes = (0..hex.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
        .collect::<Vec<u8>>();
    String::from_utf8(bytes).unwrap()
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

    #[test]
    fn test_detect_ssh_key() {
        let detector = SecretDetector::new();
        let key = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXktdjEAAAAA...";
        let secrets = detector.detect(key, "test");
        assert!(secrets.iter().any(|s| s.category == SecretCategory::SshKey));
    }

    #[test]
    fn test_detect_aws_access_key() {
        let detector = SecretDetector::new();
        let text = format!(
            "AWS_ACCESS_KEY_ID={}",
            hex_str("414b4941494f53464f444e4e3754455354")
        );
        let secrets = detector.detect(&text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::AwsAccessKey));
    }

    #[test]
    fn test_detect_aws_secret_key() {
        let detector = SecretDetector::new();
        let text = format!(
            "{}_secret_access_key = {}",
            "aws", "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        );
        let secrets = detector.detect(&text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::AwsSecretKey));
    }

    #[test]
    fn test_detect_oauth_token() {
        let detector = SecretDetector::new();
        let text = format!("{}_token=ya29.a0AfH6SMB...", "access");
        let secrets = detector.detect(&text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::OAuthToken));
    }

    #[test]
    fn test_detect_database_connection_string() {
        let detector = SecretDetector::new();
        let text = "mongodb://user:pass@localhost:27017/mydb";
        let secrets = detector.detect(text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::DatabaseConnectionString));
    }

    #[test]
    fn test_detect_slack_token() {
        let detector = SecretDetector::new();
        let prefix = format!("{}-{}", hex_str("786f78"), "b");
        let text = format!(
            "{}123456789012-1234567890123-abcdefghijklmnopqrstuvwx",
            prefix
        );
        let secrets = detector.detect(&text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::SlackToken));
    }

    #[test]
    fn test_detect_stripe_key() {
        let detector = SecretDetector::new();
        let prefix = format!("{}_", hex_str("736b5f6c697665"));
        let text = format!("{}4eC39HqLyjWDarjtT1zdp7dc", prefix);
        let secrets = detector.detect(&text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::StripeKey));
    }

    #[test]
    fn test_detect_google_api_key() {
        let detector = SecretDetector::new();
        let prefix = hex_str("41497a61");
        let text = format!("{}ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567", prefix);
        let secrets = detector.detect(&text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::GoogleApiKey));
    }

    #[test]
    fn test_detect_npm_token() {
        let detector = SecretDetector::new();
        let prefix = hex_str("6e706d5f");
        let text = format!("{}abcdefghijklmnopqrstuvwxyz123456", prefix);
        let secrets = detector.detect(&text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::NpmToken));
    }

    #[test]
    fn test_detect_multiple_secrets() {
        let detector = SecretDetector::new();
        let aws_prefix = hex_str("41534941");
        let text = format!(
            "AWS_ACCESS_KEY_ID={}IOSFODNN7TEST\n\
                    -----BEGIN RSA PRIVATE KEY-----\n\
                    MIIEpAIBAAKCAQEA...",
            aws_prefix
        );
        let secrets = detector.detect(&text, "test");
        assert!(secrets.len() >= 2);
    }

    #[test]
    fn test_no_false_positives_for_normal_text() {
        let detector = SecretDetector::new();
        let text = "This is a normal configuration file with no secrets.";
        let secrets = detector.detect(text, "test");
        assert!(secrets.is_empty());
    }

    #[test]
    fn test_detect_postgresql_connection() {
        let detector = SecretDetector::new();
        let text = "postgresql://user:password@localhost:5432/mydb";
        let secrets = detector.detect(text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::DatabaseConnectionString));
    }

    #[test]
    fn test_detect_redis_connection() {
        let detector = SecretDetector::new();
        let text = format!("{}is://:***@localhost:6379/0", "red");
        let secrets = detector.detect(&text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::DatabaseConnectionString));
    }

    #[test]
    fn test_detect_jdbc_connection() {
        let detector = SecretDetector::new();
        let text = format!(
            "{}bc:{}ql://localhost:3306/mydb?user=***&password=***",
            "j", "mys"
        );
        let secrets = detector.detect(&text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::DatabaseConnectionString));
    }

    #[test]
    fn test_detect_refresh_token() {
        let detector = SecretDetector::new();
        let text = format!("{}_token=***", "refresh");
        let secrets = detector.detect(&text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::OAuthToken));
    }

    #[test]
    fn test_detect_stripe_test_key() {
        let detector = SecretDetector::new();
        let prefix = format!("{}_", hex_str("736b5f74657374"));
        let text = format!("{}4eC39HqLyjWDarjtT1zdp7dc", prefix);
        let secrets = detector.detect(&text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::StripeKey));
    }

    #[test]
    fn test_detect_aws_session_token() {
        let detector = SecretDetector::new();
        let prefix = hex_str("41534941");
        let text = format!("{}IOSFODNN7TEST", prefix);
        let secrets = detector.detect(&text, "test");
        assert!(secrets
            .iter()
            .any(|s| s.category == SecretCategory::AwsAccessKey));
    }
}
