//! YAML policy parser for AgentFence.

use std::fs;
use std::path::Path;

use agentfence_core::error::{AgentFenceError, Result};

use crate::model::Policy;

/// Parse a policy from a YAML string.
pub fn parse_policy(yaml: &str) -> Result<Policy> {
    let policy: Policy = serde_yaml::from_str(yaml)
        .map_err(|e| AgentFenceError::Validation(format!("Failed to parse policy: {}", e)))?;

    validate_policy(&policy)?;

    Ok(policy)
}

/// Load and parse a policy from a file.
pub fn load_policy<P: AsRef<Path>>(path: P) -> Result<Policy> {
    let content = fs::read_to_string(path)?;
    parse_policy(&content)
}

/// Validate a parsed policy.
pub fn validate_policy(policy: &Policy) -> Result<()> {
    if policy.version == 0 {
        return Err(AgentFenceError::Validation(
            "Policy version must be greater than 0".to_string(),
        ));
    }

    // Validate shell policy
    if let Some(shell) = &policy.shell {
        if shell.allow.is_empty() && shell.deny.is_empty() {
            tracing::warn!("Shell policy defined but empty — will use defaults");
        }
    }

    // Validate network policy
    if let Some(network) = &policy.network {
        for host in &network.allow {
            if host.is_empty() {
                return Err(AgentFenceError::Validation(
                    "Empty host in network allow list".to_string(),
                ));
            }
        }
    }

    // Validate MCP policy
    if let Some(mcp) = &policy.mcp {
        for tool in &mcp.allow {
            if tool.is_empty() {
                return Err(AgentFenceError::Validation(
                    "Empty tool in MCP allow list".to_string(),
                ));
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_minimal_policy() {
        let yaml = r#"
version: 1
defaults:
  shell: deny
  network: deny
  mcp: deny
  filesystem: deny
"#;
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.version, 1);
    }

    #[test]
    fn test_parse_full_policy() {
        let yaml = r#"
version: 1
defaults:
  filesystem: deny
  shell: deny
  network: deny
  mcp: deny
shell:
  allow:
    - git
    - cargo
  deny:
    - powershell
    - reg
network:
  allow:
    - github.com
    - crates.io
mcp:
  allow:
    - github
    - filesystem
"#;
        let policy = parse_policy(yaml).unwrap();
        assert_eq!(policy.version, 1);
        assert!(policy.shell.is_some());
        assert!(policy.network.is_some());
        assert!(policy.mcp.is_some());
    }

    #[test]
    fn test_invalid_version() {
        let yaml = r#"
version: 0
"#;
        let result = parse_policy(yaml);
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_host_validation() {
        let yaml = r#"
version: 1
network:
  allow:
    - ""
"#;
        let result = parse_policy(yaml);
        assert!(result.is_err());
    }
}
