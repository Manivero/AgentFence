//! Hermes configuration for AgentFence integration.
//!
//! This module generates the Hermes configuration needed to route
//! MCP, shell, and network through AgentFence.

use serde::{Deserialize, Serialize};

/// Hermes-AgentFence integration configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HermesConfig {
    /// Path to AgentFence policy file
    pub policy_path: String,
    /// AgentFence MCP proxy command
    pub mcp_proxy_command: String,
    /// AgentFence shell wrapper command
    pub shell_wrapper_command: String,
    /// AgentFence network proxy address
    pub network_proxy_addr: String,
}

impl HermesConfig {
    /// Create a new Hermes configuration with default values.
    pub fn new(policy_path: impl Into<String>) -> Self {
        Self {
            policy_path: policy_path.into(),
            mcp_proxy_command: "agentfence mcp proxy".to_string(),
            shell_wrapper_command: "agentfence exec".to_string(),
            network_proxy_addr: "127.0.0.1:8888".to_string(),
        }
    }

    /// Generate Hermes MCP server configuration.
    ///
    /// This produces the YAML snippet to add to `~/.hermes/config.yaml`
    /// under `mcp_servers`.
    pub fn generate_mcp_config(&self, server_name: &str) -> String {
        format!(
            r#"  {}:
    command: "{}"
    args: ["--server", "{}", "--policy", "{}"]
    timeout: 120
    connect_timeout: 60
"#,
            server_name, self.mcp_proxy_command, server_name, self.policy_path
        )
    }

    /// Generate Hermes shell wrapper configuration.
    ///
    /// This produces the command to use as Hermes terminal backend.
    pub fn generate_shell_wrapper(&self) -> String {
        format!(
            r#"{} --policy {} --"#,
            self.shell_wrapper_command, self.policy_path
        )
    }

    /// Generate environment variables for network proxy.
    pub fn generate_network_env(&self) -> String {
        format!(
            r#"HTTP_PROXY=http://{}
HTTPS_PROXY=http://{}
NO_PROXY=localhost,127.0.0.1"#,
            self.network_proxy_addr, self.network_proxy_addr
        )
    }

    /// Generate complete Hermes configuration snippet.
    pub fn generate_full_config(&self) -> String {
        let mut config = String::new();

        config.push_str("# AgentFence Integration for Hermes\n");
        config.push_str("# Add this to ~/.hermes/config.yaml\n\n");

        config.push_str("# MCP Servers (routed through AgentFence)\n");
        config.push_str("mcp_servers:\n");
        config.push_str(&self.generate_mcp_config("github"));
        config.push('\n');

        config.push_str("# Shell wrapper (uncomment to enable)\n");
        config.push_str("# terminal:\n");
        config.push_str(&format!(
            "#   command: \"{}\"\n\n",
            self.generate_shell_wrapper()
        ));

        config.push_str("# Network proxy (set in environment)\n");
        config.push_str(&format!("# {}\n", self.generate_network_env()));

        config
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_mcp_config() {
        let config = HermesConfig::new("agentfence.yaml");
        let mcp_config = config.generate_mcp_config("github");
        assert!(mcp_config.contains("command: \"agentfence mcp proxy\""));
        assert!(mcp_config.contains("--server"));
        assert!(mcp_config.contains("github"));
        assert!(mcp_config.contains("--policy"));
        assert!(mcp_config.contains("agentfence.yaml"));
    }

    #[test]
    fn test_generate_shell_wrapper() {
        let config = HermesConfig::new("agentfence.yaml");
        let wrapper = config.generate_shell_wrapper();
        assert!(wrapper.contains("agentfence exec"));
        assert!(wrapper.contains("--policy"));
        assert!(wrapper.contains("agentfence.yaml"));
    }

    #[test]
    fn test_generate_network_env() {
        let config = HermesConfig::new("agentfence.yaml");
        let env = config.generate_network_env();
        assert!(env.contains("HTTP_PROXY=http://127.0.0.1:8888"));
        assert!(env.contains("HTTPS_PROXY=http://127.0.0.1:8888"));
        assert!(env.contains("NO_PROXY=localhost,127.0.0.1"));
    }

    #[test]
    fn test_generate_full_config() {
        let config = HermesConfig::new("agentfence.yaml");
        let full = config.generate_full_config();
        assert!(full.contains("mcp_servers:"));
        assert!(full.contains("agentfence mcp proxy"));
        assert!(full.contains("HTTP_PROXY"));
    }
}
