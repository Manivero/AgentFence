//! MCP proxy command implementation.

use agentfence_core::types::{AgentId, SessionId};
use agentfence_mcp::proxy::{McpProxy, ProxyConfig};
use agentfence_policy::{parser::load_policy, pdp::Pdp};
use tracing::info;

pub fn execute(server: &str, policy_path: &str) {
    info!(
        "Starting MCP proxy for server '{}' with policy '{}'",
        server, policy_path
    );

    let policy = match load_policy(policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to load policy: {}", e);
            std::process::exit(1);
        }
    };

    let pdp = Pdp::new(policy);
    let config = ProxyConfig {
        server_name: server.to_string(),
        server_command: "npx".to_string(),
        server_args: vec!["-y".to_string(), format!("@modelcontextprotocol/server-{}", server)],
        session_id: SessionId::new(),
        agent_id: AgentId::new("cli"),
    };

    let proxy = McpProxy::new(pdp, config);

    println!("AgentFence MCP Proxy");
    println!("=====================");
    println!("Server: {}", server);
    println!("Policy: {}", policy_path);
    println!();
    println!("Protection Mode:   COOPERATIVE");
    println!("Security Boundary: LIMITED");
    println!();

    if let Err(e) = proxy.run() {
        eprintln!("MCP proxy error: {}", e);
        std::process::exit(1);
    }
}
