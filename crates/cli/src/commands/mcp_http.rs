//! MCP HTTP transport command implementation.

use agentfence_core::types::{AgentId, SessionId};
use agentfence_mcp::http_transport::{HttpTransport, HttpTransportConfig};
use agentfence_mcp::proxy::ProxyConfig;
use agentfence_policy::{parser::load_policy, pdp::Pdp};
use tracing::info;

use super::db;

pub fn execute(server: &str, policy_path: &str, listen_addr: &str) {
    info!(
        "Starting MCP HTTP transport for server '{}' on '{}' with policy '{}'",
        server, listen_addr, policy_path
    );

    let policy = match load_policy(policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to load policy: {}", e);
            std::process::exit(1);
        }
    };

    let pdp = Pdp::new(policy);
    let session_id = SessionId::new();
    let agent_id = AgentId::new("cli");

    // Initialize audit store
    let db_path = db::get_db_path();
    let _ = db::ensure_db_dir(&db_path);
    let audit_store = agentfence_audit::sqlite_store::SqliteStore::new(&db_path)
        .ok()
        .map(|s| std::sync::Arc::new(std::sync::Mutex::new(s)));

    let proxy_config = ProxyConfig {
        server_name: server.to_string(),
        server_command: "npx".to_string(),
        server_args: vec![
            "-y".to_string(),
            format!("@modelcontextprotocol/server-{}", server),
        ],
        session_id: session_id.clone(),
        agent_id: agent_id.clone(),
        audit_store,
    };

    let config = HttpTransportConfig {
        listen_addr: listen_addr.to_string(),
        session_id,
        agent_id,
        pdp,
        proxy_config,
        max_body_size: 1024 * 1024, // 1MB
        sse_keepalive_secs: 15,
    };

    let transport = HttpTransport::new(config);

    println!("AgentFence MCP HTTP Transport");
    println!("=============================");
    println!("Server:  {}", server);
    println!("Policy:  {}", policy_path);
    println!("Listen:  {}", listen_addr);
    println!();
    println!("Endpoints:");
    println!("  POST /mcp       — JSON-RPC tool calls");
    println!("  GET  /mcp/sse   — SSE stream");
    println!("  GET  /health    — Health check");
    println!();
    println!("Protection Mode:   COOPERATIVE");
    println!("Security Boundary: LIMITED");
    println!();

    if let Err(e) = transport.run() {
        eprintln!("MCP HTTP transport error: {}", e);
        std::process::exit(1);
    }
}
