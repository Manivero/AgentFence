//! Network proxy command implementation.

use agentfence_core::types::{AgentId, SessionId};
use agentfence_network::proxy::{NetworkProxy, NetworkProxyConfig};
use agentfence_policy::{parser::load_policy, pdp::Pdp};
use tracing::info;

use super::db;

pub fn execute(policy_path: &str, listen_addr: &str) {
    info!(
        "Starting network proxy on '{}' with policy '{}'",
        listen_addr, policy_path
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

    let config = NetworkProxyConfig {
        listen_addr: listen_addr.to_string(),
        session_id: session_id.clone(),
        agent_id: agent_id.clone(),
        audit_store,
    };

    let proxy = NetworkProxy::new(pdp, config);

    println!("AgentFence Network Proxy");
    println!("=========================");
    println!("Listen: {}", listen_addr);
    println!("Policy: {}", policy_path);
    println!();
    println!("Protection Mode:   COOPERATIVE");
    println!("Security Boundary: LIMITED");
    println!();
    println!("Note: This is a cooperative mode proxy.");
    println!("Only HTTP requests routed through this proxy are controlled.");
    println!("HTTPS requests are not intercepted.");
    println!();

    if let Err(e) = proxy.run() {
        eprintln!("Network proxy error: {}", e);
        std::process::exit(1);
    }
}
