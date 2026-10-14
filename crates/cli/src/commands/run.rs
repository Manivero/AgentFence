//! Run command implementation.
//!
//! Launches an agent process through AgentFence in cooperative mode.
//!
//! SECURITY: Starting an agent does NOT provide OS-wide interception.
//! Only actions routed through supported AgentFence gateways are controlled.

use std::process::{Command, Stdio};
use tracing::{error, info, warn};

use agentfence_core::types::{ActionId, AgentId, SessionId};
use agentfence_policy::parser::load_policy;
use agentfence_policy::pdp::Pdp;

use super::db;

/// Execute the run command.
///
/// Loads the policy, creates a session, and spawns the agent process.
/// Returns the exit code of the agent process.
pub fn execute(policy_path: &str, agent: &str) -> i32 {
    // Load and validate policy first
    let policy = match load_policy(policy_path) {
        Ok(p) => p,
        Err(e) => {
            error!("Failed to load policy: {}", e);
            eprintln!("Error: Failed to load policy from {}: {}", policy_path, e);
            return 1;
        }
    };

    if policy.version == 0 {
        eprintln!("Error: Policy version must be > 0");
        return 1;
    }

    let _pdp = Pdp::new(policy.clone());

    // Create audit session
    let session_id = SessionId::new();
    let agent_id = AgentId::new(agent);

    // Initialize audit store
    let db_path = db::get_db_path();
    if let Some(parent) = db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }
    let audit_store = match db::init_audit_db(&db_path) {
        Ok(store) => store,
        Err(e) => {
            error!("Failed to initialize audit database: {}", e);
            eprintln!("Error: Failed to initialize audit database: {}", e);
            return 1;
        }
    };

    // Record session start
    if let Err(e) = audit_store.record_event(&agentfence_audit::event::AuditEvent::new(
        session_id.clone(),
        agent_id.clone(),
        None,
        ActionId::new(),
        None,
        "session",
        "session",
        agent,
        "session_start",
        agentfence_core::types::Decision::Allow,
        agentfence_core::types::RiskLevel::Low,
        "session.start",
        policy.version.to_string(),
        "",
        "",
    )) {
        error!("Audit write failed: {}", e);
    }

    println!("AgentFence Run");
    println!("==============");
    println!("Agent:          {}", agent);
    println!("Policy:         {}", policy_path);
    println!("Session:        {}", session_id.0);
    println!("Protection:     COOPERATIVE");
    println!("Security Bound: LIMITED");
    println!();
    println!("WARNING: This is cooperative mode.");
    println!("Only actions routed through AgentFence gateways are controlled.");
    println!("Direct system access is NOT intercepted.");
    println!();

    // Spawn the agent process
    info!("Spawning agent process: {}", agent);

    let mut child = match Command::new(agent)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            error!("Failed to spawn agent process: {}", e);
            eprintln!("Error: Failed to start agent '{}': {}", agent, e);

            if let Err(e) = audit_store.record_event(&agentfence_audit::event::AuditEvent::new(
                session_id.clone(),
                agent_id.clone(),
                None,
                ActionId::new(),
                None,
                "session",
                "session",
                agent,
                "session_failed",
                agentfence_core::types::Decision::Deny,
                agentfence_core::types::RiskLevel::High,
                "session.spawn_failed",
                policy.version.to_string(),
                "",
                "",
            )) {
                error!("Audit write failed: {}", e);
            }

            return 1;
        }
    };

    // Wait for the agent to finish
    let exit_status = match child.wait() {
        Ok(status) => {
            let code = status.code().unwrap_or(1);
            info!("Agent process exited with code: {}", code);

            if let Err(e) = audit_store.record_event(&agentfence_audit::event::AuditEvent::new(
                session_id.clone(),
                agent_id.clone(),
                None,
                ActionId::new(),
                None,
                "session",
                "session",
                agent,
                "session_end",
                agentfence_core::types::Decision::Allow,
                agentfence_core::types::RiskLevel::Low,
                "session.end",
                policy.version.to_string(),
                "",
                "",
            )) {
                error!("Audit write failed: {}", e);
            }

            code
        }
        Err(e) => {
            error!("Failed to wait for agent process: {}", e);
            eprintln!("Error: Failed to wait for agent process: {}", e);
            1
        }
    };

    if exit_status != 0 {
        warn!("Agent process exited with non-zero code: {}", exit_status);
    }

    exit_status
}
