//! Exec command implementation.

use std::process::Command;

use agentfence_core::types::{ActionId, AgentId, Decision, SessionId};
use agentfence_policy::{parser::load_policy, pdp::Pdp};
use agentfence_shell::{command::ShellCommand, gateway::ShellGateway};
use tracing::info;

use super::db;

pub fn execute(policy_path: &str, command: &[String]) {
    let policy = match load_policy(policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to load policy: {}", e);
            std::process::exit(1);
        }
    };

    let pdp = Pdp::new(policy);
    let gateway = ShellGateway::new(pdp);

    let raw_cmd = command.join(" ");
    let cmd = match ShellCommand::parse(&raw_cmd) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to parse command: {}", e);
            std::process::exit(1);
        }
    };

    let session_id = SessionId::new();
    let agent_id = AgentId::new("cli");

    let record = gateway.evaluate(&cmd, &session_id, &agent_id);

    println!("AgentFence Exec");
    println!("===============");
    println!("Command: {}", raw_cmd);
    println!("Decision: {}", record.decision);
    println!("Rule:     {}", record.rule_id);
    println!("Reason:   {}", record.reason);
    println!();

    // Record audit event
    let db_path = db::get_db_path();
    let _ = db::ensure_db_dir(&db_path);
    if let Ok(store) = agentfence_audit::sqlite_store::SqliteStore::new(&db_path) {
        let event = agentfence_audit::event::AuditEvent::new(
            session_id.clone(),
            agent_id.clone(),
            None,
            ActionId::new(),
            None,
            "shell",
            "shell",
            &raw_cmd,
            "hash",
            record.decision,
            record.risk_level,
            &record.rule_id,
            &record.policy_version,
            "",
            "",
        );
        let _ = store.record_event(&event);
    }

    match record.decision {
        Decision::Allow => {
            info!("Executing command: {}", raw_cmd);
            let status = Command::new(&cmd.executable).args(&cmd.arguments).status();

            match status {
                Ok(s) => {
                    if !s.success() {
                        std::process::exit(s.code().unwrap_or(1));
                    }
                }
                Err(e) => {
                    eprintln!("Failed to execute command: {}", e);
                    std::process::exit(1);
                }
            }
        }
        Decision::Deny => {
            eprintln!("Command denied by policy");
            std::process::exit(1);
        }
        Decision::Ask => {
            eprintln!("Command requires approval");
            eprintln!("Use: agentfence approve <action_id>");
            std::process::exit(1);
        }
    }
}
