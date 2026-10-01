//! Exec command implementation.

use std::process::Command;

use agentfence_core::types::{AgentId, SessionId};
use agentfence_policy::{parser::load_policy, pdp::Pdp};
use agentfence_shell::{command::ShellCommand, gateway::ShellGateway};
use tracing::info;

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

    match record.decision {
        agentfence_core::types::Decision::Allow => {
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
        agentfence_core::types::Decision::Deny => {
            eprintln!("Command denied by policy");
            std::process::exit(1);
        }
        agentfence_core::types::Decision::Ask => {
            eprintln!("Command requires approval");
            eprintln!("Use: agentfence approve <action_id>");
            std::process::exit(1);
        }
    }
}
