//! Policy check command implementation.

use agentfence_policy::parser;
use tracing::info;

pub fn execute(path: &str) {
    info!("Checking policy at {}", path);
    println!("AgentFence Policy Check");
    println!("=======================");
    println!("Path: {}", path);
    println!();

    match parser::load_policy(path) {
        Ok(policy) => {
            println!("Policy is valid");
            println!("Version: {}", policy.version);
            println!();

            if let Some(shell) = &policy.shell {
                println!("Shell policy:");
                println!("  Allow: {:?}", shell.allow);
                println!("  Deny:  {:?}", shell.deny);
                println!();
            }

            if let Some(network) = &policy.network {
                println!("Network policy:");
                println!("  Allow: {:?}", network.allow);
                println!("  Deny:  {:?}", network.deny);
                println!();
            }

            if let Some(mcp) = &policy.mcp {
                println!("MCP policy:");
                println!("  Allow: {:?}", mcp.allow);
                println!("  Deny:  {:?}", mcp.deny);
                println!();
            }

            println!("Policy hash: {}", policy.hash());
        }
        Err(e) => {
            eprintln!("Policy is invalid: {}", e);
            std::process::exit(1);
        }
    }
}
