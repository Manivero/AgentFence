//! Policy test command implementation.

use agentfence_core::types::{ActionId, ActionType, AgentId, SessionId};
use agentfence_policy::{parser, pdp::Pdp};
use tracing::info;

pub fn execute(path: &str) {
    info!("Testing policy at {}", path);
    println!("AgentFence Policy Test");
    println!("======================");
    println!("Path: {}", path);
    println!();

    let policy = match parser::load_policy(path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to load policy: {}", e);
            std::process::exit(1);
        }
    };

    let pdp = Pdp::new(policy);

    // Test cases
    let test_cases = vec![
        ("git status", ActionType::Shell, "shell", "git status"),
        ("cargo build", ActionType::Shell, "shell", "cargo build"),
        ("npm install", ActionType::Shell, "shell", "npm install"),
        (
            "powershell -Command 'Remove-Item'",
            ActionType::Shell,
            "shell",
            "powershell",
        ),
        (
            "https://github.com/api",
            ActionType::Network,
            "network",
            "github.com",
        ),
        (
            "https://crates.io/api",
            ActionType::Network,
            "network",
            "crates.io",
        ),
        (
            "https://evil.com/api",
            ActionType::Network,
            "network",
            "evil.com",
        ),
        (
            "github.create_issue",
            ActionType::Mcp,
            "github.create_issue",
            "github",
        ),
        (
            "filesystem.read",
            ActionType::Mcp,
            "filesystem.read",
            "filesystem",
        ),
    ];

    let mut passed = 0;
    let mut failed = 0;

    for (name, action_type, tool, target) in test_cases {
        let action = agentfence_core::types::Action {
            id: ActionId::new(),
            session_id: SessionId::new(),
            agent_id: AgentId::new("test-agent"),
            task_id: None,
            action_type,
            tool: tool.to_string(),
            target: target.to_string(),
            args_hash: "test".to_string(),
            context: Default::default(),
        };

        let record = pdp.evaluate(&action);

        println!("Test: {}", name);
        println!("  Decision: {}", record.decision);
        println!("  Rule:     {}", record.rule_id);
        println!("  Reason:   {}", record.reason);
        println!();

        // Simple pass/fail based on expected behavior
        let expected = match name {
            "git status" | "cargo build" | "npm install" => agentfence_core::types::Decision::Allow,
            "powershell -Command 'Remove-Item'" => agentfence_core::types::Decision::Deny,
            "https://github.com/api" | "https://crates.io/api" => {
                agentfence_core::types::Decision::Allow
            }
            "https://evil.com/api" => agentfence_core::types::Decision::Deny,
            "github.create_issue" | "filesystem.read" => agentfence_core::types::Decision::Allow,
            _ => agentfence_core::types::Decision::Deny,
        };

        if record.decision == expected {
            passed += 1;
        } else {
            failed += 1;
            println!(
                "  FAILED: expected {:?}, got {:?}",
                expected, record.decision
            );
        }
    }

    println!();
    println!("Results: {} passed, {} failed", passed, failed);

    if failed > 0 {
        std::process::exit(1);
    }
}
