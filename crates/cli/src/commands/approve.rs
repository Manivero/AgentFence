//! Approve command implementation.
//!
//! Interactive terminal prompt for approving or denying actions.
//! The agent must never be able to approve its own actions.

use std::io::{self, Write};

use agentfence_approval::approval::{ApprovalScope, ApprovalService};
use agentfence_core::types::{ActionId, Decision, SessionId};
use std::path::PathBuf;

/// Get the default database path for approvals.
fn get_db_path() -> PathBuf {
    let data_dir = dirs_next::data_dir()
        .unwrap_or_else(|| std::env::current_dir().unwrap_or_else(|_| PathBuf::from(".")));
    data_dir.join("agentfence").join("approvals.db")
}

/// Execute the approve command.
///
/// If action_id is "list", shows pending approvals.
/// Otherwise, shows interactive prompt for the specified action.
pub fn execute(action_id: &str, decision: &str) {
    let db_path = get_db_path();
    if let Some(parent) = db_path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let service = match ApprovalService::new_with_db(db_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to initialize approval service: {}", e);
            std::process::exit(1);
        }
    };

    // Load existing approvals from DB
    if let Err(e) = service.load_from_db() {
        eprintln!("Failed to load approvals from database: {}", e);
        std::process::exit(1);
    }

    if action_id == "list" {
        list_pending_approvals(&service);
        return;
    }

    // Parse action ID
    let action_id = ActionId(action_id.to_string());
    let session_id = SessionId::new();

    // Check if there's a pending approval for this action
    let record = service.validate(&action_id, &session_id);

    if record.is_none() {
        println!("AgentFence Approve");
        println!("=================");
        println!("No pending approval found for action: {}", action_id);
        println!();
        println!("Use 'agentfence approve list' to see pending approvals.");
        return;
    }

    let record = record.unwrap();

    // If decision is specified, apply it directly
    if decision != "ask" {
        let result = match decision {
            "allow" => service.approve(&record.approval_id),
            "deny" => service.deny(&record.approval_id),
            _ => {
                eprintln!("Invalid decision: {}. Use 'allow' or 'deny'.", decision);
                std::process::exit(1);
            }
        };

        match result {
            Ok(r) => {
                println!("AgentFence Approve");
                println!("=================");
                println!("Action:   {}", action_id);
                println!("Decision: {}", r.decision);
                println!("Scope:    {:?}", r.scope);
                println!();
                println!(
                    "Approval {}.",
                    if r.decision == Decision::Allow {
                        "granted"
                    } else {
                        "denied"
                    }
                );
            }
            Err(e) => {
                eprintln!("Approval error: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    // Interactive prompt
    interactive_prompt(&service, &action_id, &session_id, &record);
}

/// List all pending approvals.
fn list_pending_approvals(service: &ApprovalService) {
    let pending = service.list_pending();

    println!("AgentFence Pending Approvals");
    println!("============================");
    println!();

    if pending.is_empty() {
        println!("No pending approvals.");
        return;
    }

    for (i, record) in pending.iter().enumerate() {
        println!("  [{}] Action: {}", i + 1, record.action_id.0);
        println!("      Approval ID: {}", record.approval_id);
        println!("      Session:     {}", record.session_id.0);
        println!("      Scope:       {:?}", record.scope);
        println!("      Issued:      {}", record.issued_at);
        if let Some(expires) = record.expires_at {
            println!("      Expires:     {}", expires);
        }
        println!();
    }

    println!("Use 'agentfence approve <action_id> --decision allow|deny' to decide.");
}

/// Interactive approval prompt.
fn interactive_prompt(
    service: &ApprovalService,
    action_id: &ActionId,
    session_id: &SessionId,
    record: &agentfence_approval::approval::ApprovalRecord,
) {
    println!();
    println!("⚠ ACTION REQUIRES APPROVAL");
    println!();
    println!("Action ID: {}", action_id);
    println!("Session:   {}", session_id);
    println!("Scope:     {:?}", record.scope);
    println!("Issued:    {}", record.issued_at);
    if let Some(expires) = record.expires_at {
        println!("Expires:   {}", expires);
    }
    println!();
    println!("[1] Deny");
    println!("[2] Allow once");
    println!("[3] Allow for session");
    println!("[4] Allow for repository");
    println!();
    print!("Choice: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    let choice = input.trim();

    let (new_decision, new_scope) = match choice {
        "1" => (Decision::Deny, record.scope.clone()),
        "2" => (Decision::Allow, ApprovalScope::Once),
        "3" => (Decision::Allow, ApprovalScope::Session),
        "4" => (Decision::Allow, ApprovalScope::Repository),
        _ => {
            eprintln!("Invalid choice: {}", choice);
            std::process::exit(1);
        }
    };

    // Apply the decision
    let result = if new_decision == Decision::Deny {
        service.deny(&record.approval_id)
    } else {
        service.approve(&record.approval_id)
    };

    match result {
        Ok(r) => {
            println!();
            println!("Decision: {}", r.decision);
            println!("Scope:    {:?}", new_scope);
            println!();
            println!(
                "Approval {}.",
                if r.decision == Decision::Allow {
                    "granted"
                } else {
                    "denied"
                }
            );
        }
        Err(e) => {
            eprintln!("Approval error: {}", e);
            std::process::exit(1);
        }
    }
}
