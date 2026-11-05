//! Approve command implementation.
//!
//! This is the operator-facing side of the approval boundary. It is a separate
//! trust boundary from the agent: the agent can *request* approval, but only this
//! command can grant or refuse it.
//!
//! SECURITY / TRUST ASSUMPTION: this command is **not authenticated**. Anyone
//! able to run `agentfence approve` in the operator's environment can decide any
//! pending request. The trust boundary is the terminal itself. The command keys
//! on the `approval_id` printed by the enforcement path (or listed by
//! `agentfence approve list`) — it never invents a request, and it refuses to
//! decide an id that is not in the store.
//!
//! SECURITY: the interactive prompt only allows *accept or refuse*. The scope is
//! fixed when the request is created; this command can never widen a one-shot
//! approval into a session- or repository-wide permission.

use std::io::{self, Write};

use agentfence_approval::approval::ApprovalService;
use agentfence_approval::broker::default_approval_db_path;
use agentfence_core::types::Decision;

/// Execute the approve command.
///
/// - `approve list` lists pending requests (`--all` also shows decided ones).
/// - `approve show <approval_id>` prints full detail.
/// - `approve <approval_id> --decision allow|deny|reject` decides a request.
/// - `approve <approval_id>` without `--decision` prompts interactively.
pub fn execute(approval_id: &str, decision: &str, show_all: bool) {
    let db_path = default_approval_db_path();
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

    if let Err(e) = service.load_from_db() {
        eprintln!("Failed to load approvals from database: {}", e);
        std::process::exit(1);
    }

    if approval_id == "list" {
        list_approvals(&service, show_all);
        return;
    }

    if decision == "show" {
        show_approval(&service, approval_id);
        return;
    }

    if decision != "ask" {
        let approve = match decision {
            "allow" => true,
            "deny" | "reject" => false,
            _ => {
                eprintln!("Invalid decision: {}. Use 'allow' or 'deny'.", decision);
                std::process::exit(1);
            }
        };
        decide(&service, approval_id, approve);
        return;
    }

    interactive_prompt(&service, approval_id);
}

/// Decide a request by its approval id.
fn decide(service: &ApprovalService, approval_id: &str, approve: bool) {
    // SECURITY: only a request that is actually in the store may be decided. A
    // caller-supplied id that matches nothing fails closed.
    let Some(record) = service.refresh(approval_id) else {
        println!("AgentFence Approve");
        println!("=================");
        println!("No approval request found with id: {}", approval_id);
        println!();
        println!("Use 'agentfence approve list' to see pending approvals.");
        return;
    };


    println!("AgentFence Approve");
    println!("=================");
    println!("Approval ID: {}", approval_id);
    println!("Action:      {}", record.action_id.0);
    println!("Tool:        {}", record.tool);
    println!("Target:      {}", record.target);
    println!("Session:     {}", record.session_id.0);
    println!("Reason:      {}", record.reason);
    println!("Issued:      {}", record.issued_at);
    if let Some(expires) = record.expires_at {
        println!("Expires:     {}", expires);
    }
    println!();

    match service.decide(approval_id, approve) {
        Ok(r) => {
            println!("Decision: {}", r.decision);
            println!("Status:   {:?}", r.status);
            println!();
            println!(
                "Approval {}.",
                if r.decision == Decision::Allow {
                    "granted"
                } else {
                    "denied"
                }
            );
            println!();
            println!("The agent's gateway consumes it once; the approval cannot be reused.");
        }
        Err(e) => {
            eprintln!("Approval error: {}", e);
            std::process::exit(1);
        }
    }
}

/// Print one request in full.
fn show_approval(service: &ApprovalService, approval_id: &str) {
    let Some(record) = service.refresh(approval_id) else {
        println!("No approval request found with id: {}", approval_id);
        return;
    };


    println!("AgentFence Approval");
    println!("===================");
    println!("Approval ID:  {}", record.approval_id);
    println!("Status:       {:?}", record.status);
    println!("Action ID:    {}", record.action_id.0);
    println!("Session ID:   {}", record.session_id.0);
    if let Some(agent) = &record.agent_id {
        println!("Agent ID:     {}", agent.0);
    }
    println!("Tool:         {}", record.tool);
    println!("Target:       {}", record.target);
    println!("Action hash:  {}", record.action_digest);
    println!("Reason:       {}", record.reason);
    println!("Scope:        {:?}", record.scope);
    println!("Issued:       {}", record.issued_at);
    println!(
        "Expires:      {}",
        record
            .expires_at
            .map(|t| t.to_rfc3339())
            .unwrap_or_else(|| "never".to_string())
    );
    if let Some(consumed) = record.consumed_at {
        println!("Consumed:     {}", consumed);
    }
    println!("Policy:       {}", record.policy_version);
}

/// List approvals.
fn list_approvals(service: &ApprovalService, all: bool) {
    println!("AgentFence Approvals");
    println!("===================");

    if all {
        let records = service.list_all();
        if records.is_empty() {
            println!();
            println!("No approval requests recorded.");
            return;
        }
        println!();
        for record in records {
            println!(
                "  {}  [{:?}]  {}  {}",
                record.approval_id, record.status, record.tool, record.target
            );
            println!(
                "      action: {}  session: {}  issued: {}",
                record.action_id.0, record.session_id.0, record.issued_at
            );
        }
        println!();
        println!("Use 'agentfence approve show <approval_id>' for detail.");
        return;
    }

    let pending = service.list_pending();

    println!();
    if pending.is_empty() {
        println!("No pending approvals.");
        return;
    }

    for record in pending.iter() {
        println!("  Approval ID: {}", record.approval_id);
        println!("  Action:      {}", record.action_id.0);
        println!("  Tool:        {}", record.tool);
        println!("  Target:      {}", record.target);
        println!("  Session:     {}", record.session_id.0);
        println!("  Reason:      {}", record.reason);
        println!("  Issued:      {}", record.issued_at);
        if let Some(expires) = record.expires_at {
            println!("  Expires:     {}", expires);
        }
        println!();
    }

    println!("Decide with: agentfence approve <approval_id> --decision allow|deny");
}

/// Interactive approval prompt.
fn interactive_prompt(service: &ApprovalService, approval_id: &str) {
    let Some(record) = service.refresh(approval_id) else {
        println!("No approval request found with id: {}", approval_id);
        return;
    };


    println!();
    println!("⚠ ACTION REQUIRES APPROVAL");
    println!();
    println!("Approval ID: {}", record.approval_id);
    println!("Action ID:   {}", record.action_id.0);
    println!("Tool:        {}", record.tool);
    println!("Target:      {}", record.target);
    println!("Session:     {}", record.session_id.0);
    println!("Reason:      {}", record.reason);
    println!("Issued:      {}", record.issued_at);
    if let Some(expires) = record.expires_at {
        println!("Expires:     {}", expires);
    }
    println!();
    println!("[1] Deny");
    println!("[2] Allow");
    println!();
    print!("Choice: ");
    io::stdout().flush().unwrap();

    let mut input = String::new();
    io::stdin().read_line(&mut input).unwrap();

    let approve = match input.trim() {
        "1" => false,
        "2" => true,
        other => {
            eprintln!("Invalid choice: {}", other);
            std::process::exit(1);
        }
    };

    match service.decide(&record.approval_id, approve) {
        Ok(r) => {
            println!();
            println!("Decision: {}", r.decision);
            println!("Status:   {:?}", r.status);
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
