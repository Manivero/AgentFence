// Prevents an extra console window on Windows in release mode.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
struct AuditEvent {
    event_id: String,
    session_id: String,
    agent_id: String,
    action_type: String,
    tool: String,
    target: String,
    decision: String,
    risk_level: String,
    rule_id: String,
    timestamp: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct ApprovalRequest {
    approval_id: String,
    action_id: String,
    session_id: String,
    tool: String,
    target: String,
    reason: String,
    requested_at: String,
}

#[tauri::command]
fn get_audit_events() -> Result<Vec<AuditEvent>, String> {
    Ok(vec![])
}

#[tauri::command]
fn get_pending_approvals() -> Result<Vec<ApprovalRequest>, String> {
    Ok(vec![])
}

#[tauri::command]
fn approve_action(approval_id: String) -> Result<(), String> {
    println!("Approving action: {}", approval_id);
    Ok(())
}

#[tauri::command]
fn deny_action(approval_id: String) -> Result<(), String> {
    println!("Denying action: {}", approval_id);
    Ok(())
}

#[tauri::command]
fn save_policy(policy_content: String) -> Result<(), String> {
    let home = std::env::var("HOME").map_err(|e| e.to_string())?;
    let policy_path = PathBuf::from(home).join(".agentfence").join("agentfence.yaml");
    if let Some(parent) = policy_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&policy_path, policy_content).map_err(|e| e.to_string())?;
    Ok(())
}

#[tauri::command]
fn load_policy() -> Result<String, String> {
    let home = std::env::var("HOME").map_err(|e| e.to_string())?;
    let policy_path = PathBuf::from(home).join(".agentfence").join("agentfence.yaml");
    if policy_path.exists() {
        fs::read_to_string(&policy_path).map_err(|e| e.to_string())
    } else {
        Ok("# AgentFence Policy\nversion: 1\n\ndefaults:\n  shell: deny\n  network: deny\n  mcp: deny\n  filesystem: deny\n".to_string())
    }
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .invoke_handler(tauri::generate_handler![
            get_audit_events,
            get_pending_approvals,
            approve_action,
            deny_action,
            save_policy,
            load_policy
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
