// Prevents an extra console window on Windows in release mode.
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;
use tauri::{Manager, State};

#[derive(Debug, Serialize, Deserialize, Clone)]
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

#[derive(Debug, Serialize, Deserialize, Clone)]
struct ApprovalRequest {
    approval_id: String,
    action_id: String,
    session_id: String,
    tool: String,
    target: String,
    reason: String,
    requested_at: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
struct PolicyUpdate {
    content: String,
    timestamp: String,
}

struct AppState {
    audit_events: Mutex<Vec<AuditEvent>>,
    pending_approvals: Mutex<Vec<ApprovalRequest>>,
}

#[tauri::command]
fn get_audit_events(state: State<AppState>) -> Result<Vec<AuditEvent>, String> {
    Ok(state.audit_events.lock().unwrap().clone())
}

#[tauri::command]
fn get_pending_approvals(state: State<AppState>) -> Result<Vec<ApprovalRequest>, String> {
    Ok(state.pending_approvals.lock().unwrap().clone())
}

#[tauri::command]
fn approve_action(approval_id: String, state: State<AppState>) -> Result<(), String> {
    println!("Approving action: {}", approval_id);
    let mut approvals = state.pending_approvals.lock().unwrap();
    approvals.retain(|a| a.approval_id != approval_id);
    Ok(())
}

#[tauri::command]
fn deny_action(approval_id: String, state: State<AppState>) -> Result<(), String> {
    println!("Denying action: {}", approval_id);
    let mut approvals = state.pending_approvals.lock().unwrap();
    approvals.retain(|a| a.approval_id != approval_id);
    Ok(())
}

#[tauri::command]
fn save_policy(policy_content: String, state: State<AppState>) -> Result<(), String> {
    let home = std::env::var("HOME").map_err(|e| e.to_string())?;
    let policy_path = PathBuf::from(home).join(".agentfence").join("agentfence.yaml");
    if let Some(parent) = policy_path.parent() {
        fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    fs::write(&policy_path, &policy_content).map_err(|e| e.to_string())?;
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

#[tauri::command]
fn emit_audit_event(event: AuditEvent, state: State<AppState>) -> Result<(), String> {
    let mut events = state.audit_events.lock().unwrap();
    events.push(event);
    Ok(())
}

#[tauri::command]
fn emit_approval_request(request: ApprovalRequest, state: State<AppState>) -> Result<(), String> {
    let mut approvals = state.pending_approvals.lock().unwrap();
    approvals.push(request);
    Ok(())
}

fn main() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState {
            audit_events: Mutex::new(Vec::new()),
            pending_approvals: Mutex::new(Vec::new()),
        })
        .invoke_handler(tauri::generate_handler![
            get_audit_events,
            get_pending_approvals,
            approve_action,
            deny_action,
            save_policy,
            load_policy,
            emit_audit_event,
            emit_approval_request
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
