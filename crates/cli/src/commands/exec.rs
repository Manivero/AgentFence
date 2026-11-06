//! Exec command implementation.

use std::path::Path;

use agentfence_approval::broker::{ApprovalBroker, ApprovalConfig};
use agentfence_core::types::{ActionId, AgentId, Decision, RiskLevel, SessionId};
use agentfence_enforcement::backend::{
    select_backend, ExecutionBackend, ExecutionMode, ExecutionRequest,
};
use agentfence_policy::{parser::load_policy, plugin_loader};
use agentfence_secrets::redact::redact;
use agentfence_shell::{command::ShellCommand, gateway::ShellGateway};
use tracing::{error, info};

use super::db;

pub fn execute(policy_path: &str, command: &[String]) {
    let policy = match load_policy(policy_path) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to load policy: {}", e);
            std::process::exit(1);
        }
    };

    let pdp = match plugin_loader::build_pdp(policy, Vec::new()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("Failed to load policy plugins: {}", e);
            std::process::exit(1);
        }
    };
    let gateway = ShellGateway::new(pdp);

    // SECURITY: the execution backend is selected once, from explicit
    // configuration, before any command is evaluated. If the container backend
    // is selected and its runtime is unavailable or its configuration invalid,
    // the command fails closed: there is no host fallback path.
    let mode = match ExecutionMode::from_env() {
        Ok(m) => m,
        Err(e) => {
            eprintln!("Execution backend unavailable: {}", e);
            std::process::exit(1);
        }
    };
    let backend = match select_backend(mode) {
        Ok(b) => b,
        Err(e) => {
            eprintln!("Execution backend unavailable: {}", e);
            std::process::exit(1);
        }
    };

    let cmd = match ShellCommand::from_argv(command) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("Failed to parse command: {}", e);
            std::process::exit(1);
        }
    };

    let session_id = SessionId::new();
    let agent_id = AgentId::new("cli");

    // SECURITY: the action is built once and used for both the policy decision
    // and any approval request, so the two are bound to the same action id.
    let action = gateway.action_for(&cmd, &session_id, &agent_id);
    let record = gateway.evaluate_action(&action);

    println!("AgentFence Exec");
    println!("===============");
    println!("Command: {}", redact(&cmd.raw).text);
    println!("Decision: {}", record.decision);
    println!("Rule:     {}", record.rule_id);
    println!("Reason:   {}", record.reason);
    println!();

    // Record audit event for the *policy* decision.
    //
    // SECURITY: the audit event must reference the action that was actually
    // evaluated, and must hash the arguments rather than recording a
    // placeholder. `record.action_id` is stamped by the PDP from the evaluated
    // action; minting a fresh id here would leave the audit trail unable to
    // correlate the event with the decision (or with an approval record).
    write_audit(
        &session_id,
        &agent_id,
        &record.action_id,
        &cmd.raw,
        record.decision,
        record.risk_level,
        &record.rule_id,
        &record.policy_version,
    );

    match record.decision {
        Decision::Allow => {
            info!("Executing command: {}", redact(&cmd.raw).text);
            let code = run_backend(backend.as_ref(), &cmd);
            if code != 0 {
                std::process::exit(code);
            }
        }
        Decision::Deny => {
            // P4: a bare `DENIED` is not acceptable. Name the rule that decided
            // and the reason, so a denial is reconstructible from the terminal.
            eprintln!(
                "Command denied by policy: rule '{}' - {}",
                record.rule_id, record.reason
            );
            std::process::exit(1);
        }
        Decision::Ask => {
            // SECURITY: an `Ask` must never silently become `Allow`. The pending
            // request is recorded, the command is NOT executed, and the action is
            // only executed if the operator approves this exact action and the
            // approval is consumed exactly once.
            eprintln!(
                "Command requires approval: rule '{}' - {}",
                record.rule_id, record.reason
            );

            let broker = match ApprovalBroker::open(ApprovalConfig::from_env()) {
                Ok(b) => b,
                Err(e) => {
                    // An approval infrastructure failure must never become an
                    // implicit Allow.
                    eprintln!("Approval service unavailable: {}", e);
                    std::process::exit(1);
                }
            };

            let approval = match broker.request(&action, &record.reason, &record.policy_version) {
                Ok(a) => a,
                Err(e) => {
                    eprintln!("Failed to record approval request: {}", e);
                    std::process::exit(1);
                }
            };

            eprintln!();
            eprintln!("Approval requested: {}", approval.approval_id);
            eprintln!("  Action:   {}", approval.action_id.0);
            eprintln!("  Session:  {}", approval.session_id.0);
            eprintln!(
                "  Expires:  {}",
                approval
                    .expires_at
                    .map(|t| t.to_rfc3339())
                    .unwrap_or_else(|| "never".to_string())
            );
            eprintln!();
            eprintln!(
                "Approve with: agentfence approve {} --decision allow",
                approval.approval_id
            );

            match broker.wait_for(&approval.approval_id, &action, None) {
                Ok(true) => {
                    // SECURITY: the approved execution must be audited as its own
                    // outcome, correlated with the policy's `Ask` event through
                    // the same action id. Without this the audit trail would show
                    // an approval but never record what it authorised.
                    write_audit(
                        &session_id,
                        &agent_id,
                        &record.action_id,
                        &cmd.raw,
                        Decision::Allow,
                        record.risk_level,
                        &record.rule_id,
                        &record.policy_version,
                    );
                    println!("Approved by operator; executing.");
                    info!("Executing approved command: {}", redact(&cmd.raw).text);
                    let code = run_backend(backend.as_ref(), &cmd);
                    if code != 0 {
                        std::process::exit(code);
                    }
                }
                Ok(false) => {
                    eprintln!("Approval not granted within the timeout; command blocked.");
                    std::process::exit(1);
                }
                Err(e) => {
                    eprintln!("Approval failed: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}

/// Execute through the selected backend and propagate output and exit status.
///
/// The backend is the only place a command becomes a process. Both the plain
/// allow path and the approved path go through here, so there is no second
/// route to the runtime.
fn run_backend(backend: &dyn ExecutionBackend, cmd: &ShellCommand) -> i32 {
    let request = ExecutionRequest {
        executable: &cmd.executable,
        arguments: &cmd.arguments,
        cwd: cmd.cwd.as_deref().map(Path::new),
    };

    match backend.execute(&request) {
        Ok(result) => {
            use std::io::Write;
            let _ = std::io::stdout().write_all(&result.stdout);
            let _ = std::io::stdout().flush();
            let _ = std::io::stderr().write_all(&result.stderr);

            if result.timed_out {
                eprintln!("Execution timed out.");
                return 124;
            }
            result.exit_code
        }
        Err(e) => {
            eprintln!("Execution backend failure: {}", e);
            1
        }
    }
}

/// Write one audit event for a shell action.
///
/// SECURITY: the event references the *evaluated* action id, so the policy
/// decision and any later approved execution of the same action can be
/// correlated. Arguments are hashed, never recorded raw.
#[allow(clippy::too_many_arguments)]
fn write_audit(
    session_id: &SessionId,
    agent_id: &AgentId,
    action_id: &ActionId,
    raw_cmd: &str,
    decision: Decision,
    risk_level: RiskLevel,
    rule_id: &str,
    policy_version: &str,
) {
    let db_path = db::get_db_path();
    let _ = db::ensure_db_dir(&db_path);
    if let Ok(store) = agentfence_audit::sqlite_store::SqliteStore::new(&db_path) {
        let event = agentfence_audit::event::AuditEvent::new(
            session_id.clone(),
            agent_id.clone(),
            None,
            action_id.clone(),
            None,
            "shell",
            "shell",
            raw_cmd,
            agentfence_shell::hash::hash_args(raw_cmd),
            decision,
            risk_level,
            rule_id,
            policy_version,
            "",
            "",
        );
        if let Err(e) = store.record_event(&event) {
            error!("Audit write failed: {}", e);
        }
    }
}
