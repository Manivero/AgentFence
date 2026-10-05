//! Audit export command implementation.

use tracing::info;

use super::db;

pub fn execute(session: Option<String>, output: &str) {
    info!(
        "Exporting audit events for session {:?} to {}",
        session, output
    );

    let db_path = db::get_db_path();

    let store = match agentfence_audit::sqlite_store::SqliteStore::new(&db_path) {
        Ok(s) => s,
        Err(e) => {
            println!("AgentFence Audit Export");
            println!("=======================");
            println!();
            println!("Error opening audit database: {}", e);
            println!();
            println!("Note: Audit events are stored in SQLite format.");
            return;
        }
    };

    println!("AgentFence Audit Export");
    println!("=======================");
    println!();

    let result = if let Some(sid) = session {
        println!("Session: {}", sid);
        store.export_jsonl(&sid, output)
    } else {
        println!("Exporting all sessions...");
        // Export all events by using empty session ID (exports everything)
        store.export_jsonl("", output)
    };

    match result {
        Ok(_) => {
            println!("Export complete: {}", output);
            println!();
            println!("Note: Exported events include hash chain metadata.");
            println!("      Use 'agentguard audit verify' to validate integrity.");
        }
        Err(e) => {
            println!("Export failed: {}", e);
        }
    }
}
