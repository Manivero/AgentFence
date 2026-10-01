//! Logs command implementation.

use tracing::info;

pub fn execute(session: Option<String>, format: &str) {
    info!(
        "Viewing logs for session {:?} in format {}",
        session, format
    );
    println!("AgentFence Logs");
    println!("===============");
    println!();
    println!("Note: Log viewing is not yet implemented in this version.");
    println!("Audit events are stored in JSONL format.");
    println!();
    if let Some(sid) = session {
        println!("Session: {}", sid);
    }
    println!("Format:  {}", format);
}
