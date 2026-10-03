//! Audit verify command implementation.

use tracing::info;

pub fn execute(session: &str) {
    info!("Verifying audit for session {}", session);

    let db_path = get_db_path();

    let store = match agentfence_audit::sqlite_store::SqliteStore::new(&db_path) {
        Ok(s) => s,
        Err(e) => {
            println!("AgentFence Audit Verify");
            println!("=======================");
            println!("Session: {}", session);
            println!();
            println!("Error opening audit database: {}", e);
            return;
        }
    };

    println!("AgentFence Audit Verify");
    println!("=======================");
    println!("Session: {}", session);
    println!();

    let events = match store.load_events(session) {
        Ok(e) => e,
        Err(e) => {
            println!("Error loading events: {}", e);
            return;
        }
    };

    println!("Events:      {}", events.len());

    let result = store.verify_session(session).unwrap();

    match result {
        agentfence_audit::hashchain::VerificationResult::Valid => {
            println!("Hash chain:  VALID");
            println!("Gaps:        0");
        }
        agentfence_audit::hashchain::VerificationResult::Invalid { event_id, reason } => {
            println!("Hash chain:  INVALID");
            println!("Error at:    {}", event_id);
            println!("Reason:     {}", reason);
        }
        agentfence_audit::hashchain::VerificationResult::Incomplete { expected, found } => {
            println!("Hash chain:  INCOMPLETE");
            println!("Expected:    {} events", expected);
            println!("Found:       {} events", found);
        }
    }

    if let Some(first_event) = events.first() {
        println!("Policy hash: {}", first_event.policy_hash);
    }
}

fn get_db_path() -> String {
    if let Ok(data_dir) = std::env::var("AGENTFENCE_DATA_DIR") {
        format!("{}/agentfence.db", data_dir)
    } else if let Some(data_dir) = dirs_next::data_dir() {
        data_dir
            .join("agentfence")
            .join("agentfence.db")
            .to_string_lossy()
            .to_string()
    } else {
        "agentfence.db".to_string()
    }
}
