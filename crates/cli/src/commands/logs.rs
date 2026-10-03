//! Logs command implementation.

use tracing::info;

pub fn execute(session: Option<String>, format: &str) {
    info!(
        "Viewing logs for session {:?} in format {}",
        session, format
    );

    let db_path = get_db_path();

    let store = match agentfence_audit::sqlite_store::SqliteStore::new(&db_path) {
        Ok(s) => s,
        Err(e) => {
            println!("AgentFence Logs");
            println!("===============");
            println!();
            println!("Error opening audit database: {}", e);
            println!();
            println!("Note: Audit events are stored in SQLite format.");
            return;
        }
    };

    println!("AgentFence Logs");
    println!("===============");
    println!();

    if let Some(sid) = session {
        match store.load_events(&sid) {
            Ok(events) => {
                if events.is_empty() {
                    println!("No events found for session: {}", sid);
                } else {
                    println!("Session: {}", sid);
                    println!("Events:  {}", events.len());
                    println!();

                    if format == "jsonl" {
                        for event in &events {
                            match serde_json::to_string(event) {
                                Ok(json) => println!("{}", json),
                                Err(e) => eprintln!("Error serializing event: {}", e),
                            }
                        }
                    } else {
                        for event in &events {
                            println!(
                                "[{}] {} | {} | {} | {} | {} | {}",
                                event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                                event.event_id,
                                event.action_type,
                                event.tool,
                                event.target,
                                event.decision,
                                event.rule_id
                            );
                        }
                    }
                }
            }
            Err(e) => {
                println!("Error loading events: {}", e);
            }
        }
    } else {
        match store.get_all_events() {
            Ok(events) => {
                if events.is_empty() {
                    println!("No audit events found.");
                } else {
                    println!("Total events: {}", events.len());
                    println!();

                    if format == "jsonl" {
                        for event in &events {
                            match serde_json::to_string(event) {
                                Ok(json) => println!("{}", json),
                                Err(e) => eprintln!("Error serializing event: {}", e),
                            }
                        }
                    } else {
                        for event in &events {
                            println!(
                                "[{}] {} | {} | {} | {} | {} | {}",
                                event.timestamp.format("%Y-%m-%d %H:%M:%S"),
                                event.event_id,
                                event.action_type,
                                event.tool,
                                event.target,
                                event.decision,
                                event.rule_id
                            );
                        }
                    }
                }
            }
            Err(e) => {
                println!("Error loading events: {}", e);
            }
        }
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
