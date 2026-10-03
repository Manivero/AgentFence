//! Database helper utilities for CLI commands.

use std::path::PathBuf;

/// Get the default database path.
pub fn get_db_path() -> PathBuf {
    if let Ok(data_dir) = std::env::var("AGENTFENCE_DATA_DIR") {
        PathBuf::from(data_dir).join("agentfence.db")
    } else if let Some(data_dir) = dirs_next::data_dir() {
        data_dir.join("agentfence").join("agentfence.db")
    } else {
        PathBuf::from("agentfence.db")
    }
}

/// Ensure the parent directory exists for the database.
pub fn ensure_db_dir(db_path: &std::path::Path) -> std::io::Result<()> {
    if let Some(parent) = db_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    Ok(())
}
