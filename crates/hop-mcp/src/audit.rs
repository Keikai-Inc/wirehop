//! MCP audit trail logging.
//!
//! Appends JSON lines to mcp_audit.jsonl for every tool invocation.

use std::io::Write;
use std::path::Path;

use serde::Serialize;

/// A single audit log entry.
#[derive(Debug, Serialize)]
pub struct AuditEntry {
    pub timestamp: String,
    pub tool: String,
    pub host: Option<String>,
    pub arguments: serde_json::Value,
    pub result_summary: String,
    pub duration_ms: u64,
    pub success: bool,
}

/// Append an audit entry to the audit log.
pub fn log_entry(config_dir: &Path, entry: &AuditEntry) {
    let path = config_dir.join("mcp_audit.jsonl");
    let line = match serde_json::to_string(entry) {
        Ok(l) => l,
        Err(e) => {
            tracing::warn!("Failed to serialize audit entry: {e}");
            return;
        }
    };

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = writeln!(file, "{line}");
    } else {
        tracing::warn!("Failed to open audit log: {}", path.display());
    }
}
