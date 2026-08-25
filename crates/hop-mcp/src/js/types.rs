//! Serde types for the JS<->Rust boundary.

use serde::{Deserialize, Serialize};

/// Result of executing a command on a single host.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExecResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Result of a fleet-wide exec.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FleetExecResult {
    pub host: String,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

/// Host info returned by hop.fleet.list() and hop.hosts().
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostInfo {
    pub name: String,
    pub node_id: String,
    pub tags: Vec<String>,
    pub online: bool,
}

/// Host status returned by hop.admin.status().
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HostStatus {
    pub version: String,
    pub peer_count: usize,
    pub active_sessions: usize,
}

/// Peer info returned by hop.admin.peers().
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PeerInfo {
    pub node_id: String,
    pub name: String,
    pub role: String,
    pub last_seen: Option<String>,
}

/// File transfer result.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TransferResult {
    pub success: bool,
    pub bytes_transferred: u64,
}

/// User info returned by hop.whoami() / hop.id().
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserInfo {
    pub node_id: String,
}
