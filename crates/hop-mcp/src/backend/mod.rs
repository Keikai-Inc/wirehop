//! OrchestratorBackend trait and implementations.
//!
//! Abstracts fleet operations so the JS bindings work with both
//! the local mux agent (current) and keik.ai (future).

pub mod direct;
pub mod local;

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use crate::js::types::*;
use hop_core::proto::RoleDefinition;

pub type BoxedBackend = Arc<dyn OrchestratorBackend>;

#[async_trait]
pub trait OrchestratorBackend: Send + Sync {
    /// List fleet hosts, optionally filtered by tag.
    async fn list_hosts(&self, tag_filter: Option<&str>) -> Result<Vec<HostInfo>>;

    /// Resolve a host name/alias to connection info.
    async fn resolve_host(&self, name_or_id: &str) -> Result<Option<String>>;

    /// Execute a command on a single host.
    async fn exec(&self, host: &str, command: &str) -> Result<ExecResult>;

    /// Execute a command across a fleet group (parallel).
    async fn fleet_exec(&self, group: &str, command: &str) -> Result<Vec<FleetExecResult>>;

    /// Get admin status from a host.
    async fn admin_status(&self, host: &str) -> Result<HostStatus>;

    /// List peers on a host.
    async fn admin_peers(&self, host: &str) -> Result<Vec<PeerInfo>>;

    /// Create an invite on a remote host.
    async fn admin_invite(&self, host: &str, username: Option<&str>, role: Option<&str>) -> Result<String>;

    /// Create a Unix user on a remote host.
    async fn admin_create_user(
        &self,
        host: &str,
        username: &str,
        sudo: bool,
        groups: &[String],
        shell: Option<&str>,
    ) -> Result<String>;

    /// Remove a peer from a remote host.
    async fn admin_remove_peer(&self, host: &str, node_id_prefix: &str) -> Result<bool>;

    /// List role definitions.
    async fn list_roles(&self, host: &str) -> Result<Vec<RoleDefinition>>;

    /// Create a role.
    async fn create_role(&self, host: &str, definition: &RoleDefinition) -> Result<String>;

    /// Update a role.
    async fn update_role(&self, host: &str, name: &str, updates: &serde_json::Value) -> Result<()>;

    /// Delete a role.
    async fn delete_role(&self, host: &str, name: &str) -> Result<()>;

    /// Push a file to a host.
    async fn fs_push(&self, host: &str, local_path: &str, remote_path: &str) -> Result<TransferResult>;

    /// Pull a file from a host.
    async fn fs_pull(&self, host: &str, remote_path: &str, local_path: &str) -> Result<TransferResult>;

    /// Push metric points to the orchestrator's datastore via admin channel.
    async fn push_metrics(&self, points: Vec<hop_core::proto::PushMetricPoint>) -> Result<usize>;

    /// Get our own NodeId.
    fn whoami(&self) -> Result<UserInfo>;
}
