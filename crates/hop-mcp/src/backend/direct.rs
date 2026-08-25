//! DirectBackend: uses the daemon's own iroh endpoint for outgoing connections.
//!
//! Unlike LocalBackend (which spawns a separate mux agent process), this backend
//! connects to remote hosts directly through the endpoint that the daemon already
//! owns. This is the correct backend for cron jobs running inside the daemon.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use iroh::endpoint::Connection;
use iroh::{Endpoint, PublicKey};
use tokio::sync::Mutex;

use hop_core::config::{self, KnownHostsStore, PeerRole};
use hop_core::fleet::FleetStore;
use hop_core::net;
use hop_core::proto::{
    self, AdminRequest, AdminResponse, ClientMessage, HostMessage, RoleDefinition, RoleUpdates,
};

use crate::backend::OrchestratorBackend;
use crate::js::types::*;
use hop_core::sandbox::SandboxPolicy;

/// Backend that uses an existing iroh endpoint to connect to remote hosts.
///
/// Maintains a connection pool so multiple operations to the same host reuse
/// a single QUIC connection, opening new bi-streams for each operation (same
/// pattern as the mux agent).
pub struct DirectBackend {
    endpoint: Arc<Endpoint>,
    config_dir: PathBuf,
    connections: Mutex<HashMap<PublicKey, Connection>>,
}

impl DirectBackend {
    pub fn new(endpoint: Arc<Endpoint>, config_dir: PathBuf) -> Self {
        Self {
            endpoint,
            config_dir,
            connections: Mutex::new(HashMap::new()),
        }
    }

    /// Get an existing live connection or create a new one (same pattern as agent.rs).
    async fn get_or_connect(
        &self,
        host_id: PublicKey,
        relay_url: Option<&iroh::RelayUrl>,
    ) -> Result<Connection> {
        let mut conns = self.connections.lock().await;

        if let Some(conn) = conns.get(&host_id) {
            if conn.close_reason().is_none() {
                return Ok(conn.clone());
            }
            conns.remove(&host_id);
        }

        let (conn, _direct) =
            net::connect_to_host(&self.endpoint, host_id, relay_url).await?;

        conns.insert(host_id, conn.clone());
        Ok(conn)
    }

    /// Open a bi-directional QUIC stream to a remote host and send a session request.
    async fn open_host_stream(
        &self,
        host: &str,
        session_request: &ClientMessage,
    ) -> Result<(
        iroh::endpoint::SendStream,
        iroh::endpoint::RecvStream,
    )> {
        let (pk, relay_url) = resolve_target(&self.config_dir, host)?;
        let public_key = PublicKey::from_bytes(&pk)?;
        let relay = relay_url
            .as_ref()
            .and_then(|u| u.parse::<iroh::RelayUrl>().ok());

        let conn = self.get_or_connect(public_key, relay.as_ref()).await?;

        let bi_result = conn.open_bi().await;
        let (mut send, recv) = match bi_result {
            Ok(pair) => pair,
            Err(_) => {
                // Connection went stale — remove from pool and reconnect
                self.connections.lock().await.remove(&public_key);
                let conn = self.get_or_connect(public_key, relay.as_ref()).await?;
                conn.open_bi().await.context("Failed to open bi-stream")?
            }
        };

        // Send the session request (hop protocol)
        proto::write_message(&mut send, session_request).await?;

        Ok((send, recv))
    }

    /// Send an admin request to a remote host.
    async fn send_admin_request(
        &self,
        host: &str,
        request: AdminRequest,
    ) -> Result<AdminResponse> {
        let session_request = ClientMessage::RequestAdmin(request);
        let timeout = std::time::Duration::from_secs(30);
        let (_send, mut recv) = tokio::time::timeout(
            timeout,
            self.open_host_stream(host, &session_request),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Admin request to '{host}' timed out after 30s"))??;

        let msg: HostMessage = proto::read_message(&mut recv)
            .await
            .context("Failed to read admin response")?;

        match msg {
            HostMessage::AdminResponse(resp) => Ok(resp),
            HostMessage::AuthResult { authorized: false } => {
                anyhow::bail!("Not authorized on host '{host}' (need Creator role)")
            }
            other => anyhow::bail!("Unexpected response from host: {other:?}"),
        }
    }

    /// Execute a command on a host with a 60-second timeout.
    async fn exec_on_host(&self, host: &str, command: &str) -> Result<ExecResult> {
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            self.exec_on_host_inner(host, command),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Exec on '{host}' timed out after 60s"))?
    }

    /// Execute a command on a host with a sandbox policy and 60-second timeout.
    async fn exec_on_host_sandboxed(
        &self,
        host: &str,
        command: &str,
        sandbox: &SandboxPolicy,
    ) -> Result<ExecResult> {
        tokio::time::timeout(
            std::time::Duration::from_secs(60),
            self.exec_on_host_sandboxed_inner(host, command, sandbox),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Exec on '{host}' timed out after 60s"))?
    }

    async fn exec_on_host_sandboxed_inner(
        &self,
        host: &str,
        command: &str,
        sandbox: &SandboxPolicy,
    ) -> Result<ExecResult> {
        let session_request = ClientMessage::RequestExecV2 {
            command: command.to_string(),
            sandbox: sandbox.clone(),
        };
        let (_send, mut recv) = self.open_host_stream(host, &session_request).await?;

        let mut stdout = Vec::new();
        let stderr = Vec::new();

        loop {
            let msg: HostMessage = proto::read_message(&mut recv)
                .await
                .context("Connection lost during exec")?;

            match msg {
                HostMessage::Output(data) => stdout.extend_from_slice(&data),
                HostMessage::Exit(code) => {
                    return Ok(ExecResult {
                        stdout: String::from_utf8_lossy(&stdout).into_owned(),
                        stderr: String::from_utf8_lossy(&stderr).into_owned(),
                        exit_code: code,
                    });
                }
                HostMessage::AuthResult { authorized: false } => {
                    anyhow::bail!("Not authorized on host '{host}'")
                }
                _ => {} // Ignore WindowSizeAck etc.
            }
        }
    }

    async fn exec_on_host_inner(&self, host: &str, command: &str) -> Result<ExecResult> {
        let session_request = ClientMessage::RequestExec {
            command: command.to_string(),
        };
        let (_send, mut recv) = self.open_host_stream(host, &session_request).await?;

        let mut stdout = Vec::new();
        let stderr = Vec::new();

        loop {
            let msg: HostMessage = proto::read_message(&mut recv)
                .await
                .context("Connection lost during exec")?;

            match msg {
                HostMessage::Output(data) => stdout.extend_from_slice(&data),
                HostMessage::Exit(code) => {
                    return Ok(ExecResult {
                        stdout: String::from_utf8_lossy(&stdout).into_owned(),
                        stderr: String::from_utf8_lossy(&stderr).into_owned(),
                        exit_code: code,
                    });
                }
                HostMessage::AuthResult { authorized: false } => {
                    anyhow::bail!("Not authorized on host '{host}'")
                }
                _ => {} // Ignore WindowSizeAck etc.
            }
        }
    }
}

/// Resolve a target name to (node_id_bytes, optional_relay_url).
fn resolve_target(config_dir: &Path, target: &str) -> Result<([u8; 32], Option<String>)> {
    // 1. Try KnownHostsStore aliases first
    if let Ok(hosts) = KnownHostsStore::load(config_dir)
        && let Some(node_id_str) = hosts.resolve_alias(target)
    {
        let pk: iroh::PublicKey = node_id_str.parse().context("Invalid NodeId in known_hosts")?;
        let relay = hosts
            .hosts
            .iter()
            .find(|h| h.node_id == node_id_str)
            .and_then(|h| h.relay_url.clone());
        return Ok((*pk.as_bytes(), relay));
    }

    // 2. Try FleetStore — match by hostname
    if let Ok(fleet) = FleetStore::load(config_dir)
        && let Some(member) = fleet.members.iter().find(|m| m.hostname == target)
    {
        let pk: iroh::PublicKey = member.node_id.parse().context("Invalid NodeId in fleet")?;
        return Ok((*pk.as_bytes(), member.relay_url.clone()));
    }

    // 3. Try parsing as raw NodeId
    let pk: iroh::PublicKey = target
        .parse()
        .with_context(|| format!("Unknown host: {target}"))?;
    Ok((*pk.as_bytes(), None))
}

#[async_trait]
impl OrchestratorBackend for DirectBackend {
    async fn list_hosts(&self, tag_filter: Option<&str>) -> Result<Vec<HostInfo>> {
        let fleet = FleetStore::load(&self.config_dir)?;
        Ok(fleet
            .members
            .iter()
            .filter(|m| {
                tag_filter
                    .map(|tag| m.tags.iter().any(|t| t == tag))
                    .unwrap_or(true)
            })
            .map(|m| HostInfo {
                name: m.hostname.clone(),
                node_id: m.node_id.clone(),
                tags: m.tags.clone(),
                online: m.online,
            })
            .collect())
    }

    async fn resolve_host(&self, name_or_id: &str) -> Result<Option<String>> {
        let hosts = KnownHostsStore::load(&self.config_dir)?;
        Ok(hosts.resolve_alias(name_or_id).map(String::from))
    }

    async fn exec(&self, host: &str, command: &str) -> Result<ExecResult> {
        self.exec_on_host(host, command).await
    }

    async fn fleet_exec(&self, group: &str, command: &str) -> Result<Vec<FleetExecResult>> {
        let tag_filter = if group == "*" { None } else { Some(group) };
        let hosts = self.list_hosts(tag_filter).await?;
        let mut results = Vec::new();

        // Execute sequentially. Each call reuses the connection pool, so the
        // first exec to a host pays the handshake cost and subsequent calls
        // open new bi-streams on the existing connection.
        for host in hosts {
            let host_name = host.name.clone();
            match self.exec_on_host(&host_name, command).await {
                Ok(result) => results.push(FleetExecResult {
                    host: host_name,
                    stdout: result.stdout,
                    stderr: result.stderr,
                    exit_code: result.exit_code,
                }),
                Err(e) => results.push(FleetExecResult {
                    host: host_name,
                    stdout: String::new(),
                    stderr: format!("Connection error: {e}"),
                    exit_code: -1,
                }),
            }
        }
        Ok(results)
    }

    async fn admin_status(&self, host: &str) -> Result<HostStatus> {
        match self.send_admin_request(host, AdminRequest::Status).await? {
            AdminResponse::HostStatus {
                version,
                peer_count,
                active_sessions,
            } => Ok(HostStatus {
                version,
                peer_count,
                active_sessions,
            }),
            AdminResponse::Error { message } => anyhow::bail!("{message}"),
            _ => anyhow::bail!("Unexpected response"),
        }
    }

    async fn admin_peers(&self, host: &str) -> Result<Vec<PeerInfo>> {
        match self.send_admin_request(host, AdminRequest::ListPeers).await? {
            AdminResponse::PeerList { peers } => Ok(peers
                .into_iter()
                .map(|p| PeerInfo {
                    node_id: p.node_id,
                    name: p.name,
                    role: format!("{:?}", p.role),
                    last_seen: p.last_seen,
                })
                .collect()),
            AdminResponse::Error { message } => anyhow::bail!("{message}"),
            _ => anyhow::bail!("Unexpected response"),
        }
    }

    async fn admin_invite(
        &self,
        host: &str,
        username: Option<&str>,
        _role: Option<&str>,
    ) -> Result<String> {
        match self
            .send_admin_request(
                host,
                AdminRequest::CreateInvite {
                    username: username.map(String::from),
                    role: PeerRole::Peer,
                    role_name: None,
                },
            )
            .await?
        {
            AdminResponse::InviteCreated { token } => Ok(token),
            AdminResponse::Error { message } => anyhow::bail!("{message}"),
            _ => anyhow::bail!("Unexpected response"),
        }
    }

    async fn admin_create_user(
        &self,
        host: &str,
        username: &str,
        sudo: bool,
        groups: &[String],
        shell: Option<&str>,
    ) -> Result<String> {
        match self
            .send_admin_request(
                host,
                AdminRequest::CreateUser {
                    username: username.to_string(),
                    sudo,
                    admin: false,
                    groups: groups.to_vec(),
                    shell: shell.map(String::from),
                    invite: true,
                },
            )
            .await?
        {
            AdminResponse::UserCreated {
                username,
                invite_token,
            } => Ok(invite_token.unwrap_or_else(|| format!("User {username} created"))),
            AdminResponse::Error { message } => anyhow::bail!("{message}"),
            _ => anyhow::bail!("Unexpected response"),
        }
    }

    async fn admin_remove_peer(&self, host: &str, node_id_prefix: &str) -> Result<bool> {
        match self
            .send_admin_request(
                host,
                AdminRequest::RemovePeer {
                    node_id_prefix: node_id_prefix.to_string(),
                },
            )
            .await?
        {
            AdminResponse::PeerRemoved { success } => Ok(success),
            AdminResponse::Error { message } => anyhow::bail!("{message}"),
            _ => anyhow::bail!("Unexpected response"),
        }
    }

    async fn list_roles(&self, host: &str) -> Result<Vec<RoleDefinition>> {
        match self.send_admin_request(host, AdminRequest::ListRoles).await? {
            AdminResponse::RoleList { roles } => Ok(roles),
            AdminResponse::Error { message } => anyhow::bail!("{message}"),
            _ => anyhow::bail!("Unexpected response"),
        }
    }

    async fn create_role(&self, host: &str, definition: &RoleDefinition) -> Result<String> {
        match self
            .send_admin_request(
                host,
                AdminRequest::CreateRole {
                    definition: definition.clone(),
                },
            )
            .await?
        {
            AdminResponse::RoleCreated { name } => Ok(name),
            AdminResponse::Error { message } => anyhow::bail!("{message}"),
            _ => anyhow::bail!("Unexpected response"),
        }
    }

    async fn update_role(&self, host: &str, name: &str, updates: &serde_json::Value) -> Result<()> {
        let role_updates: RoleUpdates =
            serde_json::from_value(updates.clone()).context("Invalid role updates")?;
        match self
            .send_admin_request(
                host,
                AdminRequest::UpdateRole {
                    name: name.to_string(),
                    updates: role_updates,
                },
            )
            .await?
        {
            AdminResponse::RoleUpdated { .. } => Ok(()),
            AdminResponse::Error { message } => anyhow::bail!("{message}"),
            _ => anyhow::bail!("Unexpected response"),
        }
    }

    async fn delete_role(&self, host: &str, name: &str) -> Result<()> {
        match self
            .send_admin_request(
                host,
                AdminRequest::DeleteRole {
                    name: name.to_string(),
                },
            )
            .await?
        {
            AdminResponse::RoleDeleted { .. } => Ok(()),
            AdminResponse::Error { message } => anyhow::bail!("{message}"),
            _ => anyhow::bail!("Unexpected response"),
        }
    }

    async fn exec_sandboxed(
        &self,
        host: &str,
        command: &str,
        sandbox: &SandboxPolicy,
    ) -> Result<ExecResult> {
        self.exec_on_host_sandboxed(host, command, sandbox).await
    }

    async fn fleet_exec_sandboxed(
        &self,
        group: &str,
        command: &str,
        sandbox: &SandboxPolicy,
    ) -> Result<Vec<FleetExecResult>> {
        let tag_filter = if group == "*" { None } else { Some(group) };
        let hosts = self.list_hosts(tag_filter).await?;
        let mut results = Vec::new();

        for host in hosts {
            let host_name = host.name.clone();
            match self
                .exec_on_host_sandboxed(&host_name, command, sandbox)
                .await
            {
                Ok(result) => results.push(FleetExecResult {
                    host: host_name,
                    stdout: result.stdout,
                    stderr: result.stderr,
                    exit_code: result.exit_code,
                }),
                Err(e) => results.push(FleetExecResult {
                    host: host_name,
                    stdout: String::new(),
                    stderr: format!("Connection error: {e}"),
                    exit_code: -1,
                }),
            }
        }
        Ok(results)
    }

    async fn fs_push(
        &self,
        _host: &str,
        _local_path: &str,
        _remote_path: &str,
    ) -> Result<TransferResult> {
        anyhow::bail!("File push not yet implemented in direct mode")
    }

    async fn fs_pull(
        &self,
        _host: &str,
        _remote_path: &str,
        _local_path: &str,
    ) -> Result<TransferResult> {
        anyhow::bail!("File pull not yet implemented in direct mode")
    }

    async fn push_metrics(&self, points: Vec<hop_core::proto::PushMetricPoint>) -> Result<usize> {
        let hosts = self.list_hosts(None).await?;
        let host = hosts
            .first()
            .map(|h| h.name.clone())
            .unwrap_or_else(|| "localhost".to_string());

        match self
            .send_admin_request(
                &host,
                AdminRequest::PushMetrics { points },
            )
            .await?
        {
            AdminResponse::MetricsReceived { count } => Ok(count),
            AdminResponse::Error { message } => anyhow::bail!("{message}"),
            _ => anyhow::bail!("Unexpected response"),
        }
    }

    fn whoami(&self) -> Result<UserInfo> {
        let secret_key = config::load_identity(&self.config_dir)?;
        let public_key = secret_key.public();
        Ok(UserInfo {
            node_id: public_key.to_string(),
        })
    }
}
