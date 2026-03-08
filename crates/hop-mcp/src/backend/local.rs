//! LocalBackend: wraps the mux agent + JSON stores for local fleet operations.
//!
//! This is the current backend that connects through the hop agent process
//! using Unix IPC, just like the CLI does.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use hop_core::config::{self, KnownHostsStore, PeerRole};
use hop_core::fleet::FleetStore;
use hop_core::proto::{self, AdminRequest, AdminResponse, ClientMessage, HostMessage, RoleDefinition, RoleUpdates};

use crate::backend::OrchestratorBackend;
use crate::js::types::*;

/// Local backend that wraps existing hop infrastructure.
pub struct LocalBackend {
    config_dir: PathBuf,
}

impl LocalBackend {
    pub fn new(config_dir: PathBuf) -> Self {
        Self { config_dir }
    }

    /// Connect to the mux agent, send a MuxConnect, wait for Ready,
    /// send the session request, and return the stream split for reading.
    async fn open_host_stream(
        &self,
        host: &str,
        session_request: &ClientMessage,
    ) -> Result<(
        tokio::net::unix::OwnedWriteHalf,
        tokio::net::unix::OwnedReadHalf,
    )> {
        let mut ipc = ensure_agent(&self.config_dir).await?;

        // Resolve target to host_id + relay_url
        let (host_id_bytes, relay_url) = resolve_target(&self.config_dir, host)?;

        // Send MuxConnect (bincode IPC)
        write_ipc(&mut ipc, &IpcMuxConnect { host_id: host_id_bytes, relay_url }).await?;

        // Read MuxResult
        let result: IpcMuxResult = read_ipc(&mut ipc).await?;
        match result {
            IpcMuxResult::Ready => {}
            IpcMuxResult::Error(msg) => anyhow::bail!("Agent connection to '{host}' failed: {msg}"),
        }

        // Send hop session request on the same stream
        proto::write_message(&mut ipc, session_request).await?;

        let (read, write) = ipc.into_split();
        Ok((write, read))
    }

    /// Send an admin request to a host via the mux agent.
    async fn send_admin_request(
        &self,
        host: &str,
        request: AdminRequest,
    ) -> Result<AdminResponse> {
        let session_request = ClientMessage::RequestAdmin(request);
        let (_write, mut read) = self.open_host_stream(host, &session_request).await?;

        let msg: HostMessage = proto::read_message(&mut read)
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

    /// Execute a command on a host, reading output until Exit.
    async fn exec_on_host(&self, host: &str, command: &str) -> Result<ExecResult> {
        let session_request = ClientMessage::RequestExec {
            command: command.to_string(),
        };
        let (_write, mut read) = self.open_host_stream(host, &session_request).await?;

        let mut stdout = Vec::new();
        let stderr = Vec::new();

        loop {
            let msg: HostMessage = proto::read_message(&mut read)
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

// --- IPC helpers (mirror hop-cli's mux protocol) ---

#[derive(serde::Serialize, serde::Deserialize)]
struct IpcMuxConnect {
    host_id: [u8; 32],
    relay_url: Option<String>,
}

#[derive(serde::Deserialize)]
enum IpcMuxResult {
    Ready,
    Error(String),
}

async fn write_ipc<T: serde::Serialize>(stream: &mut UnixStream, msg: &T) -> Result<()> {
    let payload =
        bincode::serde::encode_to_vec(msg, bincode::config::standard()).context("encode IPC")?;
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).await?;
    stream.write_all(&payload).await?;
    stream.flush().await?;
    Ok(())
}

async fn read_ipc<T: for<'de> serde::Deserialize<'de>>(stream: &mut UnixStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).await?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        anyhow::bail!("IPC frame too large: {len} bytes");
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).await?;
    let (msg, _) = bincode::serde::decode_from_slice(&payload, bincode::config::standard())
        .context("decode IPC")?;
    Ok(msg)
}

/// Connect to a running agent, or start one.
async fn ensure_agent(config_dir: &Path) -> Result<UnixStream> {
    let sock = config_dir.join("agent.sock");

    if let Ok(stream) = UnixStream::connect(&sock).await {
        return Ok(stream);
    }

    let exe = std::env::current_exe().context("could not determine hop executable path")?;
    std::process::Command::new(exe)
        .args(["agent", "--daemon", "--config"])
        .arg(config_dir)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .context("failed to spawn agent process")?;

    for i in 0..20 {
        tokio::time::sleep(std::time::Duration::from_millis(50 * (i + 1))).await;
        if let Ok(stream) = UnixStream::connect(&sock).await {
            return Ok(stream);
        }
    }
    anyhow::bail!("Agent failed to start within timeout")
}

/// Resolve a target name to (host_id_bytes, relay_url).
fn resolve_target(config_dir: &Path, target: &str) -> Result<([u8; 32], Option<String>)> {
    let hosts = KnownHostsStore::load(config_dir)?;

    if let Some(node_id_str) = hosts.resolve_alias(target) {
        let pk: iroh::PublicKey = node_id_str.parse().context("Invalid NodeId in known_hosts")?;
        let relay = hosts
            .hosts
            .iter()
            .find(|h| h.node_id == node_id_str)
            .and_then(|h| h.relay_url.clone());
        return Ok((*pk.as_bytes(), relay));
    }

    // Try parsing as NodeId directly
    let pk: iroh::PublicKey = target
        .parse()
        .with_context(|| format!("Unknown host: {target}"))?;
    Ok((*pk.as_bytes(), None))
}

#[async_trait]
impl OrchestratorBackend for LocalBackend {
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
        let hosts = self.list_hosts(Some(group)).await?;
        let mut handles = Vec::new();

        for host in hosts {
            let config_dir = self.config_dir.clone();
            let cmd = command.to_string();
            let host_name = host.name.clone();
            handles.push(tokio::spawn(async move {
                let backend = LocalBackend::new(config_dir);
                match backend.exec_on_host(&host_name, &cmd).await {
                    Ok(result) => FleetExecResult {
                        host: host_name,
                        stdout: result.stdout,
                        stderr: result.stderr,
                        exit_code: result.exit_code,
                    },
                    Err(e) => FleetExecResult {
                        host: host_name,
                        stdout: String::new(),
                        stderr: format!("Connection error: {e}"),
                        exit_code: -1,
                    },
                }
            }));
        }

        let mut results = Vec::new();
        for handle in handles {
            results.push(handle.await?);
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

    async fn fs_push(
        &self,
        _host: &str,
        _local_path: &str,
        _remote_path: &str,
    ) -> Result<TransferResult> {
        anyhow::bail!("File push not yet implemented in MCP mode")
    }

    async fn fs_pull(
        &self,
        _host: &str,
        _remote_path: &str,
        _local_path: &str,
    ) -> Result<TransferResult> {
        anyhow::bail!("File pull not yet implemented in MCP mode")
    }

    async fn push_metrics(&self, points: Vec<hop_core::proto::PushMetricPoint>) -> Result<usize> {
        // For local backend, push metrics to "self" (the orchestrator host).
        // Uses the first known host or errors if no hosts are configured.
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
