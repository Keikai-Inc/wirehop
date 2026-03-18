//! Client-side connection multiplexer IPC protocol and helpers.
//!
//! Provides the IPC protocol for communicating with the hop agent process,
//! and helpers for auto-starting the agent and connecting to remote hosts
//! through it.

use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixStream;

use hop_core::config::KnownHostsStore;
use hop_core::invite;
use hop_core::proto::{self, ClientMessage, HostMessage};

/// Client → Agent: request to connect to a host.
#[derive(Debug, Serialize, Deserialize)]
pub struct MuxConnect {
    /// Target host's PublicKey (32 bytes).
    pub host_id: [u8; 32],
    /// Optional relay URL hint for first connection to this host.
    pub relay_url: Option<String>,
}

/// Agent → Client: connection result.
#[derive(Debug, Serialize, Deserialize)]
pub enum MuxResult {
    /// Connection ready — bi-stream open, start sending hop protocol messages.
    Ready,
    /// Connection failed.
    Error(String),
}

/// Path to the agent Unix socket.
pub fn agent_sock_path(config_dir: &Path) -> PathBuf {
    config_dir.join("agent.sock")
}

/// Path to the agent PID file.
pub fn agent_pid_path(config_dir: &Path) -> PathBuf {
    config_dir.join("agent.pid")
}

/// Write a length-prefixed bincode IPC message.
pub async fn write_ipc_message<T: Serialize>(
    stream: &mut (impl AsyncWriteExt + Unpin),
    msg: &T,
) -> Result<()> {
    let payload =
        bincode::serde::encode_to_vec(msg, bincode::config::standard()).context("encode failed")?;
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).await.context("write IPC length")?;
    stream
        .write_all(&payload)
        .await
        .context("write IPC payload")?;
    stream.flush().await.context("flush IPC")?;
    Ok(())
}

/// Read a length-prefixed bincode IPC message.
pub async fn read_ipc_message<T: for<'de> Deserialize<'de>>(
    stream: &mut (impl AsyncReadExt + Unpin),
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("read IPC length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > 16 * 1024 * 1024 {
        anyhow::bail!("IPC frame too large: {len} bytes");
    }
    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .context("read IPC payload")?;
    let (msg, _) = bincode::serde::decode_from_slice(&payload, bincode::config::standard())
        .context("decode IPC message")?;
    Ok(msg)
}

/// Connect to a running agent, or start one if none is running.
///
/// Returns a connected UnixStream to the agent.
pub async fn ensure_agent(config_dir: &Path) -> Result<UnixStream> {
    let sock = agent_sock_path(config_dir);

    // Try existing agent
    if let Ok(stream) = UnixStream::connect(&sock).await {
        return Ok(stream);
    }

    // Start agent in background
    let exe = std::env::current_exe().context("could not determine hop executable path")?;
    std::process::Command::new(exe)
        .args(["agent", "--daemon", "--config"])
        .arg(config_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("failed to spawn agent process")?;

    // Wait for agent to be ready (retry with backoff)
    for i in 0..20 {
        tokio::time::sleep(Duration::from_millis(50 * (i + 1))).await;
        if let Ok(stream) = UnixStream::connect(&sock).await {
            return Ok(stream);
        }
    }
    anyhow::bail!("Agent failed to start within timeout")
}

/// Resolved target info retained for reconnection.
pub struct ResolvedHost {
    pub host_id: iroh::PublicKey,
    pub relay_url: Option<iroh::RelayUrl>,
}

/// Connect to a host through the agent. Handles target resolution (alias, invite,
/// direct NodeId), agent IPC handshake, and the hop auth/session protocol.
///
/// Returns the resolved host info plus the IPC socket split into read/write halves,
/// ready for the session protocol.
pub async fn connect_to_host(
    config_dir: &Path,
    target: &str,
    cli_name: Option<&str>,
    session_request: &ClientMessage,
) -> Result<(
    ResolvedHost,
    tokio::net::unix::OwnedWriteHalf,
    tokio::net::unix::OwnedReadHalf,
)> {
    // --- Target resolution ---

    // 1. Check known_hosts for alias match
    let hosts = KnownHostsStore::load(config_dir)?;
    if let Some(node_id_str) = hosts.resolve_alias(target) {
        let host_id: iroh::PublicKey = node_id_str
            .parse()
            .context("Invalid NodeId in known_hosts")?;

        let relay_url: Option<iroh::RelayUrl> = hosts
            .hosts
            .iter()
            .find(|h| h.node_id == node_id_str)
            .and_then(|h| h.relay_url.as_deref())
            .map(|u| u.parse())
            .transpose()
            .ok()
            .flatten();

        println!("Resolved '{}' -> {}...", target, host_id.fmt_short());

        let (mut ipc_write, ipc_read) =
            open_agent_stream(config_dir, &host_id, relay_url.as_ref().map(|u| u.to_string()))
                .await?;

        // Send session request through the transparent pipe
        proto::write_message(&mut ipc_write, session_request).await?;

        return Ok((ResolvedHost { host_id, relay_url }, ipc_write, ipc_read));
    }

    // 2. Check if invite token
    if invite::is_invite_token(target) {
        let token = invite::decode_invite(target)?;
        let host_id: iroh::PublicKey = token
            .node_id
            .parse()
            .context("Invalid NodeId in invite token")?;

        let relay_url: Option<iroh::RelayUrl> = token
            .relay_url
            .as_deref()
            .map(|u| u.parse())
            .transpose()
            .context("Invalid relay URL in invite token")?;

        println!("Connecting to host {}...", host_id.fmt_short());

        let (mut ipc_write, mut ipc_read) =
            open_agent_stream(config_dir, &host_id, relay_url.as_ref().map(|u| u.to_string()))
                .await?;

        // Send invite auth through the transparent pipe
        proto::write_message(
            &mut ipc_write,
            &ClientMessage::AuthResponse {
                secret: token.secret.as_bytes().to_vec(),
            },
        )
        .await?;

        let result: HostMessage = proto::read_message(&mut ipc_read).await?;
        match result {
            HostMessage::AuthResult { authorized: true } => {
                println!("Authorized!");

                let desired_name = cli_name
                    .map(String::from)
                    .or(token.host_name)
                    .unwrap_or_else(|| format!("host-{}", host_id.fmt_short()));

                let mut hosts = KnownHostsStore::load(config_dir)?;
                let actual_name = hosts.add_host_dedup(
                    &host_id,
                    desired_name,
                    relay_url.as_ref().map(|u| u.to_string()),
                );
                hosts.save(config_dir)?;
                println!("Saved as known host: {actual_name}");

                // Send session request on the same stream
                proto::write_message(&mut ipc_write, session_request).await?;

                return Ok((ResolvedHost { host_id, relay_url }, ipc_write, ipc_read));
            }
            HostMessage::AuthResult { authorized: false } => {
                anyhow::bail!("Invite rejected by host (expired or already used)");
            }
            other => {
                anyhow::bail!("Unexpected response from host: {other:?}");
            }
        }
    }

    // 3. Parse as NodeId (64-char hex)
    let host_id: iroh::PublicKey = target
        .parse()
        .context("Unknown host alias, invalid invite token, or invalid NodeId")?;

    println!("Connecting to {}...", host_id.fmt_short());

    // Always pass the default relay URL as a hint so iroh can reach the
    // host without relying on DNS/pkarr discovery (which can fail on musl
    // or in restricted network environments).
    let default_relay = hop_core::net::HOP_RELAY_URL.to_string();
    let (mut ipc_write, ipc_read) =
        open_agent_stream(config_dir, &host_id, Some(default_relay.clone())).await?;

    let relay_url: Option<iroh::RelayUrl> = default_relay.parse().ok();

    proto::write_message(&mut ipc_write, session_request).await?;

    Ok((
        ResolvedHost {
            host_id,
            relay_url,
        },
        ipc_write,
        ipc_read,
    ))
}

/// Open a bi-stream to a host through the agent (public for reconnection).
///
/// Sends MuxConnect, reads MuxResult::Ready, then splits the socket.
pub async fn open_agent_stream_pub(
    config_dir: &Path,
    host_id: &iroh::PublicKey,
    relay_url: Option<String>,
) -> Result<(
    tokio::net::unix::OwnedWriteHalf,
    tokio::net::unix::OwnedReadHalf,
)> {
    open_agent_stream(config_dir, host_id, relay_url).await
}

/// Open a bi-stream to a host through the agent.
///
/// Sends MuxConnect, reads MuxResult::Ready, then splits the socket.
async fn open_agent_stream(
    config_dir: &Path,
    host_id: &iroh::PublicKey,
    relay_url: Option<String>,
) -> Result<(
    tokio::net::unix::OwnedWriteHalf,
    tokio::net::unix::OwnedReadHalf,
)> {
    let mut ipc = ensure_agent(config_dir).await?;

    let req = MuxConnect {
        host_id: *host_id.as_bytes(),
        relay_url,
    };
    write_ipc_message(&mut ipc, &req).await?;

    let result: MuxResult = read_ipc_message(&mut ipc).await?;
    match result {
        MuxResult::Ready => {}
        MuxResult::Error(msg) => anyhow::bail!("Agent connection failed: {msg}"),
    }

    let (ipc_read, ipc_write) = ipc.into_split();
    Ok((ipc_write, ipc_read))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn ipc_roundtrip_mux_connect() {
        let (mut a, mut b) = tokio::net::UnixStream::pair().unwrap();
        let msg = MuxConnect {
            host_id: [7u8; 32],
            relay_url: Some("https://relay.example.com".into()),
        };
        write_ipc_message(&mut a, &msg).await.unwrap();
        let decoded: MuxConnect = read_ipc_message(&mut b).await.unwrap();
        assert_eq!(decoded.host_id, [7u8; 32]);
        assert_eq!(decoded.relay_url.as_deref(), Some("https://relay.example.com"));
    }

    #[tokio::test]
    async fn ipc_roundtrip_mux_result_ready() {
        let (mut a, mut b) = tokio::net::UnixStream::pair().unwrap();
        write_ipc_message(&mut a, &MuxResult::Ready).await.unwrap();
        let decoded: MuxResult = read_ipc_message(&mut b).await.unwrap();
        assert!(matches!(decoded, MuxResult::Ready));
    }

    #[tokio::test]
    async fn ipc_roundtrip_mux_result_error() {
        let (mut a, mut b) = tokio::net::UnixStream::pair().unwrap();
        let error_msg = "connection refused: host unreachable".to_string();
        write_ipc_message(&mut a, &MuxResult::Error(error_msg.clone()))
            .await
            .unwrap();
        let decoded: MuxResult = read_ipc_message(&mut b).await.unwrap();
        match decoded {
            MuxResult::Error(msg) => assert_eq!(msg, error_msg),
            _ => panic!("expected MuxResult::Error"),
        }
    }

    #[tokio::test]
    async fn ipc_frame_too_large_rejected() {
        let (mut a, mut b) = tokio::net::UnixStream::pair().unwrap();

        // Write a length prefix claiming 17MB (over the 16MB limit)
        let huge_len: u32 = 17 * 1024 * 1024;
        a.write_all(&huge_len.to_be_bytes()).await.unwrap();

        let result: Result<MuxConnect> = read_ipc_message(&mut b).await;
        assert!(result.is_err());
        let err_msg = format!("{}", result.unwrap_err());
        assert!(
            err_msg.contains("too large"),
            "Expected 'too large' error, got: {err_msg}"
        );
    }

    #[tokio::test]
    async fn ipc_concurrent_independent_streams() {
        let mut handles = Vec::new();

        for i in 0..50u32 {
            handles.push(tokio::spawn(async move {
                let (mut a, mut b) = tokio::net::UnixStream::pair().unwrap();
                let msg = MuxConnect {
                    host_id: {
                        let mut id = [0u8; 32];
                        id[0] = (i & 0xFF) as u8;
                        id[1] = ((i >> 8) & 0xFF) as u8;
                        id
                    },
                    relay_url: Some(format!("https://relay-{i}.example.com")),
                };
                write_ipc_message(&mut a, &msg).await.unwrap();
                let decoded: MuxConnect = read_ipc_message(&mut b).await.unwrap();
                assert_eq!(decoded.host_id[0], (i & 0xFF) as u8);
                assert_eq!(decoded.host_id[1], ((i >> 8) & 0xFF) as u8);
                assert_eq!(
                    decoded.relay_url.as_deref(),
                    Some(format!("https://relay-{i}.example.com").as_str())
                );
            }));
        }

        for h in handles {
            h.await.unwrap();
        }
    }
}
