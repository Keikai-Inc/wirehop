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
    /// Evict any pooled connection to this host before connecting. Set by the
    /// reconnect paths: after an abnormal disconnect the pooled connection may be
    /// half-open (dead path, but `close_reason()` not yet set), and reusing it
    /// would land the reconnect on the same dead path → another 75s read-deadline
    /// → an endless reconnect loop. Forcing a fresh dial closes that window
    /// without waiting for the ~90s relay-health flush. `#[serde(default)]` keeps
    /// the wire format compatible with older agents/clients.
    #[serde(default)]
    pub evict_first: bool,
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

/// Path to the agent log file.
pub fn agent_log_path(config_dir: &Path) -> PathBuf {
    config_dir.join("agent.log")
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

    // Prefer a running host daemon's mux socket. The daemon owns the machine's
    // single iroh endpoint, so routing client connects through it avoids a
    // SECOND endpoint under the same node-id — which the relay prunes against
    // the daemon every few seconds (the identity collision that destabilizes
    // both client sessions and the VPN). Falls through if no daemon is serving.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let daemon_sock = hop_core::config::system_config_dir().join("agent.sock");
        if daemon_sock != sock
            && let Ok(stream) = UnixStream::connect(&daemon_sock).await
        {
            return Ok(stream);
        }
    }

    // Try existing (user) agent
    if let Ok(stream) = UnixStream::connect(&sock).await {
        return Ok(stream);
    }

    // Start the user agent — unless one is already coming up. A live agent.pid
    // means another `hop connect` just spawned it and it's still binding its
    // socket; spawning a SECOND would create competing agents (each dialing the
    // same host), the exact pile-up behind the post-restart storm. In that case
    // skip the spawn and fall through to wait for the existing agent's socket.
    #[cfg(unix)]
    let already_starting = user_agent_alive(config_dir);
    #[cfg(not(unix))]
    let already_starting = false;
    if !already_starting {
        let exe = std::env::current_exe().context("could not determine hop executable path")?;
        let log_file = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(agent_log_path(config_dir))
            .context("failed to open agent log file")?;
        std::process::Command::new(exe)
            .args(["agent", "--daemon", "--config"])
            .arg(config_dir)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::from(log_file))
            .spawn()
            .context("failed to spawn agent process")?;
    }

    // Wait for agent to be ready (retry with backoff)
    for i in 0..20 {
        tokio::time::sleep(Duration::from_millis(50 * (i + 1))).await;
        if let Ok(stream) = UnixStream::connect(&sock).await {
            return Ok(stream);
        }
    }
    anyhow::bail!("Agent failed to start within timeout")
}

/// How long the client waits for the agent to report the connection ready
/// before giving up on a single attempt. The agent's dial to the host can hang
/// (dead path, relay flap) far longer than a user will tolerate; without this
/// the client blocks indefinitely with no feedback. On timeout we drop the IPC
/// stream, which the agent observes (it watches for IPC close) and aborts its
/// dial — so a wedged attempt can't leak. The responsive connect/reconnect loops
/// use a shorter per-attempt deadline on top of this; this is the backstop for
/// any caller.
const AGENT_DIAL_TIMEOUT: Duration = Duration::from_secs(30);

/// Resolved target info retained for reconnection.
#[derive(Clone)]
pub struct ResolvedHost {
    pub host_id: iroh::PublicKey,
    pub relay_url: Option<iroh::RelayUrl>,
}

/// One-shot authentication to perform after the dial succeeds, before the
/// session request. Resolved up front from the target so the responsive connect
/// loop only has to drive the (retriable) dial.
pub enum AuthStep {
    /// Known alias or raw NodeId — no pre-session auth.
    None,
    /// Invite token — send the secret, expect an AuthResult, then save the host.
    Invite {
        secret: Vec<u8>,
        desired_name: String,
        warren_ticket: Option<String>,
    },
}

/// A resolved connect target plus its one-shot auth step. Produced by
/// [`resolve_target`] (fast, local, prints in cooked mode); consumed by the
/// responsive connect loop. Splitting resolution from the dial is what lets the
/// initial connect enable raw mode + start polling stdin BEFORE the (slow,
/// hangable) dial — so `q`/Ctrl-C and the spinner stay live the whole time.
pub struct ConnectPlan {
    pub host_id: iroh::PublicKey,
    pub relay_url: Option<iroh::RelayUrl>,
    pub auth: AuthStep,
}

impl ConnectPlan {
    pub fn resolved(&self) -> ResolvedHost {
        ResolvedHost {
            host_id: self.host_id,
            relay_url: self.relay_url.clone(),
        }
    }

    fn relay_str(&self) -> Option<String> {
        self.relay_url.as_ref().map(|u| u.to_string())
    }
}

/// Resolve a connect target (alias / invite token / raw NodeId) into a
/// [`ConnectPlan`] without dialing. Local and fast; prints the "Resolved …" /
/// "Connecting to …" banner in cooked mode before the caller switches to raw
/// mode for the responsive dial.
pub fn resolve_target(
    config_dir: &Path,
    target: &str,
    cli_name: Option<&str>,
) -> Result<ConnectPlan> {
    // 1. Known-hosts alias.
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
        crate::agent_out::banner(&format!("Resolved '{}' -> {}...", target, host_id.fmt_short()));
        return Ok(ConnectPlan { host_id, relay_url, auth: AuthStep::None });
    }

    // 2. Invite token.
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
        let desired_name = cli_name
            .map(String::from)
            .or(token.host_name)
            .unwrap_or_else(|| format!("host-{}", host_id.fmt_short()));
        crate::agent_out::banner(&format!("Connecting to host {}...", host_id.fmt_short()));
        return Ok(ConnectPlan {
            host_id,
            relay_url,
            auth: AuthStep::Invite {
                secret: token.secret.as_bytes().to_vec(),
                desired_name,
                warren_ticket: token.warren_ticket,
            },
        });
    }

    // 3. Raw NodeId (64-char hex). Always carry the default relay as a hint so
    // iroh can reach the host without relying on DNS/pkarr discovery (which can
    // fail on musl or restricted networks).
    let host_id: iroh::PublicKey = target
        .parse()
        .context("Unknown host alias, invalid invite token, or invalid NodeId")?;
    let relay_url: Option<iroh::RelayUrl> = hop_core::net::HOP_RELAY_URL.parse().ok();
    crate::agent_out::banner(&format!("Connecting to {}...", host_id.fmt_short()));
    Ok(ConnectPlan { host_id, relay_url, auth: AuthStep::None })
}

/// One-shot blocking connect: resolve the target, dial, run any auth, and send
/// the session request. Used by the NON-interactive commands (exec, cp, sync,
/// mcp, …) that don't want the interactive spinner/retry UI — `cmd_connect`
/// drives the responsive [`crate::reconnect::run_initial_connect`] loop instead.
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
    let plan = resolve_target(config_dir, target, cli_name)?;
    let (mut write, mut read) = dial_initial(config_dir, &plan).await?;
    finish_auth_and_request(config_dir, &plan, session_request, &mut write, &mut read).await?;
    Ok((plan.resolved(), write, read))
}

/// Dial the host through the agent for an initial connect (no eviction). The
/// retriable unit the responsive loop drives; on its own it is bounded by
/// [`AGENT_DIAL_TIMEOUT`].
pub async fn dial_initial(
    config_dir: &Path,
    plan: &ConnectPlan,
) -> Result<(
    tokio::net::unix::OwnedWriteHalf,
    tokio::net::unix::OwnedReadHalf,
)> {
    open_agent_stream(config_dir, &plan.host_id, plan.relay_str(), false).await
}

/// After the dial is up, run any one-shot auth and send the session request.
/// Prints are raw-mode-safe (`\r\n`) because the caller holds raw mode by the
/// time this runs. Invite auth is intentionally NOT retried by the loop — an
/// invite is single-use, so a failure here is terminal.
pub async fn finish_auth_and_request(
    config_dir: &Path,
    plan: &ConnectPlan,
    session_request: &ClientMessage,
    write: &mut tokio::net::unix::OwnedWriteHalf,
    read: &mut tokio::net::unix::OwnedReadHalf,
) -> Result<()> {
    use std::io::Write as _;
    match &plan.auth {
        AuthStep::None => {
            proto::write_message(write, session_request).await?;
        }
        AuthStep::Invite { secret, desired_name, warren_ticket } => {
            proto::write_message(
                write,
                &ClientMessage::AuthResponse { secret: secret.clone() },
            )
            .await?;
            let result: HostMessage =
                tokio::time::timeout(AGENT_DIAL_TIMEOUT, proto::read_message(read))
                    .await
                    .context("timed out waiting for the host's auth result")??;
            match result {
                HostMessage::AuthResult { authorized: true } => {
                    print!("Authorized!\r\n");
                    let mut hosts = KnownHostsStore::load(config_dir)?;
                    let actual_name = hosts.add_host_dedup(
                        &plan.host_id,
                        desired_name.clone(),
                        plan.relay_str(),
                    );
                    hosts.save(config_dir)?;
                    print!("Saved as known host: {actual_name}\r\n");
                    let _ = std::io::stdout().flush();
                    if let Some(ticket) = warren_ticket.as_deref() {
                        let path = config_dir.join("warren-ticket");
                        if let Err(e) = std::fs::write(&path, ticket) {
                            tracing::debug!("could not persist warren ticket: {e}");
                        }
                    }
                    proto::write_message(write, session_request).await?;
                }
                HostMessage::AuthResult { authorized: false } => {
                    anyhow::bail!("Invite rejected by host (expired or already used)");
                }
                other => anyhow::bail!("Unexpected response from host: {other:?}"),
            }
        }
    }
    Ok(())
}

/// Kill a wedged USER agent (the one this client spawned) so the next dial
/// starts a fresh one — the automated form of the `killall hop` users have had
/// to run by hand when the agent gets stuck storm-redialing. Only ever touches
/// the per-user `agent.pid`/socket in `config_dir`; never the system daemon's
/// mux (a host machine has no user `agent.pid`, so this is a safe no-op there).
pub fn restart_user_agent(config_dir: &Path) {
    let pid_path = agent_pid_path(config_dir);
    if let Ok(pid_str) = std::fs::read_to_string(&pid_path)
        && let Ok(pid) = pid_str.trim().parse::<i32>()
    {
        #[cfg(unix)]
        unsafe {
            libc::kill(pid, libc::SIGKILL);
        }
    }
    let _ = std::fs::remove_file(&pid_path);
    let _ = std::fs::remove_file(agent_sock_path(config_dir));
}

/// True if a user agent we spawned is recorded and its process is alive.
#[cfg(unix)]
fn user_agent_alive(config_dir: &Path) -> bool {
    std::fs::read_to_string(agent_pid_path(config_dir))
        .ok()
        .and_then(|s| s.trim().parse::<i32>().ok())
        .map(|pid| unsafe { libc::kill(pid, 0) == 0 })
        .unwrap_or(false)
}

/// Open a bi-stream to a host through the agent (public for reconnection).
///
/// Sends MuxConnect, reads MuxResult::Ready, then splits the socket.
pub async fn open_agent_stream_pub(
    config_dir: &Path,
    host_id: &iroh::PublicKey,
    relay_url: Option<String>,
    evict_first: bool,
) -> Result<(
    tokio::net::unix::OwnedWriteHalf,
    tokio::net::unix::OwnedReadHalf,
)> {
    open_agent_stream(config_dir, host_id, relay_url, evict_first).await
}

/// Open a bi-stream to a host through the agent.
///
/// Sends MuxConnect, reads MuxResult::Ready, then splits the socket. When
/// `evict_first` is set, the agent drops any pooled connection to this host
/// before dialing (used by reconnect to avoid reusing a half-open connection).
async fn open_agent_stream(
    config_dir: &Path,
    host_id: &iroh::PublicKey,
    relay_url: Option<String>,
    evict_first: bool,
) -> Result<(
    tokio::net::unix::OwnedWriteHalf,
    tokio::net::unix::OwnedReadHalf,
)> {
    let mut ipc = ensure_agent(config_dir).await?;

    let req = MuxConnect {
        host_id: *host_id.as_bytes(),
        relay_url,
        evict_first,
    };
    write_ipc_message(&mut ipc, &req).await?;

    // Bound the wait for the agent to report ready. A hung dial (dead path,
    // relay flap) would otherwise block here for the full QUIC idle timeout with
    // no feedback. On timeout we return an error and drop `ipc`, which the agent
    // sees (it watches for IPC close) and uses to abort its dial.
    let result: MuxResult = tokio::time::timeout(AGENT_DIAL_TIMEOUT, read_ipc_message(&mut ipc))
        .await
        .context("agent timed out establishing the connection")??;
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

    #[test]
    fn resolve_target_raw_nodeid_is_noauth_with_relay() {
        let dir = tempfile::tempdir().unwrap();
        let pk = iroh::SecretKey::from_bytes(&[3u8; 32]).public();
        let plan = resolve_target(dir.path(), &pk.to_string(), None).unwrap();
        assert_eq!(plan.host_id, pk);
        assert!(matches!(plan.auth, AuthStep::None));
        // A raw NodeId carries the default relay as a discovery hint.
        assert!(plan.relay_url.is_some());
    }

    #[test]
    fn resolve_target_rejects_garbage() {
        let dir = tempfile::tempdir().unwrap();
        assert!(resolve_target(dir.path(), "not-a-host", None).is_err());
    }

    #[tokio::test]
    async fn ipc_roundtrip_mux_connect() {
        let (mut a, mut b) = tokio::net::UnixStream::pair().unwrap();
        let msg = MuxConnect {
            host_id: [7u8; 32],
            relay_url: Some("https://relay.example.com".into()),
            evict_first: false,
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
                    evict_first: false,
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
