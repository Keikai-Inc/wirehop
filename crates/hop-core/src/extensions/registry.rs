//! Extension registry — runtime tracking of installed extensions plus
//! ipc-channel rendezvous and tokio-bridge plumbing.
//!
//! ## Lifecycle
//!
//! 1. At hop daemon startup, [`ExtensionRegistry::discover`] reads
//!    manifests from `~/.config/hop/extensions/` (or wherever the
//!    operator placed them).
//! 2. Connections are established lazily on first use via
//!    [`ExtensionRegistry::ensure_connected`], or eagerly via
//!    [`ExtensionRegistry::probe_all`].
//! 3. Each connection involves a small ipc-channel rendezvous handshake
//!    (see [`connect_blocking`] for the dance) followed by a pair of
//!    bridge threads that translate sync ipc-channel `send`/`recv` to
//!    async tokio mpsc channels.
//! 4. When a connection drops (extension daemon dies, restart, etc.),
//!    the next `ensure_connected` call retries with bounded backoff.
//!
//! ## Handshake
//!
//! Both sides type their channels as [`ExtMessage`]; the [`ExtMessage::Hello`]
//! variant carries the reverse-rendezvous name so the extension can connect
//! back to hop. After the handshake, both sides have a `(IpcSender,
//! IpcReceiver)` pair and can send arbitrary `ExtMessage`s in either
//! direction.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use ipc_channel::ipc::{IpcOneShotServer, IpcReceiver, IpcSender};
use serde::{Deserialize, Serialize};
use tokio::sync::{Mutex, mpsc};
use tracing::{info, warn};

use super::bootstrap::Bootstrap;
use super::manifest::ExtensionManifest;

/// One protocol message between hop daemon and an extension daemon.
///
/// Both directions use the same enum so a single `IpcSender<ExtMessage>` /
/// `IpcReceiver<ExtMessage>` pair can carry traffic each way. Variants
/// document which direction each is sent.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtMessage {
    // hop -> extension (handshake)
    /// Initial message hop sends to complete the rendezvous. Carries the
    /// reverse-server name the extension should connect back to.
    Hello {
        hop_version: String,
        reverse_name: String,
    },

    // extension -> hop (handshake)
    /// Extension's response after connecting to hop's reverse server.
    /// Confirms the handshake completed and exchanges version info.
    HelloAck {
        ext_version: String,
    },

    // hop -> extension (operations)
    /// Single request, single response. Extension replies with [`ExtMessage::Response`].
    Request {
        request_id: u64,
        peer_id: String,
        peer_username: Option<String>,
        peer_role: String,
        payload: Vec<u8>,
    },

    /// Long-running stream subscription. Extension replies with
    /// [`ExtMessage::StreamOpened`] then 0..n [`ExtMessage::StreamFrame`]
    /// followed by [`ExtMessage::StreamClosed`].
    StreamOpen {
        request_id: u64,
        peer_id: String,
        peer_username: Option<String>,
        peer_role: String,
        payload: Vec<u8>,
    },

    /// Input bytes from peer to extension on an open stream
    /// (e.g., keystrokes for a future input-injection capability).
    StreamInput {
        stream_id: u64,
        payload: Vec<u8>,
    },

    /// Peer-side close of an open stream.
    StreamClose {
        stream_id: u64,
    },

    // extension -> hop (operation responses)
    Response {
        request_id: u64,
        ok: bool,
        payload: Vec<u8>,
    },
    StreamOpened {
        request_id: u64,
        stream_id: u64,
    },
    StreamFrame {
        stream_id: u64,
        payload: Vec<u8>,
    },
    StreamClosed {
        stream_id: u64,
        reason: Option<String>,
    },
}

/// Status of a registered extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ExtensionStatus {
    /// Manifest loaded; no connection attempt yet.
    Discovered,
    /// Currently connecting (rendezvous in flight).
    Connecting,
    /// Connected and ready to receive requests.
    Available,
    /// Last connection attempt failed; the error is surfaced for diagnostics.
    Unavailable {
        error: String,
    },
}

impl ExtensionStatus {
    pub fn is_available(&self) -> bool {
        matches!(self, ExtensionStatus::Available)
    }
}

/// Backoff applied between connection attempts after a failure.
const RETRY_BACKOFF: Duration = Duration::from_secs(5);

/// Registry of all known extensions on this host.
///
/// Cheap to clone — wraps an `Arc<Mutex<...>>` internally, so handing
/// copies to multiple async tasks works.
#[derive(Clone)]
pub struct ExtensionRegistry {
    inner: Arc<Mutex<RegistryInner>>,
}

struct RegistryInner {
    extensions: HashMap<String, ExtensionEntry>,
}

struct ExtensionEntry {
    manifest: ExtensionManifest,
    status: ExtensionStatus,
    connection: Option<ExtensionConnection>,
    last_attempt: Option<Instant>,
}

/// Bridged tokio-mpsc handles to one extension's ipc-channel pair.
struct ExtensionConnection {
    /// Async-side sender. Messages enqueued here are forwarded by the
    /// outbound bridge thread to ipc-channel.
    send_tx: mpsc::UnboundedSender<ExtMessage>,
    /// Async-side receiver. The inbound bridge thread forwards
    /// ipc-channel messages here. Wrapped in a Mutex so a single owner
    /// can `recv().await` without competition; `take_recv` lets the
    /// dispatcher (Phase 0d) take exclusive ownership.
    recv_rx: Arc<Mutex<Option<mpsc::UnboundedReceiver<ExtMessage>>>>,
}

impl ExtensionRegistry {
    /// Discover manifests at the given directory and create a registry.
    /// Connections are established lazily via
    /// [`ExtensionRegistry::ensure_connected`].
    pub async fn discover(manifest_dir: PathBuf) -> Result<Self> {
        let manifests = super::manifest::discover(&manifest_dir)?;
        info!(
            count = manifests.len(),
            dir = %manifest_dir.display(),
            "discovered extension manifests"
        );

        let mut extensions = HashMap::new();
        for m in manifests {
            extensions.insert(
                m.ext_id.clone(),
                ExtensionEntry {
                    manifest: m,
                    status: ExtensionStatus::Discovered,
                    connection: None,
                    last_attempt: None,
                },
            );
        }

        Ok(Self {
            inner: Arc::new(Mutex::new(RegistryInner { extensions })),
        })
    }

    /// Snapshot of all known extensions and their current status.
    /// Does not trigger connection attempts.
    pub async fn list(&self) -> Vec<(ExtensionManifest, ExtensionStatus)> {
        let inner = self.inner.lock().await;
        let mut out: Vec<_> = inner
            .extensions
            .values()
            .map(|e| (e.manifest.clone(), e.status.clone()))
            .collect();
        out.sort_by(|a, b| a.0.ext_id.cmp(&b.0.ext_id));
        out
    }

    /// Probe all extensions by attempting connection. Useful when an
    /// operator runs `hop ext list` and wants real-time availability.
    pub async fn probe_all(&self) -> Vec<(ExtensionManifest, ExtensionStatus)> {
        let ids: Vec<String> = {
            let inner = self.inner.lock().await;
            inner.extensions.keys().cloned().collect()
        };
        for ext_id in &ids {
            let _ = self.ensure_connected(ext_id).await;
        }
        self.list().await
    }

    /// Send one message to an extension. Establishes connection on demand.
    pub async fn send_to(&self, ext_id: &str, msg: ExtMessage) -> Result<()> {
        self.ensure_connected(ext_id).await?;
        let inner = self.inner.lock().await;
        let entry = inner
            .extensions
            .get(ext_id)
            .with_context(|| format!("unknown extension: {ext_id}"))?;
        let conn = entry
            .connection
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("extension {ext_id} not connected"))?;
        conn.send_tx
            .send(msg)
            .map_err(|_| anyhow::anyhow!("send bridge for {ext_id} closed"))?;
        Ok(())
    }

    /// Take exclusive ownership of an extension's inbound message receiver.
    ///
    /// Only the first caller succeeds; subsequent calls return None.
    /// Phase 0d's dispatcher takes the receiver to drive request/response
    /// demultiplexing.
    pub async fn take_recv(&self, ext_id: &str) -> Option<mpsc::UnboundedReceiver<ExtMessage>> {
        let inner = self.inner.lock().await;
        let conn = inner.extensions.get(ext_id)?.connection.as_ref()?;
        let mut guard = conn.recv_rx.lock().await;
        guard.take()
    }

    /// Establish a connection to the given extension if not already
    /// connected. Bounded backoff on repeated failures.
    pub async fn ensure_connected(&self, ext_id: &str) -> Result<()> {
        // Lock, fast-path, release before doing blocking I/O.
        let manifest = {
            let mut inner = self.inner.lock().await;
            let entry = inner
                .extensions
                .get_mut(ext_id)
                .with_context(|| format!("unknown extension: {ext_id}"))?;

            // Already connected.
            if entry.status.is_available() && entry.connection.is_some() {
                return Ok(());
            }

            // Backoff: don't hammer if the last attempt was very recent.
            if matches!(entry.status, ExtensionStatus::Unavailable { .. })
                && let Some(last) = entry.last_attempt
                && last.elapsed() < RETRY_BACKOFF
            {
                let err = match &entry.status {
                    ExtensionStatus::Unavailable { error } => error.clone(),
                    _ => "(unknown)".into(),
                };
                bail!("extension {ext_id} recently failed (backing off): {err}");
            }

            entry.status = ExtensionStatus::Connecting;
            entry.last_attempt = Some(Instant::now());
            entry.manifest.clone()
        };

        // Connect off the async runtime — ipc-channel APIs are sync.
        let result =
            tokio::task::spawn_blocking(move || connect_blocking(&manifest))
                .await
                .context("connect task panicked")?;

        let mut inner = self.inner.lock().await;
        let entry = inner
            .extensions
            .get_mut(ext_id)
            .ok_or_else(|| anyhow::anyhow!("extension {ext_id} disappeared mid-connect"))?;

        match result {
            Ok(conn) => {
                entry.connection = Some(conn);
                entry.status = ExtensionStatus::Available;
                info!(ext_id, "extension connected");
                Ok(())
            }
            Err(e) => {
                let msg = format!("{e:#}");
                entry.status = ExtensionStatus::Unavailable {
                    error: msg.clone(),
                };
                entry.connection = None;
                warn!(ext_id, error = %msg, "extension connect failed");
                Err(e)
            }
        }
    }
}

/// Synchronous connection routine. Performs the rendezvous handshake,
/// spawns the two bridge threads, and returns the bridged async handles.
///
/// Designed for `spawn_blocking` since ipc-channel's `recv` and `accept`
/// are blocking calls.
fn connect_blocking(manifest: &ExtensionManifest) -> Result<ExtensionConnection> {
    // 1. Read the bootstrap file. This validates ownership/permissions
    //    and gives us the extension's ipc-channel server name.
    let bs = Bootstrap::load(&manifest.bootstrap_path, manifest.expected_uid)
        .with_context(|| {
            format!("loading bootstrap {}", manifest.bootstrap_path.display())
        })?;

    if !bs.pid_alive() {
        bail!(
            "extension daemon (pid {}) is not alive; bootstrap file is stale",
            bs.pid
        );
    }

    if bs.version != manifest.version {
        bail!(
            "version mismatch: bootstrap reports {} but manifest expects {}",
            bs.version,
            manifest.version
        );
    }

    // 2. Connect to the extension's one-shot rendezvous server. After
    //    this, `tx_to_ext` is reusable for arbitrary future ExtMessages.
    let tx_to_ext: IpcSender<ExtMessage> = IpcSender::connect(bs.server_name.clone())
        .with_context(|| format!("connecting to {}", bs.server_name))?;

    // 3. Create our reverse server so the extension can connect back.
    let (rev_server, rev_name): (IpcOneShotServer<ExtMessage>, String) =
        IpcOneShotServer::new().context("creating reverse rendezvous server")?;

    // 4. Send Hello with the reverse name.
    tx_to_ext
        .send(ExtMessage::Hello {
            hop_version: env!("CARGO_PKG_VERSION").to_string(),
            reverse_name: rev_name,
        })
        .context("sending Hello to extension")?;

    // 5. Wait for the extension to connect back. This blocks until the
    //    extension constructs its IpcSender to our reverse server and
    //    sends HelloAck.
    let (rx_from_ext, ack) = rev_server
        .accept()
        .context("waiting for extension HelloAck")?;

    match ack {
        ExtMessage::HelloAck { ext_version } => {
            tracing::debug!(ext_version, "extension handshake complete");
        }
        other => bail!("expected HelloAck from extension, got {:?}", other),
    }

    // 6. Spawn bridge threads to translate sync ipc-channel ↔ async tokio.
    let send_tx = spawn_send_bridge(tx_to_ext);
    let recv_rx = spawn_recv_bridge(rx_from_ext);

    Ok(ExtensionConnection {
        send_tx,
        recv_rx: Arc::new(Mutex::new(Some(recv_rx))),
    })
}

/// Outbound bridge: drains a tokio mpsc, calling sync `send` on
/// ipc-channel for each message. Closes when either end drops.
fn spawn_send_bridge(ipc_tx: IpcSender<ExtMessage>) -> mpsc::UnboundedSender<ExtMessage> {
    let (tx, mut rx) = mpsc::unbounded_channel::<ExtMessage>();
    std::thread::spawn(move || {
        // tokio mpsc's blocking_recv is the right API outside an async
        // context — it parks until a message arrives or all senders drop.
        while let Some(msg) = rx.blocking_recv() {
            if let Err(e) = ipc_tx.send(msg) {
                tracing::warn!(error = ?e, "ipc-channel send failed; closing bridge");
                break;
            }
        }
    });
    tx
}

/// Inbound bridge: blocks on ipc-channel `recv`, forwarding each message
/// into a tokio mpsc. Closes on transport error or when the async-side
/// receiver drops.
fn spawn_recv_bridge(ipc_rx: IpcReceiver<ExtMessage>) -> mpsc::UnboundedReceiver<ExtMessage> {
    let (tx, rx) = mpsc::unbounded_channel::<ExtMessage>();
    std::thread::spawn(move || {
        loop {
            match ipc_rx.recv() {
                Ok(msg) => {
                    if tx.send(msg).is_err() {
                        // async side dropped the receiver; we're done
                        break;
                    }
                }
                Err(e) => {
                    tracing::warn!(error = ?e, "ipc-channel recv failed; closing bridge");
                    break;
                }
            }
        }
    });
    rx
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn current_uid() -> u32 {
        unsafe { libc::getuid() }
    }

    /// Spawn a tiny in-process "fake extension" that performs the server
    /// side of the handshake. Returns when the handshake is complete and
    /// any further messages would need a real protocol implementation.
    fn spawn_fake_extension(
        bootstrap_path: PathBuf,
        version: &str,
    ) -> std::thread::JoinHandle<Result<ExtMessage>> {
        let version = version.to_string();
        std::thread::spawn(move || {
            // 1. Create our rendezvous server.
            let (server, server_name) =
                IpcOneShotServer::<ExtMessage>::new().context("create server")?;

            // 2. Write bootstrap.
            let bs = Bootstrap {
                server_name,
                pid: std::process::id(),
                version: version.clone(),
            };
            let toml = toml::to_string(&bs).context("serialize bootstrap")?;
            std::fs::write(&bootstrap_path, toml).context("write bootstrap")?;
            let perms = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&bootstrap_path, perms).context("chmod bootstrap")?;

            // 3. Wait for hop to connect and send Hello.
            let (rx, hello) = server.accept().context("accept rendezvous")?;
            let reverse_name = match &hello {
                ExtMessage::Hello { reverse_name, .. } => reverse_name.clone(),
                other => bail!("unexpected first message: {:?}", other),
            };

            // 4. Connect back to hop's reverse server.
            let tx: IpcSender<ExtMessage> =
                IpcSender::connect(reverse_name).context("connect reverse")?;
            tx.send(ExtMessage::HelloAck {
                ext_version: version,
            })
            .context("send HelloAck")?;

            // 5. Receive one more message from hop and return it for the
            //    test to verify the bidirectional channel works.
            let next = rx.recv().context("recv next")?;
            Ok(next)
        })
    }

    #[tokio::test]
    async fn full_handshake_and_round_trip() {
        let dir = tempdir().unwrap();
        let bootstrap_path = dir.path().join("bootstrap");

        // Manifest pointing at our fake extension's bootstrap.
        let manifest_path = dir.path().join("ext.toml");
        std::fs::write(
            &manifest_path,
            format!(
                r#"
                ext_id = "test"
                description = "Test fake extension"
                bootstrap_path = "{}"
                expected_uid = {}
                version = "0.1.0"
                "#,
                bootstrap_path.display(),
                current_uid()
            ),
        )
        .unwrap();

        // Set stricter perms on bootstrap parent dir to satisfy the
        // Bootstrap::load checks (it inspects the bootstrap file itself,
        // not the dir, but tightening doesn't hurt).
        let mut perms = std::fs::metadata(dir.path()).unwrap().permissions();
        perms.set_mode(0o700);
        std::fs::set_permissions(dir.path(), perms).unwrap();

        // Start the fake extension. It will write the bootstrap file
        // and then wait for hop to connect.
        let ext_handle = spawn_fake_extension(bootstrap_path.clone(), "0.1.0");

        // Give the fake extension a moment to bind its server and write
        // the bootstrap file. (It runs eagerly so this should be quick.)
        tokio::time::sleep(Duration::from_millis(50)).await;

        // Discover the manifest, connect to the extension.
        let registry = ExtensionRegistry::discover(dir.path().to_path_buf())
            .await
            .unwrap();
        registry.ensure_connected("test").await.unwrap();

        // Send a request through the bridge.
        let req = ExtMessage::Request {
            request_id: 7,
            peer_id: "peer-abc".into(),
            peer_username: Some("alice".into()),
            peer_role: "peer".into(),
            payload: b"hello".to_vec(),
        };
        registry.send_to("test", req.clone()).await.unwrap();

        // The fake extension should have received it. Drain the join handle.
        let received = ext_handle.join().expect("ext thread panicked").unwrap();
        match received {
            ExtMessage::Request {
                request_id,
                peer_id,
                payload,
                ..
            } => {
                assert_eq!(request_id, 7);
                assert_eq!(peer_id, "peer-abc");
                assert_eq!(payload, b"hello".to_vec());
            }
            other => panic!("expected Request, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn discover_empty_dir_yields_empty_registry() {
        let dir = tempdir().unwrap();
        let registry = ExtensionRegistry::discover(dir.path().to_path_buf())
            .await
            .unwrap();
        assert!(registry.list().await.is_empty());
    }

    #[tokio::test]
    async fn ensure_connected_unknown_ext_errors() {
        let dir = tempdir().unwrap();
        let registry = ExtensionRegistry::discover(dir.path().to_path_buf())
            .await
            .unwrap();
        let err = registry.ensure_connected("nonexistent").await.unwrap_err();
        assert!(format!("{err:#}").contains("unknown extension"));
    }
}
