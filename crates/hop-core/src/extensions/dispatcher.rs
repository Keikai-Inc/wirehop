//! Extension dispatcher — async request/response routing on top of the
//! sync-handed `ExtensionRegistry`.
//!
//! Hop core's existing peer-op handler is sync (`peer_ops::handle_peer_request`).
//! Extension routing is inherently async (we wait for an extension daemon
//! to reply over an ipc-channel-backed mpsc). This module bridges the
//! two: it exposes a single `dispatch` async method that handles all
//! `PeerRequest::Extension*` variants and returns a `PeerResponse`.
//!
//! Per-extension demultiplexing: when the first request to an extension
//! arrives, the dispatcher spawns a demux task that owns the inbound
//! receiver and routes responses back to the caller by `request_id`.
//! The demux task lives for the lifetime of the connection.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use anyhow::Result;
use tokio::sync::{Mutex, oneshot};
use tracing::warn;

use super::registry::{ExtMessage, ExtensionRegistry};
use crate::proto::{ExtensionInfo, PeerRequest, PeerResponse};

/// Information about who's making the request, forwarded to the
/// extension so it can apply per-peer authorization.
#[derive(Debug, Clone)]
pub struct PeerContext {
    pub peer_id: String,
    pub peer_username: Option<String>,
    pub peer_role: String,
}

/// Async dispatcher for `PeerRequest::Extension*` variants.
#[derive(Clone)]
pub struct ExtensionDispatcher {
    registry: ExtensionRegistry,
    next_request_id: Arc<AtomicU64>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<(bool, Vec<u8>)>>>>,
    /// Set of extensions for which we've already started a demux task.
    /// Once started, the demux runs for the lifetime of the connection;
    /// reconnects will spawn a fresh one.
    demux_started: Arc<Mutex<HashMap<String, ()>>>,
}

impl ExtensionDispatcher {
    pub fn new(registry: ExtensionRegistry) -> Self {
        Self {
            registry,
            next_request_id: Arc::new(AtomicU64::new(1)),
            pending: Arc::new(Mutex::new(HashMap::new())),
            demux_started: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Dispatch an Extension* peer request, returning the appropriate
    /// PeerResponse. Non-extension variants are not handled here — the
    /// caller is responsible for routing those to the sync handler.
    pub async fn dispatch(&self, peer: PeerContext, request: PeerRequest) -> PeerResponse {
        match request {
            PeerRequest::ExtensionList => self.handle_list().await,
            PeerRequest::ExtensionCall { ext_id, payload } => {
                self.handle_call(peer, ext_id, payload).await
            }
            PeerRequest::ExtensionStreamOpen { .. }
            | PeerRequest::ExtensionStreamInput { .. }
            | PeerRequest::ExtensionStreamClose { .. } => PeerResponse::Error(
                "extension streaming not yet implemented; use ExtensionCall".into(),
            ),
            other => PeerResponse::Error(format!(
                "non-extension variant routed to dispatcher: {other:?}"
            )),
        }
    }

    async fn handle_list(&self) -> PeerResponse {
        let entries = self.registry.probe_all().await;
        let infos: Vec<ExtensionInfo> = entries
            .into_iter()
            .map(|(m, status)| ExtensionInfo {
                ext_id: m.ext_id,
                description: m.description,
                required_role: m.required_role,
                available: matches!(status, super::registry::ExtensionStatus::Available),
            })
            .collect();
        PeerResponse::ExtensionEntries(infos)
    }

    async fn handle_call(
        &self,
        peer: PeerContext,
        ext_id: String,
        payload: Vec<u8>,
    ) -> PeerResponse {
        // Ensure connection. ensure_connected is idempotent.
        if let Err(e) = self.registry.ensure_connected(&ext_id).await {
            return PeerResponse::Error(format!("extension {ext_id} unavailable: {e:#}"));
        }

        // Ensure a demux task is running for this extension.
        if let Err(e) = self.ensure_demux(&ext_id).await {
            return PeerResponse::Error(format!("starting demux for {ext_id}: {e:#}"));
        }

        // Allocate request_id, install pending oneshot.
        let request_id = self.next_request_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel::<(bool, Vec<u8>)>();
        {
            let mut pending = self.pending.lock().await;
            pending.insert(request_id, tx);
        }

        // Send the request through the registry.
        let msg = ExtMessage::Request {
            request_id,
            peer_id: peer.peer_id,
            peer_username: peer.peer_username,
            peer_role: peer.peer_role,
            payload,
        };
        if let Err(e) = self.registry.send_to(&ext_id, msg).await {
            // Clean up the pending entry; nothing will satisfy it now.
            let mut pending = self.pending.lock().await;
            pending.remove(&request_id);
            return PeerResponse::Error(format!("send to {ext_id}: {e:#}"));
        }

        // Wait for the demux to deliver the response.
        match rx.await {
            Ok((ok, payload)) => PeerResponse::ExtensionResult { ok, payload },
            Err(_) => {
                // Sender dropped (connection died, etc.).
                PeerResponse::Error(format!(
                    "extension {ext_id} disconnected before responding to request {request_id}"
                ))
            }
        }
    }

    /// Idempotent: ensure a demux task is running for the given extension.
    async fn ensure_demux(&self, ext_id: &str) -> Result<()> {
        // Fast path: already started.
        {
            let started = self.demux_started.lock().await;
            if started.contains_key(ext_id) {
                return Ok(());
            }
        }

        // Take the receiver from the registry. If someone else got
        // there first (or the connection isn't actually open), bail.
        let recv_rx = self
            .registry
            .take_recv(ext_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("no inbound receiver for {ext_id}"))?;

        // Mark as started before spawning so concurrent ensure_demux
        // calls don't race. Worst case: both spawn — but take_recv only
        // succeeds once, so the second spawn fails and exits cleanly.
        {
            let mut started = self.demux_started.lock().await;
            started.insert(ext_id.to_string(), ());
        }

        let pending = Arc::clone(&self.pending);
        let id_for_log = ext_id.to_string();
        let demux_started = Arc::clone(&self.demux_started);

        tokio::spawn(async move {
            run_demux(id_for_log.clone(), recv_rx, pending).await;
            // When the demux loop exits (channel closed), allow a future
            // ensure_demux to spawn a fresh one if the connection comes
            // back.
            let mut started = demux_started.lock().await;
            started.remove(&id_for_log);
        });

        Ok(())
    }
}

/// Per-extension demultiplexer. Reads incoming ExtMessages and routes
/// Response to the matching pending oneshot. Other variants are
/// currently dropped with a warning; streaming support will hook in
/// here when added.
async fn run_demux(
    ext_id: String,
    mut rx: tokio::sync::mpsc::UnboundedReceiver<ExtMessage>,
    pending: Arc<Mutex<HashMap<u64, oneshot::Sender<(bool, Vec<u8>)>>>>,
) {
    while let Some(msg) = rx.recv().await {
        match msg {
            ExtMessage::Response { request_id, ok, payload } => {
                let mut pending = pending.lock().await;
                if let Some(sender) = pending.remove(&request_id) {
                    let _ = sender.send((ok, payload));
                } else {
                    warn!(
                        ext_id = %ext_id,
                        request_id,
                        "received response for unknown request_id; ignoring"
                    );
                }
            }
            ExtMessage::HelloAck { .. } | ExtMessage::Hello { .. } => {
                // Handshake messages: shouldn't reach here post-handshake,
                // but ignore quietly if they do.
            }
            ExtMessage::StreamOpened { .. }
            | ExtMessage::StreamFrame { .. }
            | ExtMessage::StreamClosed { .. } => {
                // Streaming dispatch will hook in here. For v1, drop.
                tracing::trace!(ext_id = %ext_id, "stream message dropped (streaming not implemented)");
            }
            ExtMessage::Request { .. }
            | ExtMessage::StreamOpen { .. }
            | ExtMessage::StreamInput { .. }
            | ExtMessage::StreamClose { .. } => {
                // These flow hop -> ext, not the other way.
                warn!(ext_id = %ext_id, "extension sent hop-bound variant; ignoring");
            }
        }
    }
    // Channel closed: cancel any pending requests.
    let mut pending = pending.lock().await;
    pending.clear();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::path::PathBuf;
    use ipc_channel::ipc::{IpcOneShotServer, IpcSender};
    use tempfile::tempdir;

    fn current_uid() -> u32 {
        unsafe { libc::getuid() }
    }

    /// Spawn a fake extension that echoes any Request it receives back
    /// as a matching Response with the same payload (an "echo" extension).
    fn spawn_echo_extension(
        bootstrap_path: PathBuf,
        version: &str,
    ) -> std::thread::JoinHandle<()> {
        let version = version.to_string();
        std::thread::spawn(move || {
            let (server, server_name) =
                IpcOneShotServer::<ExtMessage>::new().expect("server");
            let bs = super::super::Bootstrap {
                server_name,
                pid: std::process::id(),
                version: version.clone(),
            };
            std::fs::write(&bootstrap_path, toml::to_string(&bs).unwrap()).unwrap();
            std::fs::set_permissions(
                &bootstrap_path,
                std::fs::Permissions::from_mode(0o600),
            )
            .unwrap();

            let (rx, hello) = server.accept().expect("accept");
            let reverse_name = match hello {
                ExtMessage::Hello { reverse_name, .. } => reverse_name,
                _ => panic!("expected Hello"),
            };
            let tx: IpcSender<ExtMessage> =
                IpcSender::connect(reverse_name).expect("reverse connect");
            tx.send(ExtMessage::HelloAck { ext_version: version }).unwrap();

            // Echo loop.
            loop {
                match rx.recv() {
                    Ok(ExtMessage::Request { request_id, payload, .. }) => {
                        if tx.send(ExtMessage::Response {
                            request_id,
                            ok: true,
                            payload,
                        })
                        .is_err()
                        {
                            break;
                        }
                    }
                    Ok(_) => {} // ignore other variants in this fake
                    Err(_) => break,
                }
            }
        })
    }

    #[tokio::test]
    async fn echo_round_trip_via_dispatcher() {
        let dir = tempdir().unwrap();
        let bootstrap_path = dir.path().join("bootstrap");
        let manifest_path = dir.path().join("echo.toml");
        std::fs::write(
            &manifest_path,
            format!(
                r#"
                ext_id = "echo"
                description = "Echo test"
                bootstrap_path = "{}"
                expected_uid = {}
                version = "0.1.0"
                "#,
                bootstrap_path.display(),
                current_uid()
            ),
        )
        .unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        // Spawn the echo extension. It writes the bootstrap then waits
        // for hop to drive the rest.
        let _ext_handle = spawn_echo_extension(bootstrap_path.clone(), "0.1.0");
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let registry = ExtensionRegistry::discover(dir.path().to_path_buf())
            .await
            .unwrap();
        let dispatcher = ExtensionDispatcher::new(registry);

        // Issue an ExtensionCall.
        let resp = dispatcher
            .dispatch(
                PeerContext {
                    peer_id: "test-peer".into(),
                    peer_username: Some("alice".into()),
                    peer_role: "peer".into(),
                },
                PeerRequest::ExtensionCall {
                    ext_id: "echo".into(),
                    payload: b"hello world".to_vec(),
                },
            )
            .await;

        match resp {
            PeerResponse::ExtensionResult { ok, payload } => {
                assert!(ok);
                assert_eq!(payload, b"hello world".to_vec());
            }
            other => panic!("unexpected response: {other:?}"),
        }

        // Issue a second call to confirm the demux handles multiple in-flight.
        let resp2 = dispatcher
            .dispatch(
                PeerContext {
                    peer_id: "test-peer".into(),
                    peer_username: Some("alice".into()),
                    peer_role: "peer".into(),
                },
                PeerRequest::ExtensionCall {
                    ext_id: "echo".into(),
                    payload: b"second".to_vec(),
                },
            )
            .await;
        match resp2 {
            PeerResponse::ExtensionResult { ok, payload } => {
                assert!(ok);
                assert_eq!(payload, b"second".to_vec());
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn list_returns_known_extensions() {
        let dir = tempdir().unwrap();
        let manifest_path = dir.path().join("a.toml");
        std::fs::write(
            &manifest_path,
            r#"
            ext_id = "a.test"
            description = "Test extension A"
            bootstrap_path = "/tmp/nonexistent"
            "#,
        )
        .unwrap();
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();

        let registry = ExtensionRegistry::discover(dir.path().to_path_buf())
            .await
            .unwrap();
        let dispatcher = ExtensionDispatcher::new(registry);

        let resp = dispatcher
            .dispatch(
                PeerContext {
                    peer_id: "x".into(),
                    peer_username: None,
                    peer_role: "peer".into(),
                },
                PeerRequest::ExtensionList,
            )
            .await;

        match resp {
            PeerResponse::ExtensionEntries(entries) => {
                assert_eq!(entries.len(), 1);
                assert_eq!(entries[0].ext_id, "a.test");
                // Bootstrap path doesn't exist, so available should be false.
                assert!(!entries[0].available);
            }
            other => panic!("unexpected: {other:?}"),
        }
    }

    #[tokio::test]
    async fn unknown_extension_in_call_returns_error() {
        let dir = tempdir().unwrap();
        let registry = ExtensionRegistry::discover(dir.path().to_path_buf())
            .await
            .unwrap();
        let dispatcher = ExtensionDispatcher::new(registry);

        let resp = dispatcher
            .dispatch(
                PeerContext {
                    peer_id: "x".into(),
                    peer_username: None,
                    peer_role: "peer".into(),
                },
                PeerRequest::ExtensionCall {
                    ext_id: "nonexistent".into(),
                    payload: vec![],
                },
            )
            .await;

        match resp {
            PeerResponse::Error(msg) => assert!(msg.contains("nonexistent")),
            other => panic!("expected error, got {other:?}"),
        }
    }
}
