//! Session registry for persistent PTY sessions across client reconnects.
//!
//! Sessions are keyed by their unique session_id (random 16-byte hex).
//! Multiple concurrent sessions per peer are supported — each `hop connect`
//! gets its own PTY, and reconnects resume a specific session by ID.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use hop_vt::VtScreen;
use portable_pty::PtySize;
use tokio::sync::{mpsc, oneshot, watch, Notify};

/// A persistent PTY session that survives client disconnects.
///
/// The PTY master handle lives in a background task (spawned by `spawn_pty_session`)
/// that keeps the PTY alive and handles resize commands.
///
/// **Cleanup contract:** removing a session from the registry must call
/// [`DetachedSession::terminate`] so the reader task is cancelled (releasing the
/// daemon's PTY master fd) and the shell process is killed. Dropping the struct
/// alone is *not* enough: although dropping it closes the resize channel (which
/// drops the master-owning task's handle), the PTY reader task holds an
/// independent clone of the master, so the kernel never hangs up the shell — the
/// shell keeps running and that cloned master fd leaks. Even killing the shell
/// isn't sufficient if a backgrounded/`nohup`'d job still holds the slave open
/// (no EOF), which is why `terminate` cancels the reader directly.
pub struct DetachedSession {
    /// Random 16-byte hex session identifier (also the registry key).
    pub session_id: String,
    /// Peer that owns this session (for authorization on resume).
    pub peer_id: String,
    /// Unix username the session runs as.
    pub username: Option<String>,
    /// OS pid of the shell child (process-group leader; the PTY puts it in its
    /// own session via `setsid`). Used by [`terminate`](Self::terminate) to
    /// terminate the shell when the session leaves the registry.
    pub child_pid: Option<u32>,
    /// Cancellation signal for the PTY reader task. Firing it makes the reader
    /// drop its master fd immediately, reclaiming the `/dev/ptmx` even if a
    /// survivor process still holds the slave open (so EOF never arrives).
    /// Fired by [`terminate`](Self::terminate) on every removal path.
    pub reader_cancel: Arc<Notify>,
    /// Send input bytes to the PTY writer task. Unbounded so the host's
    /// shell select-loop never blocks on send when a fast paste fills the
    /// PTY's kernel input buffer — blocking the loop would starve
    /// heartbeats and trip the read deadline, causing a spurious reconnect.
    pub input_tx: mpsc::UnboundedSender<Vec<u8>>,
    /// Route PTY output: `Some(tx)` = forward to client, `None` = discard.
    pub output_route: watch::Sender<Option<mpsc::Sender<Vec<u8>>>>,
    /// Current PTY dimensions, watched by the PTY master task and the
    /// VtScreen-feeder so a single send fans out to all consumers. Last-
    /// write-wins: fast resize bursts (window drags) coalesce naturally,
    /// and anyone holding a `watch::Receiver` can `borrow()` the current
    /// size synchronously without consuming it.
    pub resize_tx: watch::Sender<PtySize>,
    /// Watch channel that receives the child exit status.
    pub exit_rx: watch::Receiver<Option<i32>>,
    /// When the session was last detached (client disconnected).
    pub detached_at: Option<Instant>,
    /// Whether a client is currently attached.
    pub attached: bool,
    /// Unix ms when the session was created.
    pub started_unix_ms: u64,
    /// Monotonic epoch incremented on each attach. Allows stale
    /// disconnect handlers to detect they've been superseded by a
    /// newer attachment and skip the detach.
    pub attach_epoch: u64,
    /// Handle for the broker background task (macOS sandbox proxy).
    /// Aborted when the session is cleaned up.
    pub broker_handle: Option<tokio::task::JoinHandle<()>>,
    /// Off-screen virtual terminal that absorbs every PTY output byte.
    /// On reconnect, `screen.lock().render_full_repaint()` produces bytes
    /// that paint the current grid onto the new client's terminal —
    /// replacing the old raw-byte ring that could leak truncated escape
    /// sequences and stale mode bits.
    pub screen: Arc<Mutex<VtScreen>>,
}

impl DetachedSession {
    /// Publish a new PTY size to all watchers (PTY master, VtScreen).
    /// Idempotent in the sense that watch coalesces — if the size hasn't
    /// changed since the last send, watchers won't wake unnecessarily.
    pub fn resize(&self, size: PtySize) {
        let _ = self.resize_tx.send(size);
    }

    /// Check if the child process has exited.
    pub fn has_exited(&self) -> bool {
        (*self.exit_rx.borrow()).is_some()
    }

    /// Tear down the session's OS resources when it leaves the registry. Two
    /// independent actions, both required (see the struct docs):
    ///
    /// 1. **Cancel the reader** — fires `reader_cancel`, so the PTY reader task
    ///    drops its master fd and the `/dev/ptmx` is reclaimed *immediately*,
    ///    regardless of whether a survivor process still holds the slave open
    ///    (a backgrounded/`nohup`'d job). This is the structural guarantee.
    /// 2. **Kill the shell** — signals the shell's process group (`-pid`:
    ///    SIGHUP then SIGKILL) so the shell and its foreground job don't linger
    ///    as orphans. Skipped when the child already exited (also avoids
    ///    signalling a reused pid). The PTY is a session/group leader (`setsid`).
    pub fn terminate(&self) {
        // (1) Always release the daemon's master fd, even if the shell or a
        // leftover job survives.
        self.reader_cancel.notify_one();

        // (2) Terminate the shell process group unless it's already gone.
        if self.has_exited() {
            return;
        }
        #[cfg(unix)]
        if let Some(pid) = self.child_pid {
            unsafe {
                let gpid = -(pid as i32);
                libc::kill(gpid, libc::SIGHUP);
                libc::kill(gpid, libc::SIGKILL);
            }
        }
    }

    /// Attach a client: route output to the given sender.
    /// Returns the attach epoch so the caller can later detach
    /// only if no newer attachment has superseded it.
    pub fn attach(&mut self, client_tx: mpsc::Sender<Vec<u8>>) -> u64 {
        self.attach_epoch += 1;
        self.attached = true;
        self.detached_at = None;
        // Attaching acknowledges any bells the session rang while unwatched.
        if let Ok(screen) = self.screen.lock() {
            screen.take_bells();
        }
        let _ = self.output_route.send(Some(client_tx));
        self.attach_epoch
    }

    /// Detach the client only if the given epoch matches the current
    /// attachment. This prevents a stale disconnect handler from
    /// detaching a session that was already taken over by a new client.
    pub fn detach_if_current(&mut self, epoch: u64) -> bool {
        if self.attach_epoch == epoch {
            self.attached = false;
            self.detached_at = Some(Instant::now());
            let _ = self.output_route.send(None);
            true
        } else {
            false
        }
    }
}

/// Registry of active PTY sessions, keyed by session_id.
pub struct SessionRegistry {
    sessions: HashMap<String, DetachedSession>,
    timeout: Duration,
    max_sessions: usize,
}

impl SessionRegistry {
    /// Create a new registry with the given detach timeout and session cap.
    pub fn new(timeout: Duration, max_sessions: usize) -> Self {
        Self {
            sessions: HashMap::new(),
            timeout,
            max_sessions,
        }
    }

    /// Look up a session by session_id.
    pub fn lookup(&self, session_id: &str) -> Option<&DetachedSession> {
        self.sessions.get(session_id)
    }

    /// Every session as an operator sees it, newest first.
    pub fn summaries(&self) -> Vec<crate::proto::SessionSummary> {
        let mut out: Vec<crate::proto::SessionSummary> = self
            .sessions
            .values()
            .map(|s| {
                let (title, bells, rows, cols) = match s.screen.lock() {
                    Ok(scr) => {
                        let (r, c) = scr.dims();
                        (scr.title(), scr.bells(), r, c)
                    }
                    Err(_) => (None, 0, 0, 0),
                };
                crate::proto::SessionSummary {
                    session_id: s.session_id.clone(),
                    peer_id: s.peer_id.clone(),
                    username: s.username.clone(),
                    attached: s.attached,
                    started_ms: s.started_unix_ms,
                    idle_secs: s.detached_at.map(|t| t.elapsed().as_secs()).unwrap_or(0),
                    exited: *s.exit_rx.borrow(),
                    title,
                    bells,
                    rows,
                    cols,
                }
            })
            .collect();
        out.sort_by_key(|s| std::cmp::Reverse(s.started_ms));
        out
    }

    /// Look up a session by session_id (mutable).
    pub fn lookup_mut(&mut self, session_id: &str) -> Option<&mut DetachedSession> {
        self.sessions.get_mut(session_id)
    }

    /// Insert a new session, evicting the oldest detached session if at capacity.
    pub fn insert(&mut self, session: DetachedSession) {
        // If we're at the limit, evict the oldest detached (non-attached) session.
        if self.max_sessions > 0 && self.sessions.len() >= self.max_sessions {
            self.evict_oldest_detached();
        }
        self.sessions.insert(session.session_id.clone(), session);
    }

    /// Detach a session only if the given epoch matches the current attachment.
    /// Returns true if the session was actually detached.
    pub fn detach_if_current(&mut self, session_id: &str, epoch: u64) -> bool {
        if let Some(session) = self.sessions.get_mut(session_id) {
            session.detach_if_current(epoch)
        } else {
            false
        }
    }

    /// Remove a session and return it. Kills the shell child first so the PTY
    /// master is reclaimed (a no-op when the child has already exited, which is
    /// the usual case for the cleanup-on-exit path).
    pub fn remove(&mut self, session_id: &str) -> Option<DetachedSession> {
        let session = self.sessions.remove(session_id);
        if let Some(ref s) = session {
            s.terminate();
        }
        session
    }

    /// Number of sessions currently in the registry.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Returns `true` if the registry contains no sessions.
    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Remove sessions that have expired (detached longer than timeout)
    /// or whose child process has exited.
    pub fn reap_expired(&mut self) {
        self.sessions.retain(|_id, session| {
            if session.has_exited() && !session.attached {
                tracing::debug!("Reaping exited session {} (peer: {})", &session.session_id[..8], &session.peer_id[..10.min(session.peer_id.len())]);
                session.terminate(); // already exited → just cancels the (already-gone) reader
                return false;
            }
            if let Some(detached_at) = session.detached_at
                && !session.attached && detached_at.elapsed() > self.timeout
            {
                tracing::debug!("Reaping expired session {} (peer: {})", &session.session_id[..8], &session.peer_id[..10.min(session.peer_id.len())]);
                session.terminate(); // detached past timeout but still running → kill shell + cancel reader
                return false;
            }
            true
        });
    }

    /// Evict the detached session with the oldest `detached_at` time.
    /// If no detached sessions exist, does nothing (insertion will exceed cap).
    fn evict_oldest_detached(&mut self) {
        let oldest = self
            .sessions
            .iter()
            .filter(|(_, s)| !s.attached && s.detached_at.is_some())
            .min_by_key(|(_, s)| s.detached_at.unwrap())
            .map(|(id, _)| id.clone());

        if let Some(id) = oldest {
            tracing::info!("Evicting oldest detached session {} (at capacity)", &id[..8.min(id.len())]);
            if let Some(session) = self.sessions.remove(&id) {
                // The evicted session's shell is still running (it's detached,
                // not exited) — kill it so its PTY master is reclaimed instead
                // of leaking until the process happens to die on its own.
                session.terminate();
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Actor pattern: RegistryHandle + RegistryCommand + actor loop
// ---------------------------------------------------------------------------

/// Result of attaching to an existing session.
pub struct AttachResult {
    pub session_id: String,
    pub input_tx: mpsc::UnboundedSender<Vec<u8>>,
    pub resize_tx: watch::Sender<PtySize>,
    pub exit_rx: watch::Receiver<Option<i32>>,
    pub attach_epoch: u64,
    pub screen: Arc<Mutex<VtScreen>>,
}

/// Info returned when cleaning up an exited session.
pub struct CleanupResult {
    pub session_id: String,
    pub broker_handle: Option<tokio::task::JoinHandle<()>>,
}

/// Commands processed by the registry actor.
pub enum RegistryCommand {
    Attach {
        session_id: String,
        peer_id: String,
        client_tx: mpsc::Sender<Vec<u8>>,
        size: PtySize,
        reply: oneshot::Sender<Option<AttachResult>>,
    },
    Insert {
        session: DetachedSession,
    },
    SetBrokerHandle {
        session_id: String,
        handle: tokio::task::JoinHandle<()>,
    },
    CleanupExited {
        session_id: String,
        epoch: u64,
        reply: oneshot::Sender<Option<CleanupResult>>,
    },
    DetachIfCurrent {
        session_id: String,
        epoch: u64,
        reply: oneshot::Sender<bool>,
    },
    ReapExpired,
    /// Snapshot every session for a listing.
    List { reply: oneshot::Sender<Vec<crate::proto::SessionSummary>> },
}

/// Cloneable handle to the registry actor.
#[derive(Clone)]
pub struct RegistryHandle {
    tx: mpsc::Sender<RegistryCommand>,
}

impl RegistryHandle {
    fn new(tx: mpsc::Sender<RegistryCommand>) -> Self {
        Self { tx }
    }

    /// Attach to an existing session by session_id.
    /// Validates that the requesting peer_id matches the session owner.
    /// Returns `None` if the session doesn't exist, has exited, or peer_id doesn't match.
    pub async fn attach(
        &self,
        session_id: String,
        peer_id: String,
        client_tx: mpsc::Sender<Vec<u8>>,
        size: PtySize,
    ) -> Option<AttachResult> {
        let (reply, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(RegistryCommand::Attach {
                session_id,
                peer_id,
                client_tx,
                size,
                reply,
            })
            .await;
        rx.await.unwrap_or(None)
    }

    /// Insert a newly spawned session (fire-and-forget).
    pub async fn insert(&self, session: DetachedSession) {
        let _ = self
            .tx
            .send(RegistryCommand::Insert { session })
            .await;
    }

    /// Set the broker handle on an existing session (fire-and-forget).
    pub async fn set_broker_handle(&self, session_id: String, handle: tokio::task::JoinHandle<()>) {
        let _ = self
            .tx
            .send(RegistryCommand::SetBrokerHandle { session_id, handle })
            .await;
    }

    /// Remove a session if we're still the current attachment (epoch matches).
    /// Returns the session's broker handle and ID for cleanup.
    pub async fn cleanup_exited(
        &self,
        session_id: String,
        epoch: u64,
    ) -> Option<CleanupResult> {
        let (reply, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(RegistryCommand::CleanupExited { session_id, epoch, reply })
            .await;
        rx.await.unwrap_or(None)
    }

    /// Detach a session only if the given epoch is still current.
    pub async fn detach_if_current(&self, session_id: String, epoch: u64) -> bool {
        let (reply, rx) = oneshot::channel();
        let _ = self
            .tx
            .send(RegistryCommand::DetachIfCurrent { session_id, epoch, reply })
            .await;
        rx.await.unwrap_or(false)
    }

    /// Trigger a reap of expired/exited sessions (fire-and-forget).
    pub async fn reap_expired(&self) {
        let _ = self.tx.send(RegistryCommand::ReapExpired).await;
    }

    /// Every session on this host, newest first.
    pub async fn list(&self) -> Vec<crate::proto::SessionSummary> {
        let (reply, rx) = oneshot::channel();
        let _ = self.tx.send(RegistryCommand::List { reply }).await;
        rx.await.unwrap_or_default()
    }
}

/// Spawn the registry actor task and return a handle to it.
pub fn spawn_registry_actor(timeout: Duration, max_sessions: usize) -> RegistryHandle {
    let (tx, rx) = mpsc::channel(64);
    tokio::spawn(run_registry_actor(rx, timeout, max_sessions));
    RegistryHandle::new(tx)
}

/// The actor loop: owns `SessionRegistry`, processes commands sequentially.
async fn run_registry_actor(
    mut rx: mpsc::Receiver<RegistryCommand>,
    timeout: Duration,
    max_sessions: usize,
) {
    let mut registry = SessionRegistry::new(timeout, max_sessions);

    while let Some(cmd) = rx.recv().await {
        match cmd {
            RegistryCommand::Attach {
                session_id,
                peer_id,
                client_tx,
                size,
                reply,
            } => {
                let result = if let Some(session) = registry.lookup(&session_id) {
                    if session.has_exited() || session.peer_id != peer_id {
                        None
                    } else {
                        let session = registry.lookup_mut(&session_id).unwrap();
                        session.resize(size);
                        let epoch = session.attach(client_tx);
                        Some(AttachResult {
                            session_id: session.session_id.clone(),
                            input_tx: session.input_tx.clone(),
                            resize_tx: session.resize_tx.clone(),
                            exit_rx: session.exit_rx.clone(),
                            attach_epoch: epoch,
                            screen: session.screen.clone(),
                        })
                    }
                } else {
                    None
                };
                let _ = reply.send(result);
            }
            RegistryCommand::Insert { session } => {
                registry.insert(session);
            }
            RegistryCommand::SetBrokerHandle { session_id, handle } => {
                if let Some(session) = registry.lookup_mut(&session_id) {
                    session.broker_handle = Some(handle);
                }
            }
            RegistryCommand::CleanupExited { session_id, epoch, reply } => {
                let result =
                    if registry.lookup(&session_id).map(|s| s.attach_epoch == epoch).unwrap_or(false) {
                        registry.remove(&session_id).map(|s| CleanupResult {
                            session_id: s.session_id,
                            broker_handle: s.broker_handle,
                        })
                    } else {
                        None
                    };
                let _ = reply.send(result);
            }
            RegistryCommand::DetachIfCurrent { session_id, epoch, reply } => {
                let detached = registry.detach_if_current(&session_id, epoch);
                let _ = reply.send(detached);
            }
            RegistryCommand::List { reply } => {
                let _ = reply.send(registry.summaries());
            }
            RegistryCommand::ReapExpired => {
                registry.reap_expired();
            }
        }
    }
}

/// Generate a random 16-byte hex session ID.
pub fn generate_session_id() -> String {
    use rand::Rng;
    let mut bytes = [0u8; 16];
    rand::rng().fill(&mut bytes);
    hex::encode(bytes)
}

/// Unix time in milliseconds.
pub fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a DetachedSession for testing.
    fn make_session(id: &str, peer: &str, attached: bool, exited: Option<i32>) -> DetachedSession {
        let (input_tx, _input_rx) = mpsc::unbounded_channel();
        let (output_route, _output_rx) = watch::channel(None);
        let initial_size = PtySize { rows: 24, cols: 80, pixel_width: 0, pixel_height: 0 };
        let (resize_tx, _resize_rx) = watch::channel(initial_size);
        let (exit_tx, exit_rx) = watch::channel(exited);
        drop(exit_tx); // keep the value set

        DetachedSession {
            session_id: id.into(),
            peer_id: peer.into(),
            username: None,
            child_pid: None,
            reader_cancel: Arc::new(Notify::new()),
            input_tx,
            output_route,
            resize_tx,
            exit_rx,
            detached_at: if attached { None } else { Some(Instant::now()) },
            attached,
            started_unix_ms: 0,
            attach_epoch: 0,
            broker_handle: None,
            screen: Arc::new(Mutex::new(VtScreen::new(24, 80))),
        }
    }

    #[test]
    fn reap_removes_expired_detached_sessions() {
        let mut reg = SessionRegistry::new(Duration::from_millis(0), 10);
        let mut session = make_session("s1", "peer1", false, None);
        session.detached_at = Some(Instant::now() - Duration::from_secs(10));
        reg.insert(session);
        assert_eq!(reg.len(), 1);

        reg.reap_expired();
        assert_eq!(reg.len(), 0, "expired detached session should be reaped");
    }

    #[test]
    fn reap_preserves_attached_sessions() {
        let mut reg = SessionRegistry::new(Duration::from_millis(0), 10);
        let session = make_session("s1", "peer1", true, None);
        reg.insert(session);
        assert_eq!(reg.len(), 1);

        reg.reap_expired();
        assert_eq!(reg.len(), 1, "attached session should not be reaped");
    }

    #[test]
    fn eviction_at_capacity_removes_oldest_detached() {
        let mut reg = SessionRegistry::new(Duration::from_secs(3600), 2);

        let mut s1 = make_session("s1", "peer1", false, None);
        s1.detached_at = Some(Instant::now() - Duration::from_secs(60));
        reg.insert(s1);

        let s2 = make_session("s2", "peer2", true, None);
        reg.insert(s2);

        assert_eq!(reg.len(), 2);

        let s3 = make_session("s3", "peer3", false, None);
        reg.insert(s3);

        assert_eq!(reg.len(), 2);
        assert!(
            reg.lookup("s1").is_none(),
            "oldest detached session should be evicted"
        );
        assert!(
            reg.lookup("s2").is_some(),
            "attached session should survive eviction"
        );
        assert!(
            reg.lookup("s3").is_some(),
            "new session should be inserted"
        );
    }

    #[test]
    fn has_exited_detection() {
        let session_alive = make_session("alive", "peer1", true, None);
        assert!(!session_alive.has_exited(), "session with no exit code should not be exited");

        let session_dead = make_session("dead", "peer1", true, Some(0));
        assert!(session_dead.has_exited(), "session with exit code should be exited");

        let session_error = make_session("error", "peer1", true, Some(1));
        assert!(session_error.has_exited(), "session with non-zero exit should be exited");
    }

    /// Regression (PTY fd leak): removing a session must `terminate` it —
    /// killing the shell child AND firing `reader_cancel`. Spawns a real child
    /// in its own session (mirroring the PTY shell's `setsid`) so the group-kill
    /// can't touch the test runner, then asserts removal killed it and signalled
    /// the reader.
    #[cfg(unix)]
    #[test]
    fn terminate_on_removal_kills_shell_and_cancels_reader() {
        use std::os::unix::process::CommandExt;

        let mut cmd = std::process::Command::new("sleep");
        cmd.arg("300");
        // setsid() in the child → its own session/process group, exactly like
        // portable-pty's PTY shell. Without this, terminate's `-pid` group
        // signal would hit the test process's own group.
        unsafe {
            cmd.pre_exec(|| {
                libc::setsid();
                Ok(())
            });
        }
        let child = cmd.spawn().expect("spawn sleep");
        let pid = child.id();
        // Don't let std's Child reap it on drop — we reap manually below.
        std::mem::forget(child);

        assert_eq!(
            unsafe { libc::kill(pid as i32, 0) },
            0,
            "child should be alive before removal"
        );

        let mut reg = SessionRegistry::new(Duration::from_secs(3600), 10);
        let mut session = make_session("leaky", "peer1", false, None);
        session.child_pid = Some(pid);
        // Observe the reader-cancel signal: a task parked on `notified()` must be
        // woken by removal.
        let cancel = session.reader_cancel.clone();
        let notified = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let notified_w = notified.clone();
        let waiter = std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap();
            rt.block_on(async {
                tokio::time::timeout(Duration::from_secs(5), cancel.notified())
                    .await
                    .expect("reader_cancel should fire on removal");
            });
            notified_w.store(true, std::sync::atomic::Ordering::SeqCst);
        });
        // Give the waiter a moment to park on notified().
        std::thread::sleep(Duration::from_millis(100));

        reg.insert(session);
        let removed = reg.remove("leaky");
        assert!(removed.is_some(), "session should have been removed");

        waiter.join().unwrap();
        assert!(
            notified.load(std::sync::atomic::Ordering::SeqCst),
            "removal must fire reader_cancel (releases the daemon's master fd)"
        );

        // Reap the killed child, then confirm the pid is gone.
        std::thread::sleep(Duration::from_millis(250));
        unsafe { libc::waitpid(pid as i32, std::ptr::null_mut(), 0) };
        let still_alive = unsafe { libc::kill(pid as i32, 0) } == 0;
        assert!(
            !still_alive,
            "removing the session must have killed the shell child"
        );
    }

    #[test]
    fn multiple_sessions_same_peer() {
        let mut reg = SessionRegistry::new(Duration::from_secs(3600), 10);

        let s1 = make_session("session-a", "peer1", true, None);
        let s2 = make_session("session-b", "peer1", true, None);
        reg.insert(s1);
        reg.insert(s2);

        assert_eq!(reg.len(), 2, "same peer should have two sessions");
        assert!(reg.lookup("session-a").is_some());
        assert!(reg.lookup("session-b").is_some());
    }
}
