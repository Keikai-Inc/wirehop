//! Session registry for persistent PTY sessions across client reconnects.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use portable_pty::PtySize;
use tokio::sync::{mpsc, watch};

/// Key identifying a session: one session per (peer_id, username) pair.
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
pub struct SessionKey {
    pub peer_id: String,
    pub username: Option<String>,
}

/// A persistent PTY session that survives client disconnects.
///
/// The PTY master handle lives in a background task (spawned by `spawn_pty_session`)
/// that keeps the PTY alive and handles resize commands. Dropping this struct closes
/// the resize channel, which causes the background task to exit and drop the master,
/// sending SIGHUP to the shell.
pub struct DetachedSession {
    /// Random 16-byte hex session identifier.
    pub session_id: String,
    /// Send input bytes to the PTY writer task.
    pub input_tx: mpsc::Sender<Vec<u8>>,
    /// Route PTY output: `Some(tx)` = forward to client, `None` = discard.
    pub output_route: watch::Sender<Option<mpsc::Sender<Vec<u8>>>>,
    /// Send resize commands to the background task holding the PTY master.
    pub resize_tx: mpsc::Sender<PtySize>,
    /// Watch channel that receives the child exit status.
    pub exit_rx: watch::Receiver<Option<i32>>,
    /// When the session was last detached (client disconnected).
    pub detached_at: Option<Instant>,
    /// Whether a client is currently attached.
    pub attached: bool,
    /// Monotonic epoch incremented on each attach. Allows stale
    /// disconnect handlers to detect they've been superseded by a
    /// newer attachment and skip the detach.
    pub attach_epoch: u64,
    /// Handle for the broker background task (macOS sandbox proxy).
    /// Aborted when the session is cleaned up.
    pub broker_handle: Option<tokio::task::JoinHandle<()>>,
}

impl DetachedSession {
    /// Resize the PTY to the given dimensions.
    pub fn resize(&self, size: PtySize) {
        let _ = self.resize_tx.try_send(size);
    }

    /// Check if the child process has exited.
    pub fn has_exited(&self) -> bool {
        (*self.exit_rx.borrow()).is_some()
    }

    /// Attach a client: route output to the given sender.
    /// Returns the attach epoch so the caller can later detach
    /// only if no newer attachment has superseded it.
    pub fn attach(&mut self, client_tx: mpsc::Sender<Vec<u8>>) -> u64 {
        self.attach_epoch += 1;
        self.attached = true;
        self.detached_at = None;
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

/// Registry of active PTY sessions, keyed by (peer_id, username).
pub struct SessionRegistry {
    sessions: HashMap<SessionKey, DetachedSession>,
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

    /// Look up a session by key.
    pub fn lookup(&self, key: &SessionKey) -> Option<&DetachedSession> {
        self.sessions.get(key)
    }

    /// Look up a session by key (mutable).
    pub fn lookup_mut(&mut self, key: &SessionKey) -> Option<&mut DetachedSession> {
        self.sessions.get_mut(key)
    }

    /// Insert a new session, evicting the oldest detached session if at capacity.
    pub fn insert(&mut self, key: SessionKey, session: DetachedSession) {
        // If we're at the limit, evict the oldest detached (non-attached) session.
        if self.max_sessions > 0 && self.sessions.len() >= self.max_sessions {
            self.evict_oldest_detached();
        }
        self.sessions.insert(key, session);
    }

    /// Detach a session only if the given epoch matches the current attachment.
    /// Returns true if the session was actually detached.
    pub fn detach_if_current(&mut self, key: &SessionKey, epoch: u64) -> bool {
        if let Some(session) = self.sessions.get_mut(key) {
            session.detach_if_current(epoch)
        } else {
            false
        }
    }

    /// Remove a session and return it (dropping it will close the PTY).
    pub fn remove(&mut self, key: &SessionKey) -> Option<DetachedSession> {
        self.sessions.remove(key)
    }

    /// Number of sessions currently in the registry.
    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    /// Remove sessions that have expired (detached longer than timeout)
    /// or whose child process has exited.
    pub fn reap_expired(&mut self) {
        self.sessions.retain(|key, session| {
            if session.has_exited() && !session.attached {
                tracing::debug!("Reaping exited session for {:?}", key);
                return false;
            }
            if let Some(detached_at) = session.detached_at {
                if !session.attached && detached_at.elapsed() > self.timeout {
                    tracing::debug!("Reaping expired session for {:?}", key);
                    return false;
                }
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
            .map(|(k, _)| k.clone());

        if let Some(key) = oldest {
            tracing::info!("Evicting oldest detached session for {:?} (at capacity)", key);
            self.sessions.remove(&key);
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper to create a DetachedSession for testing.
    fn make_session(id: &str, attached: bool, exited: Option<i32>) -> DetachedSession {
        let (input_tx, _input_rx) = mpsc::channel(1);
        let (output_route, _output_rx) = watch::channel(None);
        let (resize_tx, _resize_rx) = mpsc::channel(1);
        let (exit_tx, exit_rx) = watch::channel(exited);
        drop(exit_tx); // keep the value set

        DetachedSession {
            session_id: id.into(),
            input_tx,
            output_route,
            resize_tx,
            exit_rx,
            detached_at: if attached { None } else { Some(Instant::now()) },
            attached,
            attach_epoch: 0,
            broker_handle: None,
        }
    }

    fn make_key(peer: &str) -> SessionKey {
        SessionKey {
            peer_id: peer.into(),
            username: None,
        }
    }

    #[test]
    fn reap_removes_expired_detached_sessions() {
        let mut reg = SessionRegistry::new(Duration::from_millis(0), 10);
        let mut session = make_session("s1", false, None);
        // Set detached_at to the past so it's already expired
        session.detached_at = Some(Instant::now() - Duration::from_secs(10));
        reg.insert(make_key("peer1"), session);
        assert_eq!(reg.len(), 1);

        reg.reap_expired();
        assert_eq!(reg.len(), 0, "expired detached session should be reaped");
    }

    #[test]
    fn reap_preserves_attached_sessions() {
        let mut reg = SessionRegistry::new(Duration::from_millis(0), 10);
        let session = make_session("s1", true, None);
        reg.insert(make_key("peer1"), session);
        assert_eq!(reg.len(), 1);

        reg.reap_expired();
        assert_eq!(reg.len(), 1, "attached session should not be reaped");
    }

    #[test]
    fn eviction_at_capacity_removes_oldest_detached() {
        let mut reg = SessionRegistry::new(Duration::from_secs(3600), 2);

        // Insert first detached session (oldest)
        let mut s1 = make_session("s1", false, None);
        s1.detached_at = Some(Instant::now() - Duration::from_secs(60));
        reg.insert(make_key("peer1"), s1);

        // Insert attached session
        let s2 = make_session("s2", true, None);
        reg.insert(make_key("peer2"), s2);

        assert_eq!(reg.len(), 2);

        // Insert third session — should evict s1 (oldest detached), not s2 (attached)
        let s3 = make_session("s3", false, None);
        reg.insert(make_key("peer3"), s3);

        assert_eq!(reg.len(), 2);
        assert!(
            reg.lookup(&make_key("peer1")).is_none(),
            "oldest detached session should be evicted"
        );
        assert!(
            reg.lookup(&make_key("peer2")).is_some(),
            "attached session should survive eviction"
        );
        assert!(
            reg.lookup(&make_key("peer3")).is_some(),
            "new session should be inserted"
        );
    }

    #[test]
    fn has_exited_detection() {
        let session_alive = make_session("alive", true, None);
        assert!(!session_alive.has_exited(), "session with no exit code should not be exited");

        let session_dead = make_session("dead", true, Some(0));
        assert!(session_dead.has_exited(), "session with exit code should be exited");

        let session_error = make_session("error", true, Some(1));
        assert!(session_error.has_exited(), "session with non-zero exit should be exited");
    }
}
