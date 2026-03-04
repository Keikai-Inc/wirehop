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
    pub fn attach(&mut self, client_tx: mpsc::Sender<Vec<u8>>) {
        self.attached = true;
        self.detached_at = None;
        let _ = self.output_route.send(Some(client_tx));
    }

    /// Detach the client: stop routing output.
    pub fn detach(&mut self) {
        self.attached = false;
        self.detached_at = Some(Instant::now());
        let _ = self.output_route.send(None);
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

    /// Mark a session as detached.
    pub fn detach(&mut self, key: &SessionKey) {
        if let Some(session) = self.sessions.get_mut(key) {
            session.detach();
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
