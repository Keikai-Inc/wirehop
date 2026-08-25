//! Wire types for the hop-tap extension subprotocol.
//!
//! These types are the contract between hop-tap-d (the extension
//! daemon) and any caller that wants to ask it for sessions or
//! subscribe to live output. The only callers we ship are:
//!
//! - **`hop-tap-probe`** — bundled in this workspace; talks ipc-channel
//!   directly to a running hop-tap-d for development / smoke testing.
//! - **`hop-cli`** — the production path; relays through hop's
//!   extension dispatcher. Pulls this crate in via path dependency.
//!
//! The wire format is bincode 2 with `serde`. Encode every request /
//! response with `bincode::serde::encode_to_vec(value, bincode::config::standard())`,
//! decode with `bincode::serde::decode_from_slice`.
//!
//! ## Why a separate crate?
//!
//! Originally this lived inside hop-tap-d as a private module. Once
//! hop-cli grew a `tap` verb we needed a single source of truth for
//! the wire types — extracting prevents silent drift if a field is
//! renamed in one place but not the other. The crate is intentionally
//! tiny (just serde derives, no logic) so cross-workspace consumers
//! don't pay a transitive cost.

#![forbid(unsafe_code)]

use serde::{Deserialize, Serialize};

pub mod local;

/// Peer-initiated request. Carried inside `ExtMessage::Request.payload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TapRequest {
    /// List currently-active sessions. Returns [`TapResponse::SessionList`].
    List,
    /// Snapshot the visible screen for a given pty index. Returns
    /// [`TapResponse::Snapshot`] on success or [`TapResponse::Error`]
    /// if the index isn't currently being captured.
    Snapshot { pty_index: i32 },
    /// Write `bytes` into the captured session's pty master, as if
    /// the user typed them. Authorized only for the session's opener
    /// or a creator-role peer — read scope alone is not enough. The
    /// daemon clones the master fd from whoever holds it (sshd, tmux,
    /// the local terminal) via `pidfd_getfd` and writes through that.
    Inject { pty_index: i32, bytes: Vec<u8> },
    /// Send a signal to the session's opener (the shell). Default is
    /// SIGHUP — the same signal a closed terminal emulator sends, so
    /// well-behaved shells exit cleanly and propagate to children.
    /// If `force` is set we send SIGKILL instead.
    /// Same write-scope authorization as Inject.
    Kill { pty_index: i32, force: bool },
    /// Display an admin message to the user attached to the captured
    /// session. Unlike Inject, this is *terminal output* (written to
    /// /dev/pts/N from the daemon) so the bytes don't get parsed as
    /// shell input — they just appear on screen, formatted distinctly.
    /// Same write-scope authorization as Inject.
    AdminMessage {
        pty_index: i32,
        message: String,
        /// Display name shown to the recipient as "[admin: <name>]".
        /// The CLI fills it in with the local username; the daemon
        /// trusts it (same trust model as the rest of the protocol —
        /// the kernel-authoritative uid is on PeerContext separately).
        from: String,
    },
    /// Freeze (or thaw) the captured session by SIGSTOPping its
    /// foreground process group. While locked, anything the user
    /// types into the session is queued in the kernel's pty input
    /// buffer but never read by the shell. On unlock the daemon
    /// flushes that buffer (so accumulated keystrokes don't suddenly
    /// run as commands) and SIGCONTs the group. Same write-scope
    /// authorization as Inject.
    SetLock { pty_index: i32, locked: bool },
    /// Transition (or release) the captured session into a
    /// sandboxed honeypot. While quarantined the user is talking to
    /// an impostor bash running in a Linux-namespace sandbox; their
    /// real shell stays SIGSTOPped in the background so the swap is
    /// reversible. Same write-scope authorization as Inject.
    SetQuarantine { pty_index: i32, quarantined: bool },
    /// Update an open subscription's viewport. The subscriber sends
    /// this when its local terminal resizes (SIGWINCH); the daemon
    /// updates the StreamRecord and triggers an immediate re-render
    /// targeting the new dimensions, including a screen-clear so
    /// any newly-revealed rows are clean instead of showing stale
    /// content from before the resize. Replies with
    /// `TapResponse::SubscriptionResized` on success or
    /// `TapResponse::Error` if the stream_id isn't valid.
    ResizeSubscription {
        stream_id: u64,
        rows: u16,
        cols: u16,
    },
    /// Send a chat message back to whoever is tapping the caller's
    /// own session. The daemon uses the kernel-authoritative
    /// controlling tty of the calling peer (from SO_PEERCRED on the
    /// local socket) to identify which session to attribute the
    /// reply to; subscribers of that session all receive a
    /// `TapStreamFrame::UserReply` frame. No tapper privilege is
    /// required — anyone can reply to whoever is observing them.
    Reply {
        /// Display name shown to subscribers as `[user: <name>]`.
        /// Convention: caller fills in their local username; the
        /// daemon trusts it (same trust model as AdminMessage's
        /// `from` field; the kernel-authoritative uid is on the
        /// PeerContext separately for any caller that wants to
        /// cross-check).
        from: String,
        /// The reply text. UTF-8.
        message: String,
    },
}

/// Daemon's reply. Carried inside `ExtMessage::Response.payload`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TapResponse {
    SessionList(Vec<SessionInfo>),
    Snapshot {
        pty_index: i32,
        rows: u16,
        cols: u16,
        /// One entry per row, top-to-bottom, with no trailing CR/LF.
        /// Trailing whitespace is preserved so the caller can choose
        /// whether to display a 24-row block verbatim or trim.
        contents: Vec<String>,
    },
    /// Reply to a successful [`TapRequest::Inject`]. `bytes_written`
    /// can be smaller than the requested length on a short write
    /// (rare for ptys; the kernel buffer is typically large enough).
    Injected {
        pty_index: i32,
        bytes_written: usize,
    },
    /// Reply to a successful [`TapRequest::Kill`]. Reports which
    /// pid we signaled and the signal number used.
    Killed {
        pty_index: i32,
        pid: u32,
        signal: i32,
    },
    /// Reply to a successful [`TapRequest::AdminMessage`].
    MessageDelivered {
        pty_index: i32,
        bytes_written: usize,
    },
    /// Reply to a successful [`TapRequest::SetLock`]. `pgrp` is the
    /// foreground process group we signaled; useful for diagnostics.
    LockSet {
        pty_index: i32,
        locked: bool,
        pgrp: i32,
    },
    /// Reply to a successful [`TapRequest::SetQuarantine`]. On
    /// quarantine, `impostor_pid` is the PID of the spawned
    /// sandboxed bash; on release it's None.
    QuarantineSet {
        pty_index: i32,
        quarantined: bool,
        impostor_pid: Option<u32>,
    },
    /// Reply to a successful [`TapRequest::ResizeSubscription`].
    /// Echoes the new dimensions for confirmation.
    SubscriptionResized {
        stream_id: u64,
        rows: u16,
        cols: u16,
    },
    /// Reply to a successful [`TapRequest::Reply`]. `subscribers` is
    /// how many tappers received the reply — useful for the caller
    /// to know whether anyone was actually listening.
    Replied {
        pty_index: i32,
        subscribers: usize,
    },
    Error(String),
}

/// One row of a [`TapResponse::SessionList`].
///
/// Mirrors the fields of `SessionState` we expose to peers. Internal
/// fields (the alacritty `Term`, the parser, raw byte counts beyond
/// what we surface) stay daemon-side.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionInfo {
    pub pty_index: i32,
    /// Sticky identity captured the first time the daemon saw this
    /// pty. For sessions that started after the daemon, this is the
    /// controlling shell — i.e., who logged in. Diverges from
    /// `last_*` whenever a privileged sub-command (sudo, su) writes
    /// into the same pty. **Use `opener_*` for authorization
    /// decisions** (e.g. "is this peer allowed to view this
    /// session"); use `last_*` for diagnostic display.
    pub opener_pid: u32,
    pub opener_comm: String,
    pub opener_uid: u32,
    pub opener_gid: u32,
    pub opener_username: Option<String>,
    /// Most recent writer — what's actually emitting bytes right
    /// now. Updates on every event.
    pub last_pid: u32,
    pub last_comm: String,
    pub last_uid: u32,
    pub last_gid: u32,
    /// Best-effort username resolution via `getpwuid_r`. None if
    /// the uid doesn't exist in the daemon's view of /etc/passwd
    /// (common under PID/user namespacing).
    pub last_username: Option<String>,
    pub output_bytes: u64,
    pub input_bytes: u64,
    pub output_events: u64,
    pub input_events: u64,
    /// Milliseconds since session creation.
    pub age_ms: u64,
    /// Milliseconds since last observed activity.
    pub idle_ms: u64,
    /// True if an admin has frozen this session via `TapRequest::SetLock`.
    /// While set, the user's input is queued but never reaches the
    /// shell. Lives in daemon memory only — survives reconnects but
    /// not daemon restarts (the underlying SIGSTOP does, though).
    #[serde(default)]
    pub locked: bool,
    /// True if an admin has transitioned this session into a
    /// honeypot sandbox via `TapRequest::SetQuarantine`. The real
    /// shell is SIGSTOPped (and thus also `locked`) and an impostor
    /// bash running in a namespace sandbox owns the captured pty.
    #[serde(default)]
    pub quarantined: bool,
}

/// Carried inside `ExtMessage::StreamOpen.payload`. The peer asks
/// to subscribe to live updates from a specific session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TapStreamRequest {
    /// Open a subscription to the captured pty's grid.
    ///
    /// `viewport_rows` / `viewport_cols` is the subscriber's local
    /// terminal size. The daemon renders the captured pty's grid
    /// clipped to (or padded out from) these dimensions and streams
    /// cell-positioned cursor moves + SGR + UTF-8 — never raw pty
    /// bytes from the captured session. That decouples the
    /// subscriber's terminal size from the captured pty's size and
    /// closes the class of bugs where the subscriber's terminal
    /// volunteers protocol responses (OSC color queries, focus
    /// events, mouse) that race back into the captured app's input
    /// stream as keystrokes.
    Subscribe {
        pty_index: i32,
        viewport_rows: u16,
        viewport_cols: u16,
    },
}

/// Carried inside `ExtMessage::StreamFrame.payload`. The first frame
/// after `StreamOpened` is always [`TapStreamFrame::Initial`] which
/// catches the subscriber up to current state; subsequent frames
/// stream live as the session produces output.
///
/// Both `Initial::replay_bytes` and `Output(bytes)` carry rendered
/// terminal output — cursor-positioned cells, SGR runs, UTF-8 —
/// targeting the subscriber's viewport size. Subscribers write the
/// bytes to their stdout verbatim. The bytes are *not* the raw
/// captured pty stream; they're a re-render of the daemon's grid
/// state for this specific subscriber's terminal dimensions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TapStreamFrame {
    /// Sent once, immediately after `StreamOpened`. Carries the
    /// captured pty's dimensions (informational — what the captured
    /// app thinks its window size is) plus `replay_bytes` rendered
    /// to the subscriber's viewport. Write it to your terminal first
    /// so the screen is in sync before live frames start arriving.
    Initial {
        rows: u16,
        cols: u16,
        replay_bytes: Vec<u8>,
    },
    /// A new full re-render of the captured pty's grid, clipped /
    /// padded to the subscriber's viewport. Each frame paints all
    /// visible cells; cursor moves position the writes at the right
    /// row/col. Subscribers can dump this into their stdout without
    /// any state tracking — every render is self-contained.
    Output(Vec<u8>),
    /// The captured pty's kernel-reported dimensions changed
    /// (TIOCSWINSZ on the captured side). Informational. The
    /// subscriber's viewport is unchanged — the daemon will keep
    /// rendering at the subscriber's size.
    Resize { rows: u16, cols: u16 },
    /// The captured user replied via `tap reply`. Subscribers
    /// receive this frame and can render it however they like
    /// (typically as an overlay banner, mirroring how the captured
    /// user sees admin messages). Multiple subscribers attached to
    /// the same session all receive the same UserReply frame.
    UserReply { from: String, message: String },
}
