//! Wire types for the **local** socket — the path used by the
//! `tap` CLI talking directly to `hop-tap-d` over a Unix domain
//! socket (`/run/hop-tap/local.sock`).
//!
//! This protocol is intentionally separate from the hop-extension
//! `ExtMessage` envelope: a local CLI shouldn't need to know
//! anything about hop, peer_id, peer_role, or the
//! Hello/HelloAck rendezvous dance. Authentication on the local
//! socket is `SO_PEERCRED` — the daemon learns the caller's uid
//! authoritatively from the kernel — so there's no need to carry
//! identity claims on the wire.
//!
//! ## Wire framing
//!
//! Each message is length-prefixed bincode of [`LocalMessage`]:
//!
//! ```text
//! +-- 4 bytes BE --+-- N bytes --+
//! |   length (u32) | bincode pl. |
//! +----------------+-------------+
//! ```
//!
//! Length excludes the 4-byte prefix itself. Maximum payload size
//! capped by the daemon at 16 MiB (matching hop-core's frame cap)
//! to prevent decompression-bomb-ish behaviour from a hostile
//! local client.

use serde::{Deserialize, Serialize};

use crate::{TapRequest, TapResponse, TapStreamFrame, TapStreamRequest};

/// One protocol message, in either direction. The daemon and the
/// CLI use the same type — direction-of-flow is documented per
/// variant.
///
/// Each `Call` / `Subscribe` from the client gets a `request_id`;
/// responses echo that id back. Stream frames after a successful
/// `Subscribe` reference the `stream_id` the daemon assigned in
/// the `StreamOpened` reply.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum LocalMessage {
    /// client → daemon: one-shot request that gets exactly one
    /// `Reply` back.
    Call {
        request_id: u64,
        payload: TapRequest,
    },

    /// client → daemon: open a stream subscription. Daemon replies
    /// with `StreamOpened { request_id, stream_id }`, then 0..n
    /// `StreamFrame { stream_id, .. }`, then `StreamClosed`.
    Subscribe {
        request_id: u64,
        payload: TapStreamRequest,
    },

    /// daemon → client: response to a `Call`. `request_id` matches
    /// the original `Call`.
    Reply {
        request_id: u64,
        payload: TapResponse,
    },

    /// daemon → client: stream subscription accepted; subsequent
    /// `StreamFrame`s for this `stream_id` belong to it.
    StreamOpened {
        request_id: u64,
        stream_id: u64,
    },

    /// daemon → client: live frame on an open stream.
    StreamFrame {
        stream_id: u64,
        payload: TapStreamFrame,
    },

    /// daemon → client: stream is done. Reasons:
    ///   - "session ended" — kernel-side `tty_release_struct`
    ///   - "no session with pty_index=N" — pty doesn't exist (or
    ///     the caller isn't authorised to see it)
    ///   - "forbidden" — caller's uid can't see the requested pty
    StreamClosed {
        stream_id: u64,
        reason: Option<String>,
    },
}
