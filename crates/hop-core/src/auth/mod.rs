//! Connection authentication and peer authorization.
//!
//! Responsibilities:
//! - Verify connecting peer's NodeId against authorized peers
//! - Handle invite-based auth flow (challenge-response)
//! - Add/remove peers from the authorized store
//! - Persist authorization state to peers.json
