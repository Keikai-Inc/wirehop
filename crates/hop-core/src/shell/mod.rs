//! PTY and terminal management.
//!
//! Responsibilities:
//! - Spawn PTY with user's default shell (host side)
//! - Read/write PTY I/O and forward over protocol
//! - Enter raw terminal mode (client side)
//! - Handle window resize events
