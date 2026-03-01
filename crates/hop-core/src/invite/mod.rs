//! Invite token generation and verification.
//!
//! Responsibilities:
//! - Generate cryptographic one-time secrets
//! - Encode/decode invite tokens (base64url)
//! - Verify invite secrets via Argon2 hash comparison
//! - Embedded web UI for browser-based invite acceptance
