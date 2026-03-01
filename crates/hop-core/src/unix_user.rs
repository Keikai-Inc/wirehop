//! Unix user validation and privilege helpers.

use anyhow::{bail, Result};
use std::ffi::CString;

/// Returns `true` if the current process is running as root (euid == 0).
pub fn is_running_as_root() -> bool {
    // SAFETY: geteuid() is always safe to call.
    unsafe { libc::geteuid() == 0 }
}

/// Returns `true` if `username` exists on the system (via `getpwnam`).
pub fn user_exists(username: &str) -> bool {
    let Ok(c_name) = CString::new(username) else {
        return false;
    };
    // SAFETY: getpwnam is safe with a valid C string; we only read the return pointer.
    let pw = unsafe { libc::getpwnam(c_name.as_ptr()) };
    !pw.is_null()
}

/// Validate a username for use with per-user shell sessions.
///
/// Checks:
/// 1. Format: 1-32 chars, `[a-zA-Z0-9_-]` only.
/// 2. Not `root` (hard block).
/// 3. User exists on the system.
pub fn validate_username(username: &str) -> Result<()> {
    // Format check
    if username.is_empty() || username.len() > 32 {
        bail!("invalid username: must be 1-32 characters, got {}", username.len());
    }
    if !username
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
    {
        bail!(
            "invalid username '{username}': only [a-zA-Z0-9_-] characters are allowed"
        );
    }

    // Block root
    if username == "root" {
        bail!(
            "refusing to bind a peer to 'root' — \
             peers should use a regular account and escalate with sudo inside the session"
        );
    }

    // Existence check
    if !user_exists(username) {
        bail!("user '{username}' does not exist on this system");
    }

    Ok(())
}
