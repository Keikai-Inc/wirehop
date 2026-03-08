//! Unix user validation and privilege helpers.

use anyhow::{bail, Result};
use std::ffi::CString;

/// Returns `true` if the current process is running as root (euid == 0).
pub fn is_running_as_root() -> bool {
    // SAFETY: geteuid() is always safe to call.
    unsafe { libc::geteuid() == 0 }
}

/// Returns the username of the current (real) user, or `None` on failure.
pub fn current_username() -> Option<String> {
    // SAFETY: getuid() is always safe; getpwuid is safe with a valid uid.
    let uid = unsafe { libc::getuid() };
    let pw = unsafe { libc::getpwuid(uid) };
    if pw.is_null() {
        return None;
    }
    let name = unsafe { std::ffi::CStr::from_ptr((*pw).pw_name) };
    name.to_str().ok().map(String::from)
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

/// Returns the login shell for `username` from the passwd database.
///
/// Falls back to `$SHELL` or `/bin/sh` if the lookup fails.
pub fn user_login_shell(username: &str) -> String {
    let Ok(c_name) = CString::new(username) else {
        return std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    };
    // SAFETY: getpwnam is safe with a valid C string; we only read the return pointer.
    let pw = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if pw.is_null() {
        return std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());
    }
    let shell = unsafe { std::ffi::CStr::from_ptr((*pw).pw_shell) };
    shell
        .to_str()
        .ok()
        .filter(|s| !s.is_empty())
        .map(String::from)
        .unwrap_or_else(|| std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into()))
}

/// Returns the value of `SUDO_USER` if set and not empty/root.
///
/// When `hop host` is launched via `sudo`, the original username is
/// preserved in this variable.
pub fn sudo_user() -> Option<String> {
    std::env::var("SUDO_USER")
        .ok()
        .filter(|u| !u.is_empty() && u != "root")
}

/// Returns the first regular user (UID >= 1000) with a valid login shell
/// by parsing `/etc/passwd`.
///
/// "Valid" means the shell is not `/usr/sbin/nologin`, `/bin/false`, or
/// `/sbin/nologin`.
pub fn first_regular_user() -> Option<String> {
    let content = std::fs::read_to_string("/etc/passwd").ok()?;
    for line in content.lines() {
        let fields: Vec<&str> = line.split(':').collect();
        if fields.len() < 7 {
            continue;
        }
        let username = fields[0];
        let uid: u32 = match fields[2].parse() {
            Ok(v) => v,
            Err(_) => continue,
        };
        let shell = fields[6];
        if uid >= 1000
            && !username.is_empty()
            && username != "nobody"
            && !shell.ends_with("/nologin")
            && !shell.ends_with("/false")
        {
            return Some(username.to_string());
        }
    }
    None
}

/// Picks a username for the creator invite when running as root.
///
/// Tries `SUDO_USER` first, then falls back to the first regular user
/// in `/etc/passwd`.
pub fn default_creator_username() -> Option<String> {
    sudo_user().or_else(first_regular_user)
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sudo_user_filters_empty_and_root() {
        // SAFETY: test-only; these tests must run with --test-threads=1
        // if they share env vars, but each is self-contained here.
        unsafe {
            // Empty string
            std::env::set_var("SUDO_USER", "");
            assert_eq!(sudo_user(), None);

            // Root
            std::env::set_var("SUDO_USER", "root");
            assert_eq!(sudo_user(), None);

            // Valid user
            std::env::set_var("SUDO_USER", "alice");
            assert_eq!(sudo_user(), Some("alice".into()));

            // Clean up
            std::env::remove_var("SUDO_USER");
        }
    }

    #[test]
    fn sudo_user_unset() {
        // SAFETY: test-only env manipulation
        unsafe {
            std::env::remove_var("SUDO_USER");
        }
        assert_eq!(sudo_user(), None);
    }

    #[test]
    fn first_regular_user_parses_passwd() {
        // This test only works on systems with /etc/passwd and at least one
        // regular user. On CI/macOS it may return None; that's fine.
        let result = first_regular_user();
        if let Some(ref name) = result {
            assert!(!name.is_empty());
            assert_ne!(name, "root");
            assert_ne!(name, "nobody");
        }
    }

    #[test]
    fn default_creator_username_prefers_sudo_user() {
        // SAFETY: test-only env manipulation
        unsafe {
            std::env::set_var("SUDO_USER", "bob");
        }
        let result = default_creator_username();
        assert_eq!(result, Some("bob".into()));
        unsafe {
            std::env::remove_var("SUDO_USER");
        }
    }
}
