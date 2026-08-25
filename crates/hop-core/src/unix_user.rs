//! Unix user validation and privilege helpers.

use anyhow::{bail, Result};
#[cfg(unix)]
use uzers::os::unix::UserExt;

/// Returns `true` if the current process is running as root (euid == 0).
pub fn is_running_as_root() -> bool {
    nix::unistd::geteuid().is_root()
}

/// Returns the username of the current (real) user, or `None` on failure.
pub fn current_username() -> Option<String> {
    uzers::get_current_username()
        .map(|name| name.to_string_lossy().to_string())
}

/// Returns `true` if `username` exists on the system.
pub fn user_exists(username: &str) -> bool {
    uzers::get_user_by_name(username).is_some()
}

/// Returns the login shell for `username` from the passwd database.
///
/// Falls back to `$SHELL` or `/bin/sh` if the lookup fails.
pub fn user_login_shell(username: &str) -> String {
    let fallback = || std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".into());

    uzers::get_user_by_name(username)
        .and_then(|u| {
            let shell = u.shell().to_string_lossy().to_string();
            if shell.is_empty() { None } else { Some(shell) }
        })
        .unwrap_or_else(fallback)
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

/// Returns the first regular user (UID >= 500 on macOS, >= 1000 on Linux)
/// with a valid login shell.
///
/// On Linux, parses `/etc/passwd`. On macOS, uses `dscl` since local
/// accounts are stored in Directory Services, not `/etc/passwd`.
pub fn first_regular_user() -> Option<String> {
    // Try /etc/passwd first (works on Linux, partial on macOS)
    if let Some(user) = first_regular_user_from_passwd() {
        return Some(user);
    }

    // macOS: use dscl to list local users
    #[cfg(target_os = "macos")]
    {
        if let Some(user) = first_regular_user_from_dscl() {
            return Some(user);
        }
    }

    None
}

fn first_regular_user_from_passwd() -> Option<String> {
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
        if uid >= 500
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

#[cfg(target_os = "macos")]
fn first_regular_user_from_dscl() -> Option<String> {
    let output = std::process::Command::new("dscl")
        .args([".", "-list", "/Users"])
        .output()
        .ok()?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    for name in stdout.lines() {
        let name = name.trim();
        // Skip system users (start with _) and root
        if name.is_empty() || name.starts_with('_') || name == "root"
            || name == "nobody" || name == "daemon" || name == "Guest"
        {
            continue;
        }
        // Verify user has a home dir (real user, not a service account)
        if std::path::Path::new(&format!("/Users/{name}")).is_dir() {
            return Some(name.to_string());
        }
    }
    None
}

/// Picks a username for the creator invite when running as root.
///
/// Tries `SUDO_USER` first, then falls back to the first regular user
/// on the system.
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

    /// All SUDO_USER tests in one function to avoid parallel env var races.
    /// Env vars are process-global mutable state — parallel tests that
    /// set/remove the same var will interfere with each other.
    #[test]
    fn sudo_user_and_default_creator() {
        // SAFETY: test-only env manipulation
        unsafe {
            // Unset → sudo_user returns None
            std::env::remove_var("SUDO_USER");
            assert_eq!(sudo_user(), None);

            // Empty → None
            std::env::set_var("SUDO_USER", "");
            assert_eq!(sudo_user(), None);

            // Root → None (filtered)
            std::env::set_var("SUDO_USER", "root");
            assert_eq!(sudo_user(), None);

            // Valid user → Some
            std::env::set_var("SUDO_USER", "alice");
            assert_eq!(sudo_user(), Some("alice".into()));

            // default_creator_username prefers SUDO_USER
            std::env::set_var("SUDO_USER", "bob");
            assert_eq!(default_creator_username(), Some("bob".into()));

            // Cleanup
            std::env::remove_var("SUDO_USER");
        }
    }

    #[test]
    fn first_regular_user_parses_passwd() {
        let result = first_regular_user();
        if let Some(ref name) = result {
            assert!(!name.is_empty());
            assert_ne!(name, "root");
            assert_ne!(name, "nobody");
        }
    }
}
