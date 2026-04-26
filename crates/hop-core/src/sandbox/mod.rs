//! Sandbox enforcement for restricting what connected peers can do.
//!
//! The sandbox has three layers:
//!
//! 1. **Application-layer validator** (`validator`): catches obvious violations
//!    (denied commands, metacharacters) before any process is spawned.
//!
//! 2. **OS-native kernel sandbox**: the real security boundary.
//!    - macOS: Apple Seatbelt / sandbox-exec with SBPL profiles
//!    - Linux: Landlock (filesystem) + PR_SET_NO_NEW_PRIVS
//!
//! 3. **Hardcoded safety net**: `PR_SET_NO_NEW_PRIVS` on Linux to prevent
//!    privilege escalation via setuid binaries.

pub mod broker;
pub mod policy;
pub mod validator;

#[cfg(target_os = "macos")]
pub mod macos;

#[cfg(target_os = "linux")]
pub mod linux;

pub use policy::SandboxPolicy;
pub use validator::{ValidationError, validate_command};

use std::process::Stdio;

/// Spawn a sandboxed command (non-PTY exec session).
///
/// Validates the command against the policy, then spawns it under the
/// OS-native sandbox. Returns the spawned child process.
pub fn spawn_sandboxed_command(
    cmd: &str,
    policy: &SandboxPolicy,
    username: Option<&str>,
) -> std::io::Result<tokio::process::Child> {
    // Layer 1: Application-level validation
    if policy.is_restricted()
        && let Err(e) = validate_command(cmd, policy)
    {
        return Err(std::io::Error::new(std::io::ErrorKind::PermissionDenied, e.to_string()));
    }

    // Layer 2: OS-native sandbox
    let mut command = build_exec_command(cmd, policy, username);

    command.spawn()
}

/// Build the appropriate exec command for the current platform.
fn build_exec_command(
    cmd: &str,
    policy: &SandboxPolicy,
    username: Option<&str>,
) -> tokio::process::Command {
    if !policy.is_restricted() {
        // No sandbox — use the same spawning logic as before
        return build_unsandboxed_exec(cmd, username);
    }

    // On macOS, broker-safe commands (ps, netstat, etc.) are setuid binaries
    // that sandbox-exec categorically blocks. Run them unsandboxed as the
    // session user — they're read-only monitoring tools already validated
    // by the policy layer above.
    #[cfg(target_os = "macos")]
    {
        let first_word = cmd.split_whitespace().next().unwrap_or("");
        let cmd_name = std::path::Path::new(first_word)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or(first_word);
        if broker::is_broker_safe(cmd_name) {
            return build_unsandboxed_exec(cmd, username);
        }
    }

    #[cfg(target_os = "macos")]
    {
        if let Some(user) = username {
            // login is setuid — sandbox-exec cannot exec it.
            // Run login first to switch users, then sandbox-exec inside:
            // login -fpq <user> /usr/bin/sandbox-exec -p <profile> <shell> -lc <cmd>
            let user_shell = crate::unix_user::user_login_shell(user);
            let wrapped = with_rc_source(cmd, &user_shell);
            let profile = macos::generate_sbpl_profile(policy);
            let mut command = tokio::process::Command::new("login");
            command
                .args(["-fpq", user, "/usr/bin/sandbox-exec", "-p"])
                .arg(&profile)
                .args([&user_shell, "-lc", &wrapped])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            command
        } else {
            macos::sandboxed_command(cmd, policy)
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Some(user) = username {
            let policy_clone = policy.clone();
            let mut command = tokio::process::Command::new("su");
            command
                .args(["-", user, "-c", cmd])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            unsafe {
                command.pre_exec(move || {
                    linux::apply_sandbox(&policy_clone);
                    Ok(())
                });
            }
            command
        } else {
            linux::sandboxed_command(cmd, policy)
        }
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = policy;
        build_unsandboxed_exec(cmd, username)
    }
}

/// Wrap a command to source the user's shell rc file first.
///
/// Login shells (`-l`) source `.zprofile`/`.bash_profile` but NOT `.zshrc`/`.bashrc`
/// (those are for interactive shells). Many users put PATH additions in `.zshrc`.
/// We source it explicitly (with stderr suppressed to avoid prompt tool noise like
/// starship warnings) before running the actual command.
pub fn with_rc_source(cmd: &str, shell: &str) -> String {
    let rc_file = if shell.ends_with("/zsh") {
        "~/.zshrc"
    } else if shell.ends_with("/bash") {
        "~/.bashrc"
    } else {
        return cmd.to_string(); // no rc file to source for other shells
    };
    format!(". {rc_file} 2>/dev/null; {cmd}")
}

/// Build an unsandboxed exec command using the user's login shell.
///
/// Uses the user's shell from passwd (zsh, bash, etc.) with `-lc` flag
/// so the profile is sourced — matching the interactive `hop connect` environment.
fn build_unsandboxed_exec(cmd: &str, username: Option<&str>) -> tokio::process::Command {
    if let Some(user) = username {
        let user_shell = crate::unix_user::user_login_shell(user);
        let wrapped = with_rc_source(cmd, &user_shell);
        #[cfg(target_os = "macos")]
        {
            let mut command = tokio::process::Command::new("login");
            command
                .args(["-fpq", user, &user_shell, "-lc", &wrapped])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            command
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            let mut command = tokio::process::Command::new("su");
            command
                .args(["-", user, "-s", &user_shell, "-c", &wrapped])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            command
        }
        #[cfg(not(unix))]
        {
            let _ = user;
            let mut command = tokio::process::Command::new("/bin/sh");
            command
                .args(["-c", cmd])
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::piped());
            command
        }
    } else {
        let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string());
        let mut command = tokio::process::Command::new(&shell);
        command
            .args(["-lc", cmd])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }
}

/// Build a sandboxed shell command for PTY sessions.
///
/// Returns `(binary, args)` suitable for `CommandBuilder::new(binary).args(args)`.
///
/// If `broker_config_dir` is provided (macOS only), the SBPL profile will allow
/// access to the broker directory for shim symlinks and Unix socket communication.
pub fn sandboxed_shell(
    policy: &SandboxPolicy,
    shell: &str,
    username: Option<&str>,
    broker_config_dir: Option<&std::path::Path>,
) -> (String, Vec<String>) {
    if !policy.is_restricted() {
        // No sandbox — return plain shell command
        return plain_shell(shell, username);
    }

    #[cfg(target_os = "macos")]
    {
        macos::sandboxed_shell_command_with_broker(policy, shell, username, broker_config_dir)
    }

    #[cfg(target_os = "linux")]
    {
        let _ = broker_config_dir;
        // On Linux, the sandbox is applied via a self-exec wrapper:
        // hop __sandbox-shell --policy <json> -- <shell> <args>
        return linux::sandboxed_shell_command(policy, shell, username);
    }

    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = (policy, broker_config_dir);
        plain_shell(shell, username)
    }
}

/// Plain shell command without sandboxing (visible for tests).
fn plain_shell(shell: &str, username: Option<&str>) -> (String, Vec<String>) {
    if let Some(user) = username {
        #[cfg(target_os = "macos")]
        {
            ("login".to_string(), vec!["-fp".into(), user.into()])
        }
        #[cfg(all(unix, not(target_os = "macos")))]
        {
            ("su".to_string(), vec!["-".into(), user.into()])
        }
        #[cfg(not(unix))]
        {
            let _ = user;
            (shell.to_string(), vec!["-l".into()])
        }
    } else {
        (shell.to_string(), vec!["-l".into()])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An unrestricted policy should return the plain shell directly,
    /// not a sandbox wrapper binary.
    #[test]
    fn sandboxed_shell_unrestricted_returns_plain_shell() {
        let policy = SandboxPolicy::unrestricted();
        let (bin, args) = sandboxed_shell(&policy, "/bin/bash", None, None);
        // Should be the shell itself, not sandbox-exec or hop wrapper
        assert_eq!(bin, "/bin/bash");
        assert_eq!(args, vec!["-l"]);
    }

    /// A restricted policy should return a wrapper binary (sandbox-exec
    /// on macOS, the hop binary on Linux) — never the bare shell.
    #[test]
    fn sandboxed_shell_restricted_wraps() {
        let policy = SandboxPolicy {
            read_only: true,
            ..Default::default()
        };
        let (bin, _args) = sandboxed_shell(&policy, "/bin/bash", None, None);
        // On macOS: sandbox-exec; on Linux: hop __sandbox-shell wrapper
        #[cfg(target_os = "macos")]
        assert_eq!(bin, "/usr/bin/sandbox-exec", "macOS must use sandbox-exec");
        #[cfg(target_os = "linux")]
        assert_ne!(bin, "/bin/bash", "Linux must not return the bare shell");
    }
}
