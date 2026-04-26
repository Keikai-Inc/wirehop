//! Application-layer command validation.
//!
//! Currently only validates that commands are non-empty. Command-level
//! restrictions (allowlists, denylists, metacharacter blocking) have been
//! removed — the OS-native sandbox (Seatbelt on macOS, Landlock on Linux)
//! enforces filesystem and network restrictions at the kernel level.
//! Comprehensive command-level restriction belongs in a future seccomp
//! integration, not in string scanning.

use std::fmt;

use super::policy::SandboxPolicy;

/// Errors from command validation.
#[derive(Debug)]
pub enum ValidationError {
    EmptyCommand,
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCommand => write!(f, "empty command"),
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validate a command string against the sandbox policy.
///
/// Currently only checks that the command is non-empty. The OS-native
/// sandbox (Layer 2) is the actual security boundary.
pub fn validate_command(cmd: &str, _policy: &SandboxPolicy) -> Result<(), ValidationError> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return Err(ValidationError::EmptyCommand);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_any_command() {
        let p = SandboxPolicy::default();
        assert!(validate_command("rm -rf /", &p).is_ok());
        assert!(validate_command("cat /etc/passwd | grep root", &p).is_ok());
        assert!(validate_command("echo $HOME", &p).is_ok());
        assert!(validate_command("ls /Users/*/.local/bin/claude", &p).is_ok());
    }

    #[test]
    fn empty_command_rejected() {
        let p = SandboxPolicy::default();
        assert!(matches!(
            validate_command("", &p),
            Err(ValidationError::EmptyCommand)
        ));
    }

    #[test]
    fn whitespace_only_command_is_empty() {
        let p = SandboxPolicy::default();
        assert!(matches!(
            validate_command("   ", &p),
            Err(ValidationError::EmptyCommand)
        ));
    }
}
