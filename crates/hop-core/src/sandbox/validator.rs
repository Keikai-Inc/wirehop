//! Application-layer command validation (Layer 1).
//!
//! This is defense-in-depth. The OS-native sandbox (Layer 2) is the actual
//! security boundary. The validator catches obvious violations before any
//! process is spawned.

use super::policy::SandboxPolicy;
use std::fmt;
use std::path::Path;

/// Errors from command validation.
#[derive(Debug)]
pub enum ValidationError {
    EmptyCommand,
    InvalidCommand,
    DeniedCommand(String),
    CommandNotAllowed(String),
    ShellMetacharacter(char),
}

impl fmt::Display for ValidationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyCommand => write!(f, "empty command"),
            Self::InvalidCommand => write!(f, "could not parse command"),
            Self::DeniedCommand(cmd) => write!(f, "command denied: {cmd}"),
            Self::CommandNotAllowed(cmd) => write!(f, "command not in allowlist: {cmd}"),
            Self::ShellMetacharacter(ch) => {
                write!(f, "shell metacharacter not allowed in sandbox: '{ch}'")
            }
        }
    }
}

impl std::error::Error for ValidationError {}

/// Validate a command string against the sandbox policy.
///
/// Returns `Ok(())` if the command is allowed, or an error describing the
/// violation. This is NOT a security boundary — the kernel sandbox enforces
/// restrictions regardless.
pub fn validate_command(cmd: &str, policy: &SandboxPolicy) -> Result<(), ValidationError> {
    let cmd = cmd.trim();
    if cmd.is_empty() {
        return Err(ValidationError::EmptyCommand);
    }

    // Reject shell metacharacters in restricted modes to prevent trivial bypass
    // of allowlist/denylist via pipes, redirects, etc.
    if policy.read_only || !policy.allowed_commands.is_empty() {
        reject_shell_metacharacters(cmd)?;
    }

    // Split into tokens for binary name extraction
    let parts = shell_split(cmd).ok_or(ValidationError::InvalidCommand)?;
    let binary = parts.first().ok_or(ValidationError::EmptyCommand)?;

    // Extract basename (handle /usr/bin/ls -> ls)
    let basename = Path::new(binary)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(binary);

    // Check denied commands (always enforced)
    if policy
        .denied_commands
        .iter()
        .any(|d| d.eq_ignore_ascii_case(basename))
    {
        return Err(ValidationError::DeniedCommand(basename.into()));
    }

    // Check allowlist if configured
    if !policy.allowed_commands.is_empty()
        && !policy
            .allowed_commands
            .iter()
            .any(|a| a.eq_ignore_ascii_case(basename))
    {
        return Err(ValidationError::CommandNotAllowed(basename.into()));
    }

    Ok(())
}

/// Reject dangerous shell metacharacters that could bypass the allowlist.
fn reject_shell_metacharacters(cmd: &str) -> Result<(), ValidationError> {
    // We scan character by character, tracking quoting state.
    // Characters inside single quotes are safe (no expansion).
    let mut in_single = false;
    let mut in_double = false;
    let mut prev = '\0';

    for ch in cmd.chars() {
        match ch {
            '\'' if !in_double && prev != '\\' => {
                in_single = !in_single;
            }
            '"' if !in_single && prev != '\\' => {
                in_double = !in_double;
            }
            _ if in_single => {
                // Everything inside single quotes is literal
            }
            // Metacharacters that enable command chaining or I/O redirection
            ';' | '|' | '&' | '>' | '<' => {
                return Err(ValidationError::ShellMetacharacter(ch));
            }
            // Command substitution
            '`' => {
                return Err(ValidationError::ShellMetacharacter(ch));
            }
            // $(...) command substitution — check for $(
            '$' => {
                // We'll catch this on the next character
            }
            '(' if prev == '$' => {
                return Err(ValidationError::ShellMetacharacter('$'));
            }
            _ => {}
        }
        prev = ch;
    }

    Ok(())
}

/// Minimal shell-like word splitting (respects quotes).
/// Returns None if quotes are unbalanced.
fn shell_split(cmd: &str) -> Option<Vec<String>> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_single = false;
    let mut in_double = false;
    let mut escaped = false;

    for ch in cmd.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if !in_single => {
                escaped = true;
            }
            '\'' if !in_double => {
                in_single = !in_single;
            }
            '"' if !in_single => {
                in_double = !in_double;
            }
            ' ' | '\t' if !in_single && !in_double => {
                if !current.is_empty() {
                    parts.push(std::mem::take(&mut current));
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }

    // Unbalanced quotes
    if in_single || in_double {
        return None;
    }

    if !current.is_empty() {
        parts.push(current);
    }

    Some(parts)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy_readonly() -> SandboxPolicy {
        SandboxPolicy {
            read_only: true,
            ..Default::default()
        }
    }

    fn policy_allowlist() -> SandboxPolicy {
        SandboxPolicy {
            allowed_commands: vec!["ps".into(), "ls".into(), "cat".into()],
            ..Default::default()
        }
    }

    fn policy_denylist() -> SandboxPolicy {
        SandboxPolicy {
            denied_commands: vec!["rm".into(), "dd".into()],
            ..Default::default()
        }
    }

    #[test]
    fn unrestricted_allows_anything() {
        let p = SandboxPolicy::default();
        assert!(validate_command("rm -rf /", &p).is_ok());
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
    fn readonly_rejects_pipe() {
        let p = policy_readonly();
        assert!(matches!(
            validate_command("cat /etc/passwd | grep root", &p),
            Err(ValidationError::ShellMetacharacter('|'))
        ));
    }

    #[test]
    fn readonly_rejects_redirect() {
        let p = policy_readonly();
        assert!(matches!(
            validate_command("echo test > /tmp/file", &p),
            Err(ValidationError::ShellMetacharacter('>'))
        ));
    }

    #[test]
    fn readonly_rejects_semicolon() {
        let p = policy_readonly();
        assert!(matches!(
            validate_command("ls; rm -rf /", &p),
            Err(ValidationError::ShellMetacharacter(';'))
        ));
    }

    #[test]
    fn readonly_rejects_backtick() {
        let p = policy_readonly();
        assert!(matches!(
            validate_command("echo `whoami`", &p),
            Err(ValidationError::ShellMetacharacter('`'))
        ));
    }

    #[test]
    fn readonly_rejects_command_substitution() {
        let p = policy_readonly();
        assert!(matches!(
            validate_command("echo $(whoami)", &p),
            Err(ValidationError::ShellMetacharacter('$'))
        ));
    }

    #[test]
    fn readonly_allows_simple_command() {
        let p = policy_readonly();
        assert!(validate_command("ps aux", &p).is_ok());
    }

    #[test]
    fn allowlist_allows_listed() {
        let p = policy_allowlist();
        assert!(validate_command("ps aux", &p).is_ok());
        assert!(validate_command("ls -la /var/log", &p).is_ok());
        assert!(validate_command("cat /etc/hostname", &p).is_ok());
    }

    #[test]
    fn allowlist_rejects_unlisted() {
        let p = policy_allowlist();
        assert!(matches!(
            validate_command("rm /tmp/test", &p),
            Err(ValidationError::CommandNotAllowed(_))
        ));
    }

    #[test]
    fn allowlist_handles_full_path() {
        let p = policy_allowlist();
        assert!(validate_command("/usr/bin/ps aux", &p).is_ok());
        assert!(validate_command("/bin/ls", &p).is_ok());
    }

    #[test]
    fn denylist_blocks_denied() {
        let p = policy_denylist();
        assert!(matches!(
            validate_command("rm /tmp/file", &p),
            Err(ValidationError::DeniedCommand(_))
        ));
        assert!(matches!(
            validate_command("dd if=/dev/zero", &p),
            Err(ValidationError::DeniedCommand(_))
        ));
    }

    #[test]
    fn denylist_allows_others() {
        let p = policy_denylist();
        assert!(validate_command("ls -la", &p).is_ok());
        assert!(validate_command("ps aux", &p).is_ok());
    }

    #[test]
    fn shell_split_basic() {
        assert_eq!(
            shell_split("ls -la /var/log"),
            Some(vec!["ls".into(), "-la".into(), "/var/log".into()])
        );
    }

    #[test]
    fn shell_split_quoted() {
        assert_eq!(
            shell_split(r#"echo "hello world""#),
            Some(vec!["echo".into(), "hello world".into()])
        );
    }

    #[test]
    fn shell_split_single_quoted() {
        assert_eq!(
            shell_split("echo 'hello world'"),
            Some(vec!["echo".into(), "hello world".into()])
        );
    }

    #[test]
    fn shell_split_unbalanced() {
        assert_eq!(shell_split("echo \"hello"), None);
    }
}
