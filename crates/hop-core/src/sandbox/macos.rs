//! macOS sandbox enforcement via Apple's Seatbelt/sandbox-exec.
//!
//! Generates a Scheme-based SBPL (Sandbox Profile Language) policy and spawns
//! the command through `/usr/bin/sandbox-exec -p '<profile>'`.
//!
//! `sandbox-exec` is deprecated by Apple but still functional and widely used
//! by Apple's own system services, Chromium, Claude Code, and Google Gemini CLI.

use super::policy::SandboxPolicy;
use std::path::PathBuf;
use std::process::Stdio;

/// Generate an SBPL profile string from a `SandboxPolicy`.
pub fn generate_sbpl_profile(policy: &SandboxPolicy) -> String {
    let mut p = String::with_capacity(2048);
    p.push_str("(version 1)\n");
    p.push_str("(deny default)\n");

    // Always allow process execution and basic operations
    p.push_str("(allow process-exec)\n");
    p.push_str("(allow process-fork)\n");
    p.push_str("(allow signal)\n");
    p.push_str("(allow sysctl-read)\n");
    p.push_str("(allow mach-lookup)\n");
    p.push_str("(allow mach-register)\n");
    p.push_str("(allow ipc-posix-shm-read-data)\n");
    p.push_str("(allow ipc-posix-shm-write-data)\n");

    // Read access
    if policy.allowed_paths.is_empty() {
        // No scope restrictions — allow reading everything
        p.push_str("(allow file-read*)\n");
    } else {
        // Essential system paths required for commands to function
        let system_paths = [
            "/usr",
            "/bin",
            "/sbin",
            "/lib",
            "/dev",
            "/private/var/db",
            "/private/var/run",
            "/private/var/folders",
            "/private/etc",
            "/System",
            "/Applications/Utilities",
            "/Library/Preferences",
            "/var/select",
            "/var/db",
            "/etc",
            "/tmp",
        ];
        for sys_path in &system_paths {
            p.push_str(&format!("(allow file-read* (subpath \"{sys_path}\"))\n"));
        }
        // User-specified paths
        for path in &policy.allowed_paths {
            let canon = std::fs::canonicalize(path)
                .unwrap_or_else(|_| path.clone());
            p.push_str(&format!(
                "(allow file-read* (subpath \"{}\"))\n",
                canon.display()
            ));
        }
    }

    // Write access
    if policy.read_only {
        // Allow writing to stdout/stderr/PTY only
        p.push_str("(allow file-write* (literal \"/dev/null\"))\n");
        p.push_str("(allow file-write* (literal \"/dev/dfd\"))\n");
        p.push_str("(allow file-write* (regex #\"^/dev/ttys[0-9]+$\"))\n");
        p.push_str("(allow file-write* (regex #\"^/dev/pty[a-z][0-9a-f]$\"))\n");
        // /tmp write access for temp files that some commands need
        p.push_str("(allow file-write* (subpath \"/private/var/folders\"))\n");
        p.push_str("(allow file-write* (subpath \"/tmp\"))\n");
    } else {
        p.push_str("(allow file-write*)\n");
    }

    // Network access
    if !policy.no_network {
        p.push_str("(allow network*)\n");
    }
    // If no_network: network is denied by default from (deny default)

    p
}

/// Build a `tokio::process::Command` that runs `cmd` under sandbox-exec.
///
/// The returned command is ready to spawn but has not been spawned yet,
/// so the caller can add stdin/stdout/stderr configuration.
pub fn sandboxed_command(cmd: &str, policy: &SandboxPolicy) -> tokio::process::Command {
    let profile = generate_sbpl_profile(policy);

    let mut command = tokio::process::Command::new("/usr/bin/sandbox-exec");
    command
        .arg("-p")
        .arg(&profile)
        .arg("/bin/sh")
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    command
}

/// Build a `portable_pty::CommandBuilder` that runs a shell under sandbox-exec.
///
/// Used for interactive PTY sessions where the shell itself is sandboxed.
pub fn sandboxed_shell_command(
    policy: &SandboxPolicy,
    shell: &str,
    username: Option<&str>,
) -> (String, Vec<String>) {
    let profile = generate_sbpl_profile(policy);

    // We wrap the shell invocation through sandbox-exec.
    // For per-user shells, the caller handles login/su wrapping separately.
    let bin = "/usr/bin/sandbox-exec".to_string();
    let args = if let Some(user) = username {
        // On macOS: login -fp <user> launches a login shell for that user.
        // We wrap: sandbox-exec -p <profile> login -fp <user>
        vec![
            "-p".into(),
            profile,
            "login".into(),
            "-fp".into(),
            user.into(),
        ]
    } else {
        vec![
            "-p".into(),
            profile,
            shell.into(),
            "-l".into(),
        ]
    };
    (bin, args)
}

/// Resolve allowed_paths, adding macOS-specific essential paths.
pub fn resolve_paths_for_macos(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut resolved = paths.to_vec();
    // On macOS, /proc doesn't exist; /sys is minimal.
    // Add common paths that monitoring tools need.
    let essentials = ["/private/var/log"];
    for p in essentials {
        let pb = PathBuf::from(p);
        if pb.exists() && !resolved.contains(&pb) {
            resolved.push(pb);
        }
    }
    resolved
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unrestricted_profile_allows_all_rw() {
        let policy = SandboxPolicy::default();
        let profile = generate_sbpl_profile(&policy);
        assert!(profile.contains("(allow file-read*)"));
        assert!(profile.contains("(allow file-write*)"));
        assert!(profile.contains("(allow network*)"));
    }

    #[test]
    fn readonly_denies_writes() {
        let policy = SandboxPolicy {
            read_only: true,
            ..Default::default()
        };
        let profile = generate_sbpl_profile(&policy);
        assert!(profile.contains("(allow file-read*)"));
        // Should NOT have blanket file-write*
        // (it will have specific write allowances for TTY/tmp)
        let lines: Vec<&str> = profile.lines().collect();
        let blanket_write = lines
            .iter()
            .any(|l| l.trim() == "(allow file-write*)");
        assert!(!blanket_write, "should not have blanket file-write*");
    }

    #[test]
    fn no_network_omits_network() {
        let policy = SandboxPolicy {
            no_network: true,
            ..Default::default()
        };
        let profile = generate_sbpl_profile(&policy);
        assert!(!profile.contains("(allow network*)"));
    }

    #[test]
    fn scoped_paths_appear_in_profile() {
        let policy = SandboxPolicy {
            allowed_paths: vec![PathBuf::from("/var/log")],
            ..Default::default()
        };
        let profile = generate_sbpl_profile(&policy);
        assert!(profile.contains("/var/log"));
        // System paths should also be present
        assert!(profile.contains("/usr"));
    }

    #[test]
    fn sandboxed_shell_command_with_user() {
        let policy = SandboxPolicy {
            read_only: true,
            ..Default::default()
        };
        let (bin, args) = sandboxed_shell_command(&policy, "/bin/bash", Some("alice"));
        assert_eq!(bin, "/usr/bin/sandbox-exec");
        assert!(args.contains(&"login".to_string()));
        assert!(args.contains(&"alice".to_string()));
    }

    #[test]
    fn sandboxed_shell_command_without_user() {
        let policy = SandboxPolicy {
            read_only: true,
            ..Default::default()
        };
        let (bin, args) = sandboxed_shell_command(&policy, "/bin/bash", None);
        assert_eq!(bin, "/usr/bin/sandbox-exec");
        assert!(args.contains(&"/bin/bash".to_string()));
        assert!(args.contains(&"-l".to_string()));
    }
}
