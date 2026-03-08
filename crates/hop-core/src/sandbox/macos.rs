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
///
/// If `broker_config_dir` is provided, the broker directory is added to the
/// allowed read paths so the sandboxed shell can access shim symlinks and
/// connect to the broker Unix socket.
pub fn generate_sbpl_profile(policy: &SandboxPolicy) -> String {
    generate_sbpl_profile_with_broker(policy, None)
}

/// Generate an SBPL profile, optionally allowing access to a broker directory.
pub fn generate_sbpl_profile_with_broker(
    policy: &SandboxPolicy,
    broker_config_dir: Option<&std::path::Path>,
) -> String {
    let mut p = String::with_capacity(2048);
    p.push_str("(version 1)\n");

    // Start permissive — only deny what the policy restricts.
    //
    // We intentionally use (allow default) instead of (deny default) because
    // sandbox-exec strips the setuid bit from child processes under ANY
    // sandbox profile. A deny-default allowlist blocks setuid binaries like
    // ps, top, and login even with (allow process-exec). The allow-default
    // approach still kernel-enforces the restrictions that matter (no writes,
    // no network) via targeted deny rules below.
    p.push_str("(allow default)\n");

    // --- Read restrictions (only when paths are scoped) ---
    if !policy.allowed_paths.is_empty() {
        // Deny all reads, then re-allow system paths + scoped paths.
        p.push_str("(deny file-read*)\n");

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
            "/private/tmp",
            "/tmp",
        ];
        for sys_path in &system_paths {
            p.push_str(&format!("(allow file-read* (subpath \"{sys_path}\"))\n"));
        }
        for path in &policy.allowed_paths {
            let canon = std::fs::canonicalize(path)
                .unwrap_or_else(|_| path.clone());
            p.push_str(&format!(
                "(allow file-read* (subpath \"{}\"))\n",
                canon.display()
            ));
        }

        // Allow reads to broker directory so shim symlinks + socket are accessible
        if let Some(config_dir) = broker_config_dir {
            let broker_dir = config_dir.join("broker");
            p.push_str(&format!(
                "(allow file-read* (subpath \"{}\"))\n",
                broker_dir.display()
            ));
        }
    }

    // --- Write restrictions ---
    if policy.read_only {
        // Deny all writes, then re-allow PTY/tmp.
        p.push_str("(deny file-write*)\n");
        p.push_str("(allow file-write* (literal \"/dev/null\"))\n");
        p.push_str("(allow file-write* (literal \"/dev/dfd\"))\n");
        p.push_str("(allow file-write* (regex #\"^/dev/ttys[0-9]+$\"))\n");
        p.push_str("(allow file-write* (regex #\"^/dev/pty[a-z][0-9a-f]$\"))\n");
        p.push_str("(allow file-write* (subpath \"/private/var/folders\"))\n");
        p.push_str("(allow file-write* (subpath \"/private/tmp\"))\n");
        p.push_str("(allow file-write* (subpath \"/tmp\"))\n");
    }

    // --- Network restrictions ---
    if policy.no_network {
        // Block TCP/UDP but allow Unix domain sockets (needed for broker IPC).
        // `(deny network*)` blocks ALL sockets including Unix domain sockets.
        // IP-specific denies block TCP/UDP while preserving Unix socket access.
        p.push_str("(deny network-outbound (remote ip \"*:*\"))\n");
        p.push_str("(deny network-inbound (local ip \"*:*\"))\n");
    }

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
/// If `broker_config_dir` is provided, the SBPL profile will allow access
/// to the broker directory for shim symlinks and Unix socket communication.
pub fn sandboxed_shell_command_with_broker(
    policy: &SandboxPolicy,
    shell: &str,
    username: Option<&str>,
    broker_config_dir: Option<&std::path::Path>,
) -> (String, Vec<String>) {
    let profile = generate_sbpl_profile_with_broker(policy, broker_config_dir);

    // We wrap the shell invocation through sandbox-exec.
    // For per-user shells, the caller handles login/su wrapping separately.
    if let Some(user) = username {
        // login is setuid — sandbox-exec cannot exec it.
        // Run login first to switch users, then sandbox-exec the shell:
        // login -fp <user> /usr/bin/sandbox-exec -p <profile> <shell> -l
        let bin = "login".to_string();
        let args = vec![
            "-fp".into(),
            user.into(),
            "/usr/bin/sandbox-exec".into(),
            "-p".into(),
            profile,
            shell.into(),
            "-l".into(),
        ];
        (bin, args)
    } else {
        let bin = "/usr/bin/sandbox-exec".to_string();
        let args = vec![
            "-p".into(),
            profile,
            shell.into(),
            "-l".into(),
        ];
        (bin, args)
    }
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
    fn unrestricted_profile_allows_all() {
        let policy = SandboxPolicy::default();
        let profile = generate_sbpl_profile(&policy);
        assert!(profile.contains("(allow default)"));
        // No deny rules for an unrestricted policy
        assert!(!profile.contains("(deny file-write*)"));
        assert!(!profile.contains("(deny file-read*)"));
        assert!(!profile.contains("(deny network"));
    }

    #[test]
    fn readonly_denies_writes() {
        let policy = SandboxPolicy {
            read_only: true,
            ..Default::default()
        };
        let profile = generate_sbpl_profile(&policy);
        assert!(profile.contains("(allow default)"));
        assert!(profile.contains("(deny file-write*)"));
        // Should have re-allow rules for PTY/tmp
        assert!(profile.contains("(allow file-write* (subpath \"/tmp\"))"));
    }

    #[test]
    fn no_network_denies_network() {
        let policy = SandboxPolicy {
            no_network: true,
            ..Default::default()
        };
        let profile = generate_sbpl_profile(&policy);
        // IP-specific denies block TCP/UDP while allowing Unix domain sockets
        assert!(profile.contains("(deny network-outbound (remote ip \"*:*\"))"));
        assert!(profile.contains("(deny network-inbound (local ip \"*:*\"))"));
    }

    #[test]
    fn scoped_paths_restrict_reads() {
        let policy = SandboxPolicy {
            allowed_paths: vec![PathBuf::from("/var/log")],
            ..Default::default()
        };
        let profile = generate_sbpl_profile(&policy);
        // Should deny reads then re-allow system + scoped paths
        assert!(profile.contains("(deny file-read*)"));
        assert!(profile.contains("/var/log"));
        assert!(profile.contains("/usr"));
    }

    #[test]
    fn sandboxed_shell_command_with_user() {
        let policy = SandboxPolicy {
            read_only: true,
            ..Default::default()
        };
        let (bin, args) = sandboxed_shell_command_with_broker(&policy, "/bin/bash", Some("alice"), None);
        // login runs first (setuid), then sandbox-exec wraps the shell
        assert_eq!(bin, "login");
        assert!(args.contains(&"-fp".to_string()));
        assert!(args.contains(&"alice".to_string()));
        assert!(args.contains(&"/usr/bin/sandbox-exec".to_string()));
        assert!(args.contains(&"/bin/bash".to_string()));
    }

    #[test]
    fn sandbox_exec_actually_denies_writes() {
        let policy = SandboxPolicy {
            read_only: true,
            ..Default::default()
        };
        let profile = generate_sbpl_profile(&policy);
        let output = std::process::Command::new("/usr/bin/sandbox-exec")
            .args([
                "-p",
                &profile,
                "/bin/sh",
                "-c",
                "echo test > /var/tmp/hop-sandbox-test 2>&1 && echo WRITE_OK || echo WRITE_DENIED",
            ])
            .output()
            .expect("sandbox-exec should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("WRITE_DENIED"),
            "sandbox-exec must deny writes to /var/tmp in read-only mode, got: {stdout}"
        );
    }

    #[test]
    fn sandboxed_shell_command_without_user() {
        let policy = SandboxPolicy {
            read_only: true,
            ..Default::default()
        };
        let (bin, args) = sandboxed_shell_command_with_broker(&policy, "/bin/bash", None, None);
        assert_eq!(bin, "/usr/bin/sandbox-exec");
        assert!(args.contains(&"/bin/bash".to_string()));
        assert!(args.contains(&"-l".to_string()));
    }

    // --- sandbox-exec integration tests ---

    #[test]
    fn sandbox_exec_readonly_allows_reads() {
        let policy = SandboxPolicy {
            read_only: true,
            ..Default::default()
        };
        let profile = generate_sbpl_profile(&policy);
        let output = std::process::Command::new("/usr/bin/sandbox-exec")
            .args(["-p", &profile, "/bin/sh", "-c", "cat /etc/hosts"])
            .output()
            .expect("sandbox-exec should run");
        assert!(
            output.status.success(),
            "read-only sandbox should allow reading /etc/hosts, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("localhost"),
            "/etc/hosts should contain localhost, got: {stdout}"
        );
    }

    #[test]
    fn sandbox_exec_no_network_blocks_connections() {
        let policy = SandboxPolicy {
            no_network: true,
            ..Default::default()
        };
        let profile = generate_sbpl_profile(&policy);
        let output = std::process::Command::new("/usr/bin/sandbox-exec")
            .args([
                "-p",
                &profile,
                "/bin/sh",
                "-c",
                "curl -s --connect-timeout 2 http://1.1.1.1 2>&1 && echo NET_OK || echo NET_BLOCKED",
            ])
            .output()
            .expect("sandbox-exec should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        let combined = format!("{stdout}{stderr}");
        assert!(
            combined.contains("NET_BLOCKED") || combined.contains("deny") || !output.status.success(),
            "no-network sandbox should block outbound connections, got stdout: {stdout}, stderr: {stderr}"
        );
    }

    #[test]
    fn sandbox_exec_scoped_paths_restricts_reads() {
        let policy = SandboxPolicy {
            allowed_paths: vec![PathBuf::from("/etc")],
            ..Default::default()
        };
        let profile = generate_sbpl_profile(&policy);
        // Try to read a file outside allowed paths (home directory)
        let home = std::env::var("HOME").unwrap_or_else(|_| "/Users/nobody".into());
        let output = std::process::Command::new("/usr/bin/sandbox-exec")
            .args([
                "-p",
                &profile,
                "/bin/sh",
                "-c",
                &format!("ls {home}"),
            ])
            .output()
            .expect("sandbox-exec should run");
        // The sandbox should deny reads outside allowed paths — either non-zero exit
        // or stderr contains denial info. sandbox-exec may suppress stderr.
        assert!(
            !output.status.success(),
            "scoped sandbox should deny reads outside allowed paths (exit={}), stdout: {}, stderr: {}",
            output.status,
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    /// Regression test: verify the PTY/shell path also enforces sandboxing,
    /// not just the exec path (sandboxed_command).
    /// This catches Bug 2 where PTY sessions could bypass the sandbox.
    #[test]
    fn sandbox_shell_path_denies_writes() {
        let policy = SandboxPolicy {
            read_only: true,
            ..Default::default()
        };
        // Without a username, bin is sandbox-exec directly
        let (bin, args) = sandboxed_shell_command_with_broker(&policy, "/bin/sh", None, None);
        assert_eq!(bin, "/usr/bin/sandbox-exec");
        assert!(args.len() >= 2, "expected at least -p and profile");
        let output = std::process::Command::new(&bin)
            .arg(&args[0]) // -p
            .arg(&args[1]) // profile
            .arg("/bin/sh")
            .arg("-c")
            .arg("echo test > /var/tmp/hop-shell-sandbox-test 2>&1 && echo WRITE_OK || echo WRITE_DENIED")
            .output()
            .expect("sandbox-exec should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            stdout.contains("WRITE_DENIED"),
            "sandboxed shell must deny writes in read-only mode via the PTY path, got: {stdout}"
        );
    }

    #[test]
    fn sandbox_exec_unrestricted_allows_writes() {
        let policy = SandboxPolicy::default();
        let profile = generate_sbpl_profile(&policy);
        let test_file = "/tmp/hop-sandbox-unrestricted-test";
        let output = std::process::Command::new("/usr/bin/sandbox-exec")
            .args([
                "-p",
                &profile,
                "/bin/sh",
                "-c",
                &format!("echo ok > {test_file} && cat {test_file} && rm {test_file}"),
            ])
            .output()
            .expect("sandbox-exec should run");
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("ok"),
            "unrestricted sandbox should allow writes, got: {stdout}, stderr: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
