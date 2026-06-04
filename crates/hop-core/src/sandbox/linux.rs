//! Linux sandbox enforcement via Landlock and process hardening.
//!
//! Layer 2 (kernel-enforced) sandbox for Linux:
//! - Landlock filesystem access control (restrict read/write paths) — Linux 5.13+.
//! - Landlock network rules (deny TCP bind/connect for `no_network`) — Linux 6.7+
//!   (ABI v4). **Limitation:** Landlock cannot restrict UDP, so DNS and QUIC
//!   still function under `no_network`; this blocks TCP egress only. On kernels
//!   without ABI v4 the network restriction is unenforceable and is logged.
//! - `PR_SET_NO_NEW_PRIVS`: prevent privilege escalation via setuid/setgid.
//!
//! Applied *after* fork, *before* exec in the child process. When the policy is
//! restricted, a failure to enforce the filesystem ruleset is **fatal** (the
//! session is refused) rather than silently running unsandboxed — see
//! `apply_sandbox` (security-audit H5/H6).

use super::policy::SandboxPolicy;
use std::path::PathBuf;
use std::process::Stdio;

/// Apply Linux sandbox restrictions to the current process.
///
/// Called in the child process after fork, before exec (or in the
/// `__sandbox-shell` self-exec wrapper). Sets `PR_SET_NO_NEW_PRIVS`, then
/// applies the Landlock filesystem ruleset and — for `no_network` — the
/// Landlock TCP rules.
///
/// Returns `Err` when a restricted policy cannot be enforced (e.g. the kernel
/// lacks Landlock): the caller must refuse the session rather than run the peer
/// unsandboxed. Network-rule unavailability is logged but not fatal, because it
/// degrades to "no TCP isolation" which the caller documents, whereas a missing
/// filesystem boundary would silently expose the whole host.
pub fn apply_sandbox(policy: &SandboxPolicy) -> Result<(), String> {
    // Layer 3: Always set no_new_privs to prevent privilege escalation
    set_no_new_privs();

    // Layer 2: Landlock filesystem restrictions (fatal when restricted).
    apply_landlock(policy)?;

    // Layer 2b: Landlock network restriction for no_network (best-effort).
    if policy.no_network {
        apply_landlock_net();
    }
    Ok(())
}

/// Set `PR_SET_NO_NEW_PRIVS` to prevent the child from gaining privileges
/// via setuid/setgid binaries (e.g., `su`, `sudo`, `passwd`).
fn set_no_new_privs() {
    #[cfg(target_os = "linux")]
    {
        let ret = unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) };
        if ret != 0 {
            tracing::warn!("prctl(PR_SET_NO_NEW_PRIVS) failed: {}", std::io::Error::last_os_error());
        }
    }
}

/// Apply Landlock filesystem access restrictions using the `landlock` crate.
///
/// Landlock is available on Linux 5.13+ and provides unprivileged filesystem
/// sandboxing. If the kernel doesn't support it, this returns an error but
/// the process continues unsandboxed (defense in depth — not the only layer).
fn apply_landlock(policy: &SandboxPolicy) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use landlock::{
            Access, AccessFs, PathBeneath, PathFd, Ruleset, RulesetAttr,
            RulesetCreatedAttr, ABI,
        };

        let read_access = AccessFs::Execute | AccessFs::ReadFile | AccessFs::ReadDir;
        let write_access = AccessFs::WriteFile
            | AccessFs::RemoveDir
            | AccessFs::RemoveFile
            | AccessFs::MakeChar
            | AccessFs::MakeDir
            | AccessFs::MakeReg
            | AccessFs::MakeSock
            | AccessFs::MakeFifo
            | AccessFs::MakeBlock
            | AccessFs::MakeSym;
        let all_access = read_access | write_access;

        if !policy.read_only && policy.allowed_paths.is_empty() {
            return Ok(()); // No filesystem restrictions
        }

        let abi = ABI::V1;
        let mut ruleset = Ruleset::default()
            .handle_access(AccessFs::from_all(abi))
            .map_err(|e| format!("landlock handle_access: {e}"))?
            .create()
            .map_err(|e| format!("landlock create: {e}"))?;

        // Helper: add a path rule (skip paths that don't exist)
        let mut add_rule = |path: &str, access: landlock::BitFlags<AccessFs>| -> Result<(), String> {
            let Ok(fd) = PathFd::new(path) else { return Ok(()) };
            ruleset.as_mut()
                .add_rule(PathBeneath::new(fd, access))
                .map_err(|e| format!("landlock add_rule for {path}: {e}"))?;
            Ok(())
        };

        // System paths always get read + execute access
        let system_paths = [
            "/usr", "/bin", "/sbin", "/lib", "/lib64",
            "/dev", "/proc", "/sys", "/etc", "/tmp",
            "/run", "/var/run", "/var/lib",
        ];

        for sys_path in &system_paths {
            let _ = add_rule(sys_path, read_access);
        }

        if policy.read_only {
            if policy.allowed_paths.is_empty() {
                add_rule("/", read_access)?;
            } else {
                for path in &policy.allowed_paths {
                    add_rule(&path.to_string_lossy(), read_access)?;
                }
            }
            let _ = add_rule("/tmp", all_access);
            let _ = add_rule("/var/tmp", all_access);
        } else {
            if policy.allowed_paths.is_empty() {
                add_rule("/", all_access)?;
            } else {
                add_rule("/", read_access)?;
                for path in &policy.allowed_paths {
                    add_rule(&path.to_string_lossy(), all_access)?;
                }
            }
        }

        let status = ruleset.restrict_self()
            .map_err(|e| format!("landlock restrict_self: {e}"))?;

        // H6: a restricted policy that the kernel won't enforce is fatal — the
        // caller refuses the session rather than running the peer unsandboxed.
        if matches!(status.ruleset, landlock::RulesetStatus::NotEnforced) {
            return Err(
                "Landlock unavailable (kernel < 5.13); refusing restricted session".to_string(),
            );
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy;
    }

    Ok(())
}

/// Deny TCP bind/connect for `no_network` policies via Landlock network rules
/// (ABI v4, Linux 6.7+). Best-effort: on kernels without network-Landlock this
/// can't be enforced and is logged loudly. **Does not** restrict UDP (DNS/QUIC
/// remain reachable) — that is a Landlock limitation, documented at module level
/// (security-audit H5).
#[allow(unused_variables)]
fn apply_landlock_net() {
    #[cfg(target_os = "linux")]
    {
        use landlock::{AccessNet, Ruleset, RulesetAttr, RulesetCreatedAttr, RulesetStatus};

        let result = (|| -> Result<RulesetStatus, String> {
            // Handle bind+connect but add no allow rules → all TCP denied.
            // Default BestEffort compat degrades to NotEnforced on kernels < 6.7.
            let status = Ruleset::default()
                .handle_access(AccessNet::BindTcp | AccessNet::ConnectTcp)
                .map_err(|e| format!("landlock net handle_access: {e}"))?
                .create()
                .map_err(|e| format!("landlock net create: {e}"))?
                .restrict_self()
                .map_err(|e| format!("landlock net restrict_self: {e}"))?;
            Ok(status.ruleset)
        })();
        match result {
            Ok(RulesetStatus::NotEnforced) => tracing::error!(
                "no_network requested but Landlock network rules are unenforceable \
                 (kernel < 6.7 / ABI < v4): TCP egress is NOT isolated"
            ),
            Ok(_) => {}
            Err(e) => tracing::error!("no_network: failed to apply Landlock network rules: {e}"),
        }
    }
}

/// Build a `tokio::process::Command` that applies sandbox restrictions.
///
/// On Linux, we use a wrapper script approach: the sandbox is applied via
/// `PR_SET_NO_NEW_PRIVS` + Landlock in a pre-exec hook on the child process.
pub fn sandboxed_command(cmd: &str, policy: &SandboxPolicy) -> tokio::process::Command {
    let mut command = tokio::process::Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(cmd)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    // Apply sandbox in pre-exec hook (runs in child after fork, before exec)
    if policy.is_restricted() {
        let policy_clone = policy.clone();
        unsafe {
            command.pre_exec(move || {
                apply_sandbox(&policy_clone)
                    .map_err(|e| std::io::Error::new(std::io::ErrorKind::PermissionDenied, e))
            });
        }
    }

    command
}

/// Build arguments for a sandboxed shell session on Linux.
///
/// Returns `(binary, args)` for spawning via portable-pty. Since
/// `portable_pty::CommandBuilder` doesn't support `pre_exec` hooks, we use a
/// self-exec wrapper: the hop binary re-invokes itself with `__sandbox-shell`
/// to apply Landlock + no_new_privs in-process, then execs the real shell.
pub fn sandboxed_shell_command(
    policy: &SandboxPolicy,
    shell: &str,
    username: Option<&str>,
) -> (String, Vec<String>) {
    let hop_bin = std::env::current_exe()
        .unwrap_or_else(|_| PathBuf::from("hop"))
        .to_string_lossy()
        .to_string();

    let policy_json = serde_json::to_string(policy).unwrap_or_default();

    let mut args = vec![
        "__sandbox-shell".into(),
        "--policy".into(),
        policy_json,
        "--".into(),
    ];

    if let Some(user) = username {
        args.push("su".into());
        args.push("-".into());
        args.push(user.into());
    } else {
        args.push(shell.into());
        args.push("-l".into());
    }

    (hop_bin, args)
}

/// Resolve allowed_paths, adding Linux-specific essential paths.
pub fn resolve_paths_for_linux(paths: &[PathBuf]) -> Vec<PathBuf> {
    let mut resolved = paths.to_vec();
    let essentials = ["/proc", "/sys", "/var/log"];
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
    fn sandboxed_shell_with_user() {
        let policy = SandboxPolicy {
            read_only: true,
            ..Default::default()
        };
        let (bin, args) = sandboxed_shell_command(&policy, "/bin/bash", Some("alice"));
        // Should use self-exec wrapper
        assert!(bin.contains("hop") || bin.ends_with("sandbox-linux") || !bin.is_empty());
        assert!(args.contains(&"__sandbox-shell".to_string()));
        assert!(args.contains(&"--policy".to_string()));
        assert!(args.contains(&"su".to_string()));
        assert!(args.contains(&"alice".to_string()));
    }

    #[test]
    fn sandboxed_shell_without_user() {
        let policy = SandboxPolicy {
            read_only: true,
            ..Default::default()
        };
        let (bin, args) = sandboxed_shell_command(&policy, "/bin/bash", None);
        // Should use self-exec wrapper
        assert!(args.contains(&"__sandbox-shell".to_string()));
        assert!(args.contains(&"--policy".to_string()));
        assert!(args.contains(&"/bin/bash".to_string()));
        assert!(args.contains(&"-l".to_string()));
        let _ = bin; // hop binary path
    }

    #[test]
    fn sandboxed_shell_policy_json_roundtrips() {
        let policy = SandboxPolicy {
            read_only: true,
            no_network: true,
            ..Default::default()
        };
        let (_bin, args) = sandboxed_shell_command(&policy, "/bin/zsh", None);
        let policy_idx = args.iter().position(|a| a == "--policy").unwrap();
        let json = &args[policy_idx + 1];
        let parsed: SandboxPolicy = serde_json::from_str(json).unwrap();
        assert!(parsed.read_only);
        assert!(parsed.no_network);
    }

    /// Regression test for Bug 2: verify that a fully populated SandboxPolicy
    /// survives the JSON roundtrip through sandboxed_shell_command, ensuring
    /// the Linux PTY path doesn't silently lose sandbox fields.
    #[test]
    fn sandboxed_shell_full_policy_roundtrip() {
        let policy = SandboxPolicy {
            read_only: true,
            no_network: true,
            allowed_paths: vec![
                PathBuf::from("/var/log"),
                PathBuf::from("/etc"),
                PathBuf::from("/proc"),
            ],
            allowed_commands: vec!["ps".into(), "top".into(), "cat".into()],
            denied_commands: vec!["rm".into(), "dd".into(), "shutdown".into()],
        };

        let (_bin, args) = sandboxed_shell_command(&policy, "/bin/bash", None);

        // Extract and parse the JSON from the args
        let policy_idx = args.iter().position(|a| a == "--policy").unwrap();
        let json = &args[policy_idx + 1];
        let parsed: SandboxPolicy = serde_json::from_str(json)
            .expect("policy JSON from sandboxed_shell_command must be valid");

        assert_eq!(parsed, policy, "all SandboxPolicy fields must survive the JSON roundtrip");
    }
}
