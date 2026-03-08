//! Linux sandbox enforcement via Landlock, seccomp-BPF, and process hardening.
//!
//! Layer 2 (kernel-enforced) sandbox for Linux:
//! - Landlock: filesystem access control (restrict read/write paths)
//! - PR_SET_NO_NEW_PRIVS: prevent privilege escalation via setuid/setgid
//!
//! Applied *after* fork, *before* exec in the child process.

use super::policy::SandboxPolicy;
use std::path::PathBuf;
use std::process::Stdio;

/// Apply Linux sandbox restrictions to the current process.
///
/// This should be called in the child process after fork, before exec.
/// It sets `PR_SET_NO_NEW_PRIVS` and applies Landlock rules if available.
///
/// Failures are logged but not fatal — the sandbox is best-effort on older
/// kernels that lack Landlock support.
pub fn apply_sandbox(policy: &SandboxPolicy) {
    // Layer 3: Always set no_new_privs to prevent privilege escalation
    set_no_new_privs();

    // Layer 2: Landlock filesystem restrictions
    if let Err(e) = apply_landlock(policy) {
        tracing::warn!("Landlock sandbox not applied: {e}");
    }
}

/// Set `PR_SET_NO_NEW_PRIVS` to prevent the child from gaining privileges
/// via setuid/setgid binaries (e.g., `su`, `sudo`, `passwd`).
fn set_no_new_privs() {
    #[cfg(target_os = "linux")]
    unsafe {
        let ret = libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
        if ret != 0 {
            tracing::warn!("prctl(PR_SET_NO_NEW_PRIVS) failed: {}", std::io::Error::last_os_error());
        }
    }
}

/// Apply Landlock filesystem access restrictions.
///
/// Landlock is available on Linux 5.13+ and provides unprivileged filesystem
/// sandboxing. If the kernel doesn't support it, this returns an error but
/// the process continues unsandboxed (defense in depth — not the only layer).
fn apply_landlock(policy: &SandboxPolicy) -> Result<(), String> {
    #[cfg(target_os = "linux")]
    {
        use std::os::unix::io::AsRawFd;

        // Landlock ABI v1 constants
        const LANDLOCK_CREATE_RULESET: i64 = 444;
        const LANDLOCK_ADD_RULE: i64 = 445;
        const LANDLOCK_RESTRICT_SELF: i64 = 446;

        const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;

        // Access rights for files and directories
        const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
        const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
        const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
        const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
        const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
        const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
        const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
        const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
        const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
        const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
        const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
        const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
        const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;

        const ALL_READ: u64 = LANDLOCK_ACCESS_FS_EXECUTE
            | LANDLOCK_ACCESS_FS_READ_FILE
            | LANDLOCK_ACCESS_FS_READ_DIR;

        const ALL_WRITE: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE
            | LANDLOCK_ACCESS_FS_REMOVE_DIR
            | LANDLOCK_ACCESS_FS_REMOVE_FILE
            | LANDLOCK_ACCESS_FS_MAKE_CHAR
            | LANDLOCK_ACCESS_FS_MAKE_DIR
            | LANDLOCK_ACCESS_FS_MAKE_REG
            | LANDLOCK_ACCESS_FS_MAKE_SOCK
            | LANDLOCK_ACCESS_FS_MAKE_FIFO
            | LANDLOCK_ACCESS_FS_MAKE_BLOCK
            | LANDLOCK_ACCESS_FS_MAKE_SYM;

        const ALL_ACCESS: u64 = ALL_READ | ALL_WRITE;

        // Determine what access mask to handle
        let handled_access = if policy.read_only {
            ALL_ACCESS // Handle everything, only grant read
        } else if !policy.allowed_paths.is_empty() {
            ALL_ACCESS // Handle everything, grant read+write to specific paths
        } else {
            return Ok(()); // No filesystem restrictions
        };

        #[repr(C)]
        struct LandlockRulesetAttr {
            handled_access_fs: u64,
            handled_access_net: u64,
        }

        #[repr(C)]
        struct LandlockPathBeneathAttr {
            allowed_access: u64,
            parent_fd: i32,
        }

        let attr = LandlockRulesetAttr {
            handled_access_fs: handled_access,
            handled_access_net: 0,
        };

        let ruleset_fd = unsafe {
            libc::syscall(
                LANDLOCK_CREATE_RULESET,
                &attr as *const _,
                std::mem::size_of::<LandlockRulesetAttr>(),
                0u32,
            )
        };

        if ruleset_fd < 0 {
            return Err(format!(
                "landlock_create_ruleset failed: {}",
                std::io::Error::last_os_error()
            ));
        }

        let ruleset_fd = ruleset_fd as i32;

        // Helper: add a path rule to the ruleset
        let add_rule = |path: &str, access: u64| -> Result<(), String> {
            let fd = match std::fs::File::open(path) {
                Ok(f) => f,
                Err(_) => return Ok(()), // Skip paths that don't exist
            };

            let rule = LandlockPathBeneathAttr {
                allowed_access: access,
                parent_fd: fd.as_raw_fd(),
            };

            let ret = unsafe {
                libc::syscall(
                    LANDLOCK_ADD_RULE,
                    ruleset_fd,
                    LANDLOCK_RULE_PATH_BENEATH,
                    &rule as *const _,
                    0u32,
                )
            };

            if ret < 0 {
                return Err(format!(
                    "landlock_add_rule for {path} failed: {}",
                    std::io::Error::last_os_error()
                ));
            }

            Ok(())
        };

        // System paths always get read + execute access
        let system_paths = [
            "/usr", "/bin", "/sbin", "/lib", "/lib64",
            "/dev", "/proc", "/sys", "/etc", "/tmp",
            "/run", "/var/run", "/var/lib",
        ];

        for sys_path in &system_paths {
            let _ = add_rule(sys_path, ALL_READ);
        }

        if policy.read_only {
            // Read-only mode: grant read access everywhere (or to scoped paths)
            if policy.allowed_paths.is_empty() {
                // Unrestricted read — add / with read access
                add_rule("/", ALL_READ)?;
            } else {
                // Scoped read
                for path in &policy.allowed_paths {
                    let p = path.to_string_lossy();
                    add_rule(&p, ALL_READ)?;
                }
            }
            // Always allow writing to /tmp and /var/tmp for temp files
            let _ = add_rule("/tmp", ALL_READ | ALL_WRITE);
            let _ = add_rule("/var/tmp", ALL_READ | ALL_WRITE);
        } else {
            // Write-enabled mode with path scoping
            if policy.allowed_paths.is_empty() {
                // No path restrictions — grant full access to everything
                add_rule("/", ALL_ACCESS)?;
            } else {
                // Read everything, write only to specified paths
                add_rule("/", ALL_READ)?;
                for path in &policy.allowed_paths {
                    let p = path.to_string_lossy();
                    add_rule(&p, ALL_ACCESS)?;
                }
            }
        }

        // Enforce the ruleset
        let ret = unsafe {
            libc::syscall(LANDLOCK_RESTRICT_SELF, ruleset_fd, 0u32)
        };

        unsafe { libc::close(ruleset_fd) };

        if ret < 0 {
            return Err(format!(
                "landlock_restrict_self failed: {}",
                std::io::Error::last_os_error()
            ));
        }
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = policy;
    }

    Ok(())
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
                apply_sandbox(&policy_clone);
                Ok(())
            });
        }
    }

    command
}

/// Build arguments for a sandboxed shell session on Linux.
///
/// Returns `(binary, args)` for spawning via portable-pty. The sandbox
/// is applied via pre-exec hooks in the PTY spawning code, not here.
pub fn sandboxed_shell_command(
    _policy: &SandboxPolicy,
    shell: &str,
    username: Option<&str>,
) -> (String, Vec<String>) {
    if let Some(user) = username {
        // su - <user> launches a login shell for that user
        let bin = "su".to_string();
        let args = vec!["-".into(), user.into()];
        (bin, args)
    } else {
        let bin = shell.to_string();
        let args = vec!["-l".into()];
        (bin, args)
    }
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
        assert_eq!(bin, "su");
        assert!(args.contains(&"alice".to_string()));
    }

    #[test]
    fn sandboxed_shell_without_user() {
        let policy = SandboxPolicy::default();
        let (bin, args) = sandboxed_shell_command(&policy, "/bin/bash", None);
        assert_eq!(bin, "/bin/bash");
        assert!(args.contains(&"-l".to_string()));
    }
}
