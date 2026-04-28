//! Extension bootstrap-rendezvous file.
//!
//! Each extension daemon writes a tiny TOML file on startup containing the
//! ipc-channel server name it's listening on, plus its PID and protocol
//! version. Hop reads the file when it wants to connect.
//!
//! Path is declared in the extension's manifest (`bootstrap_path` field).
//!
//! Format:
//!
//! ```toml
//! server_name = "/tmp/.ipc-channel-randomXYZ"
//! pid         = 12345
//! version     = "0.1.0"
//! ```
//!
//! Security properties (see `docs/hop-tap-plan.md` §6.2):
//!
//! - The file is effectively a credential — anyone who reads the
//!   `server_name` can connect to the extension's ipc-channel server.
//! - Hop verifies file ownership matches the manifest's `expected_uid`
//!   before trusting the contents.
//! - File permissions should not include world-write/read; we sanity-
//!   check this at read time and refuse files looser than 0640.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Contents of a bootstrap file. Written by the extension daemon on
/// startup; read by Hop when it wants to connect.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Bootstrap {
    /// ipc-channel server name (an opaque string; on Unix this is the
    /// path to a Unix domain socket).
    pub server_name: String,

    /// PID of the extension daemon at the time it wrote this file.
    /// Used to detect stale entries (the daemon crashed without
    /// cleanup and the address is no longer listening).
    pub pid: u32,

    /// Protocol version the extension speaks. Compared against the
    /// manifest's `version` at handshake time; mismatches are surfaced
    /// as connection errors rather than soft failures.
    pub version: String,
}

impl Bootstrap {
    /// Read and validate a bootstrap file.
    ///
    /// `expected_uid` is from the extension's manifest; if the file is
    /// owned by anyone else, we refuse to trust it. (An attacker who
    /// can write to the bootstrap file as the wrong UID could otherwise
    /// substitute a malicious `server_name`.)
    pub fn load(path: &Path, expected_uid: u32) -> Result<Self> {
        let meta = std::fs::metadata(path)
            .with_context(|| format!("stat bootstrap {}", path.display()))?;

        // Ownership check.
        let owner = meta.uid();
        if owner != expected_uid {
            bail!(
                "bootstrap file {} is owned by uid {} but manifest expects {}",
                path.display(),
                owner,
                expected_uid
            );
        }

        // Permission check: refuse anything looser than 0640. World-readable
        // (others having any access) is unacceptable since the file is a
        // credential. Group write is also rejected — the file should be
        // writable only by its owner.
        let mode = meta.mode() & 0o777;
        if mode & 0o007 != 0 {
            bail!(
                "bootstrap file {} has world-accessible mode {:o}; refusing to trust",
                path.display(),
                mode
            );
        }
        if mode & 0o020 != 0 {
            bail!(
                "bootstrap file {} is group-writable (mode {:o}); refusing to trust",
                path.display(),
                mode
            );
        }

        // Now safe to read contents.
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading bootstrap {}", path.display()))?;
        let bs: Self = toml::from_str(&raw)
            .with_context(|| format!("parsing bootstrap {}", path.display()))?;
        bs.validate()
            .with_context(|| format!("validating bootstrap {}", path.display()))?;
        Ok(bs)
    }

    fn validate(&self) -> Result<()> {
        if self.server_name.is_empty() {
            bail!("server_name must not be empty");
        }
        if self.pid == 0 {
            bail!("pid must not be zero");
        }
        if self.version.is_empty() {
            bail!("version must not be empty");
        }
        Ok(())
    }

    /// Returns true if the daemon process referenced by `pid` is still
    /// alive. This is a best-effort check used to skip stale bootstrap
    /// files; not a security check.
    pub fn pid_alive(&self) -> bool {
        // SAFETY: kill(pid, 0) is the canonical existence check on Unix.
        // Returns 0 if the process exists and we can signal it, -1
        // otherwise. We don't actually send any signal.
        unsafe { libc::kill(self.pid as libc::pid_t, 0) == 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn write_with_mode(path: &Path, content: &str, mode: u32) {
        std::fs::write(path, content).unwrap();
        let mut perms = std::fs::metadata(path).unwrap().permissions();
        perms.set_mode(mode);
        std::fs::set_permissions(path, perms).unwrap();
    }

    fn current_uid() -> u32 {
        // SAFETY: getuid is always safe.
        unsafe { libc::getuid() }
    }

    #[test]
    fn load_valid_bootstrap() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bootstrap");
        write_with_mode(
            &path,
            r#"
            server_name = "/tmp/.test-server"
            pid = 1234
            version = "0.1.0"
            "#,
            0o600,
        );

        let bs = Bootstrap::load(&path, current_uid()).unwrap();
        assert_eq!(bs.server_name, "/tmp/.test-server");
        assert_eq!(bs.pid, 1234);
        assert_eq!(bs.version, "0.1.0");
    }

    #[test]
    fn rejects_world_readable() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bootstrap");
        write_with_mode(
            &path,
            r#"server_name = "/tmp/x"
pid = 1
version = "0.1""#,
            0o644, // world-readable
        );
        let err = Bootstrap::load(&path, current_uid()).unwrap_err();
        assert!(format!("{err:#}").contains("world-accessible"));
    }

    #[test]
    fn rejects_group_writable() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bootstrap");
        write_with_mode(
            &path,
            r#"server_name = "/tmp/x"
pid = 1
version = "0.1""#,
            0o620, // group-writable
        );
        let err = Bootstrap::load(&path, current_uid()).unwrap_err();
        assert!(format!("{err:#}").contains("group-writable"));
    }

    #[test]
    fn rejects_uid_mismatch() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("bootstrap");
        write_with_mode(
            &path,
            r#"server_name = "/tmp/x"
pid = 1
version = "0.1""#,
            0o600,
        );
        // Pick a UID that's almost certainly not ours.
        let wrong_uid = if current_uid() == 0 { 65534 } else { 0 };
        let err = Bootstrap::load(&path, wrong_uid).unwrap_err();
        assert!(format!("{err:#}").contains("owned by"));
    }

    #[test]
    fn pid_alive_for_self() {
        let bs = Bootstrap {
            server_name: "x".into(),
            pid: std::process::id(),
            version: "0.1".into(),
        };
        assert!(bs.pid_alive());
    }

    #[test]
    fn pid_alive_false_for_nonexistent() {
        // Pick a PID guaranteed not to exist on most systems.
        let bs = Bootstrap {
            server_name: "x".into(),
            pid: 999_999,
            version: "0.1".into(),
        };
        assert!(!bs.pid_alive());
    }
}
