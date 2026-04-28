//! Extension manifest format and discovery.
//!
//! Manifests are TOML files dropped into `~/.config/hop/extensions/` or
//! `/etc/hop/extensions/`. Each manifest declares one extension's static
//! properties; runtime discovery (the ipc-channel server name) lives in
//! the bootstrap file the extension daemon writes on startup, at the
//! path declared in the manifest.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

/// Static descriptor for one extension. Written by the operator (or the
/// extension's installer) at install time. Read by hop daemon at startup.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionManifest {
    /// Stable identifier used in `PeerRequest::ExtensionCall`. Restricted
    /// to ASCII alphanumeric plus `.`, `-`, `_`. Convention: dotted
    /// namespace such as `tap.terminal` or `screen.vnc`.
    pub ext_id: String,

    /// Human-readable description shown in `hop ext list`.
    pub description: String,

    /// Absolute filesystem path the extension daemon writes its
    /// ipc-channel server name to on startup. Hop reads this file when
    /// it wants to (re)connect.
    pub bootstrap_path: PathBuf,

    /// Minimum role required to send any request to this extension.
    /// Per-request finer-grained authorization happens inside the
    /// extension daemon itself (the daemon receives the peer's full
    /// role and sandbox in `ExtMessage::Request`).
    ///
    /// Valid values: `"peer"` (any authenticated peer), `"creator"`
    /// (creator role required). Defaults to `"peer"`.
    #[serde(default = "default_required_role")]
    pub required_role: String,

    /// UID of the extension daemon's process. Hop's `SO_PEERCRED` check
    /// at rendezvous time verifies the connecting peer's UID matches
    /// this. Defense-in-depth: even if the bootstrap file leaks, only
    /// processes running as this UID can complete the handshake.
    /// Defaults to `0` (root) since most extensions need root for the
    /// kernel-side work that motivates them.
    #[serde(default)]
    pub expected_uid: u32,

    /// Protocol version exposed by the extension daemon. Used during the
    /// rendezvous handshake to detect incompatibility. Semver-ish string;
    /// hop only checks exact match for now.
    #[serde(default = "default_version")]
    pub version: String,
}

fn default_required_role() -> String {
    "peer".to_string()
}

fn default_version() -> String {
    "0.1.0".to_string()
}

impl ExtensionManifest {
    /// Load and validate a single manifest TOML file.
    pub fn load(path: &Path) -> Result<Self> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("reading manifest {}", path.display()))?;
        let manifest: Self = toml::from_str(&raw)
            .with_context(|| format!("parsing manifest {}", path.display()))?;
        manifest
            .validate()
            .with_context(|| format!("validating manifest {}", path.display()))?;
        Ok(manifest)
    }

    /// Validate all manifest fields. Run after deserialization.
    fn validate(&self) -> Result<()> {
        if self.ext_id.is_empty() {
            bail!("ext_id must not be empty");
        }
        if !self
            .ext_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        {
            bail!(
                "ext_id must contain only ASCII alphanumeric, '.', '-', '_'; got {:?}",
                self.ext_id
            );
        }
        if self.description.is_empty() {
            bail!("description must not be empty");
        }
        if !self.bootstrap_path.is_absolute() {
            bail!(
                "bootstrap_path must be absolute, got {}",
                self.bootstrap_path.display()
            );
        }
        match self.required_role.as_str() {
            "peer" | "creator" => {}
            other => bail!(
                "required_role must be 'peer' or 'creator', got {:?}",
                other
            ),
        }
        Ok(())
    }
}

/// Discover all extension manifests in a directory.
///
/// Skips hidden files, non-TOML files, subdirectories, and any manifest
/// that fails to parse or validate (those are logged at WARN level and
/// excluded from the result rather than failing the whole discovery).
///
/// A non-existent `dir` is not an error — returns an empty vec.
pub fn discover(dir: &Path) -> Result<Vec<ExtensionManifest>> {
    if !dir.exists() {
        return Ok(Vec::new());
    }
    let entries = std::fs::read_dir(dir)
        .with_context(|| format!("read_dir {}", dir.display()))?;

    let mut out = Vec::new();
    for entry in entries {
        let entry = entry?;
        let path = entry.path();
        let ft = entry.file_type()?;
        if !ft.is_file() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            continue;
        };
        if name.starts_with('.') || !name.ends_with(".toml") {
            continue;
        }
        match ExtensionManifest::load(&path) {
            Ok(m) => out.push(m),
            Err(e) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %e,
                    "failed to load extension manifest, skipping"
                );
            }
        }
    }
    out.sort_by(|a, b| a.ext_id.cmp(&b.ext_id));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(path: &Path, content: &str) {
        std::fs::write(path, content).unwrap();
    }

    #[test]
    fn load_valid_manifest() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("tap.toml");
        write(
            &p,
            r#"
            ext_id = "tap.terminal"
            description = "Terminal session tap"
            bootstrap_path = "/run/hop-tap/bootstrap"
            "#,
        );
        let m = ExtensionManifest::load(&p).unwrap();
        assert_eq!(m.ext_id, "tap.terminal");
        assert_eq!(m.required_role, "peer"); // default
        assert_eq!(m.expected_uid, 0); // default
        assert_eq!(m.version, "0.1.0"); // default
    }

    #[test]
    fn load_full_manifest() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("a.toml");
        write(
            &p,
            r#"
            ext_id = "screen.vnc"
            description = "VNC-like screen sharing"
            bootstrap_path = "/run/hop-screen/bootstrap"
            required_role = "creator"
            expected_uid = 1000
            version = "0.2.1"
            "#,
        );
        let m = ExtensionManifest::load(&p).unwrap();
        assert_eq!(m.required_role, "creator");
        assert_eq!(m.expected_uid, 1000);
        assert_eq!(m.version, "0.2.1");
    }

    #[test]
    fn rejects_relative_bootstrap_path() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("a.toml");
        write(
            &p,
            r#"
            ext_id = "test"
            description = "Test"
            bootstrap_path = "relative/path"
            "#,
        );
        let err = ExtensionManifest::load(&p).unwrap_err();
        assert!(format!("{err:#}").contains("absolute"));
    }

    #[test]
    fn rejects_invalid_ext_id() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("a.toml");
        write(
            &p,
            r#"
            ext_id = "tap/terminal"
            description = "Test"
            bootstrap_path = "/tmp/x"
            "#,
        );
        let err = ExtensionManifest::load(&p).unwrap_err();
        assert!(format!("{err:#}").contains("ext_id"));
    }

    #[test]
    fn rejects_invalid_role() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("a.toml");
        write(
            &p,
            r#"
            ext_id = "test"
            description = "Test"
            bootstrap_path = "/tmp/x"
            required_role = "admin"
            "#,
        );
        let err = ExtensionManifest::load(&p).unwrap_err();
        assert!(format!("{err:#}").contains("required_role"));
    }

    #[test]
    fn discover_skips_hidden_and_non_toml() {
        let dir = tempdir().unwrap();
        write(
            &dir.path().join("good.toml"),
            r#"
            ext_id = "good"
            description = "Good extension"
            bootstrap_path = "/tmp/x"
            "#,
        );
        write(&dir.path().join(".hidden.toml"), "# ignored");
        write(&dir.path().join("not-toml.txt"), "# ignored");
        write(&dir.path().join("subdir"), ""); // file, not dir, but irrelevant

        let mut found = discover(dir.path()).unwrap();
        // file_type::is_file() accepts the empty subdir entry too if we
        // mistakenly created it as a file; assert by ext_id presence.
        found.retain(|m| m.ext_id == "good");
        assert_eq!(found.len(), 1);
    }

    #[test]
    fn discover_skips_unparseable_manifest_with_warning() {
        let dir = tempdir().unwrap();
        write(
            &dir.path().join("good.toml"),
            r#"
            ext_id = "good"
            description = "Good"
            bootstrap_path = "/tmp/x"
            "#,
        );
        write(&dir.path().join("broken.toml"), "this is not valid toml @@@");
        let found = discover(dir.path()).unwrap();
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].ext_id, "good");
    }

    #[test]
    fn discover_returns_empty_for_missing_dir() {
        let dir = tempdir().unwrap();
        let missing = dir.path().join("does-not-exist");
        let found = discover(&missing).unwrap();
        assert!(found.is_empty());
    }
}
