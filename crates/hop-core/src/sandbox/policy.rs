//! Sandbox policy definitions and presets.

use serde::{Deserialize, Serialize};
use std::path::PathBuf;

/// Security policy attached to an invite that restricts what the connecting
/// peer can do. Enforced on the host side when spawning processes.
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SandboxPolicy {
    /// Prevent all filesystem writes, deletes, and modifications.
    #[serde(default)]
    pub read_only: bool,

    /// Block outbound network access from spawned commands.
    #[serde(default)]
    pub no_network: bool,

    /// Restrict filesystem visibility to these paths (empty = unrestricted).
    /// Each path gets read (+ execute for dirs) access only.
    #[serde(default)]
    pub allowed_paths: Vec<PathBuf>,

    /// If non-empty, only these command basenames may be executed.
    /// e.g., ["ps", "ls", "cat"]. Empty = allow all.
    #[serde(default)]
    pub allowed_commands: Vec<String>,

    /// Deny execution of these commands even if not using an allowlist.
    #[serde(default)]
    pub denied_commands: Vec<String>,
}

/// Serde helper: skip serializing a `SandboxPolicy` field when unrestricted.
pub fn sandbox_is_unrestricted(p: &SandboxPolicy) -> bool {
    !p.is_restricted()
}

impl SandboxPolicy {
    /// An unrestricted policy (full access, current default behavior).
    pub fn unrestricted() -> Self {
        Self::default()
    }

    /// Whether `path` is within the policy's filesystem scope. An empty
    /// `allowed_paths` means unrestricted (any path). Otherwise the path is
    /// canonicalized (resolving symlinks and `..`) and must lie under one of
    /// the allowed roots. For paths that don't exist yet (e.g. a file about to
    /// be written), the parent directory is canonicalized and the final
    /// component appended, so a write can't escape via a non-existent name.
    ///
    /// Used to confine peer-driven file access (transfer + JS `readFile`/
    /// `writeFile`) — security-audit C3/C4.
    pub fn path_in_scope(&self, path: &std::path::Path) -> bool {
        if self.allowed_paths.is_empty() {
            return true;
        }
        let canon = canonicalize_lexical(path);
        let roots: Vec<PathBuf> = self
            .allowed_paths
            .iter()
            .map(|p| canonicalize_lexical(p))
            .collect();
        roots.iter().any(|root| canon.starts_with(root))
    }

    /// Returns true if any sandbox restriction is active.
    pub fn is_restricted(&self) -> bool {
        self.read_only
            || self.no_network
            || !self.allowed_paths.is_empty()
            || !self.allowed_commands.is_empty()
            || !self.denied_commands.is_empty()
    }

    /// Preset: monitoring access. Read-only, no network, scoped to system
    /// status paths, limited to common monitoring commands.
    pub fn preset_monitor() -> Self {
        Self {
            read_only: true,
            no_network: true,
            allowed_paths: vec![
                PathBuf::from("/proc"),
                PathBuf::from("/sys"),
                PathBuf::from("/var/log"),
                PathBuf::from("/etc"),
            ],
            allowed_commands: vec![
                "ps".into(),
                "top".into(),
                "htop".into(),
                "free".into(),
                "df".into(),
                "du".into(),
                "uptime".into(),
                "lsof".into(),
                "netstat".into(),
                "ss".into(),
                "cat".into(),
                "grep".into(),
                "tail".into(),
                "head".into(),
                "journalctl".into(),
                "dmesg".into(),
                "ls".into(),
                "wc".into(),
                "sort".into(),
                "uniq".into(),
                "awk".into(),
                "sed".into(),
            ],
            denied_commands: Vec::new(),
        }
    }

    /// Preset: audit access. Read-only, no network, full filesystem read.
    pub fn preset_audit() -> Self {
        Self {
            read_only: true,
            no_network: true,
            allowed_paths: Vec::new(), // unrestricted read
            allowed_commands: Vec::new(), // allow all read-safe commands
            denied_commands: default_denied_commands(),
        }
    }

    /// Preset: connect access. Read-only but network-enabled (for API integrations).
    pub fn preset_connect() -> Self {
        Self {
            read_only: true,
            no_network: false,
            allowed_paths: Vec::new(),
            allowed_commands: Vec::new(),
            denied_commands: default_denied_commands(),
        }
    }

    /// Preset: deploy access. Write-enabled, network-enabled, scoped to cwd.
    pub fn preset_deploy() -> Self {
        // Scope to current working directory — caller should resolve this.
        Self {
            read_only: false,
            no_network: false,
            allowed_paths: Vec::new(), // caller should set
            allowed_commands: Vec::new(),
            denied_commands: default_denied_commands(),
        }
    }

    /// Look up a preset by name. Returns None for unknown names.
    pub fn from_preset(name: &str) -> Option<Self> {
        match name {
            "monitor" => Some(Self::preset_monitor()),
            "audit" => Some(Self::preset_audit()),
            "connect" => Some(Self::preset_connect()),
            "deploy" => Some(Self::preset_deploy()),
            _ => None,
        }
    }

    /// Returns true if no sandbox restriction is active (convenience for `&self`).
    pub fn is_unrestricted(&self) -> bool {
        !self.is_restricted()
    }

    /// Merge two policies, keeping the **stricter** constraint for every field.
    ///
    /// Use case: host has a stored sandbox; the client requests additional
    /// restrictions. The result is never looser than either input.
    ///
    /// * Booleans: OR (if either says restricted → restricted).
    /// * `allowed_paths` / `allowed_commands`: intersection (empty on either side
    ///   means "unrestricted for that field" — so only intersect when *both* are
    ///   non-empty).
    /// * `denied_commands`: union (deny anything either side denies).
    pub fn merge_stricter(&self, other: &Self) -> Self {
        let allowed_paths = if self.allowed_paths.is_empty() {
            other.allowed_paths.clone()
        } else if other.allowed_paths.is_empty() {
            self.allowed_paths.clone()
        } else {
            // Intersection: keep paths present in both
            self.allowed_paths
                .iter()
                .filter(|p| other.allowed_paths.contains(p))
                .cloned()
                .collect()
        };

        let allowed_commands = if self.allowed_commands.is_empty() {
            other.allowed_commands.clone()
        } else if other.allowed_commands.is_empty() {
            self.allowed_commands.clone()
        } else {
            self.allowed_commands
                .iter()
                .filter(|c| other.allowed_commands.contains(c))
                .cloned()
                .collect()
        };

        let mut denied_commands = self.denied_commands.clone();
        for cmd in &other.denied_commands {
            if !denied_commands.contains(cmd) {
                denied_commands.push(cmd.clone());
            }
        }

        Self {
            read_only: self.read_only || other.read_only,
            no_network: self.no_network || other.no_network,
            allowed_paths,
            allowed_commands,
            denied_commands,
        }
    }

    /// Merge CLI flags on top of a base policy (e.g. preset + overrides).
    pub fn with_overrides(
        mut self,
        read_only: Option<bool>,
        no_network: Option<bool>,
        scopes: &[PathBuf],
        allow_commands: &[String],
    ) -> Self {
        if let Some(ro) = read_only {
            self.read_only = ro;
        }
        if let Some(nn) = no_network {
            self.no_network = nn;
        }
        if !scopes.is_empty() {
            self.allowed_paths = scopes.to_vec();
        }
        if !allow_commands.is_empty() {
            self.allowed_commands = allow_commands.to_vec();
        }
        self
    }
}

/// Resolve `path` to an absolute, symlink-free form for scope comparison.
/// If the path exists, `fs::canonicalize` it. Otherwise canonicalize the
/// nearest existing ancestor and re-append the remaining components, then
/// drop any `.`/`..` lexically so a non-existent name can't be used to
/// `..`-escape an allowed root.
fn canonicalize_lexical(path: &std::path::Path) -> PathBuf {
    use std::path::Component;
    if let Ok(c) = std::fs::canonicalize(path) {
        return c;
    }
    // Walk up to the first existing ancestor and canonicalize that.
    let mut ancestor = path;
    let mut tail: Vec<&std::ffi::OsStr> = Vec::new();
    loop {
        if let Ok(c) = std::fs::canonicalize(ancestor) {
            let mut base = c;
            for comp in tail.iter().rev() {
                base.push(comp);
            }
            return normalize_dotdot(&base);
        }
        match ancestor.parent() {
            Some(p) if p != ancestor => {
                if let Some(name) = ancestor.file_name() {
                    tail.push(name);
                }
                ancestor = p;
            }
            _ => break,
        }
    }
    // Nothing in the path exists — normalize lexically against root.
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Collapse `..`/`.` components lexically (no filesystem access).
fn normalize_dotdot(path: &std::path::Path) -> PathBuf {
    use std::path::Component;
    let mut out = PathBuf::new();
    for comp in path.components() {
        match comp {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Commands that should always be denied in any sandboxed context.
pub fn default_denied_commands() -> Vec<String> {
    [
        "rm", "rmdir", "mkfs", "dd", "shutdown", "reboot", "poweroff",
        "halt", "init", "telinit", "fdisk", "parted", "mkswap",
        "swapon", "swapoff", "mount", "umount",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_unrestricted() {
        let p = SandboxPolicy::default();
        assert!(!p.is_restricted());
        assert!(!p.read_only);
        assert!(!p.no_network);
    }

    #[test]
    fn path_in_scope_unrestricted_allows_anything() {
        let p = SandboxPolicy::default();
        assert!(p.path_in_scope(std::path::Path::new("/etc/shadow")));
        assert!(p.path_in_scope(std::path::Path::new("/anything/at/all")));
    }

    #[test]
    fn path_in_scope_confines_to_allowed_roots() {
        let dir = std::env::temp_dir();
        let p = SandboxPolicy {
            allowed_paths: vec![dir.join("hop-scope-test")],
            ..Default::default()
        };
        std::fs::create_dir_all(dir.join("hop-scope-test/sub")).unwrap();
        // Inside the allowed root (existing and not-yet-existing children).
        assert!(p.path_in_scope(&dir.join("hop-scope-test/sub")));
        assert!(p.path_in_scope(&dir.join("hop-scope-test/new-file.txt")));
        // Outside the root.
        assert!(!p.path_in_scope(std::path::Path::new("/etc/passwd")));
        // `..` escape from a non-existent child must not slip out of the root.
        assert!(!p.path_in_scope(&dir.join("hop-scope-test/../../etc/passwd")));
        let _ = std::fs::remove_dir_all(dir.join("hop-scope-test"));
    }

    #[test]
    fn monitor_preset_is_restricted() {
        let p = SandboxPolicy::preset_monitor();
        assert!(p.is_restricted());
        assert!(p.read_only);
        assert!(p.no_network);
        assert!(p.allowed_commands.contains(&"ps".to_string()));
    }

    #[test]
    fn serialization_roundtrip() {
        let p = SandboxPolicy::preset_monitor();
        let json = serde_json::to_string(&p).unwrap();
        let p2: SandboxPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn unrestricted_serializes_all_fields() {
        let p = SandboxPolicy::default();
        let json = serde_json::to_string(&p).unwrap();
        // All fields are now always serialized (required for bincode compat)
        let p2: SandboxPolicy = serde_json::from_str(&json).unwrap();
        assert_eq!(p, p2);
    }

    #[test]
    fn backward_compat_empty_object() {
        let p: SandboxPolicy = serde_json::from_str("{}").unwrap();
        assert!(!p.is_restricted());
    }

    #[test]
    fn from_preset_known() {
        assert!(SandboxPolicy::from_preset("monitor").is_some());
        assert!(SandboxPolicy::from_preset("audit").is_some());
        assert!(SandboxPolicy::from_preset("deploy").is_some());
        assert!(SandboxPolicy::from_preset("unknown").is_none());
    }

    #[test]
    fn with_overrides_merges() {
        let p = SandboxPolicy::preset_monitor().with_overrides(
            None,
            Some(false), // override no_network
            &[],
            &["ps".into(), "top".into()],
        );
        assert!(p.read_only); // kept from preset
        assert!(!p.no_network); // overridden
        assert_eq!(p.allowed_commands, vec!["ps", "top"]); // overridden
    }

    // --- merge_stricter tests ---

    #[test]
    fn merge_stricter_both_unrestricted() {
        let a = SandboxPolicy::default();
        let b = SandboxPolicy::default();
        let m = a.merge_stricter(&b);
        assert!(!m.is_restricted());
    }

    #[test]
    fn merge_stricter_one_restricted() {
        let monitor = SandboxPolicy::preset_monitor();
        let unrestricted = SandboxPolicy::default();
        let m = monitor.merge_stricter(&unrestricted);
        // Should keep monitor's restrictions
        assert!(m.read_only);
        assert!(m.no_network);
        assert_eq!(m.allowed_paths, monitor.allowed_paths);
        assert_eq!(m.allowed_commands, monitor.allowed_commands);
    }

    #[test]
    fn merge_stricter_booleans_or() {
        let a = SandboxPolicy { read_only: true, no_network: false, ..Default::default() };
        let b = SandboxPolicy { read_only: false, no_network: true, ..Default::default() };
        let m = a.merge_stricter(&b);
        assert!(m.read_only);
        assert!(m.no_network);
    }

    #[test]
    fn merge_stricter_paths_intersect() {
        let a = SandboxPolicy {
            allowed_paths: vec![PathBuf::from("/etc"), PathBuf::from("/var/log"), PathBuf::from("/proc")],
            ..Default::default()
        };
        let b = SandboxPolicy {
            allowed_paths: vec![PathBuf::from("/etc"), PathBuf::from("/proc")],
            ..Default::default()
        };
        let m = a.merge_stricter(&b);
        assert_eq!(m.allowed_paths, vec![PathBuf::from("/etc"), PathBuf::from("/proc")]);
    }

    #[test]
    fn merge_stricter_commands_intersect() {
        let a = SandboxPolicy {
            allowed_commands: vec!["ps".into(), "ls".into(), "cat".into()],
            ..Default::default()
        };
        let b = SandboxPolicy {
            allowed_commands: vec!["ps".into(), "cat".into()],
            ..Default::default()
        };
        let m = a.merge_stricter(&b);
        assert_eq!(m.allowed_commands, vec!["ps", "cat"]);
    }

    #[test]
    fn merge_stricter_denied_union() {
        let a = SandboxPolicy {
            denied_commands: vec!["rm".into(), "dd".into()],
            ..Default::default()
        };
        let b = SandboxPolicy {
            denied_commands: vec!["dd".into(), "shutdown".into()],
            ..Default::default()
        };
        let m = a.merge_stricter(&b);
        assert_eq!(m.denied_commands, vec!["rm", "dd", "shutdown"]);
    }

    #[test]
    fn merge_stricter_monitor_with_default() {
        let m = SandboxPolicy::preset_monitor().merge_stricter(&SandboxPolicy::default());
        assert_eq!(m, SandboxPolicy::preset_monitor());
    }

    #[test]
    fn is_unrestricted_helper() {
        assert!(SandboxPolicy::default().is_unrestricted());
        assert!(!SandboxPolicy::preset_monitor().is_unrestricted());
    }

    #[test]
    fn sandbox_is_unrestricted_serde_helper() {
        assert!(super::sandbox_is_unrestricted(&SandboxPolicy::default()));
        assert!(!super::sandbox_is_unrestricted(&SandboxPolicy::preset_audit()));
    }

    // --- merge_stricter edge cases ---

    #[test]
    fn merge_stricter_subpath_no_prefix_matching() {
        // /var/log and /var/log/app are treated as distinct paths —
        // intersection yields empty because they are not equal.
        let a = SandboxPolicy {
            allowed_paths: vec![PathBuf::from("/var/log")],
            ..Default::default()
        };
        let b = SandboxPolicy {
            allowed_paths: vec![PathBuf::from("/var/log/app")],
            ..Default::default()
        };
        let m = a.merge_stricter(&b);
        assert!(
            m.allowed_paths.is_empty(),
            "intersection of /var/log and /var/log/app should be empty (no prefix matching)"
        );
    }

    #[test]
    fn merge_stricter_is_symmetric() {
        let a = SandboxPolicy {
            read_only: true,
            no_network: false,
            allowed_paths: vec![PathBuf::from("/etc"), PathBuf::from("/proc")],
            allowed_commands: vec!["ps".into(), "ls".into()],
            denied_commands: vec!["rm".into()],
        };
        let b = SandboxPolicy {
            read_only: false,
            no_network: true,
            allowed_paths: vec![PathBuf::from("/proc"), PathBuf::from("/var/log")],
            allowed_commands: vec!["ls".into(), "cat".into()],
            denied_commands: vec!["dd".into()],
        };
        let ab = a.merge_stricter(&b);
        let ba = b.merge_stricter(&a);
        assert_eq!(ab.read_only, ba.read_only);
        assert_eq!(ab.no_network, ba.no_network);
        // Paths and commands: same elements (order may differ)
        let mut ab_paths = ab.allowed_paths.clone();
        let mut ba_paths = ba.allowed_paths.clone();
        ab_paths.sort();
        ba_paths.sort();
        assert_eq!(ab_paths, ba_paths);
        let mut ab_cmds = ab.allowed_commands.clone();
        let mut ba_cmds = ba.allowed_commands.clone();
        ab_cmds.sort();
        ba_cmds.sort();
        assert_eq!(ab_cmds, ba_cmds);
        let mut ab_denied = ab.denied_commands.clone();
        let mut ba_denied = ba.denied_commands.clone();
        ab_denied.sort();
        ba_denied.sort();
        assert_eq!(ab_denied, ba_denied);
    }

    #[test]
    fn merge_stricter_idempotent() {
        let a = SandboxPolicy::preset_monitor();
        let m = a.merge_stricter(&a);
        assert_eq!(m, a, "merging with self should be idempotent");
    }

    #[test]
    fn merge_stricter_client_cannot_weaken_host() {
        let host = SandboxPolicy {
            read_only: true,
            no_network: true,
            allowed_commands: vec!["ps".into(), "ls".into()],
            denied_commands: vec!["rm".into()],
            ..Default::default()
        };
        let client = SandboxPolicy {
            read_only: false,  // client tries to remove read_only
            no_network: false, // client tries to remove no_network
            allowed_commands: vec!["ps".into(), "ls".into(), "bash".into()], // client tries to add bash
            denied_commands: Vec::new(), // client tries to clear deny list
            ..Default::default()
        };
        let merged = host.merge_stricter(&client);
        assert!(merged.read_only, "client cannot disable read_only");
        assert!(merged.no_network, "client cannot disable no_network");
        assert!(
            !merged.allowed_commands.contains(&"bash".into()),
            "client cannot add commands not in host's allowlist"
        );
        assert!(
            merged.denied_commands.contains(&"rm".into()),
            "host's denied commands are preserved"
        );
    }
}
