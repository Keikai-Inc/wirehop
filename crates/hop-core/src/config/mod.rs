use anyhow::{Context, Result};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use directories::ProjectDirs;
use iroh::{PublicKey, SecretKey};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// The well-known system-level config directory on macOS.
#[cfg(target_os = "macos")]
const SYSTEM_CONFIG_DIR: &str = "/Library/Application Support/hop";

/// The well-known system-level config directory on Linux.
#[cfg(target_os = "linux")]
const SYSTEM_CONFIG_DIR: &str = "/etc/hop";

/// The system-level config directory the root daemon uses (the path the
/// launchd plist / systemd unit pass via `--config`). The native daemon
/// installer must place primers here, not in the per-user dir that
/// `resolve_host_config_dir` would pick before a system identity exists.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn system_config_dir() -> PathBuf {
    PathBuf::from(SYSTEM_CONFIG_DIR)
}

/// Write a file with restricted permissions (0600) for secrets.
/// On non-Unix platforms, falls back to a regular write.
pub fn write_secret_file(path: &Path, data: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .with_context(|| format!("Failed to create {}", path.display()))?;
        file.write_all(data.as_bytes())
            .with_context(|| format!("Failed to write {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
            .with_context(|| format!("Failed to write {}", path.display()))?;
    }
    Ok(())
}

/// Write a file with group-accessible permissions (0660).
/// Used for files shared between the daemon and CLI (peers.json, pending_invites.json).
/// On non-Unix platforms, falls back to a regular write.
pub fn write_shared_file(path: &Path, data: &str) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o660)
            .open(path)
            .with_context(|| format!("Failed to create {}", path.display()))?;
        file.write_all(data.as_bytes())
            .with_context(|| format!("Failed to write {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        std::fs::write(path, data)
            .with_context(|| format!("Failed to write {}", path.display()))?;
    }
    Ok(())
}

/// Returns the default config directory (~/.config/hop on Linux/macOS).
pub fn default_config_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("", "", "hop").context("Could not determine config directory")?;
    Ok(dirs.config_dir().to_path_buf())
}

/// Ensures the config directory exists (with 0700 permissions) and returns its path.
/// Only sets permissions when the current process owns the directory, so it won't
/// clobber the system config's 2770 when the daemon calls this.
pub fn ensure_config_dir(override_path: Option<&Path>) -> Result<PathBuf> {
    let dir = match override_path {
        Some(p) => p.to_path_buf(),
        None => default_config_dir()?,
    };
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create config dir: {}", dir.display()))?;

    // Restrict directory permissions so only the owner can list/enter it.
    // Skip if the setgid bit (0o2000) is set — that means postinstall
    // intentionally configured the directory for shared daemon/CLI access.
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(&dir)
            .with_context(|| format!("Failed to read metadata for {}", dir.display()))?;
        let current_mode = meta.mode();
        if current_mode & 0o2000 == 0 {
            std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
                .with_context(|| format!("Failed to set permissions on {}", dir.display()))?;
        }
    }

    Ok(dir)
}

/// Persisted identity file format.
#[derive(Debug, Serialize, Deserialize)]
struct IdentityFile {
    secret_key: String,
    node_id: String,
}

/// Load or generate the node identity (Ed25519 keypair).
///
/// On first run, generates a new keypair and saves it to `identity.json`.
/// On subsequent runs, loads the existing keypair.
pub fn load_or_generate_identity(config_dir: &Path) -> Result<SecretKey> {
    let path = config_dir.join("identity.json");

    if path.exists() {
        // The identity secret is the root of trust for the node *and* the
        // secrets-at-rest key. If a pre-existing file has looser-than-0600
        // permissions (e.g. created before this check, or via a sloppy copy),
        // re-tighten it to 0600 when we own it (security-audit M12).
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::fs::PermissionsExt;
            if let Ok(meta) = std::fs::metadata(&path) {
                let owned_by_us = meta.uid() == unsafe { libc::geteuid() };
                if owned_by_us && meta.mode() & 0o077 != 0 {
                    let _ = std::fs::set_permissions(
                        &path,
                        std::fs::Permissions::from_mode(0o600),
                    );
                }
            }
        }

        let data = std::fs::read_to_string(&path)
            .with_context(|| format!("Failed to read {}", path.display()))?;
        let file: IdentityFile =
            serde_json::from_str(&data).context("Failed to parse identity.json")?;

        let key_bytes = URL_SAFE_NO_PAD
            .decode(&file.secret_key)
            .context("Failed to decode secret key from base64")?;
        let key_array: [u8; 32] = key_bytes
            .try_into()
            .map_err(|_| anyhow::anyhow!("Secret key must be 32 bytes"))?;
        Ok(SecretKey::from_bytes(&key_array))
    } else {
        let key = SecretKey::generate(&mut rand::rng());
        let public = key.public();

        let file = IdentityFile {
            secret_key: URL_SAFE_NO_PAD.encode(key.to_bytes()),
            node_id: public.to_string(),
        };
        let data = serde_json::to_string_pretty(&file)?;
        write_secret_file(&path, &data)?;

        tracing::info!("Generated new identity: {}", public.fmt_short());
        Ok(key)
    }
}

/// Load an existing node identity from `config_dir/identity.json` (read-only).
/// Returns an error if the file does not exist — never generates a new key.
/// Used by `hop invite` to read the daemon's identity without creating one.
pub fn load_identity(config_dir: &Path) -> Result<SecretKey> {
    let path = config_dir.join("identity.json");

    let data = std::fs::read_to_string(&path)
        .with_context(|| format!("Failed to read {} — is the daemon installed?", path.display()))?;
    let file: IdentityFile =
        serde_json::from_str(&data).context("Failed to parse identity.json")?;

    let key_bytes = URL_SAFE_NO_PAD
        .decode(&file.secret_key)
        .context("Failed to decode secret key from base64")?;
    let key_array: [u8; 32] = key_bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("Secret key must be 32 bytes"))?;
    Ok(SecretKey::from_bytes(&key_array))
}

/// Resolve the config directory for host-side commands (`invite`, `peers`).
///
/// Priority:
/// 1. `--config` override if provided
/// 2. System config dir if `identity.json` exists there (daemon installed)
/// 3. User config dir via `default_config_dir()`
///
/// Does NOT create directories or set permissions — just resolves a path.
pub fn resolve_host_config_dir(override_path: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = override_path {
        return Ok(p.to_path_buf());
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let system_dir = Path::new(SYSTEM_CONFIG_DIR);
        if system_dir.join("identity.json").exists() {
            return Ok(system_dir.to_path_buf());
        }
    }

    default_config_dir()
}

/// Resolve the host-side config dir (like [`resolve_host_config_dir`]) AND ensure
/// it exists, for commands that *write* the local daemon's state (`warren join`,
/// `host`). Creates the directory (owner-only 0700) only when it does not already
/// exist, so an existing daemon dir — typically root-owned and setgid (2770) for
/// shared daemon/CLI access — is never re-permissioned out from under the daemon.
///
/// With `--config` (the way the LaunchDaemon/systemd unit invokes `hop host`),
/// this resolves to that override unchanged, so production daemons are unaffected.
pub fn ensure_host_config_dir(override_path: Option<&Path>) -> Result<PathBuf> {
    let dir = resolve_host_config_dir(override_path)?;
    if !dir.exists() {
        std::fs::create_dir_all(&dir)
            .with_context(|| format!("Failed to create config dir: {}", dir.display()))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            // Best-effort: a created dir is owner-only; ignore failures so a
            // restrictive umask or odd mount doesn't make the command fail.
            let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
        }
    }
    Ok(dir)
}

/// Role assigned to an authorized peer.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PeerRole {
    #[default]
    Peer,
    Creator,
}

/// An authorized peer entry (host side).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Peer {
    pub node_id: String,
    pub name: String,
    pub authorized_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<String>,
    /// Unix username this peer logs in as (None = host's own user).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Auth tier of this peer (default: Peer). Creator peers get admin access.
    /// Retained as the compatibility shim while the named-role model lands.
    #[serde(default)]
    pub role: PeerRole,
    /// Named role (resolves to a `RoleDefinition`: tags → reach, sandbox →
    /// confinement). `None` = legacy peer governed only by `role`/`sandbox`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_name: Option<String>,
    /// The peer's iroh-docs author id (hex), vouched by the admin that admitted
    /// it (C1 trust binding). In enforce mode, self-owned doc entries
    /// (`vpn/ ip/ name/ tag/ posture/`) belonging to this node are honored only
    /// when authored by this author. `None` = not yet bound (announce pending).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub netdoc_author: Option<String>,
    /// The peer's self-doc **read** ticket (per-member self-document model),
    /// recorded by the admin that admitted it. Other nodes import this read-only
    /// to learn the member's self-state (`ip/ vpn/ name/ tag/ posture/`). `None` =
    /// the member has no self-doc yet (legacy member → shared-doc fallback).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub self_doc: Option<String>,
    /// The peer's admin-allocated virtual IP (per-member self-document model,
    /// #3b). The admin claims it once at admission and records it here
    /// (admin-owned ⇒ the addr→owner authority readers trust); the member then
    /// self-writes only its *endpoint* for this addr in its self-doc. Static, so
    /// no admin-online coupling for endpoint updates. `None` = legacy member
    /// (falls back to the shared `ip/` table).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vip: Option<String>,
    /// The peer's VPN endpoint as `"<endpoint_id> <relay_url>"` — the netdoc
    /// endpoint that serves `hop/vpn/1`. Recorded by the admin from this member's
    /// authenticated announce (admin-vouched, exactly like `self_doc`/
    /// `netdoc_author`). The value is **static** — a derived, key-stable endpoint
    /// id + the configured relay — so there is no admin-online coupling: routing
    /// resolves it straight from the reliably-replicated admin doc instead of
    /// importing the owner's per-member self-doc namespace (which the data plane
    /// black-holed on whenever that fragile per-namespace sync gapped). `None` =
    /// legacy member that hasn't announced one yet (falls back to the owner's
    /// self-doc, then the shared `vpn/` table).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vpn_endpoint: Option<String>,
    /// The peer's admin-allocated **4via6 site id** (overlapping-subnet routing,
    /// Tier 3a). Like `vip`, the admin claims it once at admission and records it
    /// here (admin-owned ⇒ the authoritative site→gateway mapping readers trust).
    /// A device on this peer's LAN at real IPv4 `d` is reached warren-wide via the
    /// IPv6 `via6(site_id, d)`; the decode resolves `site_id` → this gateway. Static
    /// (no admin-online coupling). `None` = legacy member (falls back to the shared
    /// `siteid/` table, then a deterministic self-claim).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub site_id: Option<u32>,
    /// Sandbox restrictions for this peer (default: unrestricted).
    #[serde(default, skip_serializing_if = "sandbox_is_unrestricted")]
    pub sandbox: crate::sandbox::SandboxPolicy,
}

/// Authorized peers store.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PeersStore {
    pub peers: Vec<Peer>,
}

impl PeersStore {
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("peers.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            Ok(serde_json::from_str(&data)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, config_dir: &Path) -> Result<()> {
        let path = config_dir.join("peers.json");
        let data = serde_json::to_string_pretty(self)?;
        write_shared_file(&path, &data)?;
        Ok(())
    }

    pub fn is_authorized(&self, node_id: &PublicKey) -> bool {
        let id_str = node_id.to_string();
        self.peers.iter().any(|p| p.node_id == id_str)
    }

    pub fn add_peer(&mut self, node_id: &PublicKey, name: String, username: Option<String>, role: PeerRole, sandbox: crate::sandbox::SandboxPolicy) {
        let id_str = node_id.to_string();
        if !self.peers.iter().any(|p| p.node_id == id_str) {
            self.peers.push(Peer {
                node_id: id_str,
                name,
                authorized_at: chrono_now(),
                // Date the member from admission (G25): invite-redeem doesn't open a
                // fresh control-plane connection, so without this a just-joined
                // member would have NO `last_seen` — it would never count as online
                // and could never be pruned (prune skips undated members). Seeding
                // it to "now" makes liveness + pruning work from join.
                last_seen: Some(chrono_now()),
                username,
                role,
                role_name: None,
                netdoc_author: None,
                self_doc: None,
                vip: None,
                vpn_endpoint: None,
                site_id: None,
                sandbox,
            });
        }
    }

    /// Look up the role of a peer by NodeId.
    pub fn peer_role(&self, node_id: &PublicKey) -> PeerRole {
        let id_str = node_id.to_string();
        self.peers
            .iter()
            .find(|p| p.node_id == id_str)
            .map(|p| p.role.clone())
            .unwrap_or_default()
    }

    /// Look up the sandbox policy for a peer.
    pub fn peer_sandbox(&self, node_id: &PublicKey) -> crate::sandbox::SandboxPolicy {
        let id_str = node_id.to_string();
        self.peers
            .iter()
            .find(|p| p.node_id == id_str)
            .map(|p| p.sandbox.clone())
            .unwrap_or_default()
    }

    /// Look up the Unix username bound to a peer (if any).
    pub fn peer_username(&self, node_id: &PublicKey) -> Option<&str> {
        let id_str = node_id.to_string();
        self.peers
            .iter()
            .find(|p| p.node_id == id_str)
            .and_then(|p| p.username.as_deref())
    }

    pub fn remove_peer(&mut self, node_id_prefix: &str) -> bool {
        let before = self.peers.len();
        self.peers
            .retain(|p| !p.node_id.starts_with(node_id_prefix));
        self.peers.len() < before
    }

    pub fn rename_peer(&mut self, id_prefix: &str, new_name: String) -> bool {
        if let Some(peer) = self.peers.iter_mut().find(|p| p.node_id.starts_with(id_prefix)) {
            peer.name = new_name;
            true
        } else {
            false
        }
    }

    pub fn update_last_seen(&mut self, node_id: &PublicKey) {
        let id_str = node_id.to_string();
        if let Some(peer) = self.peers.iter_mut().find(|p| p.node_id == id_str) {
            peer.last_seen = Some(chrono_now());
        }
    }
}

/// A known host entry (client side).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KnownHost {
    pub node_id: String,
    pub name: String,
    pub added_at: String,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub relay_url: Option<String>,
    /// Fleet groups this host belongs to (e.g., role names from aggregate invites).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
}

/// Known hosts store.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct KnownHostsStore {
    pub hosts: Vec<KnownHost>,
}

impl KnownHostsStore {
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("known_hosts.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            Ok(serde_json::from_str(&data)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, config_dir: &Path) -> Result<()> {
        let path = config_dir.join("known_hosts.json");
        let data = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, &data)?;
        Ok(())
    }

    pub fn add_host(&mut self, node_id: &PublicKey, name: String, relay_url: Option<String>) {
        let id_str = node_id.to_string();
        if !self.hosts.iter().any(|h| h.node_id == id_str) {
            self.hosts.push(KnownHost {
                node_id: id_str,
                name,
                added_at: chrono_now(),
                relay_url,
                groups: Vec::new(),
            });
        }
    }

    /// Add or update a host with deduplication: if the desired name is already
    /// taken by a *different* node_id, auto-suffix with `-2`, `-3`, etc.
    /// Updates the name if the node_id already exists. Returns the actual name used.
    pub fn add_host_dedup(&mut self, node_id: &PublicKey, desired_name: String, relay_url: Option<String>) -> String {
        let id_str = node_id.to_string();

        // Find a unique name (exclude this node_id from collision check)
        let mut candidate = desired_name.clone();
        let mut suffix = 2u32;
        while self.hosts.iter().any(|h| h.name == candidate && h.node_id != id_str) {
            candidate = format!("{desired_name}-{suffix}");
            suffix += 1;
        }

        // Update existing or insert new
        if let Some(existing) = self.hosts.iter_mut().find(|h| h.node_id == id_str) {
            existing.name = candidate.clone();
            existing.relay_url = relay_url;
        } else {
            self.hosts.push(KnownHost {
                node_id: id_str,
                name: candidate.clone(),
                added_at: chrono_now(),
                relay_url,
                groups: Vec::new(),
            });
        }

        candidate
    }

    pub fn rename_host(&mut self, id_or_name: &str, new_name: String) -> bool {
        if let Some(host) = self.hosts.iter_mut().find(|h| {
            h.node_id.starts_with(id_or_name) || h.name == id_or_name
        }) {
            host.name = new_name;
            true
        } else {
            false
        }
    }

    /// Update the cached relay URL for a known host identified by node_id.
    pub fn update_relay_url(&mut self, node_id: &str, relay_url: Option<String>) {
        if let Some(host) = self.hosts.iter_mut().find(|h| h.node_id == node_id) {
            host.relay_url = relay_url;
        }
    }

    /// Resolve an alias (host name) to its node_id. Returns `None` if not found.
    pub fn resolve_alias(&self, name: &str) -> Option<&str> {
        self.hosts
            .iter()
            .find(|h| h.name == name)
            .map(|h| h.node_id.as_str())
    }
}

/// Host-side configuration (persisted as `host_config.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostConfig {
    /// How long (in seconds) to keep a detached PTY session alive.
    /// Default: 86400 (24 hours).
    #[serde(default = "default_session_timeout")]
    pub session_timeout_secs: u64,

    /// Maximum number of detached PTY sessions to keep alive.
    /// When the limit is reached, the oldest detached session is evicted.
    /// Default: 10.
    #[serde(default = "default_max_sessions")]
    pub max_sessions: usize,

    /// Named role assigned to invites that don't specify one. Defaults to
    /// `member` — warren-mesh reach (`*`), but no host sessions. Re-point per
    /// deployment (e.g. a tag-scoped role) to restrict reach.
    #[serde(default = "default_role_name")]
    pub default_role: String,

    /// Tags for this host (e.g. `["production", "web"]`). Drive role→tag VPN
    /// reach (a role reaching tag `production` can reach hosts tagged so) and
    /// MagicDNS. Empty = untagged.
    #[serde(default)]
    pub tags: Vec<String>,
    /// Relay attention events (a detached session rang the bell) to attached
    /// clients so they can raise a desktop notification. `hop config set notify
    /// off` silences them; takes effect for sessions started afterwards.
    #[serde(default = "default_true")]
    pub notify: bool,
    /// Whether the warren VPN data plane is enabled. **On by default for a NEW
    /// host** (`HostConfig::default()`) — a fresh `hop host` / `--host` install
    /// brings up the warren VPN so a member can reach peers by name without an
    /// extra step. Opt out with `--host --no-vpn` or `hop config set vpn off`.
    ///
    /// Backward-compat: a config FILE that predates this field deserializes to
    /// `false` (`vpn_default_for_existing_config`), so upgrading an existing host
    /// never silently brings up the VPN — only brand-new configs default on.
    ///
    /// Safe to default on because the C1 warren write-capability trust gap is now
    /// closed by anchor-conditional author-validation enforce (a founder-anchored
    /// warren rejects forged `vpn/ip/name` bindings; see `netdoc::ValidationMode`),
    /// which is what the old off-by-default posture was the interim mitigation for
    /// (`docs/technical/security-audit.md`, C1). When enabled, bringup is
    /// best-effort (skips on a `100.64.0.0/10` conflict or TUN failure; core access
    /// is unaffected). `HOP_VPN=1` forces on (past the conflict guard); `HOP_VPN=0`
    /// forces off.
    #[serde(default = "vpn_default_for_existing_config")]
    pub vpn_enabled: bool,

    /// Verbosity of the per-node audit & flow log (`hop audit`). Default
    /// `connections` — records auth/membership/config/reach-denials **and**
    /// accepted connections, sessions, exec, and transfers, but not per-node flow
    /// summaries (raise to `flows` for those, or `security` for denials only, or
    /// `off`). `HOP_AUDIT_LEVEL` overrides at runtime.
    #[serde(default = "default_audit_level")]
    pub audit_level: crate::audit::AuditLevel,

    /// "Locked" session access (G23 capability scoping): when `true`, a peer may
    /// only open exec/shell/transfer/search sessions on this host if its role
    /// **explicitly** grants the matching tag (`exec_tags`/`search_tags`) — an
    /// unscoped role is denied. When `false` (**default**), an unscoped non-
    /// `network_only` role keeps open access (a small team just works). Admin roles
    /// are never locked out. This is the owner's "lock down this host" switch — e.g.
    /// flip it on for a personal laptop so peers can't search/exec it.
    #[serde(default)]
    pub require_explicit_access: bool,

    /// Auto-evict TTL (G25 roster hygiene): when set, the daemon periodically
    /// **prunes** (writes a replicated revocation for) any warren member not seen
    /// for this many seconds — the automated form of `hop fleet prune`. `None`
    /// (**default**) leaves pruning manual. Only the warren admin/founder's daemon
    /// acts on this (a non-anchor node's revocations don't validate). Never evicts
    /// this node or a member with no recorded `last_seen` (a fresh, never-contacted
    /// invite). Set e.g. to 30 days to keep the roster self-cleaning.
    #[serde(default)]
    pub prune_after_secs: Option<u64>,
}

fn default_audit_level() -> crate::audit::AuditLevel {
    crate::audit::AuditLevel::Connections
}

fn default_role_name() -> String {
    "member".to_string()
}

/// New-host default (used by `HostConfig::default()`): VPN on.
fn default_vpn_enabled() -> bool {
    true
}

/// Serde default for a config file MISSING `vpn_enabled` (predates the field):
/// off, so upgrading an existing host never silently enables the VPN.
fn vpn_default_for_existing_config() -> bool {
    false
}

fn default_true() -> bool {
    true
}

fn default_session_timeout() -> u64 {
    86400
}

fn default_max_sessions() -> usize {
    10
}

impl Default for HostConfig {
    fn default() -> Self {
        Self {
            session_timeout_secs: default_session_timeout(),
            max_sessions: default_max_sessions(),
            default_role: default_role_name(),
            tags: Vec::new(),
            notify: true,
            vpn_enabled: default_vpn_enabled(),
            audit_level: default_audit_level(),
            require_explicit_access: false,
            prune_after_secs: None,
        }
    }
}

impl HostConfig {
    /// Load config from `host_config.json` in the given directory.
    /// Returns defaults if the file doesn't exist.
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("host_config.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)
                .with_context(|| format!("Failed to read {}", path.display()))?;
            Ok(serde_json::from_str(&data)
                .with_context(|| format!("Failed to parse {}", path.display()))?)
        } else {
            Ok(Self::default())
        }
    }

    /// Save config to `host_config.json`.
    pub fn save(&self, config_dir: &Path) -> Result<()> {
        let path = config_dir.join("host_config.json");
        let data = serde_json::to_string_pretty(self)?;
        write_shared_file(&path, &data)?;
        Ok(())
    }
}

fn sandbox_is_unrestricted(policy: &crate::sandbox::SandboxPolicy) -> bool {
    !policy.is_restricted()
}

fn chrono_now() -> String {
    // Simple ISO 8601 timestamp without pulling in the chrono crate
    use std::time::SystemTime;
    let duration = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default();
    let secs = duration.as_secs();
    // Format as seconds since epoch — good enough for ordering
    // In a real app you'd use chrono, but we avoid the extra dep
    format!("{secs}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn peer_role_defaults_to_peer() {
        assert_eq!(PeerRole::default(), PeerRole::Peer);
    }

    #[test]
    fn resolve_host_config_dir_honors_override() {
        // An explicit --config always wins (this is how the daemon is invoked).
        let dir = tempfile::tempdir().unwrap();
        let resolved = resolve_host_config_dir(Some(dir.path())).unwrap();
        assert_eq!(resolved, dir.path());
    }

    #[test]
    fn ensure_host_config_dir_creates_missing_override() {
        // Host-side write commands (warren join, host) need the dir to exist.
        let base = tempfile::tempdir().unwrap();
        let target = base.path().join("nested").join("hop");
        assert!(!target.exists());
        let resolved = ensure_host_config_dir(Some(&target)).unwrap();
        assert_eq!(resolved, target);
        assert!(target.is_dir());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&target).unwrap().permissions().mode();
            assert_eq!(mode & 0o777, 0o700, "freshly created host dir is owner-only");
        }
    }

    #[test]
    fn ensure_host_config_dir_preserves_existing_perms() {
        // An existing daemon dir (e.g. root-owned, setgid 2770) must not be
        // re-permissioned out from under the daemon.
        let dir = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o2770)).unwrap();
        }
        let resolved = ensure_host_config_dir(Some(dir.path())).unwrap();
        assert_eq!(resolved, dir.path());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(dir.path()).unwrap().permissions().mode();
            assert_eq!(mode & 0o7777, 0o2770, "existing perms (incl. setgid) untouched");
        }
    }

    #[test]
    fn host_config_vpn_default_on() {
        // On by default for a NEW host: a fresh config brings up the warren VPN so
        // a member reaches peers by name without an extra step. (Safe now that C1
        // author-validation enforce closes the write-trust gap; see netdoc.)
        assert!(HostConfig::default().vpn_enabled);
    }

    #[test]
    fn host_config_backward_compat_vpn_off_for_existing_config() {
        // A config FILE predating `vpn_enabled` deserializes to OFF, so upgrading an
        // existing host never silently brings up the VPN — only brand-new configs
        // (HostConfig::default) default on.
        let json = r#"{ "session_timeout_secs": 3600, "max_sessions": 5 }"#;
        let cfg: HostConfig = serde_json::from_str(json).unwrap();
        assert!(!cfg.vpn_enabled, "missing field on an existing config must stay off");
        assert_eq!(cfg.default_role, "member");
    }

    #[test]
    fn host_config_vpn_opt_out_honored() {
        let json = r#"{ "vpn_enabled": false }"#;
        let cfg: HostConfig = serde_json::from_str(json).unwrap();
        assert!(!cfg.vpn_enabled);
    }

    #[test]
    fn peer_role_serialization_roundtrip() {
        let creator = PeerRole::Creator;
        let json = serde_json::to_string(&creator).unwrap();
        assert_eq!(json, r#""creator""#);

        let peer = PeerRole::Peer;
        let json = serde_json::to_string(&peer).unwrap();
        assert_eq!(json, r#""peer""#);

        let parsed: PeerRole = serde_json::from_str(r#""creator""#).unwrap();
        assert_eq!(parsed, PeerRole::Creator);
    }

    #[test]
    fn peers_json_backward_compat_without_role() {
        // Old peers.json entries have no "role" field — should default to Peer
        let json = r#"{
            "peers": [
                {
                    "node_id": "abc123",
                    "name": "old-peer",
                    "authorized_at": "1700000000"
                }
            ]
        }"#;
        let store: PeersStore = serde_json::from_str(json).unwrap();
        assert_eq!(store.peers.len(), 1);
        assert_eq!(store.peers[0].role, PeerRole::Peer);
        assert_eq!(store.peers[0].username, None);
    }

    #[test]
    fn peers_json_with_creator_role() {
        let json = r#"{
            "peers": [
                {
                    "node_id": "abc123",
                    "name": "admin",
                    "authorized_at": "1700000000",
                    "role": "creator"
                }
            ]
        }"#;
        let store: PeersStore = serde_json::from_str(json).unwrap();
        assert_eq!(store.peers[0].role, PeerRole::Creator);
    }

    #[test]
    fn add_peer_with_role() {
        let mut store = PeersStore::default();
        let key_bytes = [1u8; 32];
        let key = iroh::SecretKey::from_bytes(&key_bytes);
        let public = key.public();

        store.add_peer(&public, "admin".into(), None, PeerRole::Creator, crate::sandbox::SandboxPolicy::default());
        assert_eq!(store.peers.len(), 1);
        assert_eq!(store.peers[0].role, PeerRole::Creator);
        assert_eq!(store.peer_role(&public), PeerRole::Creator);

        // Duplicate add is ignored
        store.add_peer(&public, "admin2".into(), None, PeerRole::Peer, crate::sandbox::SandboxPolicy::default());
        assert_eq!(store.peers.len(), 1);
        assert_eq!(store.peers[0].name, "admin");
    }

    #[test]
    fn peer_role_lookup_default_for_unknown() {
        let store = PeersStore::default();
        let key_bytes = [2u8; 32];
        let key = iroh::SecretKey::from_bytes(&key_bytes);
        let public = key.public();
        assert_eq!(store.peer_role(&public), PeerRole::Peer);
    }

    #[test]
    fn known_hosts_backward_compat_without_groups() {
        let json = r#"{
            "hosts": [
                {
                    "node_id": "abc123",
                    "name": "myhost",
                    "added_at": "1700000000"
                }
            ]
        }"#;
        let store: KnownHostsStore = serde_json::from_str(json).unwrap();
        assert_eq!(store.hosts.len(), 1);
        assert!(store.hosts[0].groups.is_empty());
    }

    #[test]
    fn known_hosts_with_groups() {
        let json = r#"{
            "hosts": [
                {
                    "node_id": "abc123",
                    "name": "myhost",
                    "added_at": "1700000000",
                    "groups": ["developer", "staging"]
                }
            ]
        }"#;
        let store: KnownHostsStore = serde_json::from_str(json).unwrap();
        assert_eq!(store.hosts[0].groups, vec!["developer", "staging"]);
    }

    #[test]
    fn known_hosts_groups_not_serialized_when_empty() {
        let host = KnownHost {
            node_id: "abc".into(),
            name: "test".into(),
            added_at: "0".into(),
            relay_url: None,
            groups: Vec::new(),
        };
        let json = serde_json::to_string(&host).unwrap();
        assert!(!json.contains("groups"));
    }

    #[test]
    fn peers_store_load_save_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = PeersStore::default();
        let key = iroh::SecretKey::from_bytes(&[3u8; 32]);
        let public = key.public();
        store.add_peer(&public, "test-peer".into(), Some("alice".into()), PeerRole::Creator, crate::sandbox::SandboxPolicy::default());
        store.save(dir.path()).unwrap();

        let loaded = PeersStore::load(dir.path()).unwrap();
        assert_eq!(loaded.peers.len(), 1);
        assert_eq!(loaded.peers[0].role, PeerRole::Creator);
        assert_eq!(loaded.peers[0].username.as_deref(), Some("alice"));
    }

    #[test]
    fn known_hosts_store_load_save_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let mut store = KnownHostsStore::default();
        let key = iroh::SecretKey::from_bytes(&[4u8; 32]);
        let public = key.public();
        store.add_host(&public, "myhost".into(), Some("https://relay.example.com".into()));
        store.save(dir.path()).unwrap();

        let loaded = KnownHostsStore::load(dir.path()).unwrap();
        assert_eq!(loaded.hosts.len(), 1);
        assert_eq!(loaded.hosts[0].name, "myhost");
        assert!(loaded.hosts[0].groups.is_empty());
    }
}
