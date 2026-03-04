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

    #[cfg(target_os = "macos")]
    {
        let system_dir = Path::new(SYSTEM_CONFIG_DIR);
        if system_dir.join("identity.json").exists() {
            return Ok(system_dir.to_path_buf());
        }
    }

    default_config_dir()
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

    pub fn add_peer(&mut self, node_id: &PublicKey, name: String, username: Option<String>) {
        let id_str = node_id.to_string();
        if !self.peers.iter().any(|p| p.node_id == id_str) {
            self.peers.push(Peer {
                node_id: id_str,
                name,
                authorized_at: chrono_now(),
                last_seen: None,
                username,
            });
        }
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
