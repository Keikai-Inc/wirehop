use anyhow::{Context, Result};
use directories::ProjectDirs;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Returns the default config directory (~/.config/hop on Linux/macOS).
pub fn default_config_dir() -> Result<PathBuf> {
    let dirs = ProjectDirs::from("", "", "hop").context("Could not determine config directory")?;
    Ok(dirs.config_dir().to_path_buf())
}

/// Ensures the config directory exists and returns its path.
pub fn ensure_config_dir(override_path: Option<&Path>) -> Result<PathBuf> {
    let dir = match override_path {
        Some(p) => p.to_path_buf(),
        None => default_config_dir()?,
    };
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create config dir: {}", dir.display()))?;
    Ok(dir)
}

/// Persistent node identity.
#[derive(Debug, Serialize, Deserialize)]
pub struct Identity {
    /// Base64-encoded Ed25519 secret key.
    pub secret_key: String,
    /// Base64-encoded public key (NodeId).
    pub node_id: String,
}

/// An authorized peer entry (host side).
#[derive(Debug, Serialize, Deserialize)]
pub struct Peer {
    pub node_id: String,
    pub name: String,
    pub authorized_at: String,
    pub last_seen: Option<String>,
}

/// Authorized peers store.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Peers {
    pub peers: Vec<Peer>,
}

/// A known host entry (client side).
#[derive(Debug, Serialize, Deserialize)]
pub struct Host {
    pub node_id: String,
    pub name: String,
    pub added_at: String,
}

/// Known hosts store.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct KnownHosts {
    pub hosts: Vec<Host>,
}
