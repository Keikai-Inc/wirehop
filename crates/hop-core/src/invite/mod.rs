//! Invite token generation and verification.

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use iroh::PublicKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;

/// The invite token payload, encoded as base64url JSON.
#[derive(Debug, Serialize, Deserialize)]
pub struct InviteToken {
    /// Host's NodeId (hex-encoded PublicKey).
    pub node_id: String,
    /// 32-byte random secret, hex-encoded.
    pub secret: String,
    /// Relay URL for the host (enables direct relay connection without DNS lookup).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_url: Option<String>,
    /// Unix username the invited peer will log in as on the host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

/// A pending invite stored on the host side.
#[derive(Debug, Serialize, Deserialize)]
pub struct PendingInvite {
    /// Argon2 hash of the secret.
    pub secret_hash: String,
    /// Unix timestamp when the invite was created.
    pub created_at: u64,
    /// Unix username the invited peer will log in as.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct PendingInvitesStore {
    pub invites: Vec<PendingInvite>,
}

impl PendingInvitesStore {
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("pending_invites.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            Ok(serde_json::from_str(&data)?)
        } else {
            Ok(Self::default())
        }
    }

    pub fn save(&self, config_dir: &Path) -> Result<()> {
        let path = config_dir.join("pending_invites.json");
        let data = serde_json::to_string_pretty(self)?;
        crate::config::write_shared_file(&path, &data)?;
        Ok(())
    }

    /// Remove expired invites (older than `max_age_secs`).
    pub fn prune_expired(&mut self, max_age_secs: u64) {
        let now = unix_now();
        self.invites
            .retain(|inv| now.saturating_sub(inv.created_at) < max_age_secs);
    }

    /// Try to consume an invite by verifying the client's secret against stored hashes.
    /// Returns `Some(username)` if the invite was valid and has been consumed (removed),
    /// where the inner `Option<String>` is the bound Unix username (if any).
    /// Returns `None` if no matching invite was found.
    ///
    /// The client sends the raw hex-encoded secret. We hash it with Argon2 and
    /// compare against the stored hash (the plaintext secret is never persisted).
    pub fn try_consume(&mut self, client_secret: &[u8]) -> Option<Option<String>> {
        let client_secret_str = match std::str::from_utf8(client_secret) {
            Ok(s) => s,
            Err(_) => return None,
        };

        let argon2 = Argon2::default();

        let idx = self.invites.iter().position(|inv| {
            if let Ok(stored_hash) = PasswordHash::new(&inv.secret_hash) {
                argon2.verify_password(client_secret_str.as_bytes(), &stored_hash).is_ok()
            } else {
                false
            }
        });

        if let Some(idx) = idx {
            let invite = self.invites.remove(idx);
            Some(invite.username)
        } else {
            None
        }
    }
}

/// Generate a new invite: returns the token string to share and stores the hash on disk.
pub fn generate_invite(
    host_public_key: &PublicKey,
    config_dir: &Path,
    relay_url: Option<&str>,
    username: Option<&str>,
) -> Result<String> {
    // Validate the username early so bad values never reach storage
    #[cfg(unix)]
    if let Some(name) = username {
        crate::unix_user::validate_username(name)?;
    }

    // Generate 32 bytes of random secret
    let mut secret_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut secret_bytes);
    let secret_hex = hex::encode(secret_bytes);

    // Hash the secret with Argon2 for storage
    // Generate salt manually to avoid rand_core version mismatch with argon2
    let mut salt_bytes = [0u8; 16];
    rand::rng().fill_bytes(&mut salt_bytes);
    let salt_b64 = base64::engine::general_purpose::STANDARD_NO_PAD.encode(salt_bytes);
    let salt = argon2::password_hash::SaltString::from_b64(&salt_b64)
        .map_err(|e| anyhow::anyhow!("Failed to create salt: {e}"))?;
    let argon2 = Argon2::default();
    let secret_hash = argon2
        .hash_password(secret_hex.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("Failed to hash invite secret: {e}"))?
        .to_string();

    // Store the pending invite
    let mut store = PendingInvitesStore::load(config_dir)?;
    store.prune_expired(15 * 60); // 15 minute expiry
    store.invites.push(PendingInvite {
        secret_hash,
        created_at: unix_now(),
        username: username.map(String::from),
    });
    store.save(config_dir)?;

    // Build the token
    let token = InviteToken {
        node_id: host_public_key.to_string(),
        secret: secret_hex,
        relay_url: relay_url.map(String::from),
        username: username.map(String::from),
    };
    let json = serde_json::to_string(&token)?;
    let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());

    Ok(encoded)
}

/// Decode an invite token string back into its parts.
pub fn decode_invite(token: &str) -> Result<InviteToken> {
    let json_bytes = URL_SAFE_NO_PAD
        .decode(token)
        .context("Invalid invite token encoding")?;
    let invite: InviteToken =
        serde_json::from_slice(&json_bytes).context("Invalid invite token format")?;
    Ok(invite)
}

/// Check if a string looks like an invite token (base64url) vs a NodeId (hex).
pub fn is_invite_token(target: &str) -> bool {
    // NodeIds are 64-char hex strings. Invite tokens are base64url and longer.
    if target.len() == 64 && target.chars().all(|c| c.is_ascii_hexdigit()) {
        return false;
    }
    // Try to decode as invite token
    decode_invite(target).is_ok()
}

fn unix_now() -> u64 {
    use std::time::SystemTime;
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}
