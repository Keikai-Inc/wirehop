//! Invite token generation and verification.

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use iroh::PublicKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::config::PeerRole;
use crate::sandbox::SandboxPolicy;

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
    /// Human-readable name for the host (e.g. system hostname).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub host_name: Option<String>,
    /// Role assigned to the invited peer (default: Peer).
    #[serde(default, skip_serializing_if = "is_default_peer_role")]
    pub role: PeerRole,
    /// Sandbox restrictions for this invite (default: unrestricted).
    #[serde(default, skip_serializing_if = "sandbox_is_unrestricted")]
    pub sandbox: SandboxPolicy,
}

fn is_default_peer_role(role: &PeerRole) -> bool {
    *role == PeerRole::Peer
}

fn sandbox_is_unrestricted(policy: &SandboxPolicy) -> bool {
    !policy.is_restricted()
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
    /// Role assigned to the invited peer (default: Peer).
    #[serde(default)]
    pub role: PeerRole,
    /// Sandbox restrictions for this invite.
    #[serde(default)]
    pub sandbox: SandboxPolicy,
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

    /// Result of consuming an invite: username binding and role.
    pub fn try_consume(&mut self, client_secret: &[u8]) -> Option<ConsumedInvite> {
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
            Some(ConsumedInvite {
                username: invite.username,
                role: invite.role,
                sandbox: invite.sandbox,
            })
        } else {
            None
        }
    }
}

/// Result of consuming an invite.
pub struct ConsumedInvite {
    pub username: Option<String>,
    pub role: PeerRole,
    pub sandbox: SandboxPolicy,
}

/// Get the system hostname via libc.
#[cfg(unix)]
pub fn system_hostname() -> Option<String> {
    let mut buf = vec![0u8; 256];
    let ret = unsafe { libc::gethostname(buf.as_mut_ptr() as *mut libc::c_char, buf.len()) };
    if ret != 0 {
        return None;
    }
    let end = buf.iter().position(|&b| b == 0).unwrap_or(buf.len());
    String::from_utf8(buf[..end].to_vec()).ok()
}

#[cfg(not(unix))]
pub fn system_hostname() -> Option<String> {
    None
}

/// Generate a new invite: returns the token string to share and stores the hash on disk.
pub fn generate_invite(
    host_public_key: &PublicKey,
    config_dir: &Path,
    relay_url: Option<&str>,
    username: Option<&str>,
    host_name: Option<&str>,
) -> Result<String> {
    generate_invite_with_role(
        host_public_key,
        config_dir,
        relay_url,
        username,
        host_name,
        PeerRole::Peer,
        15 * 60,
        SandboxPolicy::default(),
    )
}

/// Generate a new invite with a specific role and configurable expiry.
///
/// Creator invites typically use a 1-hour expiry; regular invites use 15 minutes.
pub fn generate_invite_with_role(
    host_public_key: &PublicKey,
    config_dir: &Path,
    relay_url: Option<&str>,
    username: Option<&str>,
    host_name: Option<&str>,
    role: PeerRole,
    expiry_secs: u64,
    sandbox: SandboxPolicy,
) -> Result<String> {
    // Validate the username early so bad values never reach storage.
    // Skip validation for Creator role (maps to root).
    #[cfg(unix)]
    if role != PeerRole::Creator {
        if let Some(name) = username {
            crate::unix_user::validate_username(name)?;
        }
    }

    // Generate 32 bytes of random secret
    let mut secret_bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut secret_bytes);
    let secret_hex = hex::encode(secret_bytes);

    // Hash the secret with Argon2 for storage
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
    store.prune_expired(expiry_secs);
    store.invites.push(PendingInvite {
        secret_hash,
        created_at: unix_now(),
        username: username.map(String::from),
        role: role.clone(),
        sandbox: sandbox.clone(),
    });
    store.save(config_dir)?;

    // Build the token
    let resolved_host_name = host_name
        .map(String::from)
        .or_else(system_hostname);
    let token = InviteToken {
        node_id: host_public_key.to_string(),
        secret: secret_hex,
        relay_url: relay_url.map(String::from),
        username: username.map(String::from),
        host_name: resolved_host_name,
        role,
        sandbox,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invite_token_backward_compat_without_role() {
        // Old invite tokens have no "role" field — should default to Peer
        let json = r#"{"node_id":"abc123","secret":"deadbeef","relay_url":null,"username":"alice"}"#;
        let token: InviteToken = serde_json::from_str(json).unwrap();
        assert_eq!(token.role, PeerRole::Peer);
        assert_eq!(token.username.as_deref(), Some("alice"));
    }

    #[test]
    fn invite_token_with_creator_role() {
        let json = r#"{"node_id":"abc123","secret":"deadbeef","role":"creator"}"#;
        let token: InviteToken = serde_json::from_str(json).unwrap();
        assert_eq!(token.role, PeerRole::Creator);
    }

    #[test]
    fn invite_token_role_not_serialized_when_peer() {
        let token = InviteToken {
            node_id: "abc".into(),
            secret: "def".into(),
            relay_url: None,
            username: None,
            host_name: None,
            role: PeerRole::Peer,
            sandbox: SandboxPolicy::default(),
        };
        let json = serde_json::to_string(&token).unwrap();
        assert!(!json.contains("role"), "Peer role should not be serialized: {json}");
    }

    #[test]
    fn invite_token_role_serialized_when_creator() {
        let token = InviteToken {
            node_id: "abc".into(),
            secret: "def".into(),
            relay_url: None,
            username: None,
            host_name: None,
            role: PeerRole::Creator,
            sandbox: SandboxPolicy::default(),
        };
        let json = serde_json::to_string(&token).unwrap();
        assert!(json.contains(r#""role":"creator""#), "Creator role should be serialized: {json}");
    }

    #[test]
    fn pending_invite_backward_compat_without_role() {
        let json = r#"{"secret_hash":"$argon2id$...","created_at":1700000000}"#;
        let invite: PendingInvite = serde_json::from_str(json).unwrap();
        assert_eq!(invite.role, PeerRole::Peer);
    }

    #[test]
    fn generate_invite_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let key = iroh::SecretKey::from_bytes(&[5u8; 32]);
        let public = key.public();

        let token_str = generate_invite_with_role(
            &public,
            dir.path(),
            Some("https://relay.example.com"),
            None,
            Some("test-host"),
            PeerRole::Creator,
            3600,
            SandboxPolicy::default(),
        )
        .unwrap();

        let decoded = decode_invite(&token_str).unwrap();
        assert_eq!(decoded.node_id, public.to_string());
        assert_eq!(decoded.role, PeerRole::Creator);
        assert_eq!(decoded.host_name.as_deref(), Some("test-host"));
        assert_eq!(decoded.relay_url.as_deref(), Some("https://relay.example.com"));
        assert!(is_invite_token(&token_str));
    }

    #[test]
    fn generate_invite_default_is_peer() {
        let dir = tempfile::tempdir().unwrap();
        let key = iroh::SecretKey::from_bytes(&[6u8; 32]);
        let public = key.public();

        let token_str = generate_invite(&public, dir.path(), None, None, None).unwrap();
        let decoded = decode_invite(&token_str).unwrap();
        assert_eq!(decoded.role, PeerRole::Peer);
    }

    #[test]
    fn try_consume_returns_role() {
        let dir = tempfile::tempdir().unwrap();
        let key = iroh::SecretKey::from_bytes(&[7u8; 32]);
        let public = key.public();

        let token_str = generate_invite_with_role(
            &public,
            dir.path(),
            None,
            None,
            None,
            PeerRole::Creator,
            3600,
            SandboxPolicy::default(),
        )
        .unwrap();

        let decoded = decode_invite(&token_str).unwrap();
        let mut store = PendingInvitesStore::load(dir.path()).unwrap();
        let consumed = store.try_consume(decoded.secret.as_bytes()).unwrap();
        assert_eq!(consumed.role, PeerRole::Creator);
        assert_eq!(consumed.username, None);
    }

    #[test]
    fn try_consume_invalid_secret_returns_none() {
        let dir = tempfile::tempdir().unwrap();
        let key = iroh::SecretKey::from_bytes(&[8u8; 32]);
        let public = key.public();

        let _token = generate_invite(&public, dir.path(), None, None, None).unwrap();

        let mut store = PendingInvitesStore::load(dir.path()).unwrap();
        assert!(store.try_consume(b"wrong_secret").is_none());
    }

    #[test]
    fn try_consume_removes_invite() {
        let dir = tempfile::tempdir().unwrap();
        let key = iroh::SecretKey::from_bytes(&[9u8; 32]);
        let public = key.public();

        let token_str = generate_invite(&public, dir.path(), None, None, None).unwrap();
        let decoded = decode_invite(&token_str).unwrap();

        let mut store = PendingInvitesStore::load(dir.path()).unwrap();
        assert_eq!(store.invites.len(), 1);

        let consumed = store.try_consume(decoded.secret.as_bytes());
        assert!(consumed.is_some());
        assert_eq!(store.invites.len(), 0);

        // Second consume should fail
        let mut store2 = store;
        assert!(store2.try_consume(decoded.secret.as_bytes()).is_none());
    }

    #[test]
    fn prune_expired_removes_old_invites() {
        let mut store = PendingInvitesStore {
            invites: vec![
                PendingInvite {
                    secret_hash: "old".into(),
                    created_at: 1000,
                    username: None,
                    role: PeerRole::Peer,
                    sandbox: SandboxPolicy::default(),
                },
                PendingInvite {
                    secret_hash: "new".into(),
                    created_at: unix_now(),
                    username: None,
                    role: PeerRole::Creator,
                    sandbox: SandboxPolicy::default(),
                },
            ],
        };
        store.prune_expired(60); // 60-second expiry
        assert_eq!(store.invites.len(), 1);
        assert_eq!(store.invites[0].role, PeerRole::Creator);
    }
}
