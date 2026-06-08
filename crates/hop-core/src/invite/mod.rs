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
    /// Auth tier assigned to the invited peer (default: Peer).
    #[serde(default, skip_serializing_if = "is_default_peer_role")]
    pub role: PeerRole,
    /// Named role assigned to the invited peer (resolves to a `RoleDefinition`).
    /// `None` → the host's configured default role.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_name: Option<String>,
    /// Sandbox restrictions for this invite (default: unrestricted).
    #[serde(default, skip_serializing_if = "sandbox_is_unrestricted")]
    pub sandbox: SandboxPolicy,
    /// The warren's namespace ticket (iroh-docs `DocTicket`), so redeeming this
    /// invite can put the machine on the warren VPN as a node. `None` for hosts
    /// that have no warren yet (degrades to direct-session access only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warren_ticket: Option<String>,
    /// Explicit capability tier (see `docs/technical/install-and-invite-tiers.md`).
    /// Decides whether redeeming this invite stays a client or self-upgrades to a
    /// warren node, and (once the C1 read/write split lands) the ticket scope.
    /// Old invites have no `tier`; `tier()` infers one for them.
    #[serde(default, skip_serializing_if = "InviteTier::is_default")]
    pub tier: InviteTier,
}

/// Capability tier carried by an invite. Orthogonal axes — session reach,
/// warren membership, admin — collapsed into the four useful combinations.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InviteTier {
    /// Reach the inviting host(s); no warren node, no daemon, no sudo.
    #[default]
    Client,
    /// On the warren VPN (vIP/MagicDNS/L3 reach), but cannot open host sessions.
    WarrenOnly,
    /// On the warren AND reachable/hostable; not an admin.
    Node,
    /// Node + warren write + mint/grant.
    Admin,
}

impl InviteTier {
    fn is_default(&self) -> bool {
        *self == InviteTier::Client
    }

    /// Whether redeeming this tier makes the machine a warren node (needs the
    /// daemon → the self-upgrade / sudo path). `Client` does not.
    pub fn is_warren_node(&self) -> bool {
        !matches!(self, InviteTier::Client)
    }
}

impl InviteToken {
    /// The effective tier, inferring one for legacy invites that predate the
    /// explicit `tier` field: a warren ticket + Creator role → `Admin`; a warren
    /// ticket alone → `Node`; otherwise `Client`. New invites carry `tier`
    /// directly, so this just returns it.
    pub fn effective_tier(&self) -> InviteTier {
        if self.tier != InviteTier::Client {
            return self.tier;
        }
        match (&self.warren_ticket, &self.role) {
            (Some(_), PeerRole::Creator) => InviteTier::Admin,
            (Some(_), _) => InviteTier::Node,
            (None, _) => InviteTier::Client,
        }
    }
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
    /// Auth tier assigned to the invited peer (default: Peer).
    #[serde(default)]
    pub role: PeerRole,
    /// Named role assigned to the invited peer (`None` → host default role).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub role_name: Option<String>,
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
                role_name: invite.role_name,
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
    pub role_name: Option<String>,
    pub sandbox: SandboxPolicy,
}

/// Get the system hostname.
pub fn system_hostname() -> Option<String> {
    hostname::get().ok().and_then(|h| h.into_string().ok())
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
        None,
        15 * 60,
        SandboxPolicy::default(),
    )
}

/// Generate a new invite with a specific role and configurable expiry.
///
/// Creator invites typically use a 1-hour expiry; regular invites use 15 minutes.
#[allow(clippy::too_many_arguments)]
pub fn generate_invite_with_role(
    host_public_key: &PublicKey,
    config_dir: &Path,
    relay_url: Option<&str>,
    username: Option<&str>,
    host_name: Option<&str>,
    role: PeerRole,
    role_name: Option<String>,
    expiry_secs: u64,
    sandbox: SandboxPolicy,
) -> Result<String> {
    // Validate the username early so bad values never reach storage.
    // Skip validation for Creator role (maps to root).
    #[cfg(unix)]
    if role != PeerRole::Creator
        && let Some(name) = username
    {
        crate::unix_user::validate_username(name)?;
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
        role_name: role_name.clone(),
        sandbox: sandbox.clone(),
    });
    store.save(config_dir)?;

    // Build the token
    let resolved_host_name = host_name
        .map(String::from)
        .or_else(system_hostname);
    // Embed the warren's namespace ticket (if this host has a warren) so the
    // invite doubles as the warren join token. The daemon writes it to
    // <config>/netdoc.ticket on startup; absent → direct-session access only.
    let warren_ticket = std::fs::read_to_string(config_dir.join("netdoc.ticket"))
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());
    let token = InviteToken {
        node_id: host_public_key.to_string(),
        secret: secret_hex,
        relay_url: relay_url.map(String::from),
        username: username.map(String::from),
        host_name: resolved_host_name,
        role,
        role_name: role_name.clone(),
        sandbox,
        warren_ticket,
        // Explicit tiers aren't emitted yet (pending the C1 read/write split);
        // `effective_tier()` infers from warren_ticket+role for now.
        tier: InviteTier::default(),
    };
    let json = serde_json::to_string(&token)?;
    let encoded = URL_SAFE_NO_PAD.encode(json.as_bytes());

    Ok(encoded)
}

/// Encode an `InviteToken` back into its base64url-JSON string form.
pub fn encode_invite(token: &InviteToken) -> Result<String> {
    let json = serde_json::to_string(token)?;
    Ok(URL_SAFE_NO_PAD.encode(json.as_bytes()))
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
            role_name: None,
            sandbox: SandboxPolicy::default(),
            warren_ticket: None,
            tier: InviteTier::default(),
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
            role_name: None,
            sandbox: SandboxPolicy::default(),
            warren_ticket: None,
            tier: InviteTier::default(),
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
    fn effective_tier_infers_from_legacy_fields() {
        let mut t = InviteToken {
            node_id: "abc".into(),
            secret: "def".into(),
            relay_url: None,
            username: None,
            host_name: None,
            role: PeerRole::Peer,
            role_name: None,
            sandbox: SandboxPolicy::default(),
            warren_ticket: None,
            tier: InviteTier::default(),
        };
        // No warren ticket → Client.
        assert_eq!(t.effective_tier(), InviteTier::Client);
        // Warren ticket + Peer → Node.
        t.warren_ticket = Some("blob".into());
        assert_eq!(t.effective_tier(), InviteTier::Node);
        // Warren ticket + Creator → Admin.
        t.role = PeerRole::Creator;
        assert_eq!(t.effective_tier(), InviteTier::Admin);
        // An explicit tier wins over inference.
        t.tier = InviteTier::WarrenOnly;
        assert_eq!(t.effective_tier(), InviteTier::WarrenOnly);
    }

    #[test]
    fn invite_token_warren_ticket_roundtrips() {
        let token = InviteToken {
            node_id: "abc".into(),
            secret: "def".into(),
            relay_url: None,
            username: None,
            host_name: None,
            role: PeerRole::Peer,
            role_name: None,
            sandbox: SandboxPolicy::default(),
            warren_ticket: Some("docticketblob".into()),
            tier: InviteTier::default(),
        };
        let json = serde_json::to_string(&token).unwrap();
        let back: InviteToken = serde_json::from_str(&json).unwrap();
        assert_eq!(back.warren_ticket.as_deref(), Some("docticketblob"));
    }

    #[test]
    fn invite_token_backward_compat_without_warren_fields() {
        // Old invites predate warren_ticket — must still decode, degrading to
        // direct-session access (no node join).
        let json = r#"{"node_id":"abc","secret":"def"}"#;
        let token: InviteToken = serde_json::from_str(json).unwrap();
        assert!(token.warren_ticket.is_none());
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
            None,
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
            None,
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
                    role_name: None,
                    sandbox: SandboxPolicy::default(),
                },
                PendingInvite {
                    secret_hash: "new".into(),
                    created_at: unix_now(),
                    username: None,
                    role: PeerRole::Creator,
                    role_name: None,
                    sandbox: SandboxPolicy::default(),
                },
            ],
        };
        store.prune_expired(60); // 60-second expiry
        assert_eq!(store.invites.len(), 1);
        assert_eq!(store.invites[0].role, PeerRole::Creator);
    }
}
