//! Invite token generation and verification.

use anyhow::{Context, Result};
use argon2::{Argon2, PasswordHash, PasswordVerifier};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use iroh::PublicKey;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
    /// The warren's namespace ticket (iroh-docs `DocTicket`).
    /// Legacy (pre-hop/4) only: a token that carried this stayed a usable
    /// read (or, for a plain `hop invite`, write!) capability long after the
    /// secret was burned. Tickets are now delivered in `AuthResultV2` after
    /// the secret verified. Still decoded so old tokens keep working against
    /// old hosts; a new token never carries it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warren_ticket: Option<String>,
    /// Explicit capability tier (see `docs/technical/install-and-invite-tiers.md`).
    /// Decides whether redeeming this invite stays a client or self-upgrades to a
    /// warren node, and (once the C1 read/write split lands) the ticket scope.
    /// Old invites have no `tier`; `tier()` infers one for them.
    #[serde(default)]
    pub tier: InviteTier,
    /// The founder's iroh-docs author id (hex), pinned alongside `warren_ticket`.
    /// A joining node records this as the **trusted admin author** — the C1
    /// trust anchor used (in enforce mode) to validate admin-owned doc entries
    /// (`peer/ role/ revocation/ …`). `None` for non-warren invites.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub founder_author: Option<String>,
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

    /// Whether redeeming this tier makes the machine a warren node (needs the
    /// daemon → the self-upgrade / sudo path). `Client` does not.
    pub fn is_warren_node(&self) -> bool {
        !matches!(self, InviteTier::Client)
    }

    /// Stable lowercase name (matches the `--tier` flag values + the snake_case
    /// serde encoding).
    pub fn as_str(&self) -> &'static str {
        match self {
            InviteTier::Client => "client",
            InviteTier::WarrenOnly => "warren-only",
            InviteTier::Node => "node",
            InviteTier::Admin => "admin",
        }
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
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInvite {
    /// Hash of the secret: `sha256:<hex>` (hop/4+). Entries written by older
    /// binaries hold a `$argon2id$…` PHC string and are still verified until
    /// they expire. The secret is 256 bits of CSPRNG output, so a fast hash is
    /// the right tool; Argon2 only made every bogus attempt cost the host
    /// ~19 MiB and tens of milliseconds.
    pub secret_hash: String,
    /// Short id for `hop invite list` / `revoke`: the first 8 hex chars of
    /// sha256(secret). Empty for entries written by older binaries.
    #[serde(default)]
    pub id: String,
    /// Capability tier recorded at mint time. Decides what the host grants
    /// after the secret verifies (see [`grant_for_tier`]).
    #[serde(default)]
    pub tier: InviteTier,
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
    /// Max redemptions before the invite is removed. `None` = single-use (the
    /// default; back-compatible). `Some(n)` = reusable up to `n` times — one
    /// token N hosts redeem to join the warren (the warren-first "fleet invite").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_uses: Option<u32>,
    /// Redemptions so far (for a reusable invite).
    #[serde(default)]
    pub uses: u32,
    /// Per-invite lifetime in seconds. `0` = governed only by the caller's
    /// global prune age (legacy single-use behavior).
    #[serde(default)]
    pub expiry_secs: u64,
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

    /// Remove expired invites. An invite with its own `expiry_secs` is judged by
    /// that; legacy invites (`expiry_secs == 0`) fall back to `default_max_age`.
    pub fn prune_expired(&mut self, default_max_age: u64) {
        let now = unix_now();
        self.invites.retain(|inv| {
            let limit = if inv.expiry_secs > 0 { inv.expiry_secs } else { default_max_age };
            now.saturating_sub(inv.created_at) < limit
        });
    }

    /// Try to redeem an invite by its secret. Single-use invites are removed on
    /// redemption; reusable invites (`max_uses`) increment a counter and are
    /// removed once exhausted. A past-expiry invite is removed and not honored.
    pub fn try_consume(&mut self, client_secret: &[u8]) -> Option<ConsumedInvite> {
        let client_secret_str = match std::str::from_utf8(client_secret) {
            Ok(s) => s,
            Err(_) => return None,
        };

        // One SHA-256 per attempt, compared against every pending entry in
        // constant time. Legacy Argon2 entries are verified the slow way.
        let presented_sha = sha256_hex(client_secret_str.as_bytes());
        let idx = self
            .invites
            .iter()
            .position(|inv| secret_matches(&inv.secret_hash, client_secret_str, &presented_sha))?;

        // Reject (and drop) an expired invite before honoring it.
        let now = unix_now();
        let expiry = self.invites[idx].expiry_secs;
        if expiry > 0 && now.saturating_sub(self.invites[idx].created_at) >= expiry {
            self.invites.remove(idx);
            return None;
        }

        let inv = &mut self.invites[idx];
        let consumed = ConsumedInvite {
            id: inv.id.clone(),
            username: inv.username.clone(),
            role: inv.role.clone(),
            role_name: inv.role_name.clone(),
            sandbox: inv.sandbox.clone(),
            tier: inv.tier,
        };
        inv.uses += 1;
        // Single-use (max_uses None) is removed immediately; reusable is removed
        // once it reaches its cap.
        let exhausted = inv.max_uses.map(|max| inv.uses >= max).unwrap_or(true);
        if exhausted {
            self.invites.remove(idx);
        }
        Some(consumed)
    }
}

impl PendingInvitesStore {
    /// Pending invites as the operator sees them (`hop invite list`). Never
    /// includes the secret or its hash.
    pub fn list(&self, default_max_age: u64) -> Vec<PendingInviteInfo> {
        self.invites
            .iter()
            .map(|inv| {
                let limit = if inv.expiry_secs > 0 { inv.expiry_secs } else { default_max_age };
                PendingInviteInfo {
                    id: inv.id.clone(),
                    created_at: inv.created_at,
                    expires_at: inv.created_at.saturating_add(limit),
                    tier: inv.tier,
                    role_name: inv.role_name.clone(),
                    username: inv.username.clone(),
                    uses: inv.uses,
                    max_uses: inv.max_uses,
                }
            })
            .collect()
    }

    /// Revoke one pending invite by id or unambiguous id prefix. Returns the
    /// full id that was removed.
    pub fn revoke(&mut self, id_prefix: &str) -> Result<String> {
        anyhow::ensure!(!id_prefix.is_empty(), "invite id is empty");
        let matches: Vec<usize> = self
            .invites
            .iter()
            .enumerate()
            .filter(|(_, inv)| !inv.id.is_empty() && inv.id.starts_with(id_prefix))
            .map(|(i, _)| i)
            .collect();
        match matches.as_slice() {
            [] => anyhow::bail!("no pending invite matches '{id_prefix}' (see `hop invite list`)"),
            [i] => Ok(self.invites.remove(*i).id),
            _ => anyhow::bail!("'{id_prefix}' matches {} pending invites; give more characters", matches.len()),
        }
    }
}

/// One row of `hop invite list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PendingInviteInfo {
    pub id: String,
    pub created_at: u64,
    pub expires_at: u64,
    pub tier: InviteTier,
    pub role_name: Option<String>,
    pub username: Option<String>,
    pub uses: u32,
    pub max_uses: Option<u32>,
}

/// Result of consuming an invite.
pub struct ConsumedInvite {
    /// Short id of the pending entry (empty for entries written by older binaries).
    pub id: String,
    pub username: Option<String>,
    pub role: PeerRole,
    pub role_name: Option<String>,
    pub sandbox: SandboxPolicy,
    /// Tier recorded at mint time; decides the post-auth grant.
    pub tier: InviteTier,
}

const SHA256_PREFIX: &str = "sha256:";

fn sha256_hex(data: &[u8]) -> String {
    hex::encode(Sha256::digest(data))
}

/// Storage form of a secret: `sha256:<hex>`.
pub fn hash_secret(secret_hex: &str) -> String {
    format!("{SHA256_PREFIX}{}", sha256_hex(secret_hex.as_bytes()))
}

/// The short id an operator sees for an invite: first 8 hex chars of sha256(secret).
pub fn short_id_for_secret(secret_hex: &str) -> String {
    sha256_hex(secret_hex.as_bytes())[..8].to_string()
}

/// Constant-time equality for equal-length byte strings.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b) {
        diff |= x ^ y;
    }
    diff == 0
}

/// Does `presented` match a stored hash? `presented_sha` is sha256(presented)
/// in hex, computed once per attempt by the caller.
fn secret_matches(stored: &str, presented: &str, presented_sha: &str) -> bool {
    if let Some(h) = stored.strip_prefix(SHA256_PREFIX) {
        return ct_eq(h.as_bytes(), presented_sha.as_bytes());
    }
    if stored.starts_with("$argon2") {
        // Written by a pre-hop/4 binary; such entries expire within their TTL.
        if let Ok(ph) = PasswordHash::new(stored) {
            return Argon2::default().verify_password(presented.as_bytes(), &ph).is_ok();
        }
    }
    false
}

/// The tier a `hop invite` gets when none is asked for: a warren node if this
/// host has a warren, otherwise reach-only.
pub fn default_tier(config_dir: &Path) -> InviteTier {
    if config_dir.join("netdoc.ticket").exists() {
        InviteTier::Node
    } else {
        InviteTier::Client
    }
}

/// What a redeemed invite grants beyond reach. Delivered to the client in
/// `AuthResultV2` over the authenticated stream, after the secret verified,
/// and never embedded in the token.
#[derive(Debug, Clone, Default)]
pub struct InviteGrant {
    pub tier: InviteTier,
    /// Read ticket for node / warren-only, write ticket for admin, none for client.
    pub warren_ticket: Option<String>,
    /// The founder's netdoc author id (C1 trust anchor), warren tiers only.
    pub founder_author: Option<String>,
    /// This host's name, for the client's known-hosts alias.
    pub host_name: Option<String>,
}

/// Resolve the grant for an invite of `tier` on this host.
pub fn grant_for_tier(config_dir: &Path, tier: InviteTier) -> InviteGrant {
    let read = |name: &str| {
        std::fs::read_to_string(config_dir.join(name))
            .ok()
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
    };
    let warren_ticket = match tier {
        InviteTier::Client => None,
        InviteTier::WarrenOnly | InviteTier::Node => read("netdoc-read.ticket"),
        InviteTier::Admin => read("netdoc.ticket"),
    };
    let founder_author = if tier.is_warren_node() { resolve_founder_author(config_dir) } else { None };
    InviteGrant { tier, warren_ticket, founder_author, host_name: system_hostname() }
}

/// Get the system hostname.
pub fn system_hostname() -> Option<String> {
    hostname::get()
        .ok()
        .and_then(|h| h.into_string().ok())
        // Strip any DNS suffix the OS/DHCP appended to the hostname (e.g. macOS
        // on a home network returns the FQDN `RexMundi.lan`). The warren name is
        // the bare host label — `RexMundi`, not `RexMundi.lan` — so MagicDNS
        // serves `<label>.<warren-domain>` and `RexMundi.hop` resolves.
        .map(|h| h.split('.').next().unwrap_or(&h).to_string())
        .filter(|h| !h.is_empty())
}

/// Generate a new invite: returns the token string to share and stores the hash on disk.
pub fn generate_invite(
    host_public_key: &PublicKey,
    config_dir: &Path,
    relay_url: Option<&str>,
    username: Option<&str>,
    host_name: Option<&str>,
) -> Result<String> {
    generate_invite_with_tier(
        host_public_key,
        config_dir,
        relay_url,
        username,
        host_name,
        PeerRole::Peer,
        None,
        15 * 60,
        SandboxPolicy::default(),
        None, // single-use
        default_tier(config_dir),
    )
}

/// Generate a new invite with a specific role and configurable expiry.
///
/// Creator invites typically use a 1-hour expiry; regular invites use 15 minutes.
#[allow(clippy::too_many_arguments)]
/// Everything `hop invite` collects — serializable so the operator CLI can hand
/// it to the daemon (which owns identity/netdoc) over `daemon.sock` and get back
/// a token, no root or `_hop`-file reads needed (privsep §6).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InviteParams {
    pub username: Option<String>,
    pub role_name: Option<String>,
    pub tier: Option<InviteTier>,
    pub host_name: Option<String>,
    pub max_uses: Option<u32>,
    pub expiry: Option<u64>,
    pub sandbox: SandboxPolicy,
}

/// Resolve this host's founder (trust-anchor) doc author. A federated node has
/// it persisted (`netdoc-founder.author`); the founder itself carries it in its
/// own augmented `creator_invite`. Used to pin C1 trust into issued invites.
pub fn resolve_founder_author(config_dir: &Path) -> Option<String> {
    if let Ok(s) = std::fs::read_to_string(config_dir.join("netdoc-founder.author")) {
        let s = s.trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    let ci = std::fs::read_to_string(config_dir.join("creator_invite")).ok()?;
    decode_invite(ci.trim()).ok()?.founder_author
}

/// Mint an invite token from `params`, doing all the config-touching work:
/// warren check, tier→role resolution, generation + pending-invite storage, and
/// tier stamping (founder anchor + read ticket). Runs wherever the identity/
/// netdoc config is readable — the daemon (serving the operator CLI over
/// `daemon.sock`) or the CLI itself (non-privsep fallback).
pub fn build_invite_token(
    host_public_key: &PublicKey,
    config_dir: &Path,
    relay_url: Option<&str>,
    params: &InviteParams,
) -> Result<String> {
    // A warren tier needs an actual warren on this host.
    let has_warren = config_dir.join("netdoc.ticket").exists();
    if matches!(
        params.tier,
        Some(InviteTier::WarrenOnly | InviteTier::Node | InviteTier::Admin)
    ) && !has_warren
    {
        anyhow::bail!(
            "--tier {} needs a warren, but this host has none. Enable the VPN first \
             (`hop config set vpn on` or install with `--host`), then re-issue the invite.",
            params.tier.map(|t| t.as_str()).unwrap_or("")
        );
    }
    // Tier → recorded peer role (set BEFORE the pending invite is stored).
    let (peer_role, resolved_role_name): (PeerRole, Option<String>) = match params.tier {
        Some(InviteTier::Admin) => (PeerRole::Creator, Some("admin".to_string())),
        Some(InviteTier::WarrenOnly) => (PeerRole::Peer, Some("warren-only".to_string())),
        _ => (
            PeerRole::Peer,
            params.role_name.clone().or_else(|| {
                crate::config::HostConfig::load(config_dir)
                    .ok()
                    .map(|c| c.default_role)
            }),
        ),
    };

    // The tier is recorded with the pending invite; the host resolves the
    // matching grant (read/write ticket, founder anchor) only after the secret
    // verifies, and hands it over in `AuthResultV2`. Nothing about the warren
    // rides in the token.
    let tier = params.tier.unwrap_or_else(|| default_tier(config_dir));
    generate_invite_with_tier(
        host_public_key,
        config_dir,
        relay_url,
        params.username.as_deref(),
        params.host_name.as_deref(),
        peer_role,
        resolved_role_name,
        params.expiry.unwrap_or(15 * 60),
        params.sandbox.clone(),
        params.max_uses,
        tier,
    )
}

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
    max_uses: Option<u32>,
) -> Result<String> {
    // A creator invite on a warren host grants admin (the write ticket);
    // anything else gets the host's default tier.
    let tier = match (&role, default_tier(config_dir)) {
        (PeerRole::Creator, InviteTier::Node) => InviteTier::Admin,
        (_, t) => t,
    };
    generate_invite_with_tier(
        host_public_key,
        config_dir,
        relay_url,
        username,
        host_name,
        role,
        role_name,
        expiry_secs,
        sandbox,
        max_uses,
        tier,
    )
}

/// Generate an invite with an explicit capability tier. The tier is stored
/// with the pending invite and decides the post-auth grant; the token itself
/// carries only what the client needs to dial and prove the secret.
#[allow(clippy::too_many_arguments)]
pub fn generate_invite_with_tier(
    host_public_key: &PublicKey,
    config_dir: &Path,
    relay_url: Option<&str>,
    username: Option<&str>,
    host_name: Option<&str>,
    role: PeerRole,
    role_name: Option<String>,
    expiry_secs: u64,
    sandbox: SandboxPolicy,
    max_uses: Option<u32>,
    tier: InviteTier,
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

    let secret_hash = hash_secret(&secret_hex);
    let id = short_id_for_secret(&secret_hex);
    // Store the pending invite
    let mut store = PendingInvitesStore::load(config_dir)?;
    store.prune_expired(expiry_secs);
    store.invites.push(PendingInvite {
        secret_hash,
        id,
        tier,
        created_at: unix_now(),
        username: username.map(String::from),
        role: role.clone(),
        role_name: role_name.clone(),
        sandbox: sandbox.clone(),
        max_uses,
        uses: 0,
        expiry_secs,
    });
    store.save(config_dir)?;

    // Build the token: only what the client needs to dial the host and prove
    // the secret. Username, role and sandbox live in the pending store; the
    // warren ticket and founder anchor are granted after auth. An explicit
    // `--name` is kept, since a label is not a capability; the host's own name
    // is delivered after auth instead.
    let token = InviteToken {
        node_id: host_public_key.to_string(),
        secret: secret_hex,
        relay_url: relay_url.map(String::from),
        username: None,
        host_name: host_name.map(String::from),
        role: PeerRole::Peer,
        role_name: None,
        sandbox: SandboxPolicy::default(),
        warren_ticket: None,
        tier,
        founder_author: None,
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
            founder_author: None,
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
            founder_author: None,
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
            founder_author: None,
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
            founder_author: None,
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
            None,
        )
        .unwrap();

        let decoded = decode_invite(&token_str).unwrap();
        assert_eq!(decoded.node_id, public.to_string());
        // The role is recorded on the host, not in the token.
        assert_eq!(decoded.role, PeerRole::Peer);
        let store = PendingInvitesStore::load(dir.path()).unwrap();
        assert_eq!(store.invites[0].role, PeerRole::Creator);
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
            None,
        )
        .unwrap();

        let decoded = decode_invite(&token_str).unwrap();
        let mut store = PendingInvitesStore::load(dir.path()).unwrap();
        let consumed = store.try_consume(decoded.secret.as_bytes()).unwrap();
        assert_eq!(consumed.role, PeerRole::Creator);
        assert_eq!(consumed.username, None);
    }

    /// A reusable invite (max_uses) admits N hosts, then is exhausted + removed.
    #[test]
    fn reusable_invite_admits_n_then_exhausts() {
        let dir = tempfile::tempdir().unwrap();
        let key = iroh::SecretKey::from_bytes(&[9u8; 32]);
        let public = key.public();
        let token = generate_invite_with_role(
            &public,
            dir.path(),
            None,
            None,
            None,
            PeerRole::Peer,
            Some("ci".to_string()),
            3600,
            SandboxPolicy::default(),
            Some(3), // reusable up to 3 times
        )
        .unwrap();
        let decoded = decode_invite(&token).unwrap();
        let mut store = PendingInvitesStore::load(dir.path()).unwrap();
        // 3 redemptions succeed, all with the ci role...
        for _ in 0..3 {
            let c = store.try_consume(decoded.secret.as_bytes()).expect("redeem within cap");
            assert_eq!(c.role_name.as_deref(), Some("ci"));
        }
        // ...the 4th is rejected and the exhausted invite is gone.
        assert!(store.try_consume(decoded.secret.as_bytes()).is_none());
        assert!(store.invites.is_empty());
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
                    id: String::new(),
                    tier: InviteTier::Client,
                    created_at: 1000,
                    username: None,
                    role: PeerRole::Peer,
                    role_name: None,
                    sandbox: SandboxPolicy::default(),
                    max_uses: None,
                    uses: 0,
                    expiry_secs: 0,
                },
                PendingInvite {
                    secret_hash: "new".into(),
                    id: String::new(),
                    tier: InviteTier::Client,
                    created_at: unix_now(),
                    username: None,
                    role: PeerRole::Creator,
                    role_name: None,
                    sandbox: SandboxPolicy::default(),
                    max_uses: None,
                    uses: 0,
                    expiry_secs: 0,
                },
            ],
        };
        store.prune_expired(60); // 60-second expiry
        assert_eq!(store.invites.len(), 1);
        assert_eq!(store.invites[0].role, PeerRole::Creator);
    }
    #[test]
    fn new_tokens_carry_no_capability_or_metadata() {
        let dir = tempfile::tempdir().unwrap();
        // A warren host: both tickets on disk.
        std::fs::write(dir.path().join("netdoc.ticket"), "WRITE-TICKET").unwrap();
        std::fs::write(dir.path().join("netdoc-read.ticket"), "READ-TICKET").unwrap();
        let secret = iroh::SecretKey::from_bytes(&[7u8; 32]);
        let params = InviteParams {
            username: None,
            role_name: Some("developer".into()),
            tier: None,
            host_name: None,
            max_uses: None,
            expiry: None,
            sandbox: SandboxPolicy::default(),
        };
        let token = build_invite_token(&secret.public(), dir.path(), Some("https://relay.example"), &params).unwrap();
        let decoded = decode_invite(&token).unwrap();
        assert!(decoded.warren_ticket.is_none(), "no ticket in the token");
        assert!(decoded.founder_author.is_none());
        assert!(decoded.username.is_none(), "username stays on the host");
        assert!(decoded.host_name.is_none(), "host name is delivered after auth");
        assert_eq!(decoded.tier, InviteTier::Node, "default tier on a warren host");
        assert_eq!(decoded.relay_url.as_deref(), Some("https://relay.example"));
        let raw = String::from_utf8(URL_SAFE_NO_PAD.decode(&token).unwrap()).unwrap();
        assert!(!raw.contains("TICKET"), "raw token must not contain either ticket: {raw}");
        // The pending entry remembers everything the token no longer says.
        let store = PendingInvitesStore::load(dir.path()).unwrap();
        let inv = &store.invites[0];
        assert_eq!(inv.tier, InviteTier::Node);
        assert_eq!(inv.role_name.as_deref(), Some("developer"));
        assert!(inv.secret_hash.starts_with("sha256:"));
        assert_eq!(inv.id.len(), 8);
    }

    #[test]
    fn grant_follows_tier() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("netdoc.ticket"), "WRITE-TICKET").unwrap();
        std::fs::write(dir.path().join("netdoc-read.ticket"), "READ-TICKET").unwrap();
        std::fs::write(dir.path().join("netdoc-founder.author"), "author-abc").unwrap();
        assert_eq!(grant_for_tier(dir.path(), InviteTier::Client).warren_ticket, None);
        let node = grant_for_tier(dir.path(), InviteTier::Node);
        assert_eq!(node.warren_ticket.as_deref(), Some("READ-TICKET"));
        assert_eq!(node.founder_author.as_deref(), Some("author-abc"));
        assert_eq!(grant_for_tier(dir.path(), InviteTier::WarrenOnly).warren_ticket.as_deref(), Some("READ-TICKET"));
        assert_eq!(grant_for_tier(dir.path(), InviteTier::Admin).warren_ticket.as_deref(), Some("WRITE-TICKET"));
    }

    #[test]
    fn default_tier_is_client_without_a_warren() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(default_tier(dir.path()), InviteTier::Client);
        std::fs::write(dir.path().join("netdoc.ticket"), "x").unwrap();
        assert_eq!(default_tier(dir.path()), InviteTier::Node);
    }

    #[test]
    fn sha256_entries_verify_and_legacy_argon2_entries_still_verify() {
        use argon2::PasswordHasher;
        let secret = "deadbeefcafebabe";
        let sha = hash_secret(secret);
        let presented_sha = sha256_hex(secret.as_bytes());
        assert!(secret_matches(&sha, secret, &presented_sha));
        assert!(!secret_matches(&sha, "wrong", &sha256_hex(b"wrong")));
        // An entry written by a pre-hop/4 binary.
        let salt = argon2::password_hash::SaltString::from_b64("c29tZXNhbHRzb21lc2FsdA").unwrap();
        let legacy = Argon2::default().hash_password(secret.as_bytes(), &salt).unwrap().to_string();
        assert!(legacy.starts_with("$argon2"));
        assert!(secret_matches(&legacy, secret, &presented_sha));
        assert!(!secret_matches(&legacy, "wrong", &sha256_hex(b"wrong")));
        assert!(!secret_matches("garbage", secret, &presented_sha));
    }

    #[test]
    fn list_and_revoke_by_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let secret = iroh::SecretKey::from_bytes(&[9u8; 32]);
        let t1 = generate_invite(&secret.public(), dir.path(), None, None, None).unwrap();
        let _t2 = generate_invite(&secret.public(), dir.path(), None, None, None).unwrap();
        let mut store = PendingInvitesStore::load(dir.path()).unwrap();
        let rows = store.list(900);
        assert_eq!(rows.len(), 2);
        assert!(rows.iter().all(|r| r.expires_at == r.created_at + 900));
        let id1 = short_id_for_secret(&decode_invite(&t1).unwrap().secret);
        assert!(rows.iter().any(|r| r.id == id1));
        let removed = store.revoke(&id1[..4]).unwrap();
        assert_eq!(removed, id1);
        assert_eq!(store.invites.len(), 1);
        assert!(store.revoke("zz").is_err());
        assert!(store.revoke("").is_err());
        // The revoked secret no longer redeems.
        let s1 = decode_invite(&t1).unwrap().secret;
        assert!(store.try_consume(s1.as_bytes()).is_none());
    }

}
