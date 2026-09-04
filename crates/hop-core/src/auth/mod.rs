//! Connection authentication and peer authorization.

use anyhow::{Result, anyhow};
use iroh::PublicKey;
use std::collections::HashMap;
use std::path::Path;
use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

use crate::config::{PeerRole, PeersStore};
use crate::invite::PendingInvitesStore;
use crate::proto::{self, ClientMessage, HostMessage};
use iroh::endpoint::{RecvStream, SendStream};

/// Lock to prevent TOCTOU races when consuming invites.
/// Without this, two concurrent connections with the same invite token
/// could both pass verification before either removes the invite.
static INVITE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

/// Per-remote-node budget for invite attempts. The invite path is the only
/// thing an unauthorized node can make this host do work for, so it is
/// metered before any store is touched: a burst of [`AUTH_BURST`] attempts,
/// refilling at [`AUTH_REFILL_PER_SEC`], and a [`AUTH_BAN`] cool-off once the
/// budget is spent. Keyed by node id (the QUIC handshake already proved it).
struct AuthBucket {
    tokens: f64,
    last: Instant,
    banned_until: Option<Instant>,
}

const AUTH_BURST: f64 = 5.0;
const AUTH_REFILL_PER_SEC: f64 = 1.0 / 12.0; // 5 per minute sustained
const AUTH_BAN: Duration = Duration::from_secs(60);
const AUTH_IDLE_FORGET: Duration = Duration::from_secs(10 * 60);

static AUTH_LIMITER: LazyLock<Mutex<HashMap<PublicKey, AuthBucket>>> =
    LazyLock::new(|| Mutex::new(HashMap::new()));

/// Spend one invite attempt for `remote`. `false` means the attempt must be
/// refused without looking at the invite store.
pub fn auth_attempt_allowed(remote: &PublicKey) -> bool {
    let mut map = AUTH_LIMITER.lock().unwrap_or_else(|e| e.into_inner());
    auth_attempt_allowed_at(&mut map, remote, Instant::now())
}

fn auth_attempt_allowed_at(
    map: &mut HashMap<PublicKey, AuthBucket>,
    remote: &PublicKey,
    now: Instant,
) -> bool {
    // Forget nodes that have been quiet; keeps the map bounded under churn.
    map.retain(|_, b| now.duration_since(b.last) < AUTH_IDLE_FORGET || b.banned_until.is_some_and(|t| t > now));
    let bucket = map.entry(*remote).or_insert(AuthBucket {
        tokens: AUTH_BURST,
        last: now,
        banned_until: None,
    });
    if let Some(until) = bucket.banned_until {
        if until > now {
            bucket.last = now;
            return false;
        }
        // The ban is over: one attempt, and no refill credit for time served.
        bucket.banned_until = None;
        bucket.tokens = 1.0;
        bucket.last = now;
    }
    let elapsed = now.duration_since(bucket.last).as_secs_f64();
    bucket.tokens = (bucket.tokens + elapsed * AUTH_REFILL_PER_SEC).min(AUTH_BURST);
    bucket.last = now;
    if bucket.tokens >= 1.0 {
        bucket.tokens -= 1.0;
        true
    } else {
        bucket.banned_until = Some(now + AUTH_BAN);
        false
    }
}

/// Tell the client how auth went. hop/4 clients get the full grant; older
/// clients get the one-bit answer they understand.
async fn send_auth_result(
    send: &mut SendStream,
    protocol_version: u8,
    authorized: bool,
    reason: Option<&str>,
    grant: Option<crate::invite::InviteGrant>,
) -> Result<()> {
    if protocol_version >= 4 {
        let g = grant.unwrap_or_default();
        proto::write_message(
            send,
            &HostMessage::AuthResultV2 {
                authorized,
                reason: reason.map(String::from),
                tier: g.tier,
                warren_ticket: g.warren_ticket,
                founder_author: g.founder_author,
                host_name: g.host_name,
            },
        )
        .await
    } else {
        proto::write_message(send, &HostMessage::AuthResult { authorized }).await
    }
}

/// Result of authenticating a connecting client.
pub enum AuthOutcome {
    /// Client is an already-authorized peer.
    Authorized {
        /// Unix username this peer is bound to (None = host's own user).
        username: Option<String>,
        /// Role of this peer.
        role: PeerRole,
        /// Sandbox restrictions for this peer.
        sandbox: crate::sandbox::SandboxPolicy,
    },
    /// Client was authorized via invite (newly added).
    InviteAccepted {
        /// Unix username from the invite (None = host's own user).
        username: Option<String>,
        /// Role assigned via the invite.
        role: PeerRole,
        /// Sandbox restrictions from the invite.
        sandbox: crate::sandbox::SandboxPolicy,
    },
    /// Client was rejected.
    Rejected,
}

/// Derive a short suffix that hints at a sandbox preset.
///
/// Compares the policy against known presets and falls back to flag-based
/// labels so that `hop peers` output is immediately informative.
pub fn sandbox_suffix(sandbox: &crate::sandbox::SandboxPolicy) -> &'static str {
    use crate::sandbox::SandboxPolicy;

    if *sandbox == SandboxPolicy::preset_monitor() {
        return "monitor";
    }
    if *sandbox == SandboxPolicy::preset_audit() {
        return "audit";
    }
    if *sandbox == SandboxPolicy::preset_deploy() {
        return "deploy";
    }

    // Fall back to flag-based labels
    if sandbox.read_only && sandbox.no_network {
        return "readonly";
    }
    if sandbox.read_only {
        return "readonly";
    }
    if !sandbox.allowed_commands.is_empty() {
        return "restricted";
    }
    ""
}

/// Build a human-friendly display name for a newly-authorized peer.
///
/// Priority:
/// 1. `{username}-{short_id}` when a username is bound
/// 2. `creator-{short_id}` for the Creator role
/// 3. `peer-{short_id}-{suffix}` when the sandbox matches a known preset
/// 4. `peer-{short_id}` as the default
pub fn generate_peer_display_name(
    short_id: &str,
    username: Option<&str>,
    role: &PeerRole,
    sandbox: &crate::sandbox::SandboxPolicy,
) -> String {
    if let Some(user) = username {
        return format!("{user}-{short_id}");
    }
    if *role == PeerRole::Creator {
        return format!("creator-{short_id}");
    }
    let suffix = sandbox_suffix(sandbox);
    if !suffix.is_empty() {
        return format!("peer-{short_id}-{suffix}");
    }
    format!("peer-{short_id}")
}

/// Record a rejected (unauthorized) connection attempt in the audit log.
fn record_unauthorized(remote_id: &PublicKey) {
    crate::audit::record(
        crate::audit::AuditEvent::new(
            crate::audit::AuditCategory::Connection,
            "connection.rejected",
            crate::audit::AuditOutcome::Deny,
        )
        .actor(remote_id.to_string())
        .detail("unauthorized"),
    );
}

/// Host-side: authenticate an incoming connection.
///
/// Reads the first message from the client. If it's an `AuthResponse` (invite flow),
/// verifies the secret. If it's a `RequestShell`, checks the authorized peers list.
/// `protocol_version` is the negotiated ALPN version; on hop/4+ a successful
/// invite redemption answers with `AuthResultV2` carrying the invite's grant.
pub async fn authenticate_client(
    send: &mut SendStream,
    recv: &mut RecvStream,
    remote_id: &PublicKey,
    config_dir: &Path,
    netdoc: Option<&crate::netdoc::NetDoc>,
    protocol_version: u8,
) -> Result<(AuthOutcome, Option<ClientMessage>)> {
    let peers = PeersStore::load(config_dir)?;

    // Read the first message from the client
    let msg: ClientMessage = proto::read_message(recv).await?;

    match &msg {
        ClientMessage::AuthResponse { secret } => {
            // Meter first: an unauthorized node must not be able to make this
            // host hash anything at will.
            if !auth_attempt_allowed(remote_id) {
                send_auth_result(send, protocol_version, false, Some("too many attempts; try again in a minute"), None).await?;
                tracing::warn!("Invite attempt from {} rate-limited", remote_id.fmt_short());
                crate::audit::record(
                    crate::audit::AuditEvent::new(
                        crate::audit::AuditCategory::Connection,
                        "connection.rejected",
                        crate::audit::AuditOutcome::Deny,
                    )
                    .actor(remote_id.to_string())
                    .detail("invite attempts rate-limited"),
                );
                return Ok((AuthOutcome::Rejected, None));
            }
            // Invite flow: verify the secret.
            // Hold a lock to prevent TOCTOU races (two connections consuming the same invite).
            let consumed = {
                let _guard = INVITE_LOCK
                    .lock()
                    .map_err(|e| anyhow!("invite lock poisoned: {e}"))?;
                let mut invites = PendingInvitesStore::load(config_dir)?;
                invites.prune_expired(15 * 60);

                let result = invites.try_consume(secret);
                if result.is_some() {
                    invites.save(config_dir)?;
                }
                result
            };

            if let Some(consumed) = consumed {
                // Add to authorized peers
                let mut peers = peers;
                let short_id = remote_id.fmt_short().to_string();
                let display_name = generate_peer_display_name(
                    &short_id,
                    consumed.username.as_deref(),
                    &consumed.role,
                    &consumed.sandbox,
                );
                peers.add_peer(
                    remote_id,
                    display_name,
                    consumed.username.clone(),
                    consumed.role.clone(),
                    consumed.sandbox.clone(),
                );
                // Record the named role (resolves to a RoleDefinition: reach +
                // confinement). `None` → the peer is governed by the legacy tier.
                if let Some(p) = peers.peers.iter_mut().find(|p| p.node_id == remote_id.to_string()) {
                    p.role_name = consumed.role_name.clone();
                }
                peers.save(config_dir)?;

                // Dual-write to the network document (best-effort) so the new
                // peer replicates to other nodes. `admit_peer` also allocates the
                // member's vIP (`peer/N.vip`, the addr→owner authority the data
                // plane resolves endpoints by — #3b). Never fail auth on a doc error.
                if let Some(nd) = netdoc
                    && let Some(entry) = peers.peers.iter().find(|p| p.node_id == remote_id.to_string())
                    && let Err(e) = nd.admit_peer(entry).await
                {
                    tracing::warn!("netdoc: failed to mirror invited peer: {e:#}");
                }

                // Tell the client it is authorized, and (hop/4) what the
                // invite grants: the warren ticket and founder anchor for
                // warren tiers, resolved now rather than embedded in the token.
                let grant = crate::invite::grant_for_tier(config_dir, consumed.tier);
                send_auth_result(send, protocol_version, true, None, Some(grant)).await?;
                tracing::info!(
                    "Invite accepted for peer {} (role: {:?}, tier: {})",
                    remote_id.fmt_short(),
                    consumed.role,
                    consumed.tier.as_str()
                );
                crate::audit::record(
                    crate::audit::AuditEvent::new(
                        crate::audit::AuditCategory::Membership,
                        "member.join",
                        crate::audit::AuditOutcome::Success,
                    )
                    .actor(remote_id.to_string())
                    .user_opt(consumed.username.as_deref())
                    .detail(format!("role={:?} tier={} invite={}", consumed.role, consumed.tier.as_str(), consumed.id)),
                );
                Ok((AuthOutcome::InviteAccepted { username: consumed.username, role: consumed.role, sandbox: consumed.sandbox }, None))
            } else {
                send_auth_result(send, protocol_version, false, Some("invite rejected (expired, already used, or unknown)"), None).await?;
                tracing::warn!("Invalid invite from peer {}", remote_id.fmt_short());
                crate::audit::record(
                    crate::audit::AuditEvent::new(
                        crate::audit::AuditCategory::Connection,
                        "connection.rejected",
                        crate::audit::AuditOutcome::Deny,
                    )
                    .actor(remote_id.to_string())
                    .detail("invalid invite"),
                );
                Ok((AuthOutcome::Rejected, None))
            }
        }
        ClientMessage::RequestShell
        | ClientMessage::RequestShellV2 { .. }
        | ClientMessage::RequestShellV3 { .. }
        | ClientMessage::RequestTransfer(_)
        | ClientMessage::RequestExec { .. }
        | ClientMessage::RequestExecV2 { .. }
        | ClientMessage::RequestTunnel { .. }
        | ClientMessage::AnnounceNetdocAuthor { .. }
        | ClientMessage::RequestAdmin(_) => {
            // Authorization order:
            //   0. An *explicit* doc revocation (tombstone) rejects even a
            //      locally-authorized peer. Revocation is an intentional admin
            //      action and must take effect on every host without first
            //      requiring the local peers.json entry to be deleted
            //      (security-audit M5). Doc errors/absence still fall through to
            //      the local allow, preserving the no-lockout property.
            //   1. peers.json authorizes -> allow (trusted local truth).
            //   2. otherwise consult the replicated doc: revoked -> reject;
            //      present -> allow (federated / inviter-offline peer); else reject.
            if let Some(nd) = netdoc
                && nd.is_revoked(&remote_id.to_string()).await.unwrap_or(false)
            {
                proto::write_message(send, &HostMessage::AuthResult { authorized: false }).await?;
                tracing::warn!(
                    "Peer {} rejected: revoked in network document (overrides local entry)",
                    remote_id.fmt_short()
                );
                crate::audit::record(
                    crate::audit::AuditEvent::new(
                        crate::audit::AuditCategory::Connection,
                        "connection.rejected",
                        crate::audit::AuditOutcome::Deny,
                    )
                    .actor(remote_id.to_string())
                    .detail("revoked in network document"),
                );
                return Ok((AuthOutcome::Rejected, None));
            }
            if peers.is_authorized(remote_id) {
                let username = peers.peer_username(remote_id).map(String::from);
                let role = peers.peer_role(remote_id);
                let sandbox = peers.peer_sandbox(remote_id);
                let mut peers = peers;
                peers.update_last_seen(remote_id);
                peers.save(config_dir)?;
                crate::audit::record(
                    crate::audit::AuditEvent::new(
                        crate::audit::AuditCategory::Connection,
                        "connection.authorized",
                        crate::audit::AuditOutcome::Allow,
                    )
                    .actor(remote_id.to_string())
                    .user_opt(username.as_deref()),
                );
                Ok((AuthOutcome::Authorized { username, role, sandbox }, Some(msg)))
            } else if let Some(nd) = netdoc {
                let remote_hex = remote_id.to_string();
                if nd.is_revoked(&remote_hex).await.unwrap_or(false) {
                    proto::write_message(send, &HostMessage::AuthResult { authorized: false }).await?;
                    tracing::warn!("Revoked peer {} rejected (netdoc)", remote_id.fmt_short());
                    Ok((AuthOutcome::Rejected, None))
                } else if let Some(dp) = nd.get_peer(&remote_hex).await.ok().flatten() {
                    tracing::info!("Authorized peer {} via netdoc replica", remote_id.fmt_short());
                    crate::audit::record(
                        crate::audit::AuditEvent::new(
                            crate::audit::AuditCategory::Connection,
                            "connection.authorized",
                            crate::audit::AuditOutcome::Allow,
                        )
                        .actor(remote_id.to_string())
                        .user_opt(dp.username.as_deref())
                        .detail("via netdoc replica"),
                    );
                    Ok((
                        AuthOutcome::Authorized {
                            username: dp.username,
                            role: dp.role,
                            sandbox: dp.sandbox,
                        },
                        Some(msg),
                    ))
                } else {
                    proto::write_message(send, &HostMessage::AuthResult { authorized: false }).await?;
                    tracing::warn!("Unauthorized peer {} rejected", remote_id.fmt_short());
                    record_unauthorized(remote_id);
                    Ok((AuthOutcome::Rejected, None))
                }
            } else {
                proto::write_message(send, &HostMessage::AuthResult { authorized: false })
                    .await?;
                tracing::warn!("Unauthorized peer {} rejected", remote_id.fmt_short());
                record_unauthorized(remote_id);
                Ok((AuthOutcome::Rejected, None))
            }
        }
        _ => {
            tracing::warn!(
                "Unexpected first message from {}: {:?}",
                remote_id.fmt_short(),
                msg
            );
            Ok((AuthOutcome::Rejected, None))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxPolicy;

    fn node(n: u8) -> PublicKey {
        iroh::SecretKey::from_bytes(&[n; 32]).public()
    }

    #[test]
    fn limiter_allows_burst_then_bans_then_recovers() {
        let mut map = HashMap::new();
        let t0 = Instant::now();
        let a = node(1);
        for _ in 0..5 {
            assert!(auth_attempt_allowed_at(&mut map, &a, t0));
        }
        assert!(!auth_attempt_allowed_at(&mut map, &a, t0));
        assert!(!auth_attempt_allowed_at(&mut map, &a, t0 + Duration::from_secs(30)));
        assert!(auth_attempt_allowed_at(&mut map, &a, t0 + Duration::from_secs(61)));
        assert!(!auth_attempt_allowed_at(&mut map, &a, t0 + Duration::from_secs(62)));
    }

    #[test]
    fn limiter_is_per_node() {
        let mut map = HashMap::new();
        let t0 = Instant::now();
        let (a, b) = (node(1), node(2));
        for _ in 0..6 {
            auth_attempt_allowed_at(&mut map, &a, t0);
        }
        assert!(!auth_attempt_allowed_at(&mut map, &a, t0));
        assert!(auth_attempt_allowed_at(&mut map, &b, t0));
    }

    #[test]
    fn limiter_refills_over_time() {
        let mut map = HashMap::new();
        let t0 = Instant::now();
        let a = node(3);
        for _ in 0..5 {
            assert!(auth_attempt_allowed_at(&mut map, &a, t0));
        }
        assert!(auth_attempt_allowed_at(&mut map, &a, t0 + Duration::from_secs(12)));
    }

    #[test]
    fn name_with_username() {
        let name = generate_peer_display_name("abc1", Some("alice"), &PeerRole::Peer, &SandboxPolicy::default());
        assert_eq!(name, "alice-abc1");
    }

    #[test]
    fn name_creator_no_username() {
        let name = generate_peer_display_name("abc1", None, &PeerRole::Creator, &SandboxPolicy::default());
        assert_eq!(name, "creator-abc1");
    }

    #[test]
    fn name_creator_with_username_prefers_username() {
        let name = generate_peer_display_name("abc1", Some("bob"), &PeerRole::Creator, &SandboxPolicy::default());
        assert_eq!(name, "bob-abc1");
    }

    #[test]
    fn name_peer_monitor_sandbox() {
        let name = generate_peer_display_name("abc1", None, &PeerRole::Peer, &SandboxPolicy::preset_monitor());
        assert_eq!(name, "peer-abc1-monitor");
    }

    #[test]
    fn name_peer_audit_sandbox() {
        let name = generate_peer_display_name("abc1", None, &PeerRole::Peer, &SandboxPolicy::preset_audit());
        assert_eq!(name, "peer-abc1-audit");
    }

    #[test]
    fn name_peer_deploy_sandbox() {
        let name = generate_peer_display_name("abc1", None, &PeerRole::Peer, &SandboxPolicy::preset_deploy());
        assert_eq!(name, "peer-abc1-deploy");
    }

    #[test]
    fn name_peer_readonly_sandbox() {
        let sandbox = SandboxPolicy {
            read_only: true,
            ..Default::default()
        };
        let name = generate_peer_display_name("abc1", None, &PeerRole::Peer, &sandbox);
        assert_eq!(name, "peer-abc1-readonly");
    }

    #[test]
    fn name_peer_restricted_sandbox() {
        let sandbox = SandboxPolicy {
            allowed_commands: vec!["ls".into(), "cat".into()],
            ..Default::default()
        };
        let name = generate_peer_display_name("abc1", None, &PeerRole::Peer, &sandbox);
        assert_eq!(name, "peer-abc1-restricted");
    }

    #[test]
    fn name_peer_default_sandbox() {
        let name = generate_peer_display_name("abc1", None, &PeerRole::Peer, &SandboxPolicy::default());
        assert_eq!(name, "peer-abc1");
    }

    #[test]
    fn sandbox_suffix_empty_for_default() {
        assert_eq!(sandbox_suffix(&SandboxPolicy::default()), "");
    }

    #[test]
    fn sandbox_suffix_known_presets() {
        assert_eq!(sandbox_suffix(&SandboxPolicy::preset_monitor()), "monitor");
        assert_eq!(sandbox_suffix(&SandboxPolicy::preset_audit()), "audit");
        assert_eq!(sandbox_suffix(&SandboxPolicy::preset_deploy()), "deploy");
    }
}
