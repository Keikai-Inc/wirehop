//! Connection authentication and peer authorization.

use anyhow::{Result, anyhow};
use iroh::PublicKey;
use std::path::Path;
use std::sync::{LazyLock, Mutex};

use crate::config::{PeerRole, PeersStore};
use crate::invite::PendingInvitesStore;
use crate::proto::{self, ClientMessage, HostMessage};
use iroh::endpoint::{RecvStream, SendStream};

/// Lock to prevent TOCTOU races when consuming invites.
/// Without this, two concurrent connections with the same invite token
/// could both pass verification before either removes the invite.
static INVITE_LOCK: LazyLock<Mutex<()>> = LazyLock::new(|| Mutex::new(()));

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

/// Host-side: authenticate an incoming connection.
///
/// Reads the first message from the client. If it's an `AuthResponse` (invite flow),
/// verifies the secret. If it's a `RequestShell`, checks the authorized peers list.
pub async fn authenticate_client(
    send: &mut SendStream,
    recv: &mut RecvStream,
    remote_id: &PublicKey,
    config_dir: &Path,
    netdoc: Option<&crate::netdoc::NetDoc>,
) -> Result<(AuthOutcome, Option<ClientMessage>)> {
    let peers = PeersStore::load(config_dir)?;

    // Read the first message from the client
    let msg: ClientMessage = proto::read_message(recv).await?;

    match &msg {
        ClientMessage::AuthResponse { secret } => {
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
                // peer replicates to other nodes. Never fail auth on a doc error.
                if let Some(nd) = netdoc
                    && let Some(entry) = peers.peers.iter().find(|p| p.node_id == remote_id.to_string())
                    && let Err(e) = nd.put_peer(entry).await
                {
                    tracing::warn!("netdoc: failed to mirror invited peer: {e:#}");
                }

                // Tell client they're authorized
                proto::write_message(send, &HostMessage::AuthResult { authorized: true }).await?;

                tracing::info!("Invite accepted for peer {} (role: {:?})", remote_id.fmt_short(), consumed.role);
                Ok((AuthOutcome::InviteAccepted { username: consumed.username, role: consumed.role, sandbox: consumed.sandbox }, None))
            } else {
                proto::write_message(send, &HostMessage::AuthResult { authorized: false })
                    .await?;
                tracing::warn!("Invalid invite from peer {}", remote_id.fmt_short());
                Ok((AuthOutcome::Rejected, None))
            }
        }
        ClientMessage::RequestShell
        | ClientMessage::RequestShellV2 { .. }
        | ClientMessage::RequestShellV3 { .. }
        | ClientMessage::RequestTransfer(_)
        | ClientMessage::RequestExec { .. }
        | ClientMessage::RequestExecV2 { .. }
        | ClientMessage::RequestAdmin(_) => {
            // Authorization order, designed so the network document can never
            // lock out a locally-authorized peer:
            //   1. peers.json authorizes  -> ALWAYS allow (trusted local truth;
            //      doc state is never allowed to reject a local peer).
            //   2. otherwise consult the replicated doc: revoked -> reject;
            //      present -> allow (federated / inviter-offline peer); else reject.
            if peers.is_authorized(remote_id) {
                let username = peers.peer_username(remote_id).map(String::from);
                let role = peers.peer_role(remote_id);
                let sandbox = peers.peer_sandbox(remote_id);
                let mut peers = peers;
                peers.update_last_seen(remote_id);
                peers.save(config_dir)?;
                Ok((AuthOutcome::Authorized { username, role, sandbox }, Some(msg)))
            } else if let Some(nd) = netdoc {
                let remote_hex = remote_id.to_string();
                if nd.is_revoked(&remote_hex).await.unwrap_or(false) {
                    proto::write_message(send, &HostMessage::AuthResult { authorized: false }).await?;
                    tracing::warn!("Revoked peer {} rejected (netdoc)", remote_id.fmt_short());
                    Ok((AuthOutcome::Rejected, None))
                } else if let Some(dp) = nd.get_peer(&remote_hex).await.ok().flatten() {
                    tracing::info!("Authorized peer {} via netdoc replica", remote_id.fmt_short());
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
                    Ok((AuthOutcome::Rejected, None))
                }
            } else {
                proto::write_message(send, &HostMessage::AuthResult { authorized: false })
                    .await?;
                tracing::warn!("Unauthorized peer {} rejected", remote_id.fmt_short());
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
