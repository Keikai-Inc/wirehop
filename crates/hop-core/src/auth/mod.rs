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

/// Host-side: authenticate an incoming connection.
///
/// Reads the first message from the client. If it's an `AuthResponse` (invite flow),
/// verifies the secret. If it's a `RequestShell`, checks the authorized peers list.
pub async fn authenticate_client(
    send: &mut SendStream,
    recv: &mut RecvStream,
    remote_id: &PublicKey,
    config_dir: &Path,
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
                peers.add_peer(
                    remote_id,
                    format!("peer-{}", remote_id.fmt_short()),
                    consumed.username.clone(),
                    consumed.role.clone(),
                    consumed.sandbox.clone(),
                );
                peers.save(config_dir)?;

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
            if peers.is_authorized(remote_id) {
                let username = peers.peer_username(remote_id).map(String::from);
                let role = peers.peer_role(remote_id);
                let sandbox = peers.peer_sandbox(remote_id);
                // Update last seen
                let mut peers = peers;
                peers.update_last_seen(remote_id);
                peers.save(config_dir)?;
                Ok((AuthOutcome::Authorized { username, role, sandbox }, Some(msg)))
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
