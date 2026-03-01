//! Connection authentication and peer authorization.

use anyhow::{Result, anyhow};
use iroh::PublicKey;
use std::path::Path;
use std::sync::{LazyLock, Mutex};

use crate::config::PeersStore;
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
    },
    /// Client was authorized via invite (newly added).
    InviteAccepted {
        /// Unix username from the invite (None = host's own user).
        username: Option<String>,
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

            if let Some(username) = consumed {
                // Add to authorized peers
                let mut peers = peers;
                peers.add_peer(remote_id, format!("peer-{}", remote_id.fmt_short()), username.clone());
                peers.save(config_dir)?;

                // Tell client they're authorized
                proto::write_message(send, &HostMessage::AuthResult { authorized: true }).await?;

                tracing::info!("Invite accepted for peer {}", remote_id.fmt_short());
                Ok((AuthOutcome::InviteAccepted { username }, None))
            } else {
                proto::write_message(send, &HostMessage::AuthResult { authorized: false })
                    .await?;
                tracing::warn!("Invalid invite from peer {}", remote_id.fmt_short());
                Ok((AuthOutcome::Rejected, None))
            }
        }
        ClientMessage::RequestShell => {
            if peers.is_authorized(remote_id) {
                let username = peers.peer_username(remote_id).map(String::from);
                // Update last seen
                let mut peers = peers;
                peers.update_last_seen(remote_id);
                peers.save(config_dir)?;
                Ok((AuthOutcome::Authorized { username }, Some(msg)))
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
