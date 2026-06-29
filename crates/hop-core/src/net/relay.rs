//! Member-only BYO relay (`hop host --relay`).
//!
//! Spawns an in-process iroh relay that only warren MEMBERS may use — the fix for
//! the "open relay" problem (a public relay is free transport for any stranger who
//! learns its URL). The relay is blind regardless: every byte it carries is
//! end-to-end encrypted by iroh, so it only ever sees ciphertext; member-gating
//! is about who may *use* the transport, not about confidentiality.
//!
//! No TLS on the relay's own HTTP endpoint by default — members point
//! `HOP_RELAY_URL` at `http://<host>:<port>` (the same shape the soak's local
//! relay uses). HTTPS/ACME for an internet-facing relay is a follow-up.

use std::collections::HashSet;
use std::net::SocketAddr;
use std::sync::Arc;

use anyhow::Result;
use tokio::sync::RwLock;

/// Endpoints allowed to use the relay (warren members + self), refreshed from the
/// roster. An `RwLock` so a background task can swap the set as the roster changes.
pub type MemberSet = Arc<RwLock<HashSet<iroh::EndpointId>>>;

/// Default HTTP bind port for a BYO relay.
pub const DEFAULT_RELAY_PORT: u16 = 3340;

/// Build the member-gating access policy: an endpoint is admitted iff it is in the
/// (live) `members` set, else denied at the handshake. Extracted so the gating
/// decision is unit-testable via `AccessConfig::is_allowed` without a live relay.
fn member_access(members: MemberSet) -> iroh_relay::server::AccessConfig {
    use iroh_relay::server::{Access, AccessConfig};
    AccessConfig::Restricted(Box::new(move |endpoint_id| {
        let members = members.clone();
        Box::pin(async move {
            if members.read().await.contains(&endpoint_id) {
                Access::Allow
            } else {
                Access::Deny
            }
        }) as _
    }))
}

/// Spawn a member-only relay listening on `bind`. Only endpoints present in
/// `members` are admitted (`AccessConfig::Restricted`); everyone else is denied at
/// the handshake. Returns the running server — drop it to stop the relay.
pub async fn spawn_member_relay(
    bind: SocketAddr,
    members: MemberSet,
) -> Result<iroh_relay::server::Server> {
    use iroh_relay::server::{Limits, RelayConfig, Server, ServerConfig};

    let access = member_access(members);

    let relay = RelayConfig::<()> {
        http_bind_addr: bind,
        tls: None,
        limits: Limits::default(),
        key_cache_capacity: None,
        access,
    };
    let config = ServerConfig::<()> {
        relay: Some(relay),
        quic: None,
        metrics_addr: None,
    };
    let server = Server::spawn(config).await?;
    tracing::info!("relay: member-only BYO relay listening on http://{bind}");
    Ok(server)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The gate admits warren members and denies strangers — the "open relay" fix,
    /// proven deterministically without standing up a live relay.
    #[tokio::test]
    async fn member_gating_admits_members_denies_strangers() {
        let member = iroh::SecretKey::generate(&mut rand::rng()).public();
        let stranger = iroh::SecretKey::generate(&mut rand::rng()).public();
        let members: MemberSet =
            Arc::new(RwLock::new(HashSet::from([member])));

        let access = member_access(members);
        assert!(
            access.is_allowed(member).await,
            "a warren member must be admitted to the BYO relay"
        );
        assert!(
            !access.is_allowed(stranger).await,
            "a non-member must be denied by the BYO relay (the open-relay fix)"
        );
    }
}
