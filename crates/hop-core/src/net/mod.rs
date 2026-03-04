//! iroh endpoint lifecycle and connection management.

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId, PublicKey, RelayMode, RelayUrl, SecretKey};

use crate::proto::{ALPN_V0, ALPN_V1, ALPN_V2};

/// Hop's own relay server.
const HOP_RELAY_URL: &str = "https://relay.keik.ai";

/// Build a RelayMode using only our relay.
///
/// iroh selects its home relay by lowest latency, so including n0's public
/// relays causes our relay to be ignored.  Using only our relay guarantees
/// hop traffic flows through infrastructure we control.  If the relay is
/// unreachable, iroh still falls back to discovery-based direct connections.
fn hop_relay_mode() -> RelayMode {
    let hop_relay: RelayUrl = HOP_RELAY_URL.parse().expect("valid relay URL");
    RelayMode::custom([hop_relay])
}

/// Create an iroh endpoint configured for hosting (accepting connections).
///
/// Waits for the endpoint to come online (connected to relay, address published
/// to discovery) before returning.
pub async fn create_host_endpoint(secret_key: SecretKey) -> Result<Endpoint> {
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .relay_mode(hop_relay_mode())
        .alpns(vec![ALPN_V2.to_vec(), ALPN_V1.to_vec(), ALPN_V0.to_vec()])
        .bind()
        .await
        .context("Failed to bind iroh endpoint")?;

    // Wait until connected to relay and address is published to discovery.
    // Without this, clients cannot find us.
    endpoint.online().await;

    Ok(endpoint)
}

/// Create an iroh endpoint configured for connecting (client mode).
/// Client endpoints don't need to accept connections, so no ALPNs.
///
/// Waits up to 5 seconds for the relay to come online. Clients can still
/// connect via discovery if the relay is slow, so we proceed regardless.
pub async fn create_client_endpoint(secret_key: SecretKey) -> Result<Endpoint> {
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .relay_mode(hop_relay_mode())
        .bind()
        .await
        .context("Failed to bind iroh endpoint")?;

    if tokio::time::timeout(std::time::Duration::from_secs(5), endpoint.online())
        .await
        .is_err()
    {
        tracing::warn!("Relay did not come online within 5s, proceeding anyway");
    }

    Ok(endpoint)
}

/// Get the relay URL for a host endpoint, if available.
pub fn host_relay_url(endpoint: &Endpoint) -> Option<RelayUrl> {
    endpoint.addr().relay_urls().next().cloned()
}

/// Connect to a remote host by their PublicKey, optionally with a relay URL hint.
///
/// Uses iroh's discovery (DNS/pkarr) to find the host's address info,
/// which includes relay URLs and direct addresses. This is more reliable
/// than providing an explicit relay hint, as discovery returns the host's
/// actual published address including any direct paths.
pub async fn connect_to_host(
    endpoint: &Endpoint,
    remote_id: PublicKey,
    _relay_url: Option<&RelayUrl>,
) -> Result<(Connection, bool)> {
    // Let iroh discover the host's address via DNS/pkarr.
    // The host publishes its relay URL and direct addresses to iroh.link,
    // so discovery will find the correct path automatically.
    let addr = EndpointAddr::from(remote_id);

    tracing::info!("Connecting to {} via discovery", remote_id.fmt_short());

    let conn = endpoint
        .connect(addr, ALPN_V2)
        .await
        .context("Failed to connect to host")?;

    tracing::info!("Connected to {}", remote_id.fmt_short());

    Ok((conn, false))
}

/// Return the protocol version negotiated on a connection.
/// Returns 2 for `hop/2`, 1 for `hop/1`, 0 for `hop/0` or anything else.
pub fn negotiated_protocol_version(conn: &Connection) -> u8 {
    let alpn = conn.alpn();
    if alpn == ALPN_V2 {
        2
    } else if alpn == ALPN_V1 {
        1
    } else {
        0
    }
}

/// Get the EndpointId (public key) of an endpoint.
pub fn endpoint_id(endpoint: &Endpoint) -> EndpointId {
    endpoint.id()
}
