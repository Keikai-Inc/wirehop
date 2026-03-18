//! iroh endpoint lifecycle and connection management.

pub mod netmon;

use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, QuicTransportConfig};
use iroh::{Endpoint, EndpointAddr, EndpointId, PublicKey, RelayMode, RelayUrl, SecretKey};

use crate::proto::{ALPN_V0, ALPN_V1, ALPN_V2, ALPN_V3};

/// Hop's own relay server.
pub const HOP_RELAY_URL: &str = "https://relay.keik.ai";

/// QUIC transport configuration tuned for lossy networks (cellular, satellite).
///
/// - 30s idle timeout (iroh's default; survives 25s of packet loss instead of 6s)
/// - 5s keepalive interval (still frequent, fewer wasted packets on metered links)
/// - 300ms initial RTT estimate for cellular (prevents aggressive retransmission
///   before QUIC measures actual RTT)
fn hop_transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .max_idle_timeout(Some(Duration::from_secs(30).try_into().expect("valid idle timeout")))
        .keep_alive_interval(Duration::from_secs(5))
        .initial_rtt(Duration::from_millis(300))
        .build()
}

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
        .transport_config(hop_transport_config())
        .alpns(vec![ALPN_V3.to_vec(), ALPN_V2.to_vec(), ALPN_V1.to_vec(), ALPN_V0.to_vec()])
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
        .transport_config(hop_transport_config())
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
/// When a relay URL is provided (from known_hosts or invite tokens), it's
/// included as a hint so iroh can immediately relay traffic while also
/// attempting direct paths via discovery. Without the hint, iroh must
/// discover the relay URL via DNS/pkarr first, which can delay or fail.
pub async fn connect_to_host(
    endpoint: &Endpoint,
    remote_id: PublicKey,
    relay_url: Option<&RelayUrl>,
) -> Result<(Connection, bool)> {
    connect_to_host_with_alpn(endpoint, remote_id, relay_url, ALPN_V2).await
}

/// Connect with a specific ALPN protocol version.
pub async fn connect_to_host_with_alpn(
    endpoint: &Endpoint,
    remote_id: PublicKey,
    relay_url: Option<&RelayUrl>,
    alpn: &[u8],
) -> Result<(Connection, bool)> {
    let addr = if let Some(relay) = relay_url {
        EndpointAddr::from(remote_id).with_relay_url(relay.clone())
    } else {
        EndpointAddr::from(remote_id)
    };

    tracing::info!("Connecting to {} (relay hint: {}, alpn: {})",
        remote_id.fmt_short(), relay_url.is_some(),
        std::str::from_utf8(alpn).unwrap_or("?"));

    let conn = endpoint
        .connect(addr, alpn)
        .await
        .context("Failed to connect to host")?;

    tracing::info!("Connected to {} ({})", remote_id.fmt_short(),
        std::str::from_utf8(conn.alpn()).unwrap_or("?"));

    Ok((conn, false))
}

/// Return the protocol version negotiated on a connection.
/// Returns 3 for `hop/3`, 2 for `hop/2`, 1 for `hop/1`, 0 for `hop/0` or anything else.
pub fn negotiated_protocol_version(conn: &Connection) -> u8 {
    let alpn = conn.alpn();
    if alpn == ALPN_V3 {
        3
    } else if alpn == ALPN_V2 {
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
