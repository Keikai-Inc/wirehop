//! iroh endpoint lifecycle and connection management.

pub mod netmon;

use std::time::Duration;

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, QuicTransportConfig, presets};
use iroh::{Endpoint, EndpointAddr, EndpointId, PublicKey, RelayMode, RelayUrl, SecretKey};

use crate::proto::{ALPN_V0, ALPN_V1, ALPN_V2, ALPN_V3};

/// Hop's own relay server.
pub const HOP_RELAY_URL: &str = "https://relay.keik.ai";

/// QUIC transport configuration tuned for resilience on spotty networks.
///
/// **Connection-level:**
/// - 60s idle timeout: survives WiFi handoffs (5-15s), cellular tower switches
///   (10-30s), and brief relay hiccups. Still detects truly dead peers in ~1 min.
/// - 5s keepalive: 12 missed probes before death. ~40 bytes/5s is negligible.
/// - 300ms initial RTT estimate for cellular (prevents aggressive retransmission
///   before QUIC measures actual RTT).
///
/// **Multipath QUIC (draft-ietf-quic-multipath):**
/// - Up to 13 concurrent paths (WiFi + cellular + relay simultaneously).
///   Individual path failures don't kill the connection — traffic migrates to
///   surviving paths automatically. Single biggest resilience improvement.
/// - Per-path keepalive (5s) and idle timeout (20s) detect dead paths and
///   replace them well before the 60s connection timeout. The 20s gives a 4x
///   margin over the 5s keepalive: a single delayed probe (busy executor,
///   scheduler hiccup, or a link saturated by a large paste) no longer reaps
///   the path. This matters most on single-path connections (e.g. a plain
///   local network) where path death == connection death == a user-visible
///   reconnect — the old 6.5s timeout tolerated barely one missed probe and
///   caused spurious reconnects every few minutes. Active-path failover is
///   unaffected: it's driven by ACK/loss detection, not the idle timer.
///
/// **NAT traversal address discovery:**
/// - Peers exchange observed addresses to help discover their public IP behind
///   NAT. Improves direct connection establishment and holepunching success.
fn hop_transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        // Connection-level timeouts
        .max_idle_timeout(Some(Duration::from_secs(60).try_into().expect("valid idle timeout")))
        .keep_alive_interval(Duration::from_secs(5))
        .initial_rtt(Duration::from_millis(300))
        // Multipath: use up to 13 paths simultaneously (WiFi, cellular, relay, etc.)
        .max_concurrent_multipath_paths(13)
        .default_path_keep_alive_interval(Duration::from_secs(5))
        .default_path_max_idle_timeout(Duration::from_secs(20))
        // NAT traversal: exchange observed addresses for better holepunching
        .send_observed_address_reports(true)
        .receive_observed_address_reports(true)
        .set_max_remote_nat_traversal_addresses(12)
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
    // presets::N0 matches iroh 0.96's default builder (n0 DNS/pkarr address
    // lookup so peers are findable by EndpointId). hop overrides the relay below
    // with its own custom relay; the n0 relay default from the preset is replaced.
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .relay_mode(hop_relay_mode())
        .transport_config(hop_transport_config())
        .alpns(vec![ALPN_V3.to_vec(), ALPN_V2.to_vec(), ALPN_V1.to_vec(), ALPN_V0.to_vec()])
        .bind()
        .await
        .context("Failed to bind iroh endpoint")?;

    // Wait until connected to relay and address is published to discovery.
    // Without this, clients cannot find us. Timeout after 30s to avoid
    // hanging forever if the relay is unreachable.
    if tokio::time::timeout(std::time::Duration::from_secs(30), endpoint.online())
        .await
        .is_err()
    {
        tracing::warn!("Relay did not come online within 30s — host may be unreachable via relay");
    }

    Ok(endpoint)
}

/// Create an iroh endpoint configured for connecting (client mode).
/// Client endpoints don't need to accept connections, so no ALPNs.
///
/// Waits up to 5 seconds for the relay to come online. Clients can still
/// connect via discovery if the relay is slow, so we proceed regardless.
pub async fn create_client_endpoint(secret_key: SecretKey) -> Result<Endpoint> {
    let endpoint = Endpoint::builder(presets::N0)
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

/// Derive a stable, dedicated secret key for the network-document endpoint.
///
/// The netdoc replication endpoint runs as a *separate* iroh endpoint (distinct
/// NodeId) from the host's shell/auth endpoint, so the new iroh-docs stack is
/// fully isolated from the battle-tested connection path. Deriving the key from
/// the host secret keeps the netdoc NodeId stable across restarts without
/// storing a second secret on disk.
pub fn derive_netdoc_secret_key(host_secret: &SecretKey) -> SecretKey {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(host_secret.to_bytes());
    h.update(b"hop-netdoc-endpoint-v1");
    let out = h.finalize();
    let mut bytes = [0u8; 32];
    bytes.copy_from_slice(&out);
    SecretKey::from_bytes(&bytes)
}

/// Create the iroh endpoint for the network-document (replication) stack.
///
/// Like [`create_host_endpoint`] but binds **no ALPNs** — the iroh-docs/gossip/
/// blobs `Router` registers its own ALPNs on this endpoint when it spawns. Uses
/// hop's custom relay so doc replication flows through controlled infrastructure.
pub async fn create_netdoc_endpoint(secret_key: SecretKey) -> Result<Endpoint> {
    let endpoint = Endpoint::builder(presets::N0)
        .secret_key(secret_key)
        .relay_mode(hop_relay_mode())
        .transport_config(hop_transport_config())
        .bind()
        .await
        .context("Failed to bind netdoc endpoint")?;

    if tokio::time::timeout(std::time::Duration::from_secs(10), endpoint.online())
        .await
        .is_err()
    {
        tracing::warn!("netdoc relay did not come online within 10s, proceeding anyway");
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

    tracing::debug!("EndpointAddr for {}: relay_urls={:?}, direct_addrs={:?}",
        remote_id.fmt_short(),
        addr.relay_urls().collect::<Vec<_>>(),
        addr.ip_addrs().collect::<Vec<_>>());

    tracing::info!("Connecting to {} (relay hint: {}, alpn: {})",
        remote_id.fmt_short(), relay_url.is_some(),
        std::str::from_utf8(alpn).unwrap_or("?"));

    let conn = tokio::time::timeout(
        std::time::Duration::from_secs(30),
        endpoint.connect(addr, alpn),
    )
    .await
    .map_err(|_| anyhow::anyhow!(
        "Connection timed out after 30s. The host may be offline, behind a strict firewall, \
         or unable to reach the relay. Check that the host daemon is running and has network access."
    ))?
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
