//! iroh endpoint lifecycle and connection management.

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId, PublicKey, RelayMode, RelayUrl, SecretKey, TransportAddr};

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
/// Tries `hop/1` first; falls back to `hop/0` if the host doesn't support v1.
/// If a relay URL is provided, it's included in the endpoint address so iroh
/// can connect via relay immediately rather than waiting for DNS discovery.
/// If the relay hint fails (stale URL), automatically retries without it so
/// discovery can find the host via DNS.
///
/// Returns `(connection, relay_hint_failed)` — callers should clear a stored
/// relay URL from known_hosts when `relay_hint_failed` is true.
pub async fn connect_to_host(
    endpoint: &Endpoint,
    remote_id: PublicKey,
    relay_url: Option<&RelayUrl>,
) -> Result<(Connection, bool)> {
    if let Some(url) = relay_url {
        let addr = EndpointAddr::from_parts(remote_id, [TransportAddr::Relay(url.clone())]);

        // Try with relay hint first (3s timeout), then fall back to discovery
        let relay_result = tokio::time::timeout(
            std::time::Duration::from_secs(3),
            connect_with_alpn_fallback(endpoint, addr),
        )
        .await;

        match relay_result {
            Ok(Ok(conn)) => return Ok((conn, false)),
            Ok(Err(e)) => {
                tracing::info!("Relay hint failed ({e:#}), falling back to discovery");
            }
            Err(_) => {
                tracing::info!("Relay hint timed out, falling back to discovery");
            }
        }

        // Relay failed — connect via discovery and signal that the hint was bad
        let addr = EndpointAddr::from(remote_id);
        let conn = connect_with_alpn_fallback(endpoint, addr)
            .await
            .context("Failed to connect to host")?;
        return Ok((conn, true));
    }

    // No relay hint — default to our relay so old invites without a relay
    // URL still get the fast path.
    let hop_relay: RelayUrl = HOP_RELAY_URL.parse().expect("valid relay URL");
    let addr = EndpointAddr::from_parts(remote_id, [TransportAddr::Relay(hop_relay)]);

    let relay_result = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        connect_with_alpn_fallback(endpoint, addr),
    )
    .await;

    match relay_result {
        Ok(Ok(conn)) => return Ok((conn, false)),
        Ok(Err(e)) => {
            tracing::info!("Default relay failed ({e:#}), falling back to discovery");
        }
        Err(_) => {
            tracing::info!("Default relay timed out, falling back to discovery");
        }
    }

    let addr = EndpointAddr::from(remote_id);
    let conn = connect_with_alpn_fallback(endpoint, addr)
        .await
        .context("Failed to connect to host")?;
    Ok((conn, false))
}

/// Try connecting with hop/2 ALPN, falling back to hop/1, then hop/0.
async fn connect_with_alpn_fallback(
    endpoint: &Endpoint,
    addr: EndpointAddr,
) -> Result<Connection> {
    match endpoint.connect(addr.clone(), ALPN_V2).await {
        Ok(conn) => Ok(conn),
        Err(_) => match endpoint.connect(addr.clone(), ALPN_V1).await {
            Ok(conn) => Ok(conn),
            Err(_) => {
                endpoint
                    .connect(addr, ALPN_V0)
                    .await
                    .context("Failed to connect")
            }
        },
    }
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
