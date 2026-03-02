//! iroh endpoint lifecycle and connection management.

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId, PublicKey, RelayUrl, SecretKey, TransportAddr};

use crate::proto::{ALPN_V0, ALPN_V1};

/// Create an iroh endpoint configured for hosting (accepting connections).
///
/// Waits for the endpoint to come online (connected to relay, address published
/// to discovery) before returning.
pub async fn create_host_endpoint(secret_key: SecretKey) -> Result<Endpoint> {
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![ALPN_V1.to_vec(), ALPN_V0.to_vec()])
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
pub async fn create_client_endpoint(secret_key: SecretKey) -> Result<Endpoint> {
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .bind()
        .await
        .context("Failed to bind iroh endpoint")?;

    endpoint.online().await;

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
pub async fn connect_to_host(
    endpoint: &Endpoint,
    remote_id: PublicKey,
    relay_url: Option<&RelayUrl>,
) -> Result<Connection> {
    let addr = match relay_url {
        Some(url) => {
            EndpointAddr::from_parts(remote_id, [TransportAddr::Relay(url.clone())])
        }
        None => EndpointAddr::from(remote_id),
    };

    // Try hop/1 first, fall back to hop/0
    let conn = match endpoint.connect(addr.clone(), ALPN_V1).await {
        Ok(conn) => conn,
        Err(_) => {
            endpoint
                .connect(addr, ALPN_V0)
                .await
                .context("Failed to connect to host")?
        }
    };

    Ok(conn)
}

/// Return the protocol version negotiated on a connection.
/// Returns 1 for `hop/1`, 0 for `hop/0` or anything else.
pub fn negotiated_protocol_version(conn: &Connection) -> u8 {
    if conn.alpn() == ALPN_V1 {
        1
    } else {
        0
    }
}

/// Get the EndpointId (public key) of an endpoint.
pub fn endpoint_id(endpoint: &Endpoint) -> EndpointId {
    endpoint.id()
}
