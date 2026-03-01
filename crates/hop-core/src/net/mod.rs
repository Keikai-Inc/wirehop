//! iroh endpoint lifecycle and connection management.

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointAddr, EndpointId, PublicKey, RelayUrl, SecretKey, TransportAddr};

use crate::proto::ALPN;

/// Create an iroh endpoint configured for hosting (accepting connections).
///
/// Waits for the endpoint to come online (connected to relay, address published
/// to discovery) before returning.
pub async fn create_host_endpoint(secret_key: SecretKey) -> Result<Endpoint> {
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
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

    let conn = endpoint
        .connect(addr, ALPN)
        .await
        .context("Failed to connect to host")?;

    Ok(conn)
}

/// Get the EndpointId (public key) of an endpoint.
pub fn endpoint_id(endpoint: &Endpoint) -> EndpointId {
    endpoint.id()
}
