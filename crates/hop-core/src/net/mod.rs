//! iroh endpoint lifecycle and connection management.

use anyhow::{Context, Result};
use iroh::endpoint::Connection;
use iroh::{Endpoint, EndpointId, PublicKey, SecretKey};

use crate::proto::ALPN;

/// Create an iroh endpoint configured for hosting (accepting connections).
pub async fn create_host_endpoint(secret_key: SecretKey) -> Result<Endpoint> {
    let endpoint = Endpoint::builder()
        .secret_key(secret_key)
        .alpns(vec![ALPN.to_vec()])
        .bind()
        .await
        .context("Failed to bind iroh endpoint")?;

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

    Ok(endpoint)
}

/// Connect to a remote host by their EndpointId (PublicKey).
pub async fn connect_to_host(
    endpoint: &Endpoint,
    remote_id: PublicKey,
) -> Result<Connection> {
    let conn = endpoint
        .connect(remote_id, ALPN)
        .await
        .context("Failed to connect to host")?;

    Ok(conn)
}

/// Get the EndpointId (public key) of an endpoint.
pub fn endpoint_id(endpoint: &Endpoint) -> EndpointId {
    endpoint.id()
}
