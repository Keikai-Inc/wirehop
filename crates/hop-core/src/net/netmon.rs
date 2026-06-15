//! Lightweight interface poller that detects IP address changes and kicks
//! iroh's re-discovery via `endpoint.network_change()`.
//!
//! Belt-and-suspenders over iroh's built-in `netwatch` — catches interface
//! changes that the OS-level socket monitor sometimes misses (e.g. plugging
//! in ethernet on macOS).

use std::collections::BTreeSet;
use std::net::IpAddr;
use std::time::Duration;

use iroh::Endpoint;

/// Poll interval for interface address checks. 2s catches WiFi/cellular
/// handoffs quickly enough to trigger path migration before QUIC times out.
const POLL_INTERVAL: Duration = Duration::from_secs(2);

/// Probe the home relay's HTTPS endpoint every 30s. Catches cert expiry,
/// relay crashes, and silent iroh<->relay session breakage that the
/// interface-address watcher misses.
const RELAY_PROBE_INTERVAL: Duration = Duration::from_secs(30);

/// Time budget for a single relay probe (connect + TLS + HTTP response).
const RELAY_PROBE_TIMEOUT: Duration = Duration::from_secs(5);

/// Consecutive failures before forcing re-discovery. 3 × 30s = ~90s of
/// sustained brokenness before recovery — tolerates transient blips while
/// still beating the 30+ minute silent failure we hit on cert expiry.
const RELAY_FAILURE_THRESHOLD: u32 = 3;

/// Enumerate all non-loopback, non-link-local interface IP addresses.
#[cfg(unix)]
pub fn current_interface_addrs() -> BTreeSet<IpAddr> {
    let mut addrs = BTreeSet::new();

    let ifaddrs = match nix::ifaddrs::getifaddrs() {
        Ok(iter) => iter,
        Err(e) => {
            tracing::warn!("getifaddrs failed: {e}");
            return addrs;
        }
    };

    for ifa in ifaddrs {
        let Some(addr) = ifa.address else { continue };

        let ip = addr.as_sockaddr_in().map(|sin| IpAddr::V4(sin.ip()))
            .or_else(|| addr.as_sockaddr_in6().map(|sin6| IpAddr::V6(sin6.ip())));

        if let Some(ip) = ip {
            let skip = match ip {
                IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local(),
                IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xffc0) == 0xfe80,
            };
            if !skip {
                addrs.insert(ip);
            }
        }
    }

    addrs
}

/// Spawn a background task that polls interface addresses every 5 seconds.
///
/// When a change is detected:
/// - Calls `endpoint.network_change()` to force iroh to re-probe paths
/// - Logs added/removed addresses at INFO level
/// - If `flush_tx` is provided, waits 2s for QUIC path migration then signals
///   the caller to flush pooled connections (agent side)
pub fn spawn_interface_watcher(
    endpoint: Endpoint,
    flush_tx: Option<tokio::sync::mpsc::Sender<()>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut prev = current_interface_addrs();
        tracing::info!("Network monitor started, tracking {} address(es)", prev.len());

        loop {
            tokio::time::sleep(POLL_INTERVAL).await;

            let curr = current_interface_addrs();
            if curr != prev {
                let added: Vec<_> = curr.difference(&prev).collect();
                let removed: Vec<_> = prev.difference(&curr).collect();

                tracing::info!(
                    "Network interfaces changed: added={:?}, removed={:?}",
                    added,
                    removed
                );

                endpoint.network_change().await;
                tracing::info!("Triggered iroh network re-discovery");

                // Give QUIC path migration 2s to recover, then flush stale connections
                if let Some(ref tx) = flush_tx {
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let _ = tx.send(()).await;
                    tracing::info!("Signaled connection pool flush after network change");
                }

                prev = curr;
            }
        }
    })
}

/// Spawn a background task that probes the home relay's HTTPS endpoint.
///
/// On `RELAY_FAILURE_THRESHOLD` consecutive failures, logs at ERROR and calls
/// `endpoint.network_change()` to force iroh to drop its current relay session
/// and re-handshake. Catches failure modes the interface watcher misses:
/// expired TLS cert, relay process crash, network partition, or a hung iroh
/// relay-client task. The daemon's existing TCP session can stay ESTABLISHED
/// long after the relay link is functionally dead — this watcher closes that gap.
///
/// `flush_tx` (agent side): when re-discovery is forced, signal the caller to
/// flush pooled connections. A move between networks that keeps the same local
/// interface address (e.g. similar DHCP range, or carried while asleep) won't
/// trip the interface watcher, so the relay probe is the only thing that notices
/// the path died — and the stale pooled connections must be dropped so the next
/// connect re-dials instead of proxying onto a dead path.
pub fn spawn_relay_health_watcher(
    endpoint: Endpoint,
    flush_tx: Option<tokio::sync::mpsc::Sender<()>>,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let client = match reqwest::Client::builder()
            .timeout(RELAY_PROBE_TIMEOUT)
            .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::warn!("Relay health watcher: failed to build http client: {e}");
                return;
            }
        };

        tracing::info!(
            "Relay health watcher started (interval={}s, threshold={})",
            RELAY_PROBE_INTERVAL.as_secs(),
            RELAY_FAILURE_THRESHOLD
        );

        let mut consecutive_failures: u32 = 0;

        loop {
            tokio::time::sleep(RELAY_PROBE_INTERVAL).await;

            let Some(relay_url) = endpoint.addr().relay_urls().next().cloned() else {
                // No home relay (LOCAL_ONLY mode or still bootstrapping). Skip.
                continue;
            };

            let probe_url = format!("{}generate_204", relay_url.as_str());

            match client.get(&probe_url).send().await {
                Ok(resp) if resp.status().is_success() => {
                    if consecutive_failures > 0 {
                        tracing::info!(
                            "Relay health restored after {} consecutive failures",
                            consecutive_failures
                        );
                    }
                    consecutive_failures = 0;
                }
                Ok(resp) => {
                    consecutive_failures += 1;
                    tracing::warn!(
                        "Relay health probe to {} returned HTTP {} (failure {}/{})",
                        probe_url,
                        resp.status(),
                        consecutive_failures,
                        RELAY_FAILURE_THRESHOLD
                    );
                }
                Err(e) => {
                    consecutive_failures += 1;
                    tracing::warn!(
                        "Relay health probe to {} failed: {e} (failure {}/{})",
                        probe_url,
                        consecutive_failures,
                        RELAY_FAILURE_THRESHOLD
                    );
                }
            }

            if consecutive_failures >= RELAY_FAILURE_THRESHOLD {
                tracing::error!(
                    "Relay {} unreachable after {} consecutive probes — forcing iroh re-discovery",
                    relay_url,
                    consecutive_failures
                );
                endpoint.network_change().await;
                if let Some(ref tx) = flush_tx {
                    // Give QUIC path migration a moment, then drop stale pooled
                    // connections so the next connect re-dials on the new path.
                    tokio::time::sleep(Duration::from_secs(2)).await;
                    let _ = tx.send(()).await;
                    tracing::info!("Signaled connection pool flush after relay re-discovery");
                }
                consecutive_failures = 0;
            }
        }
    })
}
