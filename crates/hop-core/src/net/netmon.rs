//! Lightweight interface poller that detects IP address changes and kicks
//! iroh's re-discovery via `endpoint.network_change()`.
//!
//! Belt-and-suspenders over iroh's built-in `netwatch` — catches interface
//! changes that the OS-level socket monitor sometimes misses (e.g. plugging
//! in ethernet on macOS).

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;

use iroh::endpoint::Connection;
use iroh::{Endpoint, PublicKey};
use tokio::sync::Mutex;

/// Poll interval for interface address checks.
const POLL_INTERVAL: Duration = Duration::from_secs(5);

/// Enumerate all non-loopback, non-link-local interface IP addresses.
///
/// Uses `libc::getifaddrs` on Unix (libc is already a hop-core dependency).
#[cfg(unix)]
pub fn current_interface_addrs() -> BTreeSet<IpAddr> {
    use std::net::{Ipv4Addr, Ipv6Addr};

    let mut addrs = BTreeSet::new();

    unsafe {
        let mut ifaddrs: *mut libc::ifaddrs = std::ptr::null_mut();
        if libc::getifaddrs(&mut ifaddrs) != 0 {
            tracing::warn!("getifaddrs failed: {}", std::io::Error::last_os_error());
            return addrs;
        }

        let mut cursor = ifaddrs;
        while !cursor.is_null() {
            let ifa = &*cursor;
            if !ifa.ifa_addr.is_null() {
                let family = (*ifa.ifa_addr).sa_family as i32;

                let ip = if family == libc::AF_INET {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in);
                    let octets = sa.sin_addr.s_addr.to_ne_bytes();
                    Some(IpAddr::V4(Ipv4Addr::from(octets)))
                } else if family == libc::AF_INET6 {
                    let sa = &*(ifa.ifa_addr as *const libc::sockaddr_in6);
                    Some(IpAddr::V6(Ipv6Addr::from(sa.sin6_addr.s6_addr)))
                } else {
                    None
                };

                if let Some(ip) = ip {
                    // Skip loopback and link-local
                    let dominated = match ip {
                        IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local(),
                        IpAddr::V6(v6) => v6.is_loopback() || (v6.segments()[0] & 0xffc0) == 0xfe80,
                    };
                    if !dominated {
                        addrs.insert(ip);
                    }
                }
            }
            cursor = ifa.ifa_next;
        }

        libc::freeifaddrs(ifaddrs);
    }

    addrs
}

/// Spawn a background task that polls interface addresses every 5 seconds.
///
/// When a change is detected:
/// - Calls `endpoint.network_change()` to force iroh to re-probe paths
/// - Logs added/removed addresses at INFO level
///
/// Does NOT flush pooled connections — QUIC supports path migration, so
/// connections survive IP changes. Dead connections are detected lazily
/// via `close_reason()` in `get_or_connect()`.
pub fn spawn_interface_watcher(
    endpoint: Endpoint,
    _connections: Option<Arc<Mutex<HashMap<PublicKey, Connection>>>>,
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

                prev = curr;
            }
        }
    })
}
