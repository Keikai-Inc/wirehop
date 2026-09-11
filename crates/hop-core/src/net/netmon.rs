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

/// Enumerate the interface IP addresses that count as "the network": every
/// non-loopback, non-link-local address, minus IPv6 addresses the OS is
/// rotating on its own schedule (see [`transient_ipv6`]).
///
/// macOS mints a new *temporary* (privacy, RFC 4941) IPv6 address roughly daily
/// and retires the old one a while later. Neither event changes where this host
/// can be reached — the stable address, the IPv4 address and the relay session
/// are untouched — but each one used to count as a network change here: iroh
/// re-discovery plus a mux pool flush, in the middle of whatever sessions were
/// up. In the 2026-09-11 incident the one host-side event during the outage
/// was exactly such a rotation. Interface up/down, default-route and stable
/// address changes still register.
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

    let transient = transient_ipv6();

    for ifa in ifaddrs {
        let Some(addr) = ifa.address else { continue };

        let ip = addr.as_sockaddr_in().map(|sin| IpAddr::V4(sin.ip()))
            .or_else(|| addr.as_sockaddr_in6().map(|sin6| IpAddr::V6(sin6.ip())));

        if let Some(ip) = ip {
            let skip = match ip {
                IpAddr::V4(v4) => v4.is_loopback() || v4.is_link_local(),
                IpAddr::V6(v6) => {
                    v6.is_loopback()
                        || (v6.segments()[0] & 0xffc0) == 0xfe80
                        || transient.contains(&v6)
                }
            };
            if !skip {
                addrs.insert(ip);
            }
        }
    }

    addrs
}

/// IPv6 addresses that are temporary (privacy), deprecated or still tentative
/// on some interface — the ones the OS churns on its own and that must not
/// register as a network change. Empty when the platform query is unavailable
/// (then every address counts, as before).
#[cfg(target_os = "macos")]
fn transient_ipv6() -> BTreeSet<std::net::Ipv6Addr> {
    macos_in6::transient_ipv6()
}

#[cfg(target_os = "linux")]
fn transient_ipv6() -> BTreeSet<std::net::Ipv6Addr> {
    std::fs::read_to_string("/proc/net/if_inet6")
        .map(|text| parse_if_inet6_transient(&text))
        .unwrap_or_default()
}

#[cfg(all(unix, not(any(target_os = "macos", target_os = "linux"))))]
fn transient_ipv6() -> BTreeSet<std::net::Ipv6Addr> {
    BTreeSet::new()
}

/// Parse Linux `/proc/net/if_inet6` and return the addresses flagged
/// temporary (`IFA_F_TEMPORARY` 0x01), deprecated (0x20) or tentative (0x40).
/// Line format: `<32 hex addr> <ifindex> <prefixlen> <scope> <flags> <ifname>`.
#[allow(dead_code)] // only wired in on Linux; tested everywhere
fn parse_if_inet6_transient(text: &str) -> BTreeSet<std::net::Ipv6Addr> {
    const IFA_F_TEMPORARY: u32 = 0x01;
    const IFA_F_DEPRECATED: u32 = 0x20;
    const IFA_F_TENTATIVE: u32 = 0x40;
    let mut out = BTreeSet::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 5 || fields[0].len() != 32 {
            continue;
        }
        let Ok(flags) = u32::from_str_radix(fields[4], 16) else { continue };
        if flags & (IFA_F_TEMPORARY | IFA_F_DEPRECATED | IFA_F_TENTATIVE) == 0 {
            continue;
        }
        let Ok(raw) = u128::from_str_radix(fields[0], 16) else { continue };
        out.insert(std::net::Ipv6Addr::from(raw));
    }
    out
}

/// `SIOCGIFAFLAG_IN6` on Darwin: per-address IPv6 flags (`IN6_IFF_*`).
#[cfg(target_os = "macos")]
mod macos_in6 {
    use std::collections::BTreeSet;
    use std::net::Ipv6Addr;
    use std::os::fd::AsRawFd;

    /// `struct in6_ifreq` is 288 bytes on Darwin: `char ifr_name[16]` followed
    /// by a union whose first member is `struct sockaddr_in6 ifru_addr` (28
    /// bytes) and which also aliases `int ifru_flags6` at its start.
    const IN6_IFREQ_LEN: usize = 288;
    /// `_IOWR('i', 73, struct in6_ifreq)` with that size encoded.
    const SIOCGIFAFLAG_IN6: libc::c_ulong = 0xC120_6949;
    const IN6_IFF_TENTATIVE: i32 = 0x0002;
    const IN6_IFF_DUPLICATED: i32 = 0x0004;
    const IN6_IFF_DETACHED: i32 = 0x0008;
    const IN6_IFF_DEPRECATED: i32 = 0x0010;
    const IN6_IFF_TEMPORARY: i32 = 0x0080;
    const TRANSIENT: i32 = IN6_IFF_TENTATIVE
        | IN6_IFF_DUPLICATED
        | IN6_IFF_DETACHED
        | IN6_IFF_DEPRECATED
        | IN6_IFF_TEMPORARY;

    pub(super) fn transient_ipv6() -> BTreeSet<Ipv6Addr> {
        let mut out = BTreeSet::new();
        let Ok(ifaddrs) = nix::ifaddrs::getifaddrs() else { return out };
        let Ok(sock) = nix::sys::socket::socket(
            nix::sys::socket::AddressFamily::Inet6,
            nix::sys::socket::SockType::Datagram,
            nix::sys::socket::SockFlag::empty(),
            None,
        ) else {
            return out;
        };
        for ifa in ifaddrs {
            let Some(addr) = ifa.address else { continue };
            let Some(sin6) = addr.as_sockaddr_in6() else { continue };
            let ip = sin6.ip();
            if ip.is_loopback() || (ip.segments()[0] & 0xffc0) == 0xfe80 {
                continue;
            }
            if let Some(flags) = addr_flags(sock.as_raw_fd(), &ifa.interface_name, sin6)
                && flags & TRANSIENT != 0
            {
                out.insert(ip);
            }
        }
        out
    }

    fn addr_flags(fd: i32, ifname: &str, sin6: &nix::sys::socket::SockaddrIn6) -> Option<i32> {
        let mut req = [0u8; IN6_IFREQ_LEN];
        let name = ifname.as_bytes();
        if name.is_empty() || name.len() >= 16 {
            return None;
        }
        req[..name.len()].copy_from_slice(name);
        let sa: libc::sockaddr_in6 = *sin6.as_ref();
        // SAFETY: `req` is a zeroed 288-byte buffer laid out as in6_ifreq; the
        // sockaddr_in6 (28 bytes) is written at the union's offset (16) with an
        // unaligned copy, which is what the kernel reads for SIOCGIFAFLAG_IN6.
        unsafe {
            std::ptr::write_unaligned(req.as_mut_ptr().add(16) as *mut libc::sockaddr_in6, sa);
            if libc::ioctl(fd, SIOCGIFAFLAG_IN6, req.as_mut_ptr()) != 0 {
                return None;
            }
        }
        // The kernel writes `ifru_flags6` (an int) at the union's start.
        Some(i32::from_ne_bytes([req[16], req[17], req[18], req[19]]))
    }
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
                // ANY HTTP response — even 404 — proves the relay host is
                // REACHABLE: its TLS handshake and HTTP server answered. iroh-relay
                // does NOT serve `/generate_204` (it 404s), so the old
                // `is_success()` check counted every single probe as a failure,
                // tripped the threshold every ~90s, forced `network_change()` + a
                // connection-pool flush, and dropped the active hop session
                // ("Connection lost") on a perfectly healthy relay — while the VPN
                // (which doesn't ride the mux pool) stayed up. Only a
                // connection-level error means the relay is actually unreachable.
                Ok(resp) => {
                    if consecutive_failures > 0 {
                        tracing::info!(
                            "Relay reachable again (HTTP {}) after {} consecutive failures",
                            resp.status(),
                            consecutive_failures
                        );
                    }
                    consecutive_failures = 0;
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn if_inet6_parser_keeps_only_transient_flags() {
        let text = "\
20010db8000000000000000000000001 02 40 00 80 eth0
20010db800000000abcdef0123456789 02 40 00 01 eth0
20010db80000000011111111222222aa 02 40 00 21 eth0
20010db80000000011111111222222bb 02 40 00 40 eth0
00000000000000000000000000000001 01 80 10 80 lo
fe800000000000000000000000000001 02 40 20 80 eth0
garbage line
";
        let got = parse_if_inet6_transient(text);
        let a = |s: &str| s.parse::<std::net::Ipv6Addr>().unwrap();
        assert!(!got.contains(&a("2001:db8::1")), "permanent (0x80) stays");
        assert!(got.contains(&a("2001:db8::abcd:ef01:2345:6789")), "temporary (0x01) filtered");
        assert!(got.contains(&a("2001:db8::1111:1111:2222:22aa")), "deprecated (0x20) filtered");
        assert!(got.contains(&a("2001:db8::1111:1111:2222:22bb")), "tentative (0x40) filtered");
        assert_eq!(got.len(), 3);
    }

    #[cfg(unix)]
    #[test]
    fn current_addrs_excludes_transient_ipv6() {
        // Whatever this machine has, no transient address may leak through.
        let transient = transient_ipv6();
        let addrs = current_interface_addrs();
        for t in &transient {
            assert!(!addrs.contains(&IpAddr::V6(*t)), "{t} is transient but was reported");
        }
    }
}
