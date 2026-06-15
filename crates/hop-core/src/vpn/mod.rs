//! VPN data plane (Phase 3 — see `docs/technical/p2p-network.md`).
//!
//! **Status: experimental, opt-in, off by default.** Nothing in this module
//! runs unless the VPN is explicitly enabled. The pieces here are the routing
//! core (IPv4 destination parsing + virtual-IP → peer lookup against the network
//! document) and the `hop/vpn/v1` ALPN. The TUN device + forwarding loop wire
//! these together and are gated behind an explicit enable so a release can never
//! change the daemon's default networking behavior.

use std::net::Ipv4Addr;

/// ALPN for the VPN packet plane (QUIC datagrams carrying L3 IP packets).
pub const VPN_ALPN: &[u8] = b"hop/vpn/1";

/// TUN MTU. QUIC's effective datagram payload (~1232B after framing) bounds
/// this; 1280 leaves headroom and matches the IPv6 minimum-MTU convention.
pub const VPN_MTU: u16 = 1280;

/// Parse the destination IPv4 address from a raw L3 packet read off a TUN
/// device. Returns `None` for non-IPv4 (e.g. IPv6) or truncated packets.
///
/// A TUN device in this configuration hands us bare IP packets (no Ethernet
/// header). The IPv4 header's destination address is bytes 16..20, valid only
/// when the version nibble is 4 and the packet is at least 20 bytes.
pub fn parse_dest_ipv4(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 {
        return None;
    }
    let version = packet[0] >> 4;
    if version != 4 {
        return None;
    }
    Some(Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]))
}

pub mod acl;
pub mod cedar;
pub mod dns;
pub mod resolver;
pub mod tailscale_import;

/// Parse the destination transport port (TCP/UDP) from a raw L3 packet, if the
/// protocol carries ports and the packet is long enough. ICMP etc. → `None`.
pub fn parse_dest_port(packet: &[u8]) -> Option<u16> {
    if packet.len() < 24 || (packet[0] >> 4) != 4 {
        return None;
    }
    let ihl = (packet[0] & 0x0f) as usize * 4;
    let proto = packet[9];
    // TCP (6) / UDP (17): destination port is bytes 2..4 of the transport header.
    if !(proto == 6 || proto == 17) || packet.len() < ihl + 4 {
        return None;
    }
    Some(u16::from_be_bytes([packet[ihl + 2], packet[ihl + 3]]))
}

/// Parse the source IPv4 address from a raw L3 packet (bytes 12..16).
pub fn parse_src_ipv4(packet: &[u8]) -> Option<Ipv4Addr> {
    if packet.len() < 20 || (packet[0] >> 4) != 4 {
        return None;
    }
    Some(Ipv4Addr::new(packet[12], packet[13], packet[14], packet[15]))
}

/// Whether an address falls in hop's virtual range `100.64.0.0/10`.
pub fn is_virtual_addr(addr: Ipv4Addr) -> bool {
    let o = addr.octets();
    o[0] == 100 && (64..=127).contains(&o[1])
}

/// If another network interface already holds an address in `100.64.0.0/10`,
/// return it. hop's virtual network shares the CGNAT range with Tailscale and
/// some carrier-grade NATs, so when the VPN is left at its default (auto) we
/// refuse to bring up our TUN in that case rather than clobber the existing
/// overlay's route. An explicit `HOP_VPN=1` overrides this guard.
///
/// This runs *before* hop's own TUN exists, so it never matches our own address.
#[cfg(unix)]
pub fn cgnat_range_in_use() -> Option<Ipv4Addr> {
    crate::net::netmon::current_interface_addrs()
        .into_iter()
        .find_map(|ip| match ip {
            std::net::IpAddr::V4(v4) if is_virtual_addr(v4) => Some(v4),
            _ => None,
        })
}

// ── Data plane (unix only; opt-in) ───────────────────────────────────────

/// Netmask for `100.64.0.0/10` (a /10 = `255.192.0.0`).
#[cfg(unix)]
const CGNAT_NETMASK: Ipv4Addr = Ipv4Addr::new(255, 192, 0, 0);

/// Shared slot holding the active TUN device when the VPN is enabled.
/// `None` means the VPN is off — the inbound handler drops datagrams and the
/// daemon's default behavior is entirely unaffected.
#[cfg(unix)]
pub type TunSlot = std::sync::Arc<tokio::sync::RwLock<Option<std::sync::Arc<tun::AsyncDevice>>>>;

/// Create a TUN device bound to `addr` within `100.64.0.0/10` and bring it up.
/// On Linux the kernel installs the /10 route from the netmask; on macOS a
/// point-to-point utun does NOT, so we install it explicitly (`ensure_warren_route`).
#[cfg(unix)]
pub async fn create_tun(addr: Ipv4Addr) -> anyhow::Result<tun::AsyncDevice> {
    use tun::AbstractDevice;
    let mut config = tun::configure();
    config
        .address(addr)
        .netmask(CGNAT_NETMASK)
        .mtu(VPN_MTU)
        .up();
    let dev =
        tun::create_as_async(&config).map_err(|e| anyhow::anyhow!("create TUN device: {e}"))?;
    if let Ok(name) = dev.tun_name()
        && let Err(e) = ensure_warren_route(&name)
    {
        tracing::warn!("vpn: warren route setup on {name} failed: {e:#}");
    }
    // Keep the route asserted across sleep/wake + network changes (non-privsep
    // daemon is root here; under privsep the monitor runs the enforcer).
    spawn_route_enforcer();
    Ok(dev)
}

/// Ensure the warren `100.64.0.0/10` route is pinned to `iface`. macOS p2p utuns
/// don't auto-install the range route from their netmask (Linux does), so without
/// this warren traffic falls through to the default route. Idempotent: a re-add
/// of an existing route is success. macOS-only; a no-op elsewhere. Must run as
/// root (privsep monitor / non-privsep daemon both qualify).
#[cfg(target_os = "macos")]
pub fn ensure_warren_route(iface: &str) -> anyhow::Result<()> {
    // If the /10 route already points at THIS interface, do nothing — the 30s
    // enforcer calls this repeatedly, and tearing a correct route down even
    // briefly would drop in-flight packets.
    if warren_route_iface().as_deref() == Some(iface) {
        return Ok(());
    }
    // Otherwise it's missing OR points at a STALE interface — e.g. a utun from a
    // SIGKILL'd daemon, whose dead route macOS leaves in the table. A plain
    // `route add` would fail "route already exists" and leave the stale route in
    // place (the bug that black-holed traffic after `killall -9`), so delete
    // whatever's there first, then add it fresh to the current interface.
    let _ = std::process::Command::new("/sbin/route")
        .args(["-n", "delete", "-net", "100.64.0.0/10"])
        .output();
    let out = std::process::Command::new("/sbin/route")
        .args(["-n", "add", "-net", "100.64.0.0/10", "-interface", iface])
        .output()
        .map_err(|e| anyhow::anyhow!("spawning route add: {e}"))?;
    anyhow::ensure!(
        out.status.success(),
        "route add 100.64.0.0/10 -> {iface} failed: {}",
        String::from_utf8_lossy(&out.stderr).trim()
    );
    tracing::info!("vpn: installed warren route 100.64.0.0/10 -> {iface}");
    Ok(())
}

/// The interface the routing table currently uses for the warren range, if any
/// (`route -n get` → the `interface:` line). Distinguishes a correct route from
/// a stale one pointing at a dead utun, and lets the enforcer avoid churn.
#[cfg(target_os = "macos")]
fn warren_route_iface() -> Option<String> {
    let out = std::process::Command::new("/sbin/route")
        .args(["-n", "get", "100.64.0.1"]) // representative host in 100.64.0.0/10
        .output()
        .ok()?;
    String::from_utf8_lossy(&out.stdout)
        .lines()
        .find_map(|l| l.trim().strip_prefix("interface:").map(|i| i.trim().to_string()))
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn ensure_warren_route(_iface: &str) -> anyhow::Result<()> {
    Ok(()) // Linux: kernel installs the /10 route from the address/netmask.
}

/// The hop TUN interface name (a `utun*`/`tun*` carrying a `100.64.0.0/10`
/// address), if up. Used by the route enforcer to re-find the device across
/// utun renumbering. macOS-relevant; returns `None` if not found.
#[cfg(target_os = "macos")]
pub fn warren_tun_iface() -> Option<String> {
    let addrs = nix::ifaddrs::getifaddrs().ok()?;
    for ifa in addrs {
        if let Some(v4) = ifa.address.and_then(|a| a.as_sockaddr_in().map(|s| s.ip()))
            && is_virtual_addr(v4)
        {
            return Some(ifa.interface_name);
        }
    }
    None
}

/// Robustly enforce the warren route: every 30s re-find the hop TUN and re-assert
/// its `/10` route, so a route flushed by sleep/wake or a network change is
/// restored without waiting for a daemon restart. macOS-only (Linux's kernel
/// keeps the interface route); must be spawned as root. Never returns.
#[cfg(target_os = "macos")]
pub fn spawn_route_enforcer() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static STARTED: AtomicBool = AtomicBool::new(false);
    if STARTED.swap(true, Ordering::SeqCst) {
        return; // one enforcer per process
    }
    std::thread::spawn(|| {
        loop {
            std::thread::sleep(std::time::Duration::from_secs(30));
            if let Some(iface) = warren_tun_iface()
                && let Err(e) = ensure_warren_route(&iface)
            {
                tracing::debug!("vpn: route re-assert on {iface} failed: {e:#}");
            }
        }
    });
}

#[cfg(all(unix, not(target_os = "macos")))]
pub fn spawn_route_enforcer() {}

/// Address MagicDNS binds on and the OS resolver is pointed at. On Linux the
/// node's own vIP works (the kernel delivers packets addressed to a local
/// interface). On macOS a point-to-point utun routes a query to the node's OWN
/// vIP back *out* the tunnel instead of to the bound socket, so MagicDNS is
/// unreachable on the vIP from the same host — serve on loopback instead, which
/// is always locally deliverable.
pub fn magicdns_bind_addr(vip: Ipv4Addr) -> Ipv4Addr {
    if cfg!(target_os = "macos") {
        Ipv4Addr::LOCALHOST
    } else {
        vip
    }
}

/// `endpoint-id-hex → virtual IP` for every registered VPN node, shared with the
/// `NetDoc` which refreshes it. Used by `VpnInbound` to authenticate ingress.
#[cfg(unix)]
pub type VpnPeerIps = std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, Ipv4Addr>>>;
/// This host's own virtual IP (the only legitimate destination for ingress).
#[cfg(unix)]
pub type VpnLocalIp = std::sync::Arc<tokio::sync::RwLock<Option<Ipv4Addr>>>;

/// Shared notifier that asks the `NetDoc` to refresh `peer_ips` from the
/// document. `VpnInbound` fires it when a datagram arrives from a peer whose
/// registered vIP it doesn't yet know (e.g. just after that peer rebooted), so
/// reconvergence doesn't have to wait for the periodic refresh tick.
#[cfg(unix)]
pub type VpnRefresh = std::sync::Arc<tokio::sync::Notify>;

/// `remote endpoint id hex → live inbound hop/vpn/1 connection`. Registered by
/// `VpnInbound` on accept (newest wins) and shared with the outbound forwarder,
/// which PREFERS it over its own dial cache: after a peer reboots and redials,
/// replies immediately ride the fresh inbound connection instead of a
/// silently-dead cached one (no CLOSE frame is ever received from a rebooted
/// peer, so `close_reason()` can't detect it until the QUIC idle timeout).
#[cfg(unix)]
pub type VpnConns =
    std::sync::Arc<tokio::sync::RwLock<std::collections::HashMap<String, iroh::endpoint::Connection>>>;

/// iroh `ProtocolHandler` for `hop/vpn/1`: writes received QUIC datagrams (L3 IP
/// packets) to the TUN device — **after authenticating ingress** (security-audit
/// C2). A datagram is delivered only if (a) the connecting node is a registered
/// VPN peer, (b) the packet's source virtual IP matches that node's registered
/// IP (anti-spoofing), and (c) the destination is this host's own virtual IP.
/// Dropped silently when the VPN is off.
#[cfg(unix)]
#[derive(Clone)]
pub struct VpnInbound {
    tun: TunSlot,
    peer_ips: VpnPeerIps,
    local_ip: VpnLocalIp,
    refresh: VpnRefresh,
    conns: VpnConns,
}

#[cfg(unix)]
impl std::fmt::Debug for VpnInbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VpnInbound").finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl VpnInbound {
    pub fn new(
        tun: TunSlot,
        peer_ips: VpnPeerIps,
        local_ip: VpnLocalIp,
        refresh: VpnRefresh,
        conns: VpnConns,
    ) -> Self {
        Self { tun, peer_ips, local_ip, refresh, conns }
    }
}

/// Read datagrams off a hop/vpn/1 connection (inbound OR dialed — QUIC
/// datagrams are bidirectional) and deliver each to the TUN after
/// authenticating ingress (security-audit C2). Returns when the connection
/// dies. Shared by `VpnInbound::accept` and the outbound forwarder's dialed
/// connections, so replies sent back over the *same* connection a peer dialed
/// are actually read — the old accept-only pump silently discarded them.
#[cfg(unix)]
pub async fn pump_vpn_datagrams(
    conn: &iroh::endpoint::Connection,
    tun: &TunSlot,
    peer_ips: &VpnPeerIps,
    local_ip: &VpnLocalIp,
    refresh: &VpnRefresh,
) {
    // The authenticated identity of the remote node (QUIC/TLS-verified).
    let remote = conn.remote_id().to_string();
    while let Ok(dg) = conn.read_datagram().await {
        // Look up the peer's authorized vIP *per datagram* (not once up front)
        // so a refresh mid-connection — e.g. after the peer reboots and
        // re-registers — takes effect without dropping the connection.
        let expected_src = peer_ips.read().await.get(&remote).copied();
        let Some(expected) = expected_src else {
            // Unknown peer: ask the NetDoc to refresh from the document. The
            // notify coalesces and the consumer is rate-limited, so a packet
            // flood can't amplify into excessive doc reads.
            tracing::debug!(
                "vpn ingress: DROP datagram from {} — no endpoint→vIP mapping (map has {} entries); refresh requested",
                &remote[..10.min(remote.len())],
                peer_ips.read().await.len()
            );
            refresh.notify_one();
            continue;
        };
        // Anti-spoofing: the packet's source vIP must be this node's vIP. A
        // mismatch can mean the peer changed vIP — refresh and re-check next
        // datagram rather than blackholing it indefinitely.
        match parse_src_ipv4(&dg) {
            Some(src) if src == expected => {}
            _ => {
                refresh.notify_one();
                continue;
            }
        }
        // The datagram must be destined for *us* (our virtual IP).
        if let Some(local) = *local_ip.read().await
            && parse_dest_ipv4(&dg) != Some(local)
        {
            continue;
        }
        if let Some(tun) = tun.read().await.clone() {
            let _ = tun.send(&dg).await;
        }
    }
}

#[cfg(unix)]
impl iroh::protocol::ProtocolHandler for VpnInbound {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        let remote = conn.remote_id().to_string();
        // Register this connection for the outbound forwarder (newest wins): a
        // peer that just rebooted redials us, and replies must ride THIS fresh
        // connection, not a silently-dead cached dial.
        let my_id = conn.stable_id();
        self.conns.write().await.insert(remote.clone(), conn.clone());
        pump_vpn_datagrams(&conn, &self.tun, &self.peer_ips, &self.local_ip, &self.refresh).await;
        // Connection ended — unregister, unless a newer one already replaced it.
        {
            let mut conns = self.conns.write().await;
            if conns.get(&remote).map(|c| c.stable_id()) == Some(my_id) {
                conns.remove(&remote);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal IPv4 packet header with the given src/dst.
    fn ipv4(src: [u8; 4], dst: [u8; 4]) -> Vec<u8> {
        let mut p = vec![0u8; 20];
        p[0] = 0x45; // version 4, IHL 5
        p[12..16].copy_from_slice(&src);
        p[16..20].copy_from_slice(&dst);
        p
    }

    #[test]
    fn parses_ipv4_src_and_dest() {
        let p = ipv4([100, 64, 0, 1], [100, 64, 7, 42]);
        assert_eq!(parse_dest_ipv4(&p), Some(Ipv4Addr::new(100, 64, 7, 42)));
        assert_eq!(parse_src_ipv4(&p), Some(Ipv4Addr::new(100, 64, 0, 1)));
    }

    #[test]
    fn rejects_non_ipv4_and_truncated() {
        let mut v6 = vec![0u8; 20];
        v6[0] = 0x60; // version 6
        assert_eq!(parse_dest_ipv4(&v6), None);
        assert_eq!(parse_dest_ipv4(&[0x45, 0, 0]), None); // truncated
    }

    #[test]
    fn virtual_range_check() {
        assert!(is_virtual_addr(Ipv4Addr::new(100, 64, 0, 1)));
        assert!(is_virtual_addr(Ipv4Addr::new(100, 127, 255, 254)));
        assert!(!is_virtual_addr(Ipv4Addr::new(100, 63, 0, 1)));
        assert!(!is_virtual_addr(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!is_virtual_addr(Ipv4Addr::new(192, 168, 1, 1)));
    }
}
