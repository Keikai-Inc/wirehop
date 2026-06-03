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
/// The kernel installs a route for the /10 to this interface automatically.
#[cfg(unix)]
pub async fn create_tun(addr: Ipv4Addr) -> anyhow::Result<tun::AsyncDevice> {
    let mut config = tun::configure();
    config
        .address(addr)
        .netmask(CGNAT_NETMASK)
        .mtu(VPN_MTU)
        .up();
    tun::create_as_async(&config).map_err(|e| anyhow::anyhow!("create TUN device: {e}"))
}

/// iroh `ProtocolHandler` for `hop/vpn/1`: writes received QUIC datagrams (L3 IP
/// packets) to the TUN device. Dropped silently when the VPN is off.
#[cfg(unix)]
#[derive(Clone)]
pub struct VpnInbound {
    tun: TunSlot,
}

#[cfg(unix)]
impl std::fmt::Debug for VpnInbound {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("VpnInbound").finish_non_exhaustive()
    }
}

#[cfg(unix)]
impl VpnInbound {
    pub fn new(tun: TunSlot) -> Self {
        Self { tun }
    }
}

#[cfg(unix)]
impl iroh::protocol::ProtocolHandler for VpnInbound {
    async fn accept(
        &self,
        conn: iroh::endpoint::Connection,
    ) -> Result<(), iroh::protocol::AcceptError> {
        while let Ok(dg) = conn.read_datagram().await {
            if let Some(tun) = self.tun.read().await.clone() {
                let _ = tun.send(&dg).await;
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
