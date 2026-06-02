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
