//! Stateless IP/ICMP translation (SIIT, RFC 6145) for 4via6 overlapping-subnet
//! routing (Tier 3a — the multi-day core of `~/.claude/plans/warren-4via6-ipv6.md`).
//!
//! A 4via6 packet rides the warren tunnel as an **IPv6** packet. At the gateway
//! that owns the destination site, hop translates it to **IPv4** and hands it to
//! the host kernel, which forwards + masquerades it onto the physical LAN (the
//! shipped Tier-1 path). Replies arrive as IPv4 and are translated back to IPv6.
//!
//! This module is the **pure, stateless** half of that split: given a packet and
//! the four already-resolved addresses (the stateful `client_v6 ↔ pooled_v4` and
//! `site_id` mapping lives at the gateway, not here), it rewrites the L3 header
//! and recomputes every checksum whose inputs changed across the v4/v6 boundary.
//! Keeping it address-agnostic and side-effect-free makes it exhaustively
//! unit-testable against hand-built packet vectors — which is exactly how the
//! tests below exercise it (header fields + checksum validity + round-trips).
//!
//! ## What changes across the boundary
//!
//! - **IPv4 header checksum** exists only in v4 (IPv6 has none) — computed on
//!   v6→v4, dropped on v4→v6.
//! - **TCP/UDP checksum** covers a *pseudo-header* built from the L3 addresses +
//!   length + protocol, which differs entirely between v4 and v6 — so it is
//!   recomputed in both directions over the (unchanged) transport segment.
//! - **ICMP**: ICMPv4 (proto 1) ↔ ICMPv6 (proto 58) use different type numbers,
//!   and the ICMPv6 checksum includes the IPv6 pseudo-header while ICMPv4's does
//!   not. Echo request/reply (ping — the e2e's critical case) is translated
//!   fully; the common error messages (dest-unreachable, time-exceeded,
//!   packet-too-big/frag-needed) translate type/code and recompute the checksum.
//!
//! ## Scope / limitations (documented, not silent)
//!
//! - IPv4 options are dropped on v4→v6 (IPv6 has no inline options); packets with
//!   options are rare in forwarded LAN traffic.
//! - ICMP error messages carry an embedded "offending" packet header. We
//!   translate the outer ICMP type/code + checksum but do **not** recursively
//!   translate the embedded header — enough for the error to be delivered, though
//!   a strict host may not correlate it to the original flow. Full embedded
//!   translation is a refinement.
//! - Fragmented IPv4 input is not reassembled; on v6→v4 we set DF (the v6 sender
//!   assumed a fragmentation-free path) and rely on ICMP PTB/frag-needed for PMTU.

use std::net::{Ipv4Addr, Ipv6Addr};

const IP_PROTO_ICMPV4: u8 = 1;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const IP_PROTO_ICMPV6: u8 = 58;

const IPV6_HEADER_LEN: usize = 40;
const IPV4_MIN_HEADER_LEN: usize = 20;

/// RFC 1071 ones-complement checksum over `data` (16-bit big-endian words, with a
/// final odd byte padded). Returns the folded one's-complement sum. Callers pass
/// the data they want covered (e.g. a pseudo-header followed by a segment) by
/// summing partial results with [`csum_add`] / [`csum_fold`].
fn csum_fold(mut sum: u32) -> u16 {
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

/// Accumulate `data` into a running 32-bit checksum sum (pre-fold).
fn csum_add(mut sum: u32, data: &[u8]) -> u32 {
    let (chunks, remainder) = data.as_chunks::<2>();
    for c in chunks {
        sum = sum.wrapping_add(u16::from_be_bytes(*c) as u32);
    }
    if let [last] = remainder {
        sum = sum.wrapping_add((*last as u32) << 8);
    }
    sum
}

/// Full ones-complement checksum over a single buffer.
fn checksum(data: &[u8]) -> u16 {
    csum_fold(csum_add(0, data))
}

/// IPv6 pseudo-header sum for an upper-layer checksum: src(16) + dst(16) +
/// upper-layer-length(4, big-endian) + zeros(3) + next-header(1).
fn pseudo_v6_sum(src: Ipv6Addr, dst: Ipv6Addr, upper_len: u32, next_header: u8) -> u32 {
    let mut sum = 0u32;
    sum = csum_add(sum, &src.octets());
    sum = csum_add(sum, &dst.octets());
    sum = csum_add(sum, &upper_len.to_be_bytes());
    // 3 zero bytes + next header → two 16-bit words: 0x0000 then 0x00<nh>.
    sum = csum_add(sum, &[0, 0, 0, next_header]);
    sum
}

/// IPv4 pseudo-header sum for an upper-layer checksum: src(4) + dst(4) + zero(1)
/// + protocol(1) + upper-layer-length(2, big-endian).
fn pseudo_v4_sum(src: Ipv4Addr, dst: Ipv4Addr, upper_len: u16, protocol: u8) -> u32 {
    let mut sum = 0u32;
    sum = csum_add(sum, &src.octets());
    sum = csum_add(sum, &dst.octets());
    sum = csum_add(sum, &[0, protocol]);
    sum = csum_add(sum, &upper_len.to_be_bytes());
    sum
}

/// Translate an IPv6 packet to IPv4 (RFC 6145 §5), rewriting the L3 header to the
/// given IPv4 addresses and recomputing all affected checksums. Returns `None`
/// for a malformed/too-short packet, a non-IPv6 packet, or one carrying an
/// extension-header chain we don't translate (only a bare upper-layer is handled).
pub fn translate_v6_to_v4(pkt: &[u8], new_src: Ipv4Addr, new_dst: Ipv4Addr) -> Option<Vec<u8>> {
    if pkt.len() < IPV6_HEADER_LEN || (pkt[0] >> 4) != 6 {
        return None;
    }
    let traffic_class = ((pkt[0] & 0x0f) << 4) | (pkt[1] >> 4);
    let payload_len = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let next_header = pkt[6];
    let hop_limit = pkt[7];
    let v6_src = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[8..24]).ok()?);
    let v6_dst = Ipv6Addr::from(<[u8; 16]>::try_from(&pkt[24..40]).ok()?);

    let payload = pkt.get(IPV6_HEADER_LEN..IPV6_HEADER_LEN + payload_len)?;

    // Map the protocol (only the bare upper-layer protocols are translated; an
    // extension header would land here as an unknown next_header → bail).
    let v4_proto = match next_header {
        IP_PROTO_TCP | IP_PROTO_UDP => next_header,
        IP_PROTO_ICMPV6 => IP_PROTO_ICMPV4,
        _ => return None,
    };

    // Translate the upper-layer payload (checksum recompute + ICMP type remap).
    let new_payload = translate_upper_v6_to_v4(next_header, payload, v6_src, v6_dst, new_src, new_dst)?;

    let total_len = IPV4_MIN_HEADER_LEN + new_payload.len();
    if total_len > u16::MAX as usize {
        return None;
    }
    let mut out = Vec::with_capacity(total_len);
    out.push(0x45); // version 4, IHL 5 (no options)
    out.push(traffic_class); // DSCP/ECN carried from the v6 traffic class
    out.extend_from_slice(&(total_len as u16).to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // identification
    // Flags+frag: set DF (0x4000) — the v6 sender assumed no in-path fragmentation.
    out.extend_from_slice(&0x4000u16.to_be_bytes());
    out.push(hop_limit); // TTL ← hop limit
    out.push(v4_proto);
    out.extend_from_slice(&0u16.to_be_bytes()); // checksum placeholder
    out.extend_from_slice(&new_src.octets());
    out.extend_from_slice(&new_dst.octets());
    // Header checksum over the 20-byte header.
    let hc = checksum(&out[..IPV4_MIN_HEADER_LEN]);
    out[10..12].copy_from_slice(&hc.to_be_bytes());
    out.extend_from_slice(&new_payload);
    Some(out)
}

/// Translate an IPv4 packet to IPv6 (RFC 6145 §4), rewriting the L3 header to the
/// given IPv6 addresses and recomputing all affected checksums. Returns `None`
/// for a malformed/too-short packet, a non-IPv4 packet, or a fragment.
pub fn translate_v4_to_v6(pkt: &[u8], new_src: Ipv6Addr, new_dst: Ipv6Addr) -> Option<Vec<u8>> {
    if pkt.len() < IPV4_MIN_HEADER_LEN || (pkt[0] >> 4) != 4 {
        return None;
    }
    let ihl = (pkt[0] & 0x0f) as usize * 4;
    if ihl < IPV4_MIN_HEADER_LEN || pkt.len() < ihl {
        return None;
    }
    let dscp_ecn = pkt[1];
    let total_len = u16::from_be_bytes([pkt[2], pkt[3]]) as usize;
    // Reject fragments (MF set or non-zero offset) — we don't reassemble.
    let flags_frag = u16::from_be_bytes([pkt[6], pkt[7]]);
    if flags_frag & 0x2000 != 0 || flags_frag & 0x1fff != 0 {
        return None;
    }
    let ttl = pkt[8];
    let v4_proto = pkt[9];
    let v4_src = Ipv4Addr::new(pkt[12], pkt[13], pkt[14], pkt[15]);
    let v4_dst = Ipv4Addr::new(pkt[16], pkt[17], pkt[18], pkt[19]);

    if total_len < ihl || pkt.len() < total_len {
        return None;
    }
    let payload = &pkt[ihl..total_len];

    let v6_next = match v4_proto {
        IP_PROTO_TCP | IP_PROTO_UDP => v4_proto,
        IP_PROTO_ICMPV4 => IP_PROTO_ICMPV6,
        _ => return None,
    };

    let new_payload = translate_upper_v4_to_v6(v4_proto, payload, v4_src, v4_dst, new_src, new_dst)?;

    let mut out = Vec::with_capacity(IPV6_HEADER_LEN + new_payload.len());
    // version 6, traffic class from the v4 DSCP/ECN, flow label 0.
    out.push(0x60 | (dscp_ecn >> 4));
    out.push((dscp_ecn << 4) & 0xf0);
    out.extend_from_slice(&[0, 0]); // flow label low 16 bits
    out.extend_from_slice(&(new_payload.len() as u16).to_be_bytes()); // payload length
    out.push(v6_next);
    out.push(ttl); // hop limit ← TTL
    out.extend_from_slice(&new_src.octets());
    out.extend_from_slice(&new_dst.octets());
    out.extend_from_slice(&new_payload);
    Some(out)
}

/// Translate the upper-layer payload for v6→v4: recompute the transport checksum
/// against the new v4 pseudo-header, or remap+recompute ICMP.
fn translate_upper_v6_to_v4(
    next_header: u8,
    payload: &[u8],
    _v6_src: Ipv6Addr,
    _v6_dst: Ipv6Addr,
    v4_src: Ipv4Addr,
    v4_dst: Ipv4Addr,
) -> Option<Vec<u8>> {
    match next_header {
        IP_PROTO_TCP | IP_PROTO_UDP => {
            let mut seg = payload.to_vec();
            let cksum_off = if next_header == IP_PROTO_TCP { 16 } else { 6 };
            if seg.len() < cksum_off + 2 {
                return None;
            }
            seg[cksum_off] = 0;
            seg[cksum_off + 1] = 0;
            let pseudo = pseudo_v4_sum(v4_src, v4_dst, seg.len() as u16, next_header);
            let mut c = csum_fold(csum_add(pseudo, &seg));
            // UDP transmits a computed-zero checksum as 0xFFFF.
            if next_header == IP_PROTO_UDP && c == 0 {
                c = 0xffff;
            }
            seg[cksum_off..cksum_off + 2].copy_from_slice(&c.to_be_bytes());
            Some(seg)
        }
        IP_PROTO_ICMPV6 => translate_icmp_v6_to_v4(payload),
        _ => None,
    }
}

/// Translate the upper-layer payload for v4→v6.
fn translate_upper_v4_to_v6(
    v4_proto: u8,
    payload: &[u8],
    _v4_src: Ipv4Addr,
    _v4_dst: Ipv4Addr,
    v6_src: Ipv6Addr,
    v6_dst: Ipv6Addr,
) -> Option<Vec<u8>> {
    match v4_proto {
        IP_PROTO_TCP | IP_PROTO_UDP => {
            let mut seg = payload.to_vec();
            let cksum_off = if v4_proto == IP_PROTO_TCP { 16 } else { 6 };
            if seg.len() < cksum_off + 2 {
                return None;
            }
            seg[cksum_off] = 0;
            seg[cksum_off + 1] = 0;
            let pseudo = pseudo_v6_sum(v6_src, v6_dst, seg.len() as u32, v4_proto);
            let mut c = csum_fold(csum_add(pseudo, &seg));
            if v4_proto == IP_PROTO_UDP && c == 0 {
                c = 0xffff; // UDP over IPv6 must carry a non-zero checksum
            }
            seg[cksum_off..cksum_off + 2].copy_from_slice(&c.to_be_bytes());
            Some(seg)
        }
        IP_PROTO_ICMPV4 => translate_icmp_v4_to_v6(payload, v6_src, v6_dst),
        _ => None,
    }
}

/// ICMPv6 → ICMPv4 type/code remap + checksum (drops the v6 pseudo-header, which
/// ICMPv4 doesn't cover). Handles echo + the common error messages.
fn translate_icmp_v6_to_v4(payload: &[u8]) -> Option<Vec<u8>> {
    if payload.len() < 4 {
        return None;
    }
    let mut msg = payload.to_vec();
    let (ty, code) = (msg[0], msg[1]);
    let (new_ty, new_code) = match (ty, code) {
        (128, _) => (8, code),  // echo request
        (129, _) => (0, code),  // echo reply
        (1, _) => (3, icmp6_unreach_to_v4_code(code)), // dest unreachable
        (3, _) => (11, code),   // time exceeded
        (2, _) => (3, 4),       // packet too big → frag needed (DF)
        _ => return None,       // unsupported type — drop rather than mistranslate
    };
    msg[0] = new_ty;
    msg[1] = new_code;
    msg[2] = 0;
    msg[3] = 0;
    // ICMPv4 checksum is over the ICMP message only (no pseudo-header).
    let c = checksum(&msg);
    msg[2..4].copy_from_slice(&c.to_be_bytes());
    Some(msg)
}

/// ICMPv4 → ICMPv6 type/code remap + checksum (adds the v6 pseudo-header).
fn translate_icmp_v4_to_v6(payload: &[u8], v6_src: Ipv6Addr, v6_dst: Ipv6Addr) -> Option<Vec<u8>> {
    if payload.len() < 4 {
        return None;
    }
    let mut msg = payload.to_vec();
    let (ty, code) = (msg[0], msg[1]);
    let (new_ty, new_code) = match (ty, code) {
        (8, _) => (128, code), // echo request
        (0, _) => (129, code), // echo reply
        (3, 4) => (2, 0),      // frag needed → packet too big
        (3, _) => (1, icmp4_unreach_to_v6_code(code)), // dest unreachable
        (11, _) => (3, code),  // time exceeded
        _ => return None,
    };
    msg[0] = new_ty;
    msg[1] = new_code;
    msg[2] = 0;
    msg[3] = 0;
    // ICMPv6 checksum covers the IPv6 pseudo-header + message.
    let pseudo = pseudo_v6_sum(v6_src, v6_dst, msg.len() as u32, IP_PROTO_ICMPV6);
    let c = csum_fold(csum_add(pseudo, &msg));
    msg[2..4].copy_from_slice(&c.to_be_bytes());
    Some(msg)
}

/// Map an ICMPv6 dest-unreachable code to the closest ICMPv4 code (RFC 6145 §5.2).
fn icmp6_unreach_to_v4_code(code: u8) -> u8 {
    match code {
        0 => 1, // no route → host unreachable
        1 => 10, // admin prohibited → comm administratively prohibited
        3 => 1, // address unreachable → host unreachable
        4 => 3, // port unreachable → port unreachable
        _ => 1,
    }
}

/// Map an ICMPv4 dest-unreachable code to the closest ICMPv6 code (RFC 6145 §4.2).
fn icmp4_unreach_to_v6_code(code: u8) -> u8 {
    match code {
        0 | 1 => 0,  // net/host unreachable → no route
        3 => 4,      // port unreachable → port unreachable
        9 | 10 | 13 => 1, // prohibited → admin prohibited
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ── checksum primitives ──────────────────────────────────────────────

    #[test]
    fn checksum_matches_known_vector() {
        // RFC 1071 worked example: 0x0001 0xf203 0xf4f5 0xf6f7 → checksum 0x220d.
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&data), 0x220d);
    }

    #[test]
    fn checksum_handles_odd_length() {
        // Must not panic and must fold the trailing byte as a high-order octet.
        let c = checksum(&[0x12, 0x34, 0x56]);
        let expect = csum_fold(0x1234 + 0x5600);
        assert_eq!(c, expect);
    }

    /// Verify an IPv4 header's checksum field validates (sum over header == 0).
    fn ipv4_header_checksum_valid(pkt: &[u8]) -> bool {
        checksum(&pkt[..20]) == 0
    }

    /// Verify a TCP/UDP segment checksum validates against an IPv4 pseudo-header.
    fn v4_transport_checksum_valid(src: Ipv4Addr, dst: Ipv4Addr, proto: u8, seg: &[u8]) -> bool {
        let pseudo = pseudo_v4_sum(src, dst, seg.len() as u16, proto);
        csum_fold(csum_add(pseudo, seg)) == 0
    }

    /// Verify a transport/ICMPv6 segment checksum validates against a v6 pseudo-header.
    fn v6_upper_checksum_valid(src: Ipv6Addr, dst: Ipv6Addr, nh: u8, seg: &[u8]) -> bool {
        let pseudo = pseudo_v6_sum(src, dst, seg.len() as u32, nh);
        csum_fold(csum_add(pseudo, seg)) == 0
    }

    // ── packet builders ──────────────────────────────────────────────────

    fn build_v6(next_header: u8, src: Ipv6Addr, dst: Ipv6Addr, payload: &[u8]) -> Vec<u8> {
        let mut p = Vec::new();
        p.push(0x60);
        p.extend_from_slice(&[0, 0, 0]);
        p.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        p.push(next_header);
        p.push(64); // hop limit
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        p.extend_from_slice(payload);
        p
    }

    /// A UDP segment with a correct IPv6 checksum.
    fn udp_seg_v6(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
        let mut seg = Vec::new();
        let len = 8 + data.len();
        seg.extend_from_slice(&sport.to_be_bytes());
        seg.extend_from_slice(&dport.to_be_bytes());
        seg.extend_from_slice(&(len as u16).to_be_bytes());
        seg.extend_from_slice(&[0, 0]); // checksum placeholder
        seg.extend_from_slice(data);
        let pseudo = pseudo_v6_sum(src, dst, len as u32, IP_PROTO_UDP);
        let mut c = csum_fold(csum_add(pseudo, &seg));
        if c == 0 {
            c = 0xffff;
        }
        seg[6..8].copy_from_slice(&c.to_be_bytes());
        seg
    }

    /// An ICMPv6 echo request with a correct checksum.
    fn icmp6_echo(src: Ipv6Addr, dst: Ipv6Addr, id: u16, seq: u16, data: &[u8]) -> Vec<u8> {
        let mut msg = vec![128, 0, 0, 0];
        msg.extend_from_slice(&id.to_be_bytes());
        msg.extend_from_slice(&seq.to_be_bytes());
        msg.extend_from_slice(data);
        let pseudo = pseudo_v6_sum(src, dst, msg.len() as u32, IP_PROTO_ICMPV6);
        let c = csum_fold(csum_add(pseudo, &msg));
        msg[2..4].copy_from_slice(&c.to_be_bytes());
        msg
    }

    fn v6(s: &str) -> Ipv6Addr {
        s.parse().unwrap()
    }

    // ── v6→v4 translation ────────────────────────────────────────────────

    #[test]
    fn v6_to_v4_udp_header_and_checksum() {
        let v6s = v6("fd68:6f70:7669:6136::1");
        let v6d = crate::vpn::via6_encode(7, Ipv4Addr::new(192, 168, 1, 50));
        let seg = udp_seg_v6(v6s, v6d, 4444, 53, b"hello dns");
        let pkt = build_v6(IP_PROTO_UDP, v6s, v6d, &seg);

        let v4s = Ipv4Addr::new(100, 127, 0, 9);
        let v4d = Ipv4Addr::new(192, 168, 1, 50);
        let out = translate_v6_to_v4(&pkt, v4s, v4d).expect("translate");

        assert_eq!(out[0] >> 4, 4); // IPv4
        assert_eq!(out[9], IP_PROTO_UDP);
        assert_eq!(&out[12..16], &v4s.octets());
        assert_eq!(&out[16..20], &v4d.octets());
        assert_eq!(u16::from_be_bytes([out[2], out[3]]) as usize, out.len()); // total len
        assert!(ipv4_header_checksum_valid(&out), "IPv4 header checksum");
        assert!(out[6] & 0x40 != 0, "DF set");
        // The translated UDP segment must validate against the v4 pseudo-header.
        assert!(v4_transport_checksum_valid(v4s, v4d, IP_PROTO_UDP, &out[20..]));
        // Payload bytes are preserved.
        assert_eq!(&out[20 + 8..], b"hello dns");
    }

    #[test]
    fn v6_to_v4_icmp_echo_becomes_type8() {
        let v6s = v6("fd68:6f70:7669:6136::1");
        let v6d = crate::vpn::via6_encode(7, Ipv4Addr::new(192, 168, 1, 50));
        let seg = icmp6_echo(v6s, v6d, 0x1234, 1, b"ping-data");
        let pkt = build_v6(IP_PROTO_ICMPV6, v6s, v6d, &seg);

        let v4s = Ipv4Addr::new(100, 127, 0, 9);
        let v4d = Ipv4Addr::new(192, 168, 1, 50);
        let out = translate_v6_to_v4(&pkt, v4s, v4d).expect("translate");

        assert_eq!(out[9], IP_PROTO_ICMPV4);
        assert_eq!(out[20], 8, "ICMPv4 echo request type");
        assert!(ipv4_header_checksum_valid(&out));
        // ICMPv4 checksum is over the message only (no pseudo-header).
        assert_eq!(checksum(&out[20..]), 0, "ICMPv4 checksum valid");
        // Echo id/seq/data preserved.
        assert_eq!(&out[24..], &{ let mut v = vec![0x12u8,0x34,0,1]; v.extend_from_slice(b"ping-data"); v }[..]);
    }

    // ── v4→v6 translation ────────────────────────────────────────────────

    fn build_v4(proto: u8, src: Ipv4Addr, dst: Ipv4Addr, payload: &[u8]) -> Vec<u8> {
        let total = 20 + payload.len();
        let mut p = Vec::new();
        p.push(0x45);
        p.push(0);
        p.extend_from_slice(&(total as u16).to_be_bytes());
        p.extend_from_slice(&[0, 0]); // id
        p.extend_from_slice(&0x4000u16.to_be_bytes()); // DF
        p.push(64); // TTL
        p.push(proto);
        p.extend_from_slice(&[0, 0]); // checksum placeholder
        p.extend_from_slice(&src.octets());
        p.extend_from_slice(&dst.octets());
        let c = checksum(&p[..20]);
        p[10..12].copy_from_slice(&c.to_be_bytes());
        p.extend_from_slice(payload);
        p
    }

    fn udp_seg_v4(src: Ipv4Addr, dst: Ipv4Addr, sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
        let mut seg = Vec::new();
        let len = 8 + data.len();
        seg.extend_from_slice(&sport.to_be_bytes());
        seg.extend_from_slice(&dport.to_be_bytes());
        seg.extend_from_slice(&(len as u16).to_be_bytes());
        seg.extend_from_slice(&[0, 0]);
        seg.extend_from_slice(data);
        let pseudo = pseudo_v4_sum(src, dst, len as u16, IP_PROTO_UDP);
        let mut c = csum_fold(csum_add(pseudo, &seg));
        if c == 0 {
            c = 0xffff;
        }
        seg[6..8].copy_from_slice(&c.to_be_bytes());
        seg
    }

    #[test]
    fn v4_to_v6_udp_header_and_checksum() {
        let v4s = Ipv4Addr::new(192, 168, 1, 50);
        let v4d = Ipv4Addr::new(100, 127, 0, 9);
        let seg = udp_seg_v4(v4s, v4d, 53, 4444, b"dns reply!");
        let pkt = build_v4(IP_PROTO_UDP, v4s, v4d, &seg);

        let v6s = crate::vpn::via6_encode(7, v4s);
        let v6d = v6("fd68:6f70:7669:6136::1");
        let out = translate_v4_to_v6(&pkt, v6s, v6d).expect("translate");

        assert_eq!(out[0] >> 4, 6); // IPv6
        assert_eq!(out[6], IP_PROTO_UDP); // next header
        assert_eq!(u16::from_be_bytes([out[4], out[5]]) as usize, out.len() - 40); // payload len
        assert_eq!(&out[8..24], &v6s.octets());
        assert_eq!(&out[24..40], &v6d.octets());
        assert!(v6_upper_checksum_valid(v6s, v6d, IP_PROTO_UDP, &out[40..]));
        assert_eq!(&out[40 + 8..], b"dns reply!");
    }

    // ── round-trips ──────────────────────────────────────────────────────

    #[test]
    fn roundtrip_v6_v4_v6_preserves_packet() {
        // A v6→v4→v6 round-trip with the same address mapping must reproduce the
        // original packet bit-for-bit (proves both directions agree).
        let v6s = v6("fd68:6f70:7669:6136::abcd");
        let v6d = crate::vpn::via6_encode(42, Ipv4Addr::new(10, 0, 0, 7));
        let seg = udp_seg_v6(v6s, v6d, 1234, 5678, b"roundtrip payload");
        let original = build_v6(IP_PROTO_UDP, v6s, v6d, &seg);

        let v4s = Ipv4Addr::new(100, 127, 1, 2);
        let v4d = Ipv4Addr::new(10, 0, 0, 7);
        let v4 = translate_v6_to_v4(&original, v4s, v4d).unwrap();
        let back = translate_v4_to_v6(&v4, v6s, v6d).unwrap();
        assert_eq!(back, original, "v6→v4→v6 must round-trip exactly");
    }

    #[test]
    fn roundtrip_v4_v6_v4_preserves_payload_and_checksums() {
        let v4s = Ipv4Addr::new(192, 168, 1, 50);
        let v4d = Ipv4Addr::new(100, 127, 0, 9);
        let seg = udp_seg_v4(v4s, v4d, 80, 51000, b"abc123");
        let original = build_v4(IP_PROTO_UDP, v4s, v4d, &seg);

        let v6s = crate::vpn::via6_encode(7, v4s);
        let v6d = v6("fd68:6f70:7669:6136::1");
        let v6 = translate_v4_to_v6(&original, v6s, v6d).unwrap();
        let back = translate_v6_to_v4(&v6, v4s, v4d).unwrap();
        // Header checksum + transport checksum valid, payload preserved.
        assert!(ipv4_header_checksum_valid(&back));
        assert!(v4_transport_checksum_valid(v4s, v4d, IP_PROTO_UDP, &back[20..]));
        assert_eq!(&back[28..], b"abc123");
    }

    // ── rejection / robustness ───────────────────────────────────────────

    #[test]
    fn rejects_malformed_and_unsupported() {
        assert!(translate_v6_to_v4(&[0u8; 10], Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED).is_none());
        assert!(translate_v4_to_v6(&[0u8; 10], Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED).is_none());
        // An IPv6 packet whose next-header is an unsupported protocol is dropped.
        let v6s = v6("fd68:6f70:7669:6136::1");
        let pkt = build_v6(89 /* OSPF */, v6s, v6s, &[0u8; 8]);
        assert!(translate_v6_to_v4(&pkt, Ipv4Addr::UNSPECIFIED, Ipv4Addr::UNSPECIFIED).is_none());
    }

    /// A TCP segment with a correct IPv6 checksum (exercises the proto-6 path +
    /// the checksum offset 16, distinct from UDP's offset 6).
    fn tcp_seg_v6(src: Ipv6Addr, dst: Ipv6Addr, sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
        let mut seg = Vec::new();
        seg.extend_from_slice(&sport.to_be_bytes());
        seg.extend_from_slice(&dport.to_be_bytes());
        seg.extend_from_slice(&0u32.to_be_bytes()); // seq
        seg.extend_from_slice(&0u32.to_be_bytes()); // ack
        seg.push(0x50); // data offset 5, no flags-hi
        seg.push(0x18); // PSH+ACK
        seg.extend_from_slice(&64240u16.to_be_bytes()); // window
        seg.extend_from_slice(&[0, 0]); // checksum placeholder (offset 16)
        seg.extend_from_slice(&[0, 0]); // urgent ptr
        seg.extend_from_slice(data);
        let pseudo = pseudo_v6_sum(src, dst, seg.len() as u32, IP_PROTO_TCP);
        let c = csum_fold(csum_add(pseudo, &seg));
        seg[16..18].copy_from_slice(&c.to_be_bytes());
        seg
    }

    #[test]
    fn v6_to_v4_tcp_checksum_offset16() {
        let v6s = v6("fd68:6f70:7669:6136::1");
        let v6d = crate::vpn::via6_encode(3, Ipv4Addr::new(192, 168, 1, 80));
        let seg = tcp_seg_v6(v6s, v6d, 50000, 443, b"GET / HTTP/1.1");
        let pkt = build_v6(IP_PROTO_TCP, v6s, v6d, &seg);
        let v4s = Ipv4Addr::new(100, 127, 0, 5);
        let v4d = Ipv4Addr::new(192, 168, 1, 80);
        let out = translate_v6_to_v4(&pkt, v4s, v4d).expect("translate");
        assert_eq!(out[9], IP_PROTO_TCP);
        assert!(ipv4_header_checksum_valid(&out));
        assert!(v4_transport_checksum_valid(v4s, v4d, IP_PROTO_TCP, &out[20..]));
        assert_eq!(&out[20 + 20..], b"GET / HTTP/1.1");
    }

    #[test]
    fn v4_to_v6_icmp_echo_becomes_type128() {
        // ICMPv4 echo request (type 8) → ICMPv6 echo request (type 128), with the
        // checksum recomputed to include the v6 pseudo-header.
        let v4s = Ipv4Addr::new(192, 168, 1, 50);
        let v4d = Ipv4Addr::new(100, 127, 0, 9);
        let mut icmp = vec![8u8, 0, 0, 0, 0x12, 0x34, 0, 1];
        icmp.extend_from_slice(b"echo");
        let c = checksum(&icmp);
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        let pkt = build_v4(IP_PROTO_ICMPV4, v4s, v4d, &icmp);

        let v6s = crate::vpn::via6_encode(7, v4s);
        let v6d = v6("fd68:6f70:7669:6136::1");
        let out = translate_v4_to_v6(&pkt, v6s, v6d).expect("translate");
        assert_eq!(out[6], IP_PROTO_ICMPV6);
        assert_eq!(out[40], 128, "ICMPv6 echo request type");
        assert!(v6_upper_checksum_valid(v6s, v6d, IP_PROTO_ICMPV6, &out[40..]));
    }

    #[test]
    fn v6_to_v4_icmp_dest_unreachable_port() {
        // ICMPv6 dest-unreachable / port (type 1, code 4) → ICMPv4 (type 3, code 3).
        let v6s = v6("fd68:6f70:7669:6136::1");
        let v6d = crate::vpn::via6_encode(7, Ipv4Addr::new(192, 168, 1, 50));
        let mut icmp = vec![1u8, 4, 0, 0, 0, 0, 0, 0];
        icmp.extend_from_slice(&[0u8; 8]); // (stub embedded packet)
        let pseudo = pseudo_v6_sum(v6s, v6d, icmp.len() as u32, IP_PROTO_ICMPV6);
        let c = csum_fold(csum_add(pseudo, &icmp));
        icmp[2..4].copy_from_slice(&c.to_be_bytes());
        let pkt = build_v6(IP_PROTO_ICMPV6, v6s, v6d, &icmp);
        let out = translate_v6_to_v4(&pkt, Ipv4Addr::new(100, 127, 0, 9), Ipv4Addr::new(192, 168, 1, 50))
            .expect("translate");
        assert_eq!(out[20], 3, "ICMPv4 dest unreachable");
        assert_eq!(out[21], 3, "ICMPv4 port unreachable code");
        assert_eq!(checksum(&out[20..]), 0, "ICMPv4 checksum valid");
    }

    #[test]
    fn v4_to_v6_udp_zero_checksum_becomes_nonzero() {
        // A legal IPv4 UDP datagram may carry checksum 0 (no checksum); over IPv6
        // the checksum is mandatory, so the translation must compute a real one.
        let v4s = Ipv4Addr::new(192, 168, 1, 50);
        let v4d = Ipv4Addr::new(100, 127, 0, 9);
        let mut seg = Vec::new();
        seg.extend_from_slice(&53u16.to_be_bytes());
        seg.extend_from_slice(&4444u16.to_be_bytes());
        seg.extend_from_slice(&(8u16 + 3).to_be_bytes());
        seg.extend_from_slice(&[0, 0]); // checksum 0 = "none" in IPv4
        seg.extend_from_slice(b"abc");
        let pkt = build_v4(IP_PROTO_UDP, v4s, v4d, &seg);
        let v6s = crate::vpn::via6_encode(7, v4s);
        let v6d = v6("fd68:6f70:7669:6136::1");
        let out = translate_v4_to_v6(&pkt, v6s, v6d).expect("translate");
        let cks = &out[40 + 6..40 + 8];
        assert_ne!(cks, &[0, 0], "IPv6 UDP checksum must be non-zero");
        assert!(v6_upper_checksum_valid(v6s, v6d, IP_PROTO_UDP, &out[40..]));
    }

    #[test]
    fn rejects_ipv4_fragment() {
        let v4s = Ipv4Addr::new(1, 2, 3, 4);
        let v4d = Ipv4Addr::new(5, 6, 7, 8);
        let mut pkt = build_v4(IP_PROTO_UDP, v4s, v4d, &udp_seg_v4(v4s, v4d, 1, 2, b"x"));
        // Set MF (more fragments).
        pkt[6] |= 0x20;
        assert!(translate_v4_to_v6(&pkt, Ipv6Addr::UNSPECIFIED, Ipv6Addr::UNSPECIFIED).is_none());
    }
}
