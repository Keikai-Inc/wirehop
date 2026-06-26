//! MagicDNS resolver (Phase 4 — see `docs/technical/p2p-network.md`).
//!
//! A minimal DNS server that answers `A` queries for the network's domain by
//! resolving `<hostname>.<domain>` to a peer's virtual IP from the network
//! document. Designed to be pointed at via split-DNS (e.g. `/etc/resolver/hop`),
//! so only the network domain is routed here and the system resolver is
//! untouched for everything else.
//!
//! This module implements just enough of the DNS wire format for single-question
//! `A` lookups — the part most prone to bugs — and is unit-tested.

use std::net::IpAddr;

/// A parsed single-question DNS query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Query {
    pub id: u16,
    /// Lower-cased dotted name, no trailing dot (e.g. `laptop.acme.hop`).
    pub name: String,
    pub qtype: u16,
}

const TYPE_A: u16 = 1;
/// `AAAA` (IPv6) — used for 4via6 names (`<ip>-via-<site>.hop` → a via6 IPv6).
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

/// Parse a DNS query packet with exactly one question. Returns `None` if it
/// isn't a well-formed single-question query.
pub fn parse_query(packet: &[u8]) -> Option<Query> {
    if packet.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount != 1 {
        return None;
    }
    let mut pos = 12;
    let mut labels = Vec::new();
    loop {
        if pos >= packet.len() {
            return None;
        }
        let len = packet[pos] as usize;
        pos += 1;
        if len == 0 {
            break;
        }
        if len > 63 || pos + len > packet.len() {
            return None; // no compression in questions; reject oversized
        }
        labels.push(String::from_utf8_lossy(&packet[pos..pos + len]).to_lowercase());
        pos += len;
    }
    if pos + 4 > packet.len() {
        return None;
    }
    let qtype = u16::from_be_bytes([packet[pos], packet[pos + 1]]);
    Some(Query {
        id,
        name: labels.join("."),
        qtype,
    })
}

/// Build a response to `query`. `addr` is the resolved address, if any. An `A`
/// query is answered only by an IPv4 address and an `AAAA` query only by an IPv6
/// address (4via6 names); a family mismatch yields an empty `NOERROR` (the name
/// exists but has no record of that type), and an unresolved name yields an
/// authoritative `NXDOMAIN`.
pub fn build_response(query: &Query, addr: Option<IpAddr>) -> Vec<u8> {
    // The record we will actually emit: only when the resolved address family
    // matches the query type. A family mismatch is "no record of this type",
    // distinct from "name does not exist".
    let answer = match (query.qtype, addr) {
        (TYPE_A, Some(IpAddr::V4(v4))) => Some(IpAddr::V4(v4)),
        (TYPE_AAAA, Some(IpAddr::V6(v6))) => Some(IpAddr::V6(v6)),
        _ => None,
    };
    let name_exists = addr.is_some();

    let mut out = Vec::with_capacity(64);
    // Header.
    out.extend_from_slice(&query.id.to_be_bytes());
    // Flags: QR=1 (response), AA=1 (authoritative), RD/RA=0. RCODE 3 (NXDOMAIN)
    // only when the name doesn't exist at all; a type mismatch is NOERROR.
    let rcode: u16 = if name_exists { 0 } else { 3 };
    let flags: u16 = 0x8400 | rcode;
    out.extend_from_slice(&flags.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    let ancount: u16 = if answer.is_some() { 1 } else { 0 };
    out.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT

    // Question (echo the name).
    let qstart = out.len();
    for label in query.name.split('.').filter(|l| !l.is_empty()) {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0); // root
    out.extend_from_slice(&query.qtype.to_be_bytes());
    out.extend_from_slice(&CLASS_IN.to_be_bytes());

    // Answer record if the family matched the query type.
    if let Some(ip) = answer {
        // NAME: pointer to the question name at qstart.
        let ptr = 0xC000 | (qstart as u16);
        out.extend_from_slice(&ptr.to_be_bytes());
        match ip {
            IpAddr::V4(v4) => {
                out.extend_from_slice(&TYPE_A.to_be_bytes());
                out.extend_from_slice(&CLASS_IN.to_be_bytes());
                out.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
                out.extend_from_slice(&4u16.to_be_bytes()); // RDLENGTH
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.extend_from_slice(&TYPE_AAAA.to_be_bytes());
                out.extend_from_slice(&CLASS_IN.to_be_bytes());
                out.extend_from_slice(&60u32.to_be_bytes()); // TTL 60s
                out.extend_from_slice(&16u16.to_be_bytes()); // RDLENGTH
                out.extend_from_slice(&v6.octets());
            }
        }
    }
    out
}

/// Resolve a query against a name→IP lookup, honoring `A`/`AAAA` queries for
/// names under `domain`. Returns the bytes to send back.
pub fn answer<F>(packet: &[u8], domain: &str, lookup: F) -> Option<Vec<u8>>
where
    F: FnOnce(&str) -> Option<IpAddr>,
{
    let query = parse_query(packet)?;
    if query.qtype != TYPE_A && query.qtype != TYPE_AAAA {
        return Some(build_response(&query, None));
    }
    let host = query
        .name
        .strip_suffix(&format!(".{domain}"))
        .or_else(|| query.name.strip_suffix(domain).filter(|h| h.is_empty()).map(|_| ""));
    let addr = host.and_then(|h| if h.is_empty() { None } else { lookup(h) });
    Some(build_response(&query, addr))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    /// Encode a single-question A query for `name`.
    fn query_packet(id: u16, name: &str) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        p.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        p.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&TYPE_A.to_be_bytes());
        p.extend_from_slice(&CLASS_IN.to_be_bytes());
        p
    }

    #[test]
    fn parse_roundtrip() {
        let p = query_packet(0x1234, "Laptop.acme.hop");
        let q = parse_query(&p).unwrap();
        assert_eq!(q.id, 0x1234);
        assert_eq!(q.name, "laptop.acme.hop"); // lower-cased
        assert_eq!(q.qtype, TYPE_A);
    }

    /// Encode a single-question query of an arbitrary type for `name`.
    fn query_packet_typed(id: u16, name: &str, qtype: u16) -> Vec<u8> {
        let mut p = Vec::new();
        p.extend_from_slice(&id.to_be_bytes());
        p.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
        p.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        p.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // AN/NS/AR
        for label in name.split('.') {
            p.push(label.len() as u8);
            p.extend_from_slice(label.as_bytes());
        }
        p.push(0);
        p.extend_from_slice(&qtype.to_be_bytes());
        p.extend_from_slice(&CLASS_IN.to_be_bytes());
        p
    }

    #[test]
    fn answers_known_name_with_a_record() {
        let p = query_packet(7, "laptop.acme.hop");
        let resp = answer(&p, "acme.hop", |h| {
            assert_eq!(h, "laptop");
            Some(IpAddr::V4(Ipv4Addr::new(100, 64, 0, 9)))
        })
        .unwrap();
        // Header: id echoed, QR+AA set, ANCOUNT=1.
        assert_eq!(u16::from_be_bytes([resp[0], resp[1]]), 7);
        assert_eq!(resp[2] & 0x80, 0x80); // QR
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // ANCOUNT
        // Last 4 bytes are the A record IP.
        let n = resp.len();
        assert_eq!(&resp[n - 4..], &[100, 64, 0, 9]);
    }

    #[test]
    fn answers_via_name_with_aaaa_record() {
        let via6 = crate::vpn::via6_encode(7, Ipv4Addr::new(192, 168, 1, 50));
        let p = query_packet_typed(0x55, "192-168-1-50-via-7.acme.hop", TYPE_AAAA);
        let resp = answer(&p, "acme.hop", |h| {
            assert_eq!(h, "192-168-1-50-via-7");
            Some(IpAddr::V6(via6))
        })
        .unwrap();
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 1); // ANCOUNT 1
        // Last 16 bytes are the AAAA record (the via6 address).
        let n = resp.len();
        assert_eq!(&resp[n - 16..], &via6.octets());
    }

    #[test]
    fn a_query_for_v6_only_name_is_empty_noerror() {
        // An A query whose resolved address is IPv6 (a via6 name) → name exists
        // but no A record: ANCOUNT 0, RCODE NOERROR (not NXDOMAIN).
        let via6 = crate::vpn::via6_encode(7, Ipv4Addr::new(192, 168, 1, 50));
        let p = query_packet(0x56, "192-168-1-50-via-7.acme.hop");
        let resp = answer(&p, "acme.hop", |_| Some(IpAddr::V6(via6))).unwrap();
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // ANCOUNT 0
        assert_eq!(resp[3] & 0x0f, 0); // RCODE NOERROR
    }

    #[test]
    fn unknown_name_is_nxdomain() {
        let p = query_packet(8, "ghost.acme.hop");
        let resp = answer(&p, "acme.hop", |_| None).unwrap();
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0); // ANCOUNT 0
        assert_eq!(resp[3] & 0x0f, 3); // RCODE NXDOMAIN
    }

    #[test]
    fn ignores_names_outside_domain() {
        let p = query_packet(9, "example.com");
        let resp =
            answer(&p, "acme.hop", |_| Some(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)))).unwrap();
        // Outside the domain → no answer (NXDOMAIN), lookup not consulted.
        assert_eq!(u16::from_be_bytes([resp[6], resp[7]]), 0);
    }
}
