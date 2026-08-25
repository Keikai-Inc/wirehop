//! Discovery reflection (Tier 4) — answering LAN service-discovery on behalf of a
//! remote device so a non-hop client (e.g. a Tablo TV app) can find a device
//! across the warren, which plain L3 routing can't carry (broadcast/multicast
//! don't cross the tunnel).
//!
//! This is the protocol-codec layer. The responder that binds the LAN broadcast
//! socket and answers probes, and the content-aware proxy that rewrites the
//! device's embedded IP in its HTTP responses, build on it. Tablo's `BnGr` is
//! implemented here (wire format from the open-source `jessedp/tablo-api-js`); the
//! content-rewriting proxy is gated on a packet capture (relative-vs-absolute
//! URLs) — see `~/.claude/plans/warren-lan-bridging.md`.

/// The `BnGr` probe a Tablo client broadcasts (to `255.255.255.255:8881`).
pub const BNGR_PROBE: &[u8] = b"BnGr";
/// UDP port the probe is sent to.
pub const BNGR_PROBE_PORT: u16 = 8881;
/// UDP port replies are sent to / received on.
pub const BNGR_REPLY_PORT: u16 = 8882;
/// Total `BnGr` reply length (`>4s64s32s20s10s10s`).
pub const BNGR_REPLY_LEN: usize = 140;

/// A decoded Tablo `BnGr` discovery reply: six NUL-padded ASCII fields in fixed
/// slots (resp_code@0/4, host@4/64, private_ip@68/32, server_id@100/20,
/// dev_type@120/10, board@130/10).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BnGrReply {
    pub resp_code: String,
    pub host: String,
    /// The IP the client will dial. A responder sets this to the LOCAL proxy
    /// address (not the real, possibly-colliding LAN IP across the tunnel).
    pub private_ip: String,
    pub server_id: String,
    pub dev_type: String,
    pub board: String,
}

/// Whether `pkt` is a `BnGr` discovery probe.
pub fn is_probe(pkt: &[u8]) -> bool {
    pkt == BNGR_PROBE
}

/// Parse a 140-byte `BnGr` reply (each field NUL-terminated within its slot).
/// `None` if the length is wrong.
pub fn decode(pkt: &[u8]) -> Option<BnGrReply> {
    if pkt.len() != BNGR_REPLY_LEN {
        return None;
    }
    let field = |start: usize, len: usize| -> String {
        let raw = &pkt[start..start + len];
        let end = raw.iter().position(|&b| b == 0).unwrap_or(len);
        String::from_utf8_lossy(&raw[..end]).into_owned()
    };
    Some(BnGrReply {
        resp_code: field(0, 4),
        host: field(4, 64),
        private_ip: field(68, 32),
        server_id: field(100, 20),
        dev_type: field(120, 10),
        board: field(130, 10),
    })
}

/// Build a 140-byte `BnGr` reply (the responder answers a probe on behalf of a
/// remote Tablo, pointing the client at a local proxy `private_ip`). Over-long
/// fields are truncated to their slot.
pub fn encode(reply: &BnGrReply) -> [u8; BNGR_REPLY_LEN] {
    let mut buf = [0u8; BNGR_REPLY_LEN];
    {
        let mut put = |start: usize, len: usize, s: &str| {
            let b = s.as_bytes();
            let n = b.len().min(len);
            buf[start..start + n].copy_from_slice(&b[..n]);
        };
        put(0, 4, &reply.resp_code);
        put(4, 64, &reply.host);
        put(68, 32, &reply.private_ip);
        put(100, 20, &reply.server_id);
        put(120, 10, &reply.dev_type);
        put(130, 10, &reply.board);
    }
    buf
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn probe_detection() {
        assert!(is_probe(b"BnGr"));
        assert!(!is_probe(b"nope"));
        assert!(!is_probe(b"BnGrX"));
    }

    #[test]
    fn bngr_reply_roundtrips() {
        let reply = BnGrReply {
            resp_code: "BgRp".into(),
            host: "Tablo-XYZ".into(),
            private_ip: "192.168.1.127".into(),
            server_id: "SID_abc123".into(),
            dev_type: "tablo".into(),
            board: "qdvr".into(),
        };
        let bytes = encode(&reply);
        assert_eq!(bytes.len(), BNGR_REPLY_LEN);
        // The IP lands at its documented offset (68).
        assert_eq!(&bytes[68..68 + 13], b"192.168.1.127");
        assert_eq!(decode(&bytes), Some(reply));
    }

    #[test]
    fn decode_rejects_wrong_length() {
        assert_eq!(decode(b"too short"), None);
        assert_eq!(decode(&[0u8; 139]), None);
        assert!(decode(&[0u8; 140]).is_some()); // all-empty fields is valid
    }

    #[test]
    fn responder_can_rewrite_private_ip() {
        // The whole point: answer a probe pointing the client at a LOCAL proxy IP
        // instead of the real (possibly-colliding) LAN address.
        let mut reply = decode(&encode(&BnGrReply {
            private_ip: "192.168.1.127".into(),
            ..Default::default()
        }))
        .unwrap();
        reply.private_ip = "100.64.0.5".into();
        assert_eq!(decode(&encode(&reply)).unwrap().private_ip, "100.64.0.5");
    }
}
