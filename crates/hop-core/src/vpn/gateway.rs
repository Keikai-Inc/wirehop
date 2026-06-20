//! Gateway forwarding setup for Tier 1 LAN bridging.
//!
//! When a node advertises subnet/exit routes (`routes.json` → netdoc), it must
//! act as an L3 gateway: forward packets that arrive over the warren TUN for an
//! advertised destination onto its physical LAN, and (for SNAT routes)
//! masquerade them to its own LAN IP so replies return. This module enables
//! kernel IP forwarding and programs NAT.
//!
//! Linux (nftables) is implemented; macOS (`pf`) is a follow-up (plan P2). All of
//! this is **inert until a route is advertised** — `setup_gateway` is only called
//! by the daemon when `routes.json` is non-empty.

use anyhow::Result;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use anyhow::Context;

/// Name of the dedicated nftables table hop owns, so teardown never touches
/// other rules.
const NFT_TABLE: &str = "hop_gw";

/// A route the gateway forwards: its CIDR and whether to masquerade (SNAT).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GatewayRoute {
    pub cidr: String,
    pub snat: bool,
}

/// Build the nftables ruleset (`nft -f` script) for the given routes. Pure and
/// unit-testable. Creates a dedicated `inet hop_gw` table with:
/// - a **forward** chain that accepts warren↔LAN traffic for the advertised
///   CIDRs and clamps TCP MSS to the path MTU (the VPN TUN is 1280, the LAN is
///   1500 — without clamping, large segments black-hole);
/// - a **postrouting nat** chain that masquerades warren-sourced traffic
///   (`100.64.0.0/10`) onto whatever interface carries it, for SNAT routes.
///
/// Deliberately **interface-agnostic**: the masquerade matches by source range
/// (`100.64.0.0/10`), not an egress `oifname`, so it works on a multi-homed
/// gateway (the advertised subnet may be reached via a non-default interface) and
/// on a simple single-LAN host alike — no fragile LAN-interface auto-detection.
/// Which destinations actually get forwarded is gated upstream (the ingress pump
/// only hands advertised-CIDR datagrams to the TUN); here we just enable the
/// forward path + NAT. An empty `routes` slice means no masquerade.
pub fn nftables_ruleset(routes: &[GatewayRoute]) -> String {
    // Forward path + MSS clamp in an `inet` table (applies to v4+v6 forwarding).
    let mut s = format!(
        "table inet {NFT_TABLE} {{\n\
         \x20 chain forward {{\n\
         \x20   type filter hook forward priority 0; policy accept;\n\
         \x20   tcp flags syn tcp option maxseg size set rt mtu\n\
         \x20 }}\n\
         }}\n"
    );
    // SNAT/masquerade in an **IPv4 (`ip`) family** table — the broadly-supported
    // place for masquerade. NAT in an `inet` table needs kernel ≥ 5.2 and silently
    // no-ops on older/containerized kernels (the bug the subnet-routing e2e hit:
    // packets forwarded but never SNAT'd, so replies to a 100.64/10 source were
    // lost). `counter` makes a hit visible in `nft list table ip hop_gw`.
    if routes.iter().any(|r| r.snat) {
        s.push_str(&format!(
            "table ip {NFT_TABLE} {{\n\
             \x20 chain postrouting {{\n\
             \x20   type nat hook postrouting priority srcnat; policy accept;\n\
             \x20   ip saddr 100.64.0.0/10 counter masquerade\n\
             \x20 }}\n\
             }}\n"
        ));
    }
    s
}

/// Enable kernel IPv4 forwarding and apply the NAT/forward ruleset for `routes`.
/// `tun` is the warren TUN interface (logged). Idempotent: replaces any prior
/// `hop_gw` table. The ruleset is interface-agnostic (see `nftables_ruleset`), so
/// no LAN-interface detection is needed.
pub fn setup_gateway(tun: &str, routes: &[GatewayRoute]) -> Result<()> {
    if routes.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        enable_ip_forward_linux()?;
        apply_nft(&nftables_ruleset(routes))?;
        tracing::info!(
            "vpn gateway: forwarding {} route(s) on {} (ip_forward + nftables hop_gw applied)",
            routes.len(),
            tun
        );
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("sysctl")
            .args(["-w", "net.inet.ip.forwarding=1"])
            .status();
        let egress = detect_default_iface_macos().context("detecting macOS egress interface")?;
        apply_pf(&pf_ruleset(&egress, routes))?;
        tracing::info!(
            "vpn gateway: forwarding {} route(s) on {} (ip.forwarding + pf hop anchor, egress {egress})",
            routes.len(),
            tun
        );
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = tun;
        anyhow::bail!("gateway forwarding is supported on Linux (nftables) and macOS (pf) only")
    }
}

/// pf ruleset (macOS) for gateway forwarding: an MSS clamp (`scrub … max-mss`) for
/// the 1280-byte TUN, and — for SNAT routes — NAT that masquerades warren-sourced
/// traffic (`100.64.0.0/10`) out the egress interface. pf NAT is interface-scoped
/// (unlike nftables' source-match masquerade), so it takes the egress `if`. Pure
/// and unit-testable. Empty for an empty route set.
pub fn pf_ruleset(egress_if: &str, routes: &[GatewayRoute]) -> String {
    let mut s = format!("scrub on {egress_if} all max-mss 1240\n");
    if routes.iter().any(|r| r.snat) {
        s.push_str(&format!(
            "nat on {egress_if} from 100.64.0.0/10 to any -> ({egress_if})\n"
        ));
    }
    s
}

/// The interface carrying the default route on macOS (the pf NAT egress).
#[cfg(target_os = "macos")]
fn detect_default_iface_macos() -> Result<String> {
    let out = std::process::Command::new("route")
        .args(["-n", "get", "default"])
        .output()
        .context("running `route -n get default`")?;
    for line in String::from_utf8_lossy(&out.stdout).lines() {
        if let Some(rest) = line.trim().strip_prefix("interface:") {
            return Ok(rest.trim().to_string());
        }
    }
    anyhow::bail!("could not determine the macOS default-route interface")
}

/// Load hop's NAT rules into a dedicated pf anchor and enable pf. NOTE: the anchor
/// must be referenced from the main ruleset (`nat-anchor "com.hop"` in
/// `/etc/pf.conf`) to be evaluated — that integration + a real 2-machine run are
/// the remaining macOS gateway steps; the ruleset itself is generated + syntax-
/// validated here.
#[cfg(target_os = "macos")]
const PF_CONF: &str = "/etc/pf.conf";

/// Build a main pf ruleset that references hop's `com.hop` anchor — preserving the
/// existing `com.apple` anchors — by injecting `*-anchor "com.hop"` lines after the
/// matching `com.apple` ones in the system `/etc/pf.conf`. An anchor loaded with
/// `pfctl -a com.hop -f` is **inert** until the main ruleset points at it (this was
/// the macOS-gateway bug a 2-machine e2e surfaced: nat rule present, `Evaluations:
/// 0`). Returns `None` if the anchor is already referenced (idempotent) or the file
/// can't be read. Keeps pf's grammar order (scrub → nat → rdr → filter).
#[cfg(target_os = "macos")]
fn pf_main_ruleset_with_hop_anchor() -> Option<String> {
    let conf = std::fs::read_to_string(PF_CONF).ok()?;
    if conf.contains("\"com.hop\"") {
        return None; // already referenced — the running main ruleset is fine
    }
    let mut out = String::new();
    for line in conf.lines() {
        out.push_str(line);
        out.push('\n');
        match line.trim() {
            "scrub-anchor \"com.apple/*\"" => out.push_str("scrub-anchor \"com.hop\"\n"),
            "nat-anchor \"com.apple/*\"" => out.push_str("nat-anchor \"com.hop\"\n"),
            "anchor \"com.apple/*\"" => out.push_str("anchor \"com.hop\"\n"),
            _ => {}
        }
    }
    Some(out)
}

#[cfg(target_os = "macos")]
fn pfctl_load(anchor: Option<&str>, ruleset: &str) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    let mut cmd = Command::new("pfctl");
    if let Some(a) = anchor {
        cmd.args(["-a", a]);
    }
    let mut child = cmd
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .context("spawning pfctl")?;
    child.stdin.take().context("pfctl stdin")?.write_all(ruleset.as_bytes())?;
    if !child.wait().context("waiting for pfctl")?.success() {
        anyhow::bail!("pfctl -f failed (anchor {anchor:?})");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn apply_pf(ruleset: &str) -> Result<()> {
    use std::process::Command;
    let _ = Command::new("pfctl").arg("-E").status(); // enable pf (idempotent)
    // Point the main ruleset at com.hop (so the anchor's rules are evaluated),
    // preserving the com.apple anchors. Idempotent: skipped if already referenced.
    if let Some(main) = pf_main_ruleset_with_hop_anchor() {
        pfctl_load(None, &main).context("referencing com.hop from the main pf ruleset")?;
    }
    // Load hop's nat/scrub rules into the (now-referenced) com.hop anchor.
    pfctl_load(Some("com.hop"), ruleset).context("loading the com.hop anchor")?;
    Ok(())
}

/// Tear down hop's gateway NAT (remove the `hop_gw` table). Best-effort.
pub fn teardown_gateway() {
    #[cfg(target_os = "linux")]
    {
        for fam in ["inet", "ip"] {
            let _ = std::process::Command::new("nft")
                .args(["delete", "table", fam, NFT_TABLE])
                .status();
        }
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("pfctl").args(["-a", "com.hop", "-F", "all"]).status();
        // Drop the com.hop anchor references we injected by reloading the pristine
        // system main ruleset (re-reads /etc/pf.conf, which has only com.apple).
        let _ = std::process::Command::new("pfctl").args(["-f", PF_CONF]).status();
    }
}

#[cfg(target_os = "linux")]
fn enable_ip_forward_linux() -> Result<()> {
    const P: &str = "/proc/sys/net/ipv4/ip_forward";
    // Already enabled — by the host, a sysctl, or a container runtime? Then we're
    // done. This also covers a read-only `/proc/sys` (common in containers) where
    // the write would EROFS even though forwarding is already on: don't fail when
    // the desired state already holds.
    if std::fs::read_to_string(P).map(|s| s.trim() == "1").unwrap_or(false) {
        return Ok(());
    }
    std::fs::write(P, "1").with_context(|| {
        format!(
            "enabling {P} (need CAP_NET_ADMIN + a writable /proc/sys, or set \
             net.ipv4.ip_forward=1 externally e.g. via sysctl)"
        )
    })?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_nft(ruleset: &str) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    // Replace any prior tables first so re-apply is idempotent (both families).
    for fam in ["inet", "ip"] {
        let _ = Command::new("nft").args(["delete", "table", fam, NFT_TABLE]).status();
    }
    let mut child = Command::new("nft")
        .args(["-f", "-"])
        .stdin(Stdio::piped())
        .spawn()
        .context("spawning nft (is nftables installed?)")?;
    child
        .stdin
        .take()
        .context("nft stdin")?
        .write_all(ruleset.as_bytes())
        .context("writing nft ruleset")?;
    let status = child.wait().context("waiting for nft")?;
    if !status.success() {
        anyhow::bail!("nft exited with {status}");
    }
    Ok(())
}


/// Whether `cidr` covers one of this host's own interface addresses — installing
/// it as a tunnel route would hijack the local LAN (the overlap footgun). The
/// **unprivileged** half of route installation; the worker checks this itself
/// before delegating the privileged `add_route_raw` under privsep.
pub fn route_collides(cidr: &str) -> bool {
    crate::net::netmon::current_interface_addrs().iter().any(|ip| {
        matches!(ip, std::net::IpAddr::V4(v4) if crate::vpn::cidr_contains_v4(cidr, *v4))
    })
}

/// Add a kernel route `cidr → dev` (the **privileged** half; no collision check —
/// the caller must have cleared `route_collides`). Idempotent.
pub fn add_route_raw(cidr: &str, dev: &str) -> Result<()> {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("ip").args(["route", "del", cidr, "dev", dev]).status();
        let st = std::process::Command::new("ip")
            .args(["route", "add", cidr, "dev", dev])
            .status()
            .context("ip route add")?;
        if !st.success() {
            anyhow::bail!("`ip route add {cidr} dev {dev}` failed");
        }
        tracing::info!("vpn route: installed {cidr} via {dev}");
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("route").args(["-n", "delete", cidr]).status();
        let st = std::process::Command::new("route")
            .args(["-n", "add", "-net", cidr, "-interface", dev])
            .status()
            .context("route add")?;
        if !st.success() {
            anyhow::bail!("`route add -net {cidr} -interface {dev}` failed");
        }
        tracing::info!("vpn route: installed {cidr} via {dev}");
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (cidr, dev);
        Ok(())
    }
}

/// The current default-route IPv4 gateway — used to pin the warren relay past an
/// exit node's split-default so the tunnel doesn't loop through the exit itself.
/// Linux-only for now (macOS exit-node pinning is a follow-up).
pub fn default_gateway_v4() -> Option<std::net::Ipv4Addr> {
    #[cfg(target_os = "linux")]
    {
        let out = std::process::Command::new("ip").args(["route", "show", "default"]).output().ok()?;
        for line in String::from_utf8_lossy(&out.stdout).lines() {
            let mut it = line.split_whitespace();
            while let Some(tok) = it.next() {
                if tok == "via"
                    && let Some(ip) = it.next()
                    && let Ok(v4) = ip.parse::<std::net::Ipv4Addr>()
                {
                    return Some(v4);
                }
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// Resolve the warren relay host (`HOP_RELAY_URL`) to its IPv4 address(es), so an
/// exit-node client can pin them via the original gateway (keeping the relay
/// reachable outside the tunnel it bootstraps).
pub fn resolve_relay_ips() -> Vec<std::net::Ipv4Addr> {
    use std::net::ToSocketAddrs;
    let host = crate::net::HOP_RELAY_URL
        .trim_start_matches("https://")
        .trim_start_matches("http://");
    let host = host.split(['/', ':']).next().unwrap_or(host);
    (host, 443u16)
        .to_socket_addrs()
        .map(|addrs| {
            addrs
                .filter_map(|a| match a.ip() {
                    std::net::IpAddr::V4(v4) => Some(v4),
                    std::net::IpAddr::V6(_) => None,
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Remove a kernel route `cidr → dev` (privileged; best-effort).
pub fn remove_route_raw(cidr: &str, dev: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("ip").args(["route", "del", cidr, "dev", dev]).status();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = dev;
        let _ = std::process::Command::new("route").args(["-n", "delete", cidr]).status();
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (cidr, dev);
    }
}

/// Install a client route with the collision guard (returns `false` if it would
/// hijack the local LAN). Convenience for the non-privsep direct path; under
/// privsep the worker uses `route_collides` + delegates `add_route_raw`.
pub fn install_client_route(cidr: &str, tun: &str) -> Result<bool> {
    if route_collides(cidr) {
        tracing::warn!(
            "vpn route: NOT installing {cidr} — it covers a local address (would hijack the \
             local LAN). Use a narrower /32 device route to reach a specific host."
        );
        return Ok(false);
    }
    add_route_raw(cidr, tun)?;
    Ok(true)
}

/// Remove a previously-installed client route (best-effort).
pub fn uninstall_client_route(cidr: &str, tun: &str) {
    remove_route_raw(cidr, tun);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_includes_masquerade_and_clamp() {
        let routes = vec![
            GatewayRoute { cidr: "192.168.1.0/24".into(), snat: true },
            GatewayRoute { cidr: "10.0.0.5/32".into(), snat: true },
        ];
        let rs = nftables_ruleset(&routes);
        // inet table carries the forward path + MSS clamp
        assert!(rs.contains("table inet hop_gw"));
        assert!(rs.contains("type filter hook forward priority 0; policy accept;"));
        assert!(rs.contains("tcp option maxseg size set rt mtu"));
        // NAT lives in an ip-family table (compatible masquerade), matched by
        // source range — no fragile LAN-interface scoping.
        assert!(rs.contains("table ip hop_gw"));
        assert!(rs.contains("ip saddr 100.64.0.0/10 counter masquerade"));
        assert!(!rs.contains("oifname"));
    }

    #[test]
    fn pf_ruleset_has_mss_clamp_and_nat() {
        let routes = vec![GatewayRoute { cidr: "192.168.1.0/24".into(), snat: true }];
        let rs = pf_ruleset("en0", &routes);
        assert!(rs.contains("scrub on en0 all max-mss 1240"));
        assert!(rs.contains("nat on en0 from 100.64.0.0/10 to any -> (en0)"));
        // snat off → no NAT, but the scrub/MSS clamp stays.
        let off = pf_ruleset("en0", &[GatewayRoute { cidr: "10.0.0.0/8".into(), snat: false }]);
        assert!(!off.contains("nat on"));
        assert!(off.contains("max-mss 1240"));
    }

    #[test]
    fn no_masquerade_when_all_snat_off() {
        let routes = vec![GatewayRoute { cidr: "192.168.1.0/24".into(), snat: false }];
        let rs = nftables_ruleset(&routes);
        assert!(!rs.contains("masquerade"));
        assert!(!rs.contains("table ip hop_gw")); // no NAT table without SNAT routes
        // the forward path (ip_forward + accept policy + MSS clamp) is still set up
        assert!(rs.contains("policy accept;"));
        assert!(rs.contains("maxseg size set rt mtu"));
    }
}
