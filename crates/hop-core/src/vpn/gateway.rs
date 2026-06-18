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
    #[cfg(not(target_os = "linux"))]
    {
        let _ = tun;
        anyhow::bail!(
            "gateway forwarding is currently Linux-only (nftables); macOS pf support is planned (P2)"
        )
    }
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


/// Install a kernel route sending `cidr` through the warren TUN, so traffic to a
/// gateway-advertised subnet leaves via the VPN. **Collision guard:** skips
/// (returns `Ok(false)`) if `cidr` already covers one of this host's own
/// interface addresses — refusing to hijack the local LAN (the overlap footgun).
/// A `/32` device route generally won't collide and still wins over the local
/// `/24`. Idempotent.
pub fn install_client_route(cidr: &str, tun: &str) -> Result<bool> {
    let locals = crate::net::netmon::current_interface_addrs();
    for ip in &locals {
        if let std::net::IpAddr::V4(v4) = ip
            && crate::vpn::cidr_contains_v4(cidr, *v4)
        {
            tracing::warn!(
                "vpn route: NOT installing {cidr} — it covers local address {v4} (would hijack \
                 the local LAN). Use a narrower /32 device route to reach a specific host."
            );
            return Ok(false);
        }
    }
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("ip").args(["route", "del", cidr, "dev", tun]).status();
        let st = std::process::Command::new("ip")
            .args(["route", "add", cidr, "dev", tun])
            .status()
            .context("ip route add")?;
        if !st.success() {
            anyhow::bail!("`ip route add {cidr} dev {tun}` failed");
        }
        tracing::info!("vpn route: installed {cidr} via {tun}");
        Ok(true)
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("route").args(["-n", "delete", cidr]).status();
        let st = std::process::Command::new("route")
            .args(["-n", "add", "-net", cidr, "-interface", tun])
            .status()
            .context("route add")?;
        if !st.success() {
            anyhow::bail!("`route add -net {cidr} -interface {tun}` failed");
        }
        tracing::info!("vpn route: installed {cidr} via {tun}");
        Ok(true)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (cidr, tun);
        Ok(false)
    }
}

/// Remove a previously-installed client route (best-effort).
pub fn uninstall_client_route(cidr: &str, _tun: &str) {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("ip").args(["route", "del", cidr, "dev", _tun]).status();
    }
    #[cfg(target_os = "macos")]
    {
        let _ = std::process::Command::new("route").args(["-n", "delete", cidr]).status();
    }
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
