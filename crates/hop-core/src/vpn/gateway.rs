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
#[cfg(target_os = "linux")]
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
///   (`100.64.0.0/10`) leaving via the LAN interface, for SNAT routes.
///
/// `tun`/`lan` are interface names; an empty `routes` slice yields an empty
/// table (no forwarding) so the function is always safe to apply.
pub fn nftables_ruleset(tun: &str, lan: &str, routes: &[GatewayRoute]) -> String {
    let mut fwd = String::new();
    // Accept established/related return traffic both ways.
    fwd.push_str("    ct state established,related accept\n");
    for r in routes {
        // warren (via tun) → LAN for this destination, and LAN → warren back.
        fwd.push_str(&format!(
            "    iifname \"{tun}\" oifname \"{lan}\" ip daddr {cidr} accept\n",
            cidr = r.cidr
        ));
        fwd.push_str(&format!(
            "    iifname \"{lan}\" oifname \"{tun}\" ip saddr {cidr} accept\n",
            cidr = r.cidr
        ));
    }
    // MSS clamp for forwarded TCP SYNs (path-MTU aware).
    fwd.push_str("    tcp flags syn tcp option maxseg size set rt mtu\n");

    let mut nat = String::new();
    if routes.iter().any(|r| r.snat) {
        nat.push_str(&format!(
            "    ip saddr 100.64.0.0/10 oifname \"{lan}\" masquerade\n"
        ));
    }

    format!(
        "table inet {NFT_TABLE} {{\n\
         \x20 chain forward {{\n\
         \x20   type filter hook forward priority 0; policy accept;\n\
         {fwd}\
         \x20 }}\n\
         \x20 chain postrouting {{\n\
         \x20   type nat hook postrouting priority srcnat;\n\
         {nat}\
         \x20 }}\n\
         }}\n"
    )
}

/// Enable kernel IPv4 forwarding and apply the NAT/forward ruleset for `routes`.
/// `tun` is the warren TUN interface; `lan` is the physical egress interface
/// (auto-detected if `None`). Idempotent: replaces any prior `hop_gw` table.
pub fn setup_gateway(tun: &str, lan: Option<&str>, routes: &[GatewayRoute]) -> Result<()> {
    if routes.is_empty() {
        return Ok(());
    }
    #[cfg(target_os = "linux")]
    {
        let lan = match lan {
            Some(l) => l.to_string(),
            None => detect_lan_iface().context("detecting LAN egress interface")?,
        };
        enable_ip_forward_linux()?;
        let ruleset = nftables_ruleset(tun, &lan, routes);
        apply_nft(&ruleset)?;
        tracing::info!(
            "vpn gateway: forwarding {} route(s) {} ↔ {} (nftables hop_gw applied)",
            routes.len(),
            tun,
            lan
        );
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (tun, lan);
        anyhow::bail!(
            "gateway forwarding is currently Linux-only (nftables); macOS pf support is planned (P2)"
        )
    }
}

/// Tear down hop's gateway NAT (remove the `hop_gw` table). Best-effort.
pub fn teardown_gateway() {
    #[cfg(target_os = "linux")]
    {
        let _ = std::process::Command::new("nft")
            .args(["delete", "table", "inet", NFT_TABLE])
            .status();
    }
}

#[cfg(target_os = "linux")]
fn enable_ip_forward_linux() -> Result<()> {
    std::fs::write("/proc/sys/net/ipv4/ip_forward", "1")
        .context("enabling net.ipv4.ip_forward (need CAP_NET_ADMIN / root)")?;
    Ok(())
}

#[cfg(target_os = "linux")]
fn apply_nft(ruleset: &str) -> Result<()> {
    use std::io::Write;
    use std::process::{Command, Stdio};
    // Replace any prior table first so re-apply is idempotent.
    let _ = Command::new("nft")
        .args(["delete", "table", "inet", NFT_TABLE])
        .status();
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

/// The interface that carries the default route (the LAN egress).
#[cfg(target_os = "linux")]
fn detect_lan_iface() -> Result<String> {
    let out = std::process::Command::new("ip")
        .args(["route", "show", "default"])
        .output()
        .context("running `ip route show default`")?;
    let text = String::from_utf8_lossy(&out.stdout);
    // "default via 192.168.1.1 dev eth0 ..." → eth0
    for line in text.lines() {
        let mut it = line.split_whitespace();
        while let Some(tok) = it.next() {
            if tok == "dev"
                && let Some(dev) = it.next()
            {
                return Ok(dev.to_string());
            }
        }
    }
    anyhow::bail!("could not determine the default-route interface")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ruleset_includes_forward_masquerade_and_clamp() {
        let routes = vec![
            GatewayRoute { cidr: "192.168.1.0/24".into(), snat: true },
            GatewayRoute { cidr: "10.0.0.5/32".into(), snat: true },
        ];
        let rs = nftables_ruleset("hop0", "eth0", &routes);
        assert!(rs.contains("table inet hop_gw"));
        // both directions for each CIDR
        assert!(rs.contains("iifname \"hop0\" oifname \"eth0\" ip daddr 192.168.1.0/24 accept"));
        assert!(rs.contains("iifname \"eth0\" oifname \"hop0\" ip saddr 10.0.0.5/32 accept"));
        // masquerade present for snat routes
        assert!(rs.contains("ip saddr 100.64.0.0/10 oifname \"eth0\" masquerade"));
        // MSS clamp
        assert!(rs.contains("tcp option maxseg size set rt mtu"));
    }

    #[test]
    fn no_masquerade_when_all_snat_off() {
        let routes = vec![GatewayRoute { cidr: "192.168.1.0/24".into(), snat: false }];
        let rs = nftables_ruleset("hop0", "eth0", &routes);
        assert!(!rs.contains("masquerade"));
        // forwarding rules still present (snat off = preserve source, needs return routes)
        assert!(rs.contains("ip daddr 192.168.1.0/24 accept"));
    }
}
