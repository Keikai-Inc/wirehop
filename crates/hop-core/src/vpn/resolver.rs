//! Automatic split-DNS configuration for MagicDNS.
//!
//! A hop node serves MagicDNS for the warren domain (`*.hop`, or
//! `*.<warren>.hop`) on its own virtual IP — but the OS resolver won't route
//! `.hop` lookups there unless something points it at the local MagicDNS server.
//! This module performs that pointing automatically (the alternative is a manual
//! `/etc/resolver/hop` edit). It is **split-DNS**: only the warren domain is
//! routed to MagicDNS; every other lookup is untouched.
//!
//! Writing resolver config is privileged (root-owned `/etc/resolver`, or
//! `resolvectl`), so under privsep this runs in the monitor via the
//! `ConfigureResolver` primitive — see `crate::privsep`. The unprivileged worker
//! never writes here directly.
//!
//! Lifecycle: applied when the VPN comes up, removed when the daemon/monitor
//! exits, so a stale entry never points at a down server for long.

use anyhow::{Context, Result};
use std::net::Ipv4Addr;

/// Set if `HOP_NO_AUTO_RESOLVER` is present — operators who manage DNS
/// themselves opt out, and the node falls back to the manual-config behavior.
pub fn auto_resolver_disabled() -> bool {
    std::env::var_os("HOP_NO_AUTO_RESOLVER").is_some()
}

/// Point the OS resolver for `domain` at the local MagicDNS server on `vip:53`
/// (split-DNS — only `domain` is affected). Idempotent. Platform-specific:
/// macOS writes `/etc/resolver/<domain>`; Linux uses `resolvectl` when
/// systemd-resolved is present, else logs a one-line manual hint and no-ops.
pub fn apply(domain: &str, vip: Ipv4Addr) -> Result<()> {
    let domain = sanitize_domain(domain)?;
    #[cfg(target_os = "macos")]
    {
        apply_macos(&domain, vip)
    }
    #[cfg(target_os = "linux")]
    {
        apply_linux(&domain, vip)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = vip;
        tracing::info!(
            "vpn: automatic DNS config unsupported on this OS; point .{domain} at \
             {vip}:53 manually for MagicDNS"
        );
        Ok(())
    }
}

/// Undo [`apply`] for `domain`. Idempotent — missing config is not an error.
pub fn remove(domain: &str) -> Result<()> {
    let domain = match sanitize_domain(domain) {
        Ok(d) => d,
        Err(_) => return Ok(()),
    };
    #[cfg(target_os = "macos")]
    {
        remove_macos(&domain)
    }
    #[cfg(target_os = "linux")]
    {
        remove_linux(&domain)
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        Ok(())
    }
}

/// Reject anything that isn't a plain DNS label path (defense-in-depth: this
/// value becomes a file name under `/etc/resolver/` and a `resolvectl` arg).
fn sanitize_domain(domain: &str) -> Result<String> {
    let d = domain.trim().trim_matches('.').to_lowercase();
    anyhow::ensure!(!d.is_empty(), "empty resolver domain");
    anyhow::ensure!(
        d.split('.')
            .all(|l| !l.is_empty() && l.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')),
        "refusing unsafe resolver domain {domain:?}"
    );
    Ok(d)
}

#[cfg(target_os = "macos")]
fn resolver_path(domain: &str) -> std::path::PathBuf {
    std::path::Path::new("/etc/resolver").join(domain)
}

/// macOS reads `/etc/resolver/<domain>` to route that domain's lookups to a
/// specific nameserver. `port 53` is explicit because MagicDNS listens on the
/// vIP, not 127.0.0.1. The directory is root-owned, so this only succeeds in the
/// monitor (or a root daemon).
#[cfg(target_os = "macos")]
fn apply_macos(domain: &str, vip: Ipv4Addr) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::path::Path::new("/etc/resolver");
    std::fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    let path = resolver_path(domain);
    let body = format!("# Managed by hop — MagicDNS for the warren.\nnameserver {vip}\nport 53\n");
    // Only rewrite when the content differs, so we don't churn the file on every
    // VPN bring-up (macOS watches /etc/resolver and reloads on change).
    if std::fs::read_to_string(&path).ok().as_deref() == Some(body.as_str()) {
        return Ok(());
    }
    std::fs::write(&path, &body).with_context(|| format!("writing {}", path.display()))?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).ok();
    tracing::info!("vpn: configured macOS resolver — .{domain} → {vip}:53 (/etc/resolver/{domain})");
    Ok(())
}

#[cfg(target_os = "macos")]
fn remove_macos(domain: &str) -> Result<()> {
    let path = resolver_path(domain);
    // Only remove files we wrote (carry our managed marker), so we never delete
    // an operator's hand-rolled resolver entry.
    match std::fs::read_to_string(&path) {
        Ok(s) if s.contains("Managed by hop") => {
            std::fs::remove_file(&path)
                .with_context(|| format!("removing {}", path.display()))?;
            tracing::info!("vpn: removed macOS resolver entry /etc/resolver/{domain}");
        }
        _ => {}
    }
    Ok(())
}

/// Linux split-DNS via systemd-resolved: route `~<domain>` (a routing-only
/// domain) on the hop TUN interface to the local MagicDNS server. `resolvectl`
/// scopes this per-interface and reverts automatically when the link drops, so
/// we never edit `/etc/resolv.conf`. If systemd-resolved isn't running we can't
/// do safe split-DNS, so we log the manual step and no-op.
#[cfg(target_os = "linux")]
fn apply_linux(domain: &str, vip: Ipv4Addr) -> Result<()> {
    let Some(iface) = hop_tun_iface(vip) else {
        tracing::warn!("vpn: could not find the hop TUN interface for {vip}; skipping DNS config");
        return Ok(());
    };
    if !resolvectl_available() {
        tracing::info!(
            "vpn: systemd-resolved not detected; for `.{domain}` resolution add \
             `nameserver {vip}` via your resolver (e.g. /etc/resolv.conf) manually"
        );
        return Ok(());
    }
    run_ok("resolvectl", &["dns", &iface, &vip.to_string()])
        .with_context(|| format!("resolvectl dns {iface} {vip}"))?;
    // The leading `~` makes it a *routing* domain: only `*.<domain>` queries go
    // to this link's nameserver; it is not a search-suffix for bare names.
    run_ok("resolvectl", &["domain", &iface, &format!("~{domain}")])
        .with_context(|| format!("resolvectl domain {iface} ~{domain}"))?;
    tracing::info!("vpn: configured systemd-resolved — .{domain} → {vip}:53 on {iface}");
    Ok(())
}

#[cfg(target_os = "linux")]
fn remove_linux(domain: &str) -> Result<()> {
    // We don't know the vIP here, but `resolvectl revert <iface>` clears all of
    // our per-link settings. Find the hop TUN by name prefix instead.
    let _ = domain;
    if !resolvectl_available() {
        return Ok(());
    }
    for iface in hop_tun_ifaces_by_name() {
        let _ = run_ok("resolvectl", &["revert", &iface]);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn resolvectl_available() -> bool {
    // systemd-resolved must be the active resolver for resolvectl to take effect.
    std::path::Path::new("/run/systemd/resolve/stub-resolv.conf").exists()
        || std::path::Path::new("/run/systemd/resolve/resolv.conf").exists()
}

/// Find the TUN interface carrying `vip` by scanning `/sys/class/net/*` and the
/// kernel's address list. We match by the assigned address so we target the hop
/// device specifically, not some other tun.
#[cfg(target_os = "linux")]
fn hop_tun_iface(vip: Ipv4Addr) -> Option<String> {
    let addrs = nix::ifaddrs::getifaddrs().ok()?;
    for ifa in addrs {
        if let Some(sa) = ifa.address.and_then(|a| a.as_sockaddr_in().map(|s| s.ip()))
            && sa == vip
        {
            return Some(ifa.interface_name);
        }
    }
    None
}

/// hop TUN interfaces by conventional name prefix (for teardown, when the vIP is
/// no longer known). hop names its devices `hop*`/`utun*` depending on platform.
#[cfg(target_os = "linux")]
fn hop_tun_ifaces_by_name() -> Vec<String> {
    let mut out = Vec::new();
    if let Ok(addrs) = nix::ifaddrs::getifaddrs() {
        for ifa in addrs {
            let n = &ifa.interface_name;
            if (n.starts_with("hop") || n.starts_with("utun")) && !out.contains(n) {
                out.push(n.clone());
            }
        }
    }
    out
}

#[cfg(target_os = "linux")]
fn run_ok(cmd: &str, args: &[&str]) -> Result<()> {
    let status = std::process::Command::new(cmd)
        .args(args)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .with_context(|| format!("spawning {cmd}"))?;
    anyhow::ensure!(status.success(), "{cmd} exited with {status}");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn domain_sanitization() {
        assert_eq!(sanitize_domain("hop").unwrap(), "hop");
        assert_eq!(sanitize_domain(".HOP.").unwrap(), "hop");
        assert_eq!(sanitize_domain("acme.hop").unwrap(), "acme.hop");
        assert!(sanitize_domain("").is_err());
        assert!(sanitize_domain("..").is_err());
        assert!(sanitize_domain("a/b").is_err()); // path traversal
        assert!(sanitize_domain("a b").is_err());
        assert!(sanitize_domain("../etc/passwd").is_err());
    }
}
