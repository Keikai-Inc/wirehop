//! Device posture collector (security-audit Path D / device posture).
//!
//! Gathers this host's device-health facts and returns them as a flat
//! `attribute -> value` map. The map is published over the per-member self-doc
//! `posture/<node_id>` path (see `NetDoc::register_posture`); because `posture/`
//! is a self-owned key and C1 author-validation enforces by default, a published
//! posture entry is **tamper-evident** (a member can't forge another's). Cedar
//! reach policies then gate on these as principal attributes, e.g.
//! `permit(...) when { principal.disk_encrypted == "true" }`.
//!
//! Everything is **best-effort**: a probe whose tool is missing or that fails
//! yields `"unknown"` (never an error, never a panic), so posture collection can
//! never block or break host bringup. Boolean-ish facts are `"true"` / `"false"`
//! / `"unknown"`. Probes run concurrently and each is capped by `PROBE_TIMEOUT`;
//! a missing binary fails fast (spawn error), so the cap only matters for a
//! genuinely hung tool.

use std::collections::BTreeMap;
use std::time::Duration;

/// Upper bound on any single probe. A missing tool errors immediately; this only
/// bounds a tool that hangs.
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// Collect this host's posture. Always includes `os`, `os_version`, `hop_version`;
/// `disk_encrypted`, `firewall`, and `screen_lock` are best-effort
/// (`"true"`/`"false"`/`"unknown"`). Probes run concurrently (≈ one probe's worth
/// of latency total).
pub async fn collect() -> BTreeMap<String, String> {
    let (os_version, disk_encrypted, firewall, screen_lock) =
        tokio::join!(os_version(), disk_encrypted(), firewall(), screen_lock());
    let mut m = BTreeMap::new();
    m.insert("os".to_string(), std::env::consts::OS.to_string());
    m.insert("hop_version".to_string(), env!("CARGO_PKG_VERSION").to_string());
    m.insert("os_version".to_string(), os_version);
    m.insert("disk_encrypted".to_string(), disk_encrypted);
    m.insert("firewall".to_string(), firewall);
    m.insert("screen_lock".to_string(), screen_lock);
    m
}

/// Run `cmd args...` with a timeout; trimmed stdout on success, else `None`.
async fn probe(cmd: &str, args: &[&str]) -> Option<String> {
    let fut = tokio::process::Command::new(cmd).args(args).output();
    let out = tokio::time::timeout(PROBE_TIMEOUT, fut).await.ok()?.ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

async fn os_version() -> String {
    #[cfg(target_os = "macos")]
    {
        return probe("sw_vers", &["-productVersion"])
            .await
            .unwrap_or_else(|| "unknown".to_string());
    }
    #[cfg(target_os = "linux")]
    {
        if let Ok(s) = tokio::fs::read_to_string("/etc/os-release").await {
            for line in s.lines() {
                if let Some(v) = line.strip_prefix("VERSION_ID=") {
                    return v.trim().trim_matches('"').to_string();
                }
            }
        }
        return "unknown".to_string();
    }
    #[allow(unreachable_code)]
    "unknown".to_string()
}

async fn disk_encrypted() -> String {
    #[cfg(target_os = "macos")]
    {
        // `fdesetup status` -> "FileVault is On." / "FileVault is Off."
        return match probe("fdesetup", &["status"]).await {
            Some(s) if s.contains("On") => "true".to_string(),
            Some(_) => "false".to_string(),
            None => "unknown".to_string(),
        };
    }
    #[cfg(target_os = "linux")]
    {
        // Any LUKS/crypt block device present means an encrypted volume is in use.
        return match probe("lsblk", &["-o", "TYPE", "-n"]).await {
            Some(s) if s.lines().any(|l| l.trim() == "crypt") => "true".to_string(),
            Some(_) => "false".to_string(),
            None => "unknown".to_string(),
        };
    }
    #[allow(unreachable_code)]
    "unknown".to_string()
}

async fn firewall() -> String {
    #[cfg(target_os = "macos")]
    {
        return match probe(
            "/usr/libexec/ApplicationFirewall/socketfilterfw",
            &["--getglobalstate"],
        )
        .await
        {
            Some(s) if s.to_lowercase().contains("enabled") => "true".to_string(),
            Some(_) => "false".to_string(),
            None => "unknown".to_string(),
        };
    }
    #[cfg(target_os = "linux")]
    {
        // ufw is the common desktop/server case (needs privilege; failure -> unknown).
        return match probe("ufw", &["status"]).await.map(|s| s.to_lowercase()) {
            Some(s) if s.contains("status: active") => "true".to_string(),
            Some(s) if s.contains("status: inactive") => "false".to_string(),
            _ => "unknown".to_string(),
        };
    }
    #[allow(unreachable_code)]
    "unknown".to_string()
}

async fn screen_lock() -> String {
    #[cfg(target_os = "macos")]
    {
        // askForPassword in com.apple.screensaver (current user). Best-effort.
        return match probe("defaults", &["read", "com.apple.screensaver", "askForPassword"]).await {
            Some(s) if s.trim() == "1" => "true".to_string(),
            Some(_) => "false".to_string(),
            None => "unknown".to_string(),
        };
    }
    #[cfg(target_os = "linux")]
    {
        // Desktop-dependent; GNOME via gsettings, otherwise unknown.
        return match probe(
            "gsettings",
            &["get", "org.gnome.desktop.screensaver", "lock-enabled"],
        )
        .await
        {
            Some(s) if s.contains("true") => "true".to_string(),
            Some(s) if s.contains("false") => "false".to_string(),
            _ => "unknown".to_string(),
        };
    }
    #[allow(unreachable_code)]
    "unknown".to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn collect_has_core_fields_and_valid_booleans() {
        let p = collect().await;
        // Always-present facts.
        assert_eq!(p.get("os").map(String::as_str), Some(std::env::consts::OS));
        assert_eq!(
            p.get("hop_version").map(String::as_str),
            Some(env!("CARGO_PKG_VERSION"))
        );
        assert!(p.contains_key("os_version"));
        // Boolean-ish facts are constrained to the tri-state, never arbitrary text.
        for k in ["disk_encrypted", "firewall", "screen_lock"] {
            let v = p.get(k).expect("present");
            assert!(
                matches!(v.as_str(), "true" | "false" | "unknown"),
                "{k} = {v:?} not in true/false/unknown"
            );
        }
    }
}
