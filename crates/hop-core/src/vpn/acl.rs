//! VPN access control (Phase 4 — see `docs/technical/p2p-network.md`).
//!
//! A default-deny packet filter evaluated on the VPN forwarding path. Rules
//! match on source/destination virtual IP and destination port; the first
//! matching rule wins, else the policy default applies. This is the low-level
//! enforcement layer; higher-level group/tag rules compile down to these.
//!
//! Stored in the network document at `acl/policy` (JSON) so it replicates to
//! every node and is enforced locally.

use std::net::Ipv4Addr;

use serde::{Deserialize, Serialize};

/// Allow or deny a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    Deny,
}

/// A single filter rule. `None` fields are wildcards.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub src: Option<Ipv4Addr>,
    #[serde(default)]
    pub dst: Option<Ipv4Addr>,
    /// Inclusive destination port range `[lo, hi]`; `None` matches any port
    /// (including portless protocols like ICMP).
    #[serde(default)]
    pub ports: Option<(u16, u16)>,
    pub action: Action,
}

impl Rule {
    fn matches(&self, src: Ipv4Addr, dst: Ipv4Addr, port: Option<u16>) -> bool {
        if self.src.is_some_and(|s| s != src) {
            return false;
        }
        if self.dst.is_some_and(|d| d != dst) {
            return false;
        }
        if let Some((lo, hi)) = self.ports {
            match port {
                Some(p) if (lo..=hi).contains(&p) => {}
                _ => return false,
            }
        }
        true
    }
}

/// An ordered rule list plus a default action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AclPolicy {
    pub default: Action,
    #[serde(default)]
    pub rules: Vec<Rule>,
}

impl Default for AclPolicy {
    fn default() -> Self {
        Self::default_deny()
    }
}

impl AclPolicy {
    /// Deny everything (no rules). The safe default.
    pub fn default_deny() -> Self {
        Self { default: Action::Deny, rules: Vec::new() }
    }

    /// Allow everything — convenience for an explicitly-trusted experimental
    /// network. Use sparingly.
    pub fn allow_all() -> Self {
        Self { default: Action::Allow, rules: Vec::new() }
    }

    /// Evaluate a packet: first matching rule wins, else `default`.
    pub fn evaluate(&self, src: Ipv4Addr, dst: Ipv4Addr, port: Option<u16>) -> Action {
        for r in &self.rules {
            if r.matches(src, dst, port) {
                return r.action;
            }
        }
        self.default
    }

    /// Convenience: is this packet permitted?
    pub fn permits(&self, src: Ipv4Addr, dst: Ipv4Addr, port: Option<u16>) -> bool {
        self.evaluate(src, dst, port) == Action::Allow
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    #[test]
    fn default_deny_blocks_everything() {
        let p = AclPolicy::default_deny();
        assert!(!p.permits(ip("100.64.0.1"), ip("100.64.0.2"), Some(22)));
        assert!(!p.permits(ip("100.64.0.1"), ip("100.64.0.2"), None));
    }

    #[test]
    fn allow_all_permits_everything() {
        let p = AclPolicy::allow_all();
        assert!(p.permits(ip("100.64.0.1"), ip("100.64.0.2"), Some(22)));
        assert!(p.permits(ip("100.64.0.1"), ip("100.64.0.2"), None));
    }

    #[test]
    fn first_matching_rule_wins_over_default() {
        let p = AclPolicy {
            default: Action::Deny,
            rules: vec![
                // Allow SSH from .1 to .2.
                Rule {
                    src: Some(ip("100.64.0.1")),
                    dst: Some(ip("100.64.0.2")),
                    ports: Some((22, 22)),
                    action: Action::Allow,
                },
            ],
        };
        assert!(p.permits(ip("100.64.0.1"), ip("100.64.0.2"), Some(22)));
        // Wrong port → falls through to default deny.
        assert!(!p.permits(ip("100.64.0.1"), ip("100.64.0.2"), Some(80)));
        // Wrong src → default deny.
        assert!(!p.permits(ip("100.64.0.9"), ip("100.64.0.2"), Some(22)));
        // Portless (ICMP) → port rule doesn't match → default deny.
        assert!(!p.permits(ip("100.64.0.1"), ip("100.64.0.2"), None));
    }

    #[test]
    fn wildcards_and_port_ranges() {
        let p = AclPolicy {
            default: Action::Deny,
            rules: vec![Rule {
                src: None,
                dst: None,
                ports: Some((8000, 9000)),
                action: Action::Allow,
            }],
        };
        assert!(p.permits(ip("100.64.5.5"), ip("100.64.9.9"), Some(8080)));
        assert!(!p.permits(ip("100.64.5.5"), ip("100.64.9.9"), Some(443)));
    }

    #[test]
    fn json_roundtrip() {
        let p = AclPolicy {
            default: Action::Deny,
            rules: vec![Rule {
                src: None,
                dst: Some(ip("100.64.0.2")),
                ports: Some((22, 22)),
                action: Action::Allow,
            }],
        };
        let s = serde_json::to_string(&p).unwrap();
        let back: AclPolicy = serde_json::from_str(&s).unwrap();
        assert_eq!(back.default, Action::Deny);
        assert_eq!(back.rules.len(), 1);
        assert!(back.permits(ip("100.64.0.9"), ip("100.64.0.2"), Some(22)));
    }
}
