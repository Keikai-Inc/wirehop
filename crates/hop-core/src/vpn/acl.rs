//! VPN access control: role-derived reach.
//!
//! `role_reaches` is the behavioral oracle for VPN reachability — the Cedar
//! engine in `cedar.rs` compiles down to the same semantics and is checked
//! against it in tests. The low-level packet-filter `AclPolicy` that previously
//! lived here was never wired onto the forwarding path and has been removed in
//! favor of the Cedar engine (security-audit dead-code cleanup).

/// Role-derived reach (Step 5): does a role whose tags are `role_tags` permit
/// reaching a host tagged `host_tags`? `*` in the role's tags is a wildcard
/// (reaches everything); otherwise any tag intersection allows. Empty role tags
/// → reaches nothing (the least-privilege `member` default).
pub fn role_reaches(role_tags: &[String], host_tags: &[String]) -> bool {
    if role_tags.iter().any(|t| t == "*") {
        return true;
    }
    role_tags.iter().any(|rt| host_tags.iter().any(|ht| ht == rt))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tags(v: &[&str]) -> Vec<String> {
        v.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn role_reach_rules() {
        // Wildcard role reaches anything.
        assert!(role_reaches(&tags(&["*"]), &tags(&["production"])));
        // developer (developer,staging) reaches a staging host.
        assert!(role_reaches(&tags(&["developer", "staging"]), &tags(&["staging", "web"])));
        // developer does NOT reach a production-only host.
        assert!(!role_reaches(&tags(&["developer", "staging"]), &tags(&["production"])));
        // member (no tags) reaches nothing.
        assert!(!role_reaches(&[], &tags(&["production"])));
        assert!(!role_reaches(&[], &[]));
        // untagged host is unreachable except by wildcard.
        assert!(!role_reaches(&tags(&["developer"]), &[]));
        assert!(role_reaches(&tags(&["*"]), &[]));
    }
}
