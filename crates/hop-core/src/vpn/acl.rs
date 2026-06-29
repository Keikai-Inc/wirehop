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

/// A fleet operation a peer may attempt on a host (G23 capability scoping). The
/// host derives this from the request: a READ-ONLY session (e.g. `hop fleet grep`,
/// an exec under a `read_only` sandbox) is a [`Action::Search`]; anything that can
/// mutate the host (shell, plain exec, transfer, tunnel) is [`Action::Exec`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Read-only / observe: log search, audit-read, metrics.
    Search,
    /// Anything that can change the host: shell / exec / transfer / tunnel.
    Exec,
}

impl Action {
    pub fn verb(self) -> &'static str {
        match self {
            Action::Search => "search",
            Action::Exec => "open exec/shell sessions on",
        }
    }
}

/// May a peer with role `role` perform `action` on a host tagged `host_tags`?
/// (G23 capability scoping — the host-side session gate.) The capability ladder,
/// per role → host-tag:
/// - `reach` (L3) is separate ([`role_reaches`] on `host_tags`).
/// - `exec` = shell/exec/transfer/tunnel: a `network_only` role gets NONE;
///   otherwise `role.exec_tags` scopes it — **empty = open** (any host, today's
///   behavior, no regression), set to restrict (`["dev"]`), `*` = all.
/// - `search` = read-only ops: granted by `exec` (exec implies search) OR an
///   explicit `role.search_tags` match — the new middle tier that lets a role (even
///   `network_only`) read logs on hosts it may not mutate.
///
/// `require_explicit` is the HOST's "locked" switch (default off): when off an
/// unscoped role keeps open access; when on, only explicitly-granted tags pass.
/// **Admin roles are never locked out** (anti-lockout for the founder/operators).
pub fn capability_allowed(
    role: &crate::proto::RoleDefinition,
    action: Action,
    host_tags: &[String],
    require_explicit: bool,
) -> bool {
    if role.admin {
        return true; // founder/admin: never locked out of their own fleet
    }
    let exec_ok = !role.network_only
        && if role.exec_tags.is_empty() {
            !require_explicit // empty exec_tags: open unless the host is locked
        } else {
            role_reaches(&role.exec_tags, host_tags)
        };
    match action {
        Action::Exec => exec_ok,
        Action::Search => {
            exec_ok || (!role.search_tags.is_empty() && role_reaches(&role.search_tags, host_tags))
        }
    }
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

    fn role(name: &str) -> crate::proto::RoleDefinition {
        crate::proto::RoleDefinition {
            name: name.into(),
            host_tags: vec![],
            user_mode: Default::default(),
            sudo: false,
            admin: false,
            groups: vec![],
            shell: None,
            network_only: false,
            sandbox: Default::default(),
            capabilities: Default::default(),
            exec_tags: vec![],
            search_tags: vec![],
        }
    }

    #[test]
    fn capability_open_default_no_regression() {
        // A plain role with no exec/search tags keeps today's open access (a small
        // team just works): exec + search anywhere, when the host is not locked.
        let r = role("member");
        let prod = tags(&["prod"]);
        assert!(capability_allowed(&r, Action::Exec, &prod, false));
        assert!(capability_allowed(&r, Action::Search, &prod, false));
    }

    #[test]
    fn capability_network_only_blocks_sessions_but_search_tier_can_be_granted() {
        // marketing: network_only, no search → no exec, no search.
        let mut mk = role("marketing");
        mk.network_only = true;
        assert!(!capability_allowed(&mk, Action::Exec, &tags(&["prod"]), false));
        assert!(!capability_allowed(&mk, Action::Search, &tags(&["prod"]), false));
        // the new middle tier: grant a network_only role read-only search on a tag.
        mk.search_tags = tags(&["logs"]);
        assert!(capability_allowed(&mk, Action::Search, &tags(&["logs"]), false));
        assert!(!capability_allowed(&mk, Action::Search, &tags(&["prod"]), false)); // scoped
        assert!(!capability_allowed(&mk, Action::Exec, &tags(&["logs"]), false)); // still no exec
    }

    #[test]
    fn capability_developer_scoped_exec_wider_search() {
        // developer: exec dev only, search dev+staging.
        let mut dev = role("developer");
        dev.exec_tags = tags(&["dev"]);
        dev.search_tags = tags(&["staging"]);
        // dev host: exec + search.
        assert!(capability_allowed(&dev, Action::Exec, &tags(&["dev"]), false));
        assert!(capability_allowed(&dev, Action::Search, &tags(&["dev"]), false));
        // staging host: search only, NO exec.
        assert!(!capability_allowed(&dev, Action::Exec, &tags(&["staging"]), false));
        assert!(capability_allowed(&dev, Action::Search, &tags(&["staging"]), false));
        // prod host: neither.
        assert!(!capability_allowed(&dev, Action::Exec, &tags(&["prod"]), false));
        assert!(!capability_allowed(&dev, Action::Search, &tags(&["prod"]), false));
    }

    #[test]
    fn capability_locked_host_requires_explicit_grant_admins_exempt() {
        let prod = tags(&["prod"]);
        // Locked host: an unscoped role is denied (must be granted explicitly).
        let r = role("member");
        assert!(!capability_allowed(&r, Action::Exec, &prod, true));
        assert!(!capability_allowed(&r, Action::Search, &prod, true));
        // An explicit grant passes even when locked.
        let mut granted = role("ops");
        granted.exec_tags = tags(&["prod"]);
        assert!(capability_allowed(&granted, Action::Exec, &prod, true));
        // Admin roles are never locked out (anti-lockout).
        let mut admin = role("admin");
        admin.admin = true;
        assert!(capability_allowed(&admin, Action::Exec, &prod, true));
        assert!(capability_allowed(&admin, Action::Search, &prod, true));
    }
}
