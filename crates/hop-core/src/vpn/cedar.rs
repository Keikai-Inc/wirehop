//! Cedar-based reach engine (ACL Phase 1 — see
//! `docs/technical/acl-cedar-plan.md`).
//!
//! hop's `role → tag` reach is compiled to a Cedar policy set evaluated against
//! entities derived from the replicated network document. This is the standard,
//! analyzable policy engine; `role_reaches` (in `acl.rs`) remains the behavioral
//! oracle the parity tests check against.
//!
//! The role is flattened onto the `Peer` principal at build time (its
//! `reach_tags` + `wildcard`), so policies use only direct attributes — no
//! transitive entity-attribute access — and stay simple and fast.

use std::collections::HashMap;

use anyhow::{Context as _, Result};
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request,
};

use crate::config::Peer;
use crate::proto::RoleDefinition;

/// The generated default policy: encodes `role_reaches` (wildcard reaches all;
/// otherwise the role's tags must intersect the host's tags). Cedar is
/// deny-by-default, so the absence of a matching `permit` denies — matching
/// hop's default-deny posture.
pub const DEFAULT_REACH_POLICY: &str = r#"
permit ( principal, action == Action::"connect", resource )
when { principal.wildcard || principal.reach_tags.containsAny(resource.tags) };
"#;

/// A compiled reach decision engine over a snapshot of warren membership.
pub struct AclEngine {
    policies: PolicySet,
    entities: Entities,
    authorizer: Authorizer,
}

impl AclEngine {
    /// Build the engine from a membership snapshot:
    /// - `peers`: authorized peers (carry `role_name`),
    /// - `roles`: role definitions (`host_tags`, `admin`),
    /// - `host_tags`: `node_id → tags` for every reachable host,
    /// - `authored`: optional additional Cedar policy text (Phase 3).
    pub fn build(
        peers: &[Peer],
        roles: &[RoleDefinition],
        host_tags: &HashMap<String, Vec<String>>,
        authored: Option<&str>,
    ) -> Result<Self> {
        let role_by_name: HashMap<&str, &RoleDefinition> =
            roles.iter().map(|r| (r.name.as_str(), r)).collect();

        let mut ents: Vec<serde_json::Value> = Vec::with_capacity(peers.len() + host_tags.len());

        // Principals: each peer with its role flattened onto it.
        for p in peers {
            let (reach_tags, wildcard, admin): (Vec<String>, bool, bool) = match p
                .role_name
                .as_deref()
                .and_then(|n| role_by_name.get(n))
            {
                Some(r) => (
                    r.host_tags.clone(),
                    r.host_tags.iter().any(|t| t == "*"),
                    r.admin,
                ),
                None => (Vec::new(), false, false),
            };
            ents.push(serde_json::json!({
                "uid": { "type": "Peer", "id": p.node_id },
                "attrs": { "reach_tags": reach_tags, "wildcard": wildcard, "admin": admin },
                "parents": []
            }));
        }

        // Resources: each host with its tags.
        for (node, tags) in host_tags {
            ents.push(serde_json::json!({
                "uid": { "type": "Host", "id": node },
                "attrs": { "tags": tags },
                "parents": []
            }));
        }

        let entities = Entities::from_json_value(serde_json::Value::Array(ents), None)
            .context("building Cedar entities")?;

        let mut text = DEFAULT_REACH_POLICY.to_string();
        if let Some(extra) = authored {
            text.push('\n');
            text.push_str(extra);
        }
        let policies: PolicySet = text
            .parse()
            .map_err(|e| anyhow::anyhow!("parsing Cedar policies: {e}"))?;

        Ok(Self { policies, entities, authorizer: Authorizer::new() })
    }

    /// May `src_node` (a Peer) reach `dst_node` (a Host)? Port is reserved for
    /// Phase 2 (per-port policies); ignored here for parity with `role_reaches`.
    pub fn is_reach_allowed(&self, src_node: &str, dst_node: &str, _port: Option<u16>) -> bool {
        self.decision(src_node, dst_node, _port) == Decision::Allow
    }

    /// The raw Cedar decision (used by `is_reach_allowed` and, later, explain).
    pub fn decision(&self, src_node: &str, dst_node: &str, _port: Option<u16>) -> Decision {
        let Ok(principal) = format!(r#"Peer::"{src_node}""#).parse::<EntityUid>() else {
            return Decision::Deny;
        };
        let Ok(action) = r#"Action::"connect""#.parse::<EntityUid>() else {
            return Decision::Deny;
        };
        let Ok(resource) = format!(r#"Host::"{dst_node}""#).parse::<EntityUid>() else {
            return Decision::Deny;
        };
        let req = match Request::new(principal, action, resource, Context::empty(), None) {
            Ok(r) => r,
            Err(_) => return Decision::Deny,
        };
        self.authorizer
            .is_authorized(&req, &self.policies, &self.entities)
            .decision()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PeerRole;
    use crate::sandbox::SandboxPolicy;

    fn role(name: &str, tags: &[&str]) -> RoleDefinition {
        RoleDefinition {
            name: name.into(),
            host_tags: tags.iter().map(|s| s.to_string()).collect(),
            user_mode: Default::default(),
            sudo: false,
            admin: name == "admin",
            groups: vec![],
            shell: None,
            sandbox: SandboxPolicy::default(),
        }
    }

    fn peer(node: &str, role_name: &str) -> Peer {
        Peer {
            node_id: node.into(),
            name: node.into(),
            authorized_at: "2026-01-01T00:00:00Z".into(),
            last_seen: None,
            username: None,
            role: PeerRole::Peer,
            role_name: Some(role_name.into()),
            sandbox: SandboxPolicy::default(),
        }
    }

    fn engine() -> AclEngine {
        let roles = vec![
            role("admin", &["*"]),
            role("developer", &["developer", "staging"]),
            role("member", &[]),
        ];
        let peers = vec![
            peer("nodeAdmin", "admin"),
            peer("nodeDev", "developer"),
            peer("nodeMember", "member"),
        ];
        let mut tags = HashMap::new();
        tags.insert("hostProd".to_string(), vec!["production".to_string()]);
        tags.insert("hostStaging".to_string(), vec!["staging".to_string(), "web".to_string()]);
        tags.insert("hostUntagged".to_string(), vec![]);
        AclEngine::build(&peers, &roles, &tags, None).unwrap()
    }

    #[test]
    fn cedar_matches_role_reaches() {
        let e = engine();
        // admin (wildcard) reaches everything, including untagged.
        assert!(e.is_reach_allowed("nodeAdmin", "hostProd", None));
        assert!(e.is_reach_allowed("nodeAdmin", "hostUntagged", None));
        // developer reaches staging, not production.
        assert!(e.is_reach_allowed("nodeDev", "hostStaging", None));
        assert!(!e.is_reach_allowed("nodeDev", "hostProd", None));
        // developer does NOT reach an untagged host.
        assert!(!e.is_reach_allowed("nodeDev", "hostUntagged", None));
        // member (no tags) reaches nothing.
        assert!(!e.is_reach_allowed("nodeMember", "hostProd", None));
        assert!(!e.is_reach_allowed("nodeMember", "hostStaging", None));
        // Unknown principal → deny: attribute access on a missing entity errors,
        // so no `permit` matches (default-deny). (Unknown *resources* are denied
        // upstream at IP→node resolution before the engine is consulted; a
        // wildcard principal reaching any resource matches role_reaches(["*"], _).)
        assert!(!e.is_reach_allowed("ghost", "hostStaging", None));
    }
}
