//! Tailscale ACL/grants importer (ACL Phase 4 — see
//! `docs/technical/acl-cedar-plan.md`).
//!
//! Translates a Tailscale tailnet policy file (HuJSON / JWCC) into hop's native
//! model: Tailscale **groups** become hop **roles**, and the tags each group is
//! allowed to reach (`dst` in `accept` rules / `grants`) become that role's
//! `host_tags` — which is exactly hop's `role → tag` reach. Features that don't
//! map (tagOwners, ssh, postures, app capabilities, …) are reported, never
//! silently dropped.
//!
//! This is a pure translation: it returns roles + a report. Applying them
//! (creating the roles, tagging hosts) is a separate, deliberate step.

use std::collections::BTreeMap;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::proto::{RoleDefinition, UserMode};

/// The outcome of importing a Tailscale policy.
#[derive(Debug, Default)]
pub struct ImportResult {
    /// Roles to create (Tailscale groups → hop roles, with derived reach tags).
    pub roles: Vec<RoleDefinition>,
    /// Host tags referenced by the policy (assign these to the matching hosts).
    pub tags_seen: Vec<String>,
    /// Mapping notes (lossy-but-accepted translations).
    pub notes: Vec<String>,
    /// Features that were not translated, with the reason.
    pub skipped: Vec<String>,
}

impl ImportResult {
    /// A human-readable summary (for `hop acl import --dry-run`).
    pub fn report(&self) -> String {
        let mut s = String::new();
        s.push_str(&format!("Imported {} role(s):\n", self.roles.len()));
        for r in &self.roles {
            let tags = if r.host_tags.is_empty() {
                "(no reach)".to_string()
            } else {
                r.host_tags.join(", ")
            };
            s.push_str(&format!("  • {:<16} reaches: {tags}\n", r.name));
        }
        if !self.tags_seen.is_empty() {
            s.push_str(&format!("\nHost tags referenced (assign to hosts): {}\n", self.tags_seen.join(", ")));
        }
        if !self.notes.is_empty() {
            s.push_str("\nNotes:\n");
            for n in &self.notes {
                s.push_str(&format!("  - {n}\n"));
            }
        }
        if !self.skipped.is_empty() {
            s.push_str("\nNot imported (no hop equivalent):\n");
            for k in &self.skipped {
                s.push_str(&format!("  ! {k}\n"));
            }
        }
        s
    }
}

/// Minimal Tailscale policy shape (only the fields we translate or report).
#[derive(Debug, Deserialize, Default)]
struct TsPolicy {
    #[serde(default)]
    acls: Vec<TsAcl>,
    #[serde(default)]
    grants: Vec<TsGrant>,
    #[serde(default)]
    groups: BTreeMap<String, Vec<String>>,
    #[serde(default, rename = "tagOwners")]
    tag_owners: BTreeMap<String, serde_json::Value>,
    #[serde(default)]
    ssh: Vec<serde_json::Value>,
    #[serde(default)]
    postures: BTreeMap<String, serde_json::Value>,
    #[serde(default, rename = "nodeAttrs")]
    node_attrs: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct TsAcl {
    #[serde(default)]
    action: String,
    #[serde(default)]
    src: Vec<String>,
    #[serde(default)]
    dst: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct TsGrant {
    #[serde(default)]
    src: Vec<String>,
    #[serde(default)]
    dst: Vec<String>,
    #[serde(default)]
    ip: Vec<serde_json::Value>,
    #[serde(default)]
    app: Option<serde_json::Value>,
}

/// Import a Tailscale tailnet policy file (HuJSON) into hop's model.
pub fn import_tailscale_policy(hujson: &str) -> Result<ImportResult> {
    let json = strip_jwcc(hujson);
    let policy: TsPolicy =
        serde_json::from_str(&json).context("parsing Tailscale policy (HuJSON/JWCC)")?;

    let mut result = ImportResult::default();
    // role name → set of reach tags (deduped, ordered)
    let mut role_reach: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut tags_seen: Vec<String> = Vec::new();

    // Seed a role for every declared group (even if it appears in no rule).
    for g in policy.groups.keys() {
        role_reach.entry(role_name_of(g)).or_default();
    }

    // Translate accept-rule and grant src→dst into role→tag reach.
    let mut add_reach = |srcs: &[String], dsts: &[String], notes: &mut Vec<String>| {
        for src in srcs {
            let Some(role) = src_to_role(src, notes) else { continue };
            let reach = role_reach.entry(role).or_default();
            for d in dsts {
                match dst_to_tag(d) {
                    DstTag::Tag(t) => {
                        if !reach.contains(&t) {
                            reach.push(t.clone());
                        }
                        if !tags_seen.contains(&t) {
                            tags_seen.push(t);
                        }
                    }
                    DstTag::Wildcard => {
                        if !reach.contains(&"*".to_string()) {
                            reach.push("*".to_string());
                        }
                    }
                    DstTag::Unsupported(s) => {
                        notes.push(format!("dst {s:?} mapped to no tag (only tag:/* destinations translate)"));
                    }
                }
            }
        }
    };

    for acl in &policy.acls {
        if acl.action != "accept" {
            result.skipped.push(format!("acl action {:?} (only 'accept' is supported)", acl.action));
            continue;
        }
        add_reach(&acl.src, &acl.dst, &mut result.notes);
    }
    for grant in &policy.grants {
        add_reach(&grant.src, &grant.dst, &mut result.notes);
        if grant.app.is_some() {
            result.skipped.push(
                "grant `app` capabilities (hop app-capability grants are a separate feature)".into(),
            );
        }
        if !grant.ip.is_empty() {
            result.notes.push(
                "grant `ip` port/proto scoping flattened to tag-level reach (hop reach is tag-level by default)".into(),
            );
        }
    }

    // Build RoleDefinitions.
    for (name, mut tags) in role_reach {
        tags.sort();
        tags.dedup();
        result.roles.push(RoleDefinition {
            name,
            host_tags: tags,
            user_mode: UserMode::default(),
            sudo: false,
            admin: false,
            groups: vec![],
            shell: None,
            sandbox: Default::default(),
        });
    }
    result.roles.sort_by(|a, b| a.name.cmp(&b.name));
    tags_seen.sort();
    tags_seen.dedup();
    result.tags_seen = tags_seen;

    // Report unmapped features.
    if !policy.tag_owners.is_empty() {
        result.skipped.push(format!(
            "tagOwners ({} tag(s)) — hop assigns tags at install/role, not via owners",
            policy.tag_owners.len()
        ));
    }
    if !policy.ssh.is_empty() {
        result.skipped.push(format!("ssh rules ({}) — hop session auth is separate", policy.ssh.len()));
    }
    if !policy.postures.is_empty() {
        result.skipped.push(format!("postures ({}) — device posture is a separate hop feature", policy.postures.len()));
    }
    if !policy.node_attrs.is_empty() {
        result.skipped.push(format!("nodeAttrs ({}) — not modeled", policy.node_attrs.len()));
    }

    Ok(result)
}

enum DstTag {
    Tag(String),
    Wildcard,
    Unsupported(String),
}

/// `"group:eng"` / `"eng"` → role name `eng`. Other src forms (users, autogroups,
/// tags) are noted and skipped.
fn src_to_role(src: &str, notes: &mut Vec<String>) -> Option<String> {
    if let Some(g) = src.strip_prefix("group:") {
        return Some(g.to_string());
    }
    if src == "*" || src == "autogroup:members" {
        notes.push(format!("src {src:?} mapped to the `member` default role", ));
        return Some("member".to_string());
    }
    if src == "autogroup:admin" {
        return Some("admin".to_string());
    }
    if src.starts_with("autogroup:") || src.starts_with("tag:") {
        notes.push(format!("src {src:?} not mapped (only group:/autogroup:members/admin translate)"));
        return None;
    }
    // A bare user email → its own role (named by the local-part).
    let local = src.split('@').next().unwrap_or(src);
    notes.push(format!("user src {src:?} mapped to a role named {local:?}"));
    Some(local.to_string())
}

/// `"tag:prod:443"` / `"tag:prod:*"` → tag `prod`; `"*"`/`"*:*"` → wildcard.
fn dst_to_tag(dst: &str) -> DstTag {
    if dst == "*" || dst.starts_with("*:") {
        return DstTag::Wildcard;
    }
    if let Some(rest) = dst.strip_prefix("tag:") {
        // strip an optional :port suffix
        let tag = rest.split(':').next().unwrap_or(rest);
        return DstTag::Tag(tag.to_string());
    }
    DstTag::Unsupported(dst.to_string())
}

fn role_name_of(group: &str) -> String {
    group.strip_prefix("group:").unwrap_or(group).to_string()
}

/// Strip JWCC extensions (line/block comments, trailing commas) to plain JSON,
/// respecting string literals so `//` or `,` inside strings are preserved.
fn strip_jwcc(input: &str) -> String {
    let bytes = input.as_bytes();
    let mut out = String::with_capacity(input.len());
    let mut i = 0;
    let mut in_string = false;
    let mut escaped = false;
    while i < bytes.len() {
        let c = bytes[i] as char;
        if in_string {
            out.push(c);
            if escaped {
                escaped = false;
            } else if c == '\\' {
                escaped = true;
            } else if c == '"' {
                in_string = false;
            }
            i += 1;
            continue;
        }
        match c {
            '"' => {
                in_string = true;
                out.push(c);
                i += 1;
            }
            '/' if i + 1 < bytes.len() && bytes[i + 1] == b'/' => {
                while i < bytes.len() && bytes[i] != b'\n' {
                    i += 1;
                }
            }
            '/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                i += 2;
                while i + 1 < bytes.len() && !(bytes[i] == b'*' && bytes[i + 1] == b'/') {
                    i += 1;
                }
                i += 2;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    // Remove trailing commas: `,` followed by optional whitespace then `}`/`]`.
    let mut cleaned = String::with_capacity(out.len());
    let ob = out.as_bytes();
    let mut j = 0;
    while j < ob.len() {
        if ob[j] == b',' {
            let mut k = j + 1;
            while k < ob.len() && (ob[k] as char).is_whitespace() {
                k += 1;
            }
            if k < ob.len() && (ob[k] == b'}' || ob[k] == b']') {
                j += 1; // drop the comma
                continue;
            }
        }
        cleaned.push(ob[j] as char);
        j += 1;
    }
    cleaned
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = r#"
    {
      // Tailscale tailnet policy (HuJSON: comments + trailing commas)
      "groups": {
        "group:eng": ["alice@example.com", "bob@example.com"],
        "group:ops": ["carol@example.com"],
      },
      "tagOwners": {
        "tag:prod": ["group:ops"],
        "tag:staging": ["group:eng"],
      },
      "acls": [
        { "action": "accept", "src": ["group:eng"], "dst": ["tag:staging:443", "tag:dev:*"] },
        { "action": "accept", "src": ["group:ops"], "dst": ["*:*"] },
        { "action": "accept", "src": ["autogroup:members"], "dst": ["tag:lobby:80"] },
      ],
      "ssh": [
        { "action": "accept", "src": ["autogroup:members"], "dst": ["autogroup:self"], "users": ["root"] },
      ],
    }
    "#;

    #[test]
    fn imports_groups_to_roles_with_reach() {
        let r = import_tailscale_policy(SAMPLE).unwrap();
        let by = |n: &str| r.roles.iter().find(|x| x.name == n).cloned();

        // eng reaches staging + dev.
        let eng = by("eng").expect("eng role");
        assert_eq!(eng.host_tags, vec!["dev".to_string(), "staging".to_string()]);
        // ops reaches everything (wildcard from *:* dst).
        let ops = by("ops").expect("ops role");
        assert_eq!(ops.host_tags, vec!["*".to_string()]);
        // autogroup:members → member role reaches lobby.
        let member = by("member").expect("member role");
        assert_eq!(member.host_tags, vec!["lobby".to_string()]);

        // Host tags surfaced.
        assert!(r.tags_seen.contains(&"staging".to_string()));
        assert!(r.tags_seen.contains(&"lobby".to_string()));

        // ssh + tagOwners reported as skipped, not silently dropped.
        assert!(r.skipped.iter().any(|s| s.contains("ssh")));
        assert!(r.skipped.iter().any(|s| s.contains("tagOwners")));
    }

    #[test]
    fn grants_with_app_capabilities_are_reported() {
        let policy = r#"{
          "grants": [
            { "src": ["group:eng"], "dst": ["tag:fileserver"],
              "ip": ["443"],
              "app": { "example.com/cap/drive": [{"shares": ["projects"]}] } }
          ]
        }"#;
        let r = import_tailscale_policy(policy).unwrap();
        assert_eq!(r.roles.iter().find(|x| x.name == "eng").unwrap().host_tags, vec!["fileserver"]);
        assert!(r.skipped.iter().any(|s| s.contains("app")));
        assert!(r.notes.iter().any(|n| n.contains("ip")));
    }

    #[test]
    fn strips_comments_inside_strings_safely() {
        // A `//` inside a string value must survive.
        let p = r#"{ "groups": { "group:weird": ["a//b@example.com"] }, "acls": [] }"#;
        let r = import_tailscale_policy(p).unwrap();
        assert!(r.roles.iter().any(|x| x.name == "weird"));
    }
}
