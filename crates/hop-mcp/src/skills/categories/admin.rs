use crate::skills::{Skill, SkillExample};
use super::super::data::{s, tags, ex};

pub fn skills() -> Vec<Skill> {
    vec![
        Skill {
            id: s("admin/remote-invite"),
            category: s("admin"),
            title: s("Remote Invite Generation"),
            description: s("Create invite tokens on remote hosts. Useful for managing access to hosts you administer without needing local console access."),
            tags: tags(&["invite", "remote", "admin", "access", "token"]),
            prerequisites: vec![s("getting-started/inviting-peers"), s("getting-started/hosting")],
            examples: vec![
                ex(
                    "Generate an invite on a remote host",
                    r#"const hosts = await hop.hosts();
for (const h of hosts.filter(h => h.online)) {
    const token = await hop.admin.invite(h.name, { role: "viewer" });
    hop.log(`Invite for ${h.name}: ${token.slice(0, 40)}...`);
}"#,
                    Some("Invite for web-1: hop://invite/eyJub2RlX2lkIjoiYWJj...\nInvite for db-1: hop://invite/eyJub2RlX2lkIjoiZGVm..."),
                ),
            ],
            pitfalls: vec![
                s("You must have admin privileges on the remote host to generate invites."),
                s("Each invite is scoped to the host it was generated on."),
            ],
            related: tags(&["getting-started/inviting-peers", "fleet/aggregate-invites"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("admin/listing-peers"),
            category: s("admin"),
            title: s("Listing Authorized Peers"),
            description: s("List all authorized peers on a host. Shows each peer's node ID, display name, role, and last seen timestamp."),
            tags: tags(&["peers", "list", "authorized", "users", "who"]),
            prerequisites: vec![s("getting-started/hosting")],
            examples: vec![
                ex(
                    "List peers on a host",
                    r#"const peers = await hop.admin.peers("web-1");
hop.log(`Authorized peers on web-1: ${peers.length}\n`);
for (const p of peers) {
    hop.log(`  ${p.name} (${p.nodeId.slice(0, 8)}...)`);
    hop.log(`    Role: ${p.role}, Last seen: ${p.lastSeen}`);
}"#,
                    Some("Authorized peers on web-1: 3\n\n  alice (a1b2c3d4...)\n    Role: admin, Last seen: 2025-03-15T10:30:00Z\n  bob (e5f6g7h8...)\n    Role: developer, Last seen: 2025-03-15T09:15:00Z\n  charlie (i9j0k1l2...)\n    Role: viewer, Last seen: 2025-03-14T22:00:00Z"),
                ),
            ],
            pitfalls: vec![
                s("Last seen time reflects the last heartbeat, not necessarily the last command execution."),
            ],
            related: tags(&["admin/removing-peers", "admin/remote-invite"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("admin/removing-peers"),
            category: s("admin"),
            title: s("Removing Peers"),
            description: s("Remove authorized peers from a host. The removed peer immediately loses access and any active sessions are terminated."),
            tags: tags(&["remove", "peer", "revoke", "deauthorize", "kick"]),
            prerequisites: vec![s("admin/listing-peers")],
            examples: vec![
                ex(
                    "Remove a peer by node ID prefix",
                    r#"const peers = await hop.admin.peers("web-1");
const target = peers.find(p => p.name === "former-contractor");
if (target) {
    const ok = await hop.admin.removePeer("web-1", target.nodeId.slice(0, 8));
    hop.log(`Removed ${target.name}: ${ok}`);
} else {
    hop.log("Peer not found");
}

const after = await hop.admin.peers("web-1");
hop.log(`Remaining peers: ${after.map(p => p.name).join(", ")}`);"#,
                    Some("Removed former-contractor: true\nRemaining peers: alice, bob, charlie"),
                ),
            ],
            pitfalls: vec![
                s("Removal is immediate — the peer's active sessions are killed without warning."),
                s("You cannot remove yourself — at least one admin must remain."),
                s("The peer's node ID prefix must be unambiguous; use enough characters to be unique."),
            ],
            related: tags(&["admin/listing-peers", "fleet/removing-hosts"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("admin/creating-users"),
            category: s("admin"),
            title: s("Creating Unix Users"),
            description: s("Create Unix users on remote hosts. Used when setting up individual user mode for roles, or provisioning service accounts."),
            tags: tags(&["user", "create", "unix", "account", "provision"]),
            prerequisites: vec![s("getting-started/hosting")],
            examples: vec![
                ex(
                    "Create a user on a remote host",
                    r#"const result = await hop.admin.createUser("web-1", "deploy-bot", {
    shell: "/bin/bash",
    groups: ["docker", "www-data"],
});
hop.log(`Created user: ${result.username}`);
if (result.inviteToken) {
    hop.log(`Invite token: ${result.inviteToken}`);
}

const check = await hop.exec("web-1", "id deploy-bot");
hop.log(check.stdout.trim());"#,
                    Some("Created user: deploy-bot\nuid=1001(deploy-bot) gid=1001(deploy-bot) groups=1001(deploy-bot),998(docker),33(www-data)"),
                ),
            ],
            pitfalls: vec![
                s("Creating a user requires root/sudo privileges on the target host."),
                s("User names must comply with the target OS rules (usually lowercase, no spaces)."),
            ],
            related: tags(&["roles/user-modes", "admin/listing-peers"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("admin/host-status"),
            category: s("admin"),
            title: s("Host Status"),
            description: s("Get detailed status information for a host including version, peer count, and active session count. Useful for health checks and diagnostics."),
            tags: tags(&["status", "info", "version", "health", "diagnostics"]),
            prerequisites: vec![s("getting-started/connecting")],
            examples: vec![
                ex(
                    "Check status of multiple hosts",
                    r#"const hosts = await hop.hosts();
for (const h of hosts.filter(h => h.online)) {
    const st = await hop.admin.status(h.name);
    hop.log(`${h.name}: v${st.version} | ${st.peerCount} peers | ${st.activeSessions} sessions`);
}"#,
                    Some("web-1: v0.8.2 | 5 peers | 2 sessions\ndb-1: v0.8.2 | 3 peers | 1 sessions\ncache-1: v0.8.1 | 2 peers | 0 sessions"),
                ),
            ],
            pitfalls: vec![
                s("Status queries require at least viewer-level access on the target host."),
                s("Version mismatches across hosts may cause compatibility issues."),
            ],
            related: tags(&["monitor/uptime", "fleet/heartbeat-and-health"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("admin/audit-log"),
            category: s("admin"),
            title: s("Audit Log"),
            description: s("Understand and query the admin audit log. Hop records all administrative actions (peer additions, removals, role changes) for compliance and forensics."),
            tags: tags(&["audit", "log", "compliance", "forensics", "history"]),
            prerequisites: vec![s("getting-started/hosting")],
            examples: vec![
                ex(
                    "Query recent audit events",
                    r#"const result = await hop.exec("web-1", "hop admin audit-log --last 10 --format json");
const events = JSON.parse(result.stdout);
for (const ev of events) {
    hop.log(`[${ev.timestamp}] ${ev.action} by ${ev.actor}: ${ev.details}`);
}"#,
                    Some("[2025-03-15T10:30:00Z] peer-added by alice: Added bob (e5f6g7h8...)\n[2025-03-15T09:00:00Z] role-updated by alice: Updated developer role\n[2025-03-14T22:00:00Z] invite-created by alice: Created viewer invite"),
                ),
            ],
            pitfalls: vec![
                s("Audit logs are stored locally on each host — they are not centralized by default."),
                s("Log rotation may discard old entries; configure retention for compliance needs."),
            ],
            related: tags(&["security/user-audit", "security/sudo-audit"]),
            sub_skills: vec![],
        },
    ]
}
