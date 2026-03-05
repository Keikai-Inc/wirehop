use crate::skills::{Skill, SkillExample};
use super::super::data::{s, tags, ex};

pub fn skills() -> Vec<Skill> {
    vec![
        Skill {
            id: s("fleet/orchestrator-setup"),
            category: s("fleet"),
            title: s("Orchestrator Setup"),
            description: s("Set up a host as a fleet orchestrator. The orchestrator coordinates fleet-wide operations, tracks member health, and dispatches commands."),
            tags: tags(&["orchestrator", "fleet", "setup", "controller", "coordinator"]),
            prerequisites: vec![s("getting-started/hosting")],
            examples: vec![
                ex(
                    "Verify orchestrator is running",
                    r#"const status = await hop.admin.status("orchestrator");
hop.log(`Orchestrator version: ${status.version}`);
hop.log(`Connected fleet members: ${status.peerCount}`);
hop.log(`Active sessions: ${status.activeSessions}`);"#,
                    Some("Orchestrator version: 0.8.2\nConnected fleet members: 12\nActive sessions: 4"),
                ),
            ],
            pitfalls: vec![
                s("Only one orchestrator should be active per fleet to avoid split-brain scenarios."),
                s("The orchestrator host should have high availability — consider running it on reliable infrastructure."),
            ],
            related: tags(&["fleet/fleet-invites", "fleet/registering-hosts"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("fleet/fleet-invites"),
            category: s("fleet"),
            title: s("Fleet Invite Tokens"),
            description: s("Generate fleet invite tokens with optional tags. Fleet invites allow hosts to join the fleet and be automatically tagged for group operations."),
            tags: tags(&["fleet", "invite", "token", "tags", "onboarding"]),
            prerequisites: vec![s("fleet/orchestrator-setup")],
            examples: vec![
                ex(
                    "Generate a tagged fleet invite",
                    r#"const token = await hop.admin.invite("orchestrator", {
    role: "fleet-member",
    tags: ["region:us-east", "tier:web"],
});
hop.log(`Fleet invite for web tier: ${token}`);"#,
                    Some("Fleet invite for web tier: hop://invite/eyJmbGVldCI6..."),
                ),
            ],
            pitfalls: vec![
                s("Tags assigned at invite time are initial tags — they can be changed later."),
                s("Fleet invites should be distributed securely; anyone with the token can join."),
            ],
            related: tags(&["fleet/registering-hosts", "fleet/tagging-hosts"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("fleet/registering-hosts"),
            category: s("fleet"),
            title: s("Registering Hosts"),
            description: s("Register new hosts into a fleet using fleet invite tokens. Registered hosts appear in fleet listings and can receive fleet-wide commands."),
            tags: tags(&["register", "join", "fleet", "enroll", "member"]),
            prerequisites: vec![s("fleet/orchestrator-setup"), s("fleet/fleet-invites")],
            examples: vec![
                ex(
                    "Verify a host joined the fleet",
                    r#"const members = await hop.fleet.list();
hop.log(`Fleet members: ${members.length}`);
for (const m of members) {
    hop.log(`  ${m.name} [${m.tags.join(", ")}] online=${m.online}`);
}"#,
                    Some("Fleet members: 5\n  web-1 [region:us-east, tier:web] online=true\n  web-2 [region:us-east, tier:web] online=true\n  db-1 [region:us-east, tier:db] online=true\n  db-2 [region:us-west, tier:db] online=true\n  cache-1 [region:us-east, tier:cache] online=false"),
                ),
            ],
            pitfalls: vec![
                s("A host can only be a member of one fleet at a time."),
                s("If the host loses connectivity to the orchestrator for too long, it may be marked offline."),
            ],
            related: tags(&["fleet/fleet-invites", "fleet/listing-hosts"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("fleet/tagging-hosts"),
            category: s("fleet"),
            title: s("Tagging Hosts"),
            description: s("Add or remove tags on fleet members. Tags are key:value labels used for grouping hosts in fleet operations like exec, deploy, and monitoring."),
            tags: tags(&["tags", "labels", "group", "organize", "metadata"]),
            prerequisites: vec![s("fleet/registering-hosts")],
            examples: vec![
                ex(
                    "Tag hosts and verify",
                    r#"const members = await hop.fleet.list("tier:web");
hop.log(`Web tier hosts: ${members.length}`);
for (const m of members) {
    hop.log(`  ${m.name}: ${m.tags.join(", ")}`);
}"#,
                    Some("Web tier hosts: 2\n  web-1: region:us-east, tier:web\n  web-2: region:us-east, tier:web"),
                ),
            ],
            pitfalls: vec![
                s("Tag keys are case-sensitive: 'Tier:web' and 'tier:web' are different tags."),
                s("Removing a tag does not affect running operations that already matched it."),
            ],
            related: tags(&["fleet/listing-hosts", "fleet/fleet-exec", "roles/tag-matching"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("fleet/listing-hosts"),
            category: s("fleet"),
            title: s("Listing & Filtering Fleet Members"),
            description: s("List and filter fleet members by tags, online status, or other criteria. Essential for understanding fleet composition before running operations."),
            tags: tags(&["list", "filter", "query", "inventory", "fleet"]),
            prerequisites: vec![s("fleet/registering-hosts")],
            examples: vec![
                ex(
                    "List all fleet members",
                    r#"const all = await hop.fleet.list();
hop.log(`Total fleet members: ${all.length}`);
const online = all.filter(m => m.online);
hop.log(`Online: ${online.length}, Offline: ${all.length - online.length}`);"#,
                    Some("Total fleet members: 12\nOnline: 10, Offline: 2"),
                ),
                ex(
                    "Filter by tag",
                    r#"const dbHosts = await hop.fleet.list("tier:db");
for (const h of dbHosts) {
    hop.log(`${h.name} (${h.nodeId.slice(0, 8)}...) online=${h.online}`);
}"#,
                    Some("db-1 (a1b2c3d4...) online=true\ndb-2 (e5f6g7h8...) online=true"),
                ),
            ],
            pitfalls: vec![
                s("Offline hosts are still returned in listings — always check the online field."),
                s("Tag filters use exact matching; 'tier:web' won't match 'tier:web-frontend'."),
            ],
            related: tags(&["fleet/tagging-hosts", "fleet/fleet-exec"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("fleet/removing-hosts"),
            category: s("fleet"),
            title: s("Removing Hosts from Fleet"),
            description: s("Remove hosts from a fleet. Removed hosts lose fleet membership and will no longer receive fleet commands, but they keep their hop identity."),
            tags: tags(&["remove", "deregister", "evict", "leave", "fleet"]),
            prerequisites: vec![s("fleet/registering-hosts")],
            examples: vec![
                ex(
                    "Remove a decommissioned host",
                    r#"const peers = await hop.admin.peers("orchestrator");
const target = peers.find(p => p.name === "old-web-3");
if (target) {
    const removed = await hop.admin.removePeer("orchestrator", target.nodeId.slice(0, 8));
    hop.log(`Removed old-web-3: ${removed}`);
} else {
    hop.log("Host old-web-3 not found in fleet");
}
const remaining = await hop.fleet.list();
hop.log(`Fleet now has ${remaining.length} members`);"#,
                    Some("Removed old-web-3: true\nFleet now has 11 members"),
                ),
            ],
            pitfalls: vec![
                s("Removing a host is immediate — any in-flight operations on that host will fail."),
                s("The removed host retains its identity and data; removal only revokes fleet access."),
            ],
            related: tags(&["fleet/listing-hosts", "admin/removing-peers"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("fleet/fleet-exec"),
            category: s("fleet"),
            title: s("Fleet Exec"),
            description: s("Execute commands across a group of fleet members simultaneously. Fleet exec fans out a command to all matching hosts and collects results."),
            tags: tags(&["exec", "parallel", "fan-out", "command", "fleet"]),
            prerequisites: vec![s("fleet/listing-hosts")],
            examples: vec![
                ex(
                    "Run a command on all web hosts",
                    r#"const results = await hop.fleet.exec("tier:web", "uptime -p");
for (const r of results) {
    hop.log(`${r.host}: ${r.stdout.trim()}`);
    if (r.exitCode !== 0) {
        hop.log(`  ERROR: ${r.stderr}`);
    }
}"#,
                    Some("web-1: up 45 days, 3 hours\nweb-2: up 12 days, 7 hours\nweb-3: up 45 days, 3 hours"),
                ),
                ex(
                    "Check disk usage across database tier",
                    r#"const results = await hop.fleet.exec("tier:db", "df -h / | tail -1");
hop.log("Host          | Usage");
hop.log("--------------|------");
for (const r of results) {
    const parts = r.stdout.trim().split(/\s+/);
    hop.log(`${r.host.padEnd(14)}| ${parts[4]}`);
}"#,
                    Some("Host          | Usage\n--------------+------\ndb-1          | 42%\ndb-2          | 38%"),
                ),
            ],
            pitfalls: vec![
                s("Fleet exec targets only online hosts; offline hosts are silently skipped."),
                s("Long-running commands may time out — consider using nohup or background execution."),
                s("Results arrive as each host completes; order is not guaranteed."),
            ],
            related: tags(&["fleet/listing-hosts", "fleet/tagging-hosts"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("fleet/aggregate-invites"),
            category: s("fleet"),
            title: s("Aggregate Invites"),
            description: s("Create role-based multi-host invites that grant a user access to multiple hosts at once, governed by RBAC role definitions and tag matching."),
            tags: tags(&["aggregate", "invite", "multi-host", "role-based", "access"]),
            prerequisites: vec![s("fleet/orchestrator-setup"), s("roles/creating-roles")],
            examples: vec![
                ex(
                    "Create an aggregate invite for the developer role",
                    r#"const token = await hop.admin.invite("orchestrator", {
    role: "developer",
    aggregate: true,
});
hop.log(`Aggregate developer invite: ${token}`);

const roles = await hop.roles.list("orchestrator");
const devRole = roles.find(r => r.name === "developer");
hop.log(`Developer role matches tags: ${JSON.stringify(devRole.matchTags)}`);"#,
                    Some("Aggregate developer invite: hop://invite/eyJhZ2dyZWdhdGUi...\nDeveloper role matches tags: [\"tier:web\",\"tier:staging\"]"),
                ),
            ],
            pitfalls: vec![
                s("Aggregate invites depend on role tag-matching rules — update roles first if needed."),
                s("If new hosts matching the role tags are added later, the invited user gets automatic access."),
            ],
            related: tags(&["fleet/fleet-invites", "roles/creating-roles", "roles/tag-matching"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("fleet/heartbeat-and-health"),
            category: s("fleet"),
            title: s("Heartbeat & Health Monitoring"),
            description: s("Monitor fleet member heartbeats and health status. The orchestrator tracks last-seen times and marks hosts offline when heartbeats are missed."),
            tags: tags(&["heartbeat", "health", "monitoring", "liveness", "status"]),
            prerequisites: vec![s("fleet/orchestrator-setup"), s("fleet/registering-hosts")],
            examples: vec![
                ex(
                    "Check fleet health",
                    r#"const members = await hop.fleet.list();
const now = Date.now();
for (const m of members) {
    const status = m.online ? "ONLINE" : "OFFLINE";
    hop.log(`[${status}] ${m.name} [${m.tags.join(", ")}]`);
}
const onlineCount = members.filter(m => m.online).length;
hop.log(`\nFleet health: ${onlineCount}/${members.length} online`);"#,
                    Some("[ONLINE] web-1 [tier:web]\n[ONLINE] web-2 [tier:web]\n[OFFLINE] web-3 [tier:web]\n[ONLINE] db-1 [tier:db]\n\nFleet health: 3/4 online"),
                ),
            ],
            pitfalls: vec![
                s("Heartbeat intervals are configurable; too-short intervals increase network traffic."),
                s("A host marked offline may still be running — network partitions cause false negatives."),
            ],
            related: tags(&["fleet/listing-hosts", "monitor/uptime"]),
            sub_skills: vec![],
        },
    ]
}
