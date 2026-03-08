use crate::skills::Skill;
use super::super::data::{s, tags, ex};

pub fn skills() -> Vec<Skill> {
    vec![
        Skill {
            id: s("roles/creating-roles"),
            category: s("roles"),
            title: s("Creating Roles"),
            description: s("Create RBAC role definitions that control what peers can do on hosts. Roles define allowed commands, file access patterns, which hosts they apply to via tag matching, and optional sandbox policies (read-only, no-network, scoped paths)."),
            tags: tags(&["rbac", "role", "create", "permissions", "access-control"]),
            prerequisites: vec![s("getting-started/hosting")],
            examples: vec![
                ex(
                    "Create a developer role with sandbox policy",
                    r#"const roleId = await hop.roles.create("orchestrator", {
    name: "developer",
    description: "Web application developers",
    matchTags: ["tier:web", "tier:staging"],
    allowExec: true,
    allowedCommands: ["docker *", "systemctl status *", "journalctl *", "ls", "cat", "tail"],
    allowFileRead: true,
    allowFileWrite: false,
    userMode: "shared",
    sharedUser: "deploy",
    sandbox: { read_only: false, no_network: false },  // unrestricted (default)
});
hop.log(`Created role: ${roleId}`);

// Create a security role with audit sandbox
const secId = await hop.roles.create("orchestrator", {
    name: "security-auditor",
    matchTags: ["production", "staging"],
    sandbox: { read_only: true, no_network: true },  // audit preset
});
hop.log(`Created role: ${secId}`);"#,
                    Some("Created role: developer\nCreated role: security-auditor"),
                ),
            ],
            pitfalls: vec![
                s("Role names must be unique — creating a role with a duplicate name will fail."),
                s("Overly broad allowedCommands patterns (like '*') effectively grant shell access."),
            ],
            related: tags(&["roles/listing-roles", "roles/updating-roles", "roles/tag-matching"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("roles/listing-roles"),
            category: s("roles"),
            title: s("Listing Roles"),
            description: s("List all role definitions configured on a host or orchestrator. Shows each role's permissions, tag matching rules, and user mode."),
            tags: tags(&["rbac", "role", "list", "view", "inspect"]),
            prerequisites: vec![s("roles/creating-roles")],
            examples: vec![
                ex(
                    "List all roles",
                    r#"const roles = await hop.roles.list("orchestrator");
hop.log(`Total roles: ${roles.length}\n`);
for (const role of roles) {
    hop.log(`Role: ${role.name}`);
    hop.log(`  Description: ${role.description}`);
    hop.log(`  Match tags: ${role.matchTags.join(", ")}`);
    hop.log(`  Exec: ${role.allowExec}, File read: ${role.allowFileRead}, File write: ${role.allowFileWrite}`);
    hop.log("");
}"#,
                    Some("Total roles: 3\n\nRole: admin\n  Description: Full administrative access\n  Match tags: *\n  Exec: true, File read: true, File write: true\n\nRole: developer\n  Description: Web application developers\n  Match tags: tier:web, tier:staging\n  Exec: true, File read: true, File write: false\n\nRole: viewer\n  Description: Read-only monitoring\n  Match tags: *\n  Exec: true, File read: true, File write: false"),
                ),
            ],
            pitfalls: vec![
                s("Default seeded roles cannot be deleted, only modified."),
            ],
            related: tags(&["roles/creating-roles", "roles/default-roles"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("roles/updating-roles"),
            category: s("roles"),
            title: s("Updating Roles"),
            description: s("Modify existing role definitions. You can update permissions, tag matching rules, allowed commands, and user mode settings."),
            tags: tags(&["rbac", "role", "update", "modify", "change"]),
            prerequisites: vec![s("roles/creating-roles")],
            examples: vec![
                ex(
                    "Expand a role's allowed commands",
                    r#"await hop.roles.update("orchestrator", "developer", {
    allowedCommands: [
        "docker *", "systemctl status *", "systemctl restart myapp",
        "journalctl *", "ls", "cat", "tail", "grep", "npm run deploy",
    ],
    allowFileWrite: true,
});
hop.log("Updated developer role with expanded permissions");

const roles = await hop.roles.list("orchestrator");
const dev = roles.find(r => r.name === "developer");
hop.log(`Developer allowedCommands: ${dev.allowedCommands.length} patterns`);"#,
                    Some("Updated developer role with expanded permissions\nDeveloper allowedCommands: 9 patterns"),
                ),
            ],
            pitfalls: vec![
                s("Role updates take effect immediately for all users with that role."),
                s("Narrowing permissions may break workflows that depend on the removed capabilities."),
            ],
            related: tags(&["roles/creating-roles", "roles/listing-roles"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("roles/deleting-roles"),
            category: s("roles"),
            title: s("Deleting Roles"),
            description: s("Delete role definitions that are no longer needed. Users assigned to a deleted role lose the permissions it granted."),
            tags: tags(&["rbac", "role", "delete", "remove"]),
            prerequisites: vec![s("roles/creating-roles")],
            examples: vec![
                ex(
                    "Delete a deprecated role",
                    r#"const roles = await hop.roles.list("orchestrator");
hop.log(`Roles before: ${roles.map(r => r.name).join(", ")}`);

await hop.roles.delete("orchestrator", "legacy-ops");
hop.log("Deleted role: legacy-ops");

const after = await hop.roles.list("orchestrator");
hop.log(`Roles after: ${after.map(r => r.name).join(", ")}`);"#,
                    Some("Roles before: admin, developer, viewer, legacy-ops\nDeleted role: legacy-ops\nRoles after: admin, developer, viewer"),
                ),
            ],
            pitfalls: vec![
                s("Deleting a role is irreversible — recreate it manually if needed."),
                s("Default seeded roles (admin, operator, developer, viewer, auditor) cannot be deleted."),
            ],
            related: tags(&["roles/creating-roles", "roles/default-roles"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("roles/default-roles"),
            category: s("roles"),
            title: s("Default Roles"),
            description: s("Understand the 5 seeded default roles: admin, operator, developer, viewer, and auditor. These roles are created automatically and provide a baseline RBAC configuration."),
            tags: tags(&["rbac", "default", "seeded", "baseline", "built-in"]),
            prerequisites: vec![],
            examples: vec![
                ex(
                    "Inspect default roles",
                    r#"const roles = await hop.roles.list("orchestrator");
const defaults = ["admin", "operator", "developer", "viewer", "auditor"];
for (const name of defaults) {
    const role = roles.find(r => r.name === name);
    if (role) {
        hop.log(`${role.name}: exec=${role.allowExec} read=${role.allowFileRead} write=${role.allowFileWrite}`);
    }
}"#,
                    Some("admin: exec=true read=true write=true\noperator: exec=true read=true write=true\ndeveloper: exec=true read=true write=false\nviewer: exec=true read=true write=false\nauditor: exec=true read=true write=false"),
                ),
            ],
            pitfalls: vec![
                s("Default roles can be updated but not deleted."),
                s("The admin role always has full permissions — be careful who you assign it to."),
            ],
            related: tags(&["roles/creating-roles", "roles/listing-roles"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("roles/user-modes"),
            category: s("roles"),
            title: s("User Modes"),
            description: s("Roles support two user modes: 'individual' (each peer gets their own Unix user) and 'shared' (all peers with the role share a single Unix account). This controls session isolation."),
            tags: tags(&["user-mode", "individual", "shared", "unix", "account", "isolation"]),
            prerequisites: vec![s("roles/creating-roles")],
            examples: vec![
                ex(
                    "Compare user modes across roles",
                    r#"const roles = await hop.roles.list("orchestrator");
for (const role of roles) {
    const mode = role.userMode || "individual";
    const extra = mode === "shared" ? ` (user: ${role.sharedUser})` : "";
    hop.log(`${role.name}: ${mode}${extra}`);
}"#,
                    Some("admin: individual\noperator: individual\ndeveloper: shared (user: deploy)\nviewer: shared (user: monitor)\nauditor: individual"),
                ),
            ],
            pitfalls: vec![
                s("Shared mode means all users see each other's files in the shared home directory."),
                s("Individual mode requires the host to create a Unix user per peer, which may hit OS limits."),
            ],
            related: tags(&["roles/creating-roles", "admin/creating-users"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("roles/tag-matching"),
            category: s("roles"),
            title: s("Tag Matching"),
            description: s("Roles use tag-matching rules to determine which hosts they apply to. A role with matchTags=['tier:web'] only grants access to hosts tagged 'tier:web'. Use '*' to match all hosts."),
            tags: tags(&["tags", "matching", "filter", "scope", "rbac"]),
            prerequisites: vec![s("roles/creating-roles"), s("fleet/tagging-hosts")],
            examples: vec![
                ex(
                    "Verify role-to-host matching",
                    r#"const roles = await hop.roles.list("orchestrator");
const hosts = await hop.fleet.list();

for (const role of roles) {
    const matchingHosts = hosts.filter(h => {
        if (role.matchTags.includes("*")) return true;
        return role.matchTags.some(tag => h.tags.includes(tag));
    });
    hop.log(`${role.name} -> ${matchingHosts.length} hosts: ${matchingHosts.map(h => h.name).join(", ")}`);
}"#,
                    Some("admin -> 5 hosts: web-1, web-2, db-1, db-2, cache-1\ndeveloper -> 2 hosts: web-1, web-2\nviewer -> 5 hosts: web-1, web-2, db-1, db-2, cache-1"),
                ),
            ],
            pitfalls: vec![
                s("Tag matching is exact — 'tier:web' does not match 'tier:web-frontend'."),
                s("A role with no matchTags matches no hosts — use '*' for universal access."),
            ],
            related: tags(&["fleet/tagging-hosts", "roles/creating-roles"]),
            sub_skills: vec![],
        },
    ]
}
