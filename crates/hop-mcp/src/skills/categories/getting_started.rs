use crate::skills::Skill;
use super::super::data::{s, tags, ex};

pub fn skills() -> Vec<Skill> {
    vec![
        Skill {
            id: s("getting-started/identity-and-setup"),
            category: s("getting-started"),
            title: s("Identity & Setup"),
            description: s("View and manage your hop identity, node ID, and configuration. Every hop node has a unique cryptographic identity generated on first run."),
            tags: tags(&["identity", "setup", "config", "node-id", "whoami"]),
            prerequisites: vec![],
            examples: vec![
                ex(
                    "View your node identity",
                    r#"const nodeId = hop.id();
hop.log(`My node ID: ${nodeId}`);
const hosts = await hop.hosts();
hop.log(`Known hosts: ${hosts.length}`);
for (const h of hosts) {
    hop.log(`  ${h.name} (${h.nodeId}) - online: ${h.online}`);
}"#,
                    Some("My node ID: abc123def456...\nKnown hosts: 3\n  web-1 (node1...) - online: true\n  db-1 (node2...) - online: true\n  cache-1 (node3...) - online: false"),
                ),
            ],
            pitfalls: vec![
                s("Node ID is derived from your private key — never share or copy key files between hosts."),
                s("If you delete ~/.hop, you lose your identity and must re-authorize with all peers."),
            ],
            related: tags(&["getting-started/hosting", "getting-started/connecting"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("getting-started/hosting"),
            category: s("getting-started"),
            title: s("Hosting"),
            description: s("Start hosting to allow inbound connections. A host listens for peer connections and serves its resources (shell, files) to authorized users."),
            tags: tags(&["host", "server", "listen", "daemon", "start"]),
            prerequisites: vec![s("getting-started/identity-and-setup")],
            examples: vec![
                ex(
                    "Check host status after starting",
                    r#"const status = await hop.admin.status("localhost");
hop.log(`Version: ${status.version}`);
hop.log(`Connected peers: ${status.peerCount}`);
hop.log(`Active sessions: ${status.activeSessions}`);"#,
                    Some("Version: 0.8.2\nConnected peers: 5\nActive sessions: 2"),
                ),
            ],
            pitfalls: vec![
                s("Hosting requires a stable network connection; peers will lose access if the host goes offline."),
                s("Ensure your firewall allows the hop listening port if peers connect over WAN."),
            ],
            related: tags(&["getting-started/identity-and-setup", "getting-started/inviting-peers"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("getting-started/inviting-peers"),
            category: s("getting-started"),
            title: s("Inviting Peers"),
            description: s("Generate invite tokens so other users can connect to your host. Invites encode connection info and a one-time authorization secret."),
            tags: tags(&["invite", "token", "authorize", "peer", "onboarding"]),
            prerequisites: vec![s("getting-started/hosting")],
            examples: vec![
                ex(
                    "Generate a standard invite",
                    r#"const token = await hop.admin.invite("localhost");
hop.log(`Share this invite token with your peer:`);
hop.log(token);"#,
                    Some("Share this invite token with your peer:\nhop://invite/eyJub2RlX2lk..."),
                ),
                ex(
                    "Generate invite with options",
                    r#"const token = await hop.admin.invite("localhost", {
    role: "developer",
    expiry: "24h",
});
hop.log(`Developer invite (expires in 24h): ${token}`);"#,
                    Some("Developer invite (expires in 24h): hop://invite/eyJyb2xlIjoi..."),
                ),
                ex(
                    "Generate sandboxed invite (read-only monitoring)",
                    r#"// Use --preset flag for common sandbox configurations
const token = await hop.exec("localhost", "hop invite --preset monitor");
hop.log(`Monitor invite: ${token.stdout.trim()}`);
// Presets: monitor (read-only, no network, scoped), audit (read-only, no network), deploy (scoped write)"#,
                    Some("Monitor invite: eyJ0eXAiOiJpbnZpdGUi..."),
                ),
            ],
            pitfalls: vec![
                s("Invite tokens are single-use by default — generate one per peer."),
                s("Expired tokens cannot be reactivated; generate a new one instead."),
            ],
            related: tags(&["getting-started/connecting", "admin/remote-invite"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("getting-started/connecting"),
            category: s("getting-started"),
            title: s("Connecting to Hosts"),
            description: s("Connect to remote hosts using an alias, node ID, or invite token. Once connected, you can run commands and transfer files."),
            tags: tags(&["connect", "alias", "remote", "join", "client"]),
            prerequisites: vec![s("getting-started/identity-and-setup")],
            examples: vec![
                ex(
                    "Run a command on a known host",
                    r#"const result = await hop.exec("web-1", "hostname && uname -a");
hop.log(`Host says: ${result.stdout}`);"#,
                    Some("Host says: web-1\nLinux web-1 5.15.0 x86_64 GNU/Linux"),
                ),
                ex(
                    "List all known hosts and test connectivity",
                    r#"const hosts = await hop.hosts();
for (const h of hosts) {
    if (!h.online) {
        hop.log(`SKIP ${h.name} (offline)`);
        continue;
    }
    const r = await hop.exec(h.name, "echo pong");
    hop.log(`${h.name}: ${r.stdout.trim()}`);
}"#,
                    Some("web-1: pong\ndb-1: pong\nSKIP cache-1 (offline)"),
                ),
            ],
            pitfalls: vec![
                s("You must accept an invite or be authorized before you can connect to a host."),
                s("Connections are encrypted end-to-end; no MITM is possible if node IDs match."),
            ],
            related: tags(&["getting-started/inviting-peers", "getting-started/hosting"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("getting-started/creator-invite"),
            category: s("getting-started"),
            title: s("Creator Invite"),
            description: s("Retrieve the initial creator invite token generated when a host first starts. This is used for headless/automated setups where no interactive terminal is available."),
            tags: tags(&["creator", "bootstrap", "headless", "automation", "first-run"]),
            prerequisites: vec![s("getting-started/hosting")],
            examples: vec![
                ex(
                    "Bootstrap a headless server",
                    r#"// On the new server, after hop starts for the first time,
// the creator invite is written to a known location.
// From your admin workstation:
const result = await hop.exec("new-server", "cat /var/lib/hop/creator-invite");
hop.log(`Creator invite: ${result.stdout.trim()}`);
// Use this token to connect as the first admin user"#,
                    Some("Creator invite: hop://invite/eyJjcmVhdG9y..."),
                ),
            ],
            pitfalls: vec![
                s("The creator invite is only valid once — store it securely before use."),
                s("After the first user connects with the creator invite, it is invalidated."),
            ],
            related: tags(&["getting-started/inviting-peers", "getting-started/hosting"]),
            sub_skills: vec![],
        },
    ]
}
