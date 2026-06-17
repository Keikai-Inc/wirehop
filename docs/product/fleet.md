# Fleet Management

A fleet in hop is just your **[warren](warren.md)**, managed at scale. Any `hop host` can issue invites and define roles, but there is **no orchestrator and no master member list**: membership, roles, tags, and ACLs live in a **replicated network document** (iroh-docs) that every node holds its own copy of. Fleet features are integrated into `hop host` — there is no separate fleet server.

The warren federates across hosts via a join ticket (carried by `node`/`admin` invites; `--join` / `HOP_VPN_JOIN_TICKET`), with **additive-only reconcile** so no host can revoke another's entries. Roles drive both host access (RBAC) **and** warren VPN reach. Writes are gated by an admin/owner author binding (C1; see [security-audit.md](../technical/security-audit.md) and [per-member-self-docs.md](../technical/per-member-self-docs.md)) — author validation ships in **observe** mode by default, with **enforce** opt-in (`HOP_NETDOC_VALIDATION`) pending a multi-node federated rollout.

## Architecture

Membership and policy live in the replicated warren document — every node sees the same view, with no central registry:

```
 Warren network document (iroh-docs, replicated to every node)
   peer/<node>        ─── members: node id, name, tags, vIP
   role/<name>        ─── RBAC role definitions (admin-authored)
   acl/ + tag/        ─── role→tag reach policy + host tags
   revocation/<node>  ─── tombstones (additive-only)

 Each member also owns a write-isolated self-doc
   (its own name / tag / posture / endpoint — see per-member-self-docs.md)
```

- **No orchestrator of record.** Any host with admin rights issues invites and writes roles; the document replicates the result to every node. There is no master copy to keep in sync.
- **Members** are warren nodes — not "hosts registered with an orchestrator." A read-only mirror (`WarrenSnapshot`) is exported to `warren-members.json` so `hop fleet list/status` works without holding the store open or needing admin rights.
- Legacy `roles.json` is retained as a human-readable, git-committable source for role definitions (infrastructure-as-code). The old `fleet_registrations.json` is gone; `fleet.json` survives only behind legacy admin handlers.

## Fleet Members

Members are the warren's `peer/<node>` entries, exported into the read-only `WarrenSnapshot` that `hop fleet` reads.

| Field | Type | Description |
|---|---|---|
| `node_id` | string | Member's iroh PublicKey |
| `hostname` | string | System hostname |
| `tags` | vec | Grouping labels (e.g. `["web", "production"]`) |
| `vip` | string? | Warren virtual IP (admin-allocated) |
| `relay_url` | string? | Relay URL hint for connection |
| `last_seen` | string? | Liveness from iroh-docs gossip activity |

Liveness comes from gossip (`last_seen`), **not** a polling heartbeat — the old `online` / `last_heartbeat` fields were never wired and have been removed.

### Tag-Based Grouping

Members are organized by tags. Tags are free-form strings used for targeting fleet operations:

```bash
# Create a fleet invite with tags
hop admin <host> fleet-invite --tags web,production

# List members filtered by tag
hop admin <host> fleet-list --tag web

# Update tags on a member
hop admin <host> fleet-tag <node-id-prefix> --add staging --remove production
```

## Fleet Invites

Fleet invites are Creator-role invites issued by an admin host. When a host accepts a fleet invite, it becomes a trusted fleet member.

```bash
# Create a fleet invite (admin side; requires creator role)
hop admin <host> fleet-invite --tags web,production --max-uses 0 --expiry 86400
```

| Flag | Default | Description |
|---|---|---|
| `--tags` | none | Comma-separated tags for members using this invite |
| `--max-uses` | `0` | Max redemptions (0 = unlimited) |
| `--expiry` | `86400` | Expiry in seconds (default: 24h) |

## Aggregate Invites

Aggregate invites are role-based, reusable invites that grant access to all fleet members matching a role's host tags. They expire after 7 days.

Flow:
1. An admin host creates an aggregate invite for a role + peer name
2. The peer redeems the invite against that host
3. The host resolves matching members (whose tags match the role's `host_tags`)
4. Per-host invites are created for the peer

## CLI Commands

### Host-side: `hop fleet`

```bash
# Show fleet registration status
hop fleet status
hop fleet status --fleet <fleet-name>

# List hosts in a fleet group
hop fleet list
hop fleet list <group>

# Execute a command across a fleet group
hop fleet exec <group> -- uptime

# Add a known host to the local fleet store
hop fleet add <host-alias> --tags web,production
```

### Admin-side: `hop admin`

All fleet admin commands require creator role on the target host.

```bash
# Fleet member management
hop admin <target> fleet-invite --tags web,production
hop admin <target> fleet-list
hop admin <target> fleet-list --tag web
hop admin <target> fleet-remove <node-id-prefix>
hop admin <target> fleet-tag <node-id-prefix> --add staging --remove production

# Role management (see RBAC section below)
hop admin <target> role create <name> --tags web,production --sudo
hop admin <target> role list
hop admin <target> role update <name> --add-tags staging --remove-tags dev
hop admin <target> role delete <name>
```

## RBAC System

Roles define what fleet members a peer can access and what capabilities they have on those hosts.

### RoleDefinition Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `name` | string | required | Role identifier (e.g. `"developer"`, `"ops"`) |
| `host_tags` | vec | required | Tags a host must match (`"*"` = all hosts) |
| `user_mode` | enum | `individual` | `individual` = per-peer Unix account; `shared` = shared account |
| `sudo` | bool | `false` | Grant sudo access on target hosts |
| `admin` | bool | `false` | macOS admin group membership |
| `groups` | vec | `[]` | Extra Unix groups (e.g. `["docker"]`) |
| `shell` | string? | `None` | Override default shell |
| `sandbox` | SandboxPolicy | unrestricted | Sandbox restrictions for peers with this role |

### Default Roles (5 built-in)

Seeded on first host startup via `roles.json`:

| Role | host_tags | sudo | admin | user_mode | groups | sandbox |
|---|---|---|---|---|---|---|
| `admin` | `*` | yes | yes | individual | `docker` | unrestricted |
| `ops` | `*` | yes | no | individual | `docker` | unrestricted |
| `developer` | `developer`, `staging` | no | no | individual | -- | unrestricted |
| `security` | `production`, `staging` | no | no | individual | -- | audit preset (read-only, no network) |
| `ci` | `build` | no | no | shared | -- | deploy preset (denied destructive commands) |

### Role CLI

```bash
# Create a role
hop admin <target> role create developer --tags dev,staging
hop admin <target> role create ops --tags '*' --sudo --groups docker
hop admin <target> role create ci --tags build --shared

# List roles
hop admin <target> role list

# Update a role
hop admin <target> role update developer --add-tags production --sudo true

# Delete a role
hop admin <target> role delete temp-role
```

### Infrastructure as Code

`roles.json` is designed to be human-readable (pretty-printed JSON) and git-committable, enabling infrastructure-as-code workflows.

*Last updated: v0.6.90*
