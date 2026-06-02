# Fleet Management

hop supports fleet operations where any `hop host` can act as an orchestrator. Fleet features are integrated -- there is no separate fleet server. Fleet data is stored alongside normal host configuration.

> **Direction (largely shipped):** the "orchestrator" model below still works as
> described. Under the [warren](warren.md) it has become mostly decentralized:
> membership/role/tag state now also lives in a **replicated network document**
> (iroh-docs) that federates across hosts via a join ticket (`--join` /
> `HOP_VPN_JOIN_TICKET`), with **additive-only reconcile** so no host can revoke
> another's entries. Role definitions and role-based (aggregate) invites are kept
> and extended (roles now drive warren VPN reach). The one piece still **planned**
> is making write authority a cryptographic Owner/Admin capability (today the
> join path hands out an iroh-docs write ticket). See [warren.md](warren.md).

## Architecture

```
 Orchestrator (hop host)
   fleet.json              ─── members, tags, heartbeats
   roles.json              ─── RBAC role definitions
   aggregate_invites.json  ─── reusable role-based invites

 Member (hop host)
   fleet_registrations.json ── one entry per orchestrator
```

- **Orchestrator**: any hop host that issues fleet invites and manages members
- **Member**: a hop host registered with an orchestrator via a fleet invite
- Members store their registration(s) locally; a host can belong to multiple fleets

## Fleet Members

### FleetMember fields (orchestrator side)

| Field | Type | Description |
|---|---|---|
| `node_id` | string | Member's iroh PublicKey |
| `hostname` | string | System hostname |
| `tags` | vec | Grouping labels (e.g. `["web", "production"]`) |
| `registered_at` | string | Registration timestamp |
| `last_heartbeat` | string? | Last heartbeat timestamp |
| `relay_url` | string? | Relay URL for direct connection |
| `online` | bool | Current connectivity status |

### Tag-Based Grouping

Members are organized by tags. Tags are free-form strings used for targeting fleet operations:

```bash
# Create a fleet invite with tags
hop admin <orchestrator> fleet-invite --tags web,production

# List members filtered by tag
hop admin <orchestrator> fleet-list --tag web

# Update tags on a member
hop admin <orchestrator> fleet-tag <node-id-prefix> --add staging --remove production
```

## Fleet Invites

Fleet invites are Creator-role invites issued by the orchestrator. When a host accepts a fleet invite, it becomes a trusted fleet member.

```bash
# Create a fleet invite (orchestrator side, requires creator role)
hop admin <orchestrator> fleet-invite --tags web,production --max-uses 0 --expiry 86400
```

| Flag | Default | Description |
|---|---|---|
| `--tags` | none | Comma-separated tags for members using this invite |
| `--max-uses` | `0` | Max redemptions (0 = unlimited) |
| `--expiry` | `86400` | Expiry in seconds (default: 24h) |

## Aggregate Invites

Aggregate invites are role-based, reusable invites that grant access to all fleet members matching a role's host tags. They expire after 7 days.

Flow:
1. Orchestrator creates an aggregate invite for a role + peer name
2. Peer redeems the invite against the orchestrator
3. Orchestrator resolves matching fleet members (online hosts whose tags match the role's `host_tags`)
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

All fleet admin commands require creator role on the target orchestrator.

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

Seeded on first orchestrator startup via `roles.json`:

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

*Last updated: v0.6.33*
