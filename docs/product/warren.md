# Warren & Fleet

hop's zero-config peer-to-peer private network — virtual IPs, MagicDNS names, role-based reach — plus fleet/RBAC management (the warren at scale) and the living gap analysis. Membership is a replicated document; there is no central control plane.


---

## Warren — hop's Private Network (Product Design)

> **Status:** This document is the product vision and roadmap for hop's
> peer-to-peer private network. Some of it ships today (clearly marked
> **Shipped** / **Experimental**); the rest is **Planned**. The technical
> implementation lives in [`../technical/warren-internals.md`](../technical/warren-internals.md).

### Vision

hop has always been "SSH without a server" — one binary, reach any machine
you're invited to, no port-forwarding, no VPN appliance. The **warren** extends
that into a full private network for a team, with one defining principle:

> **The role *is* the access.** You never write ACLs. You invite someone as a
> `developer` and the network already knows what a developer can reach.

The target customer is a **small, globally-distributed startup** doing remote
work: a founder, a handful of engineers, a few servers. They should never touch
a VPN config, an exit node, or a firewall rule. They install hop, invite their
team by role, and the network configures itself.

#### Positioning

| Layer | Pitch |
|-------|-------|
| **hop** (the tool) | Reach any machine you're invited to. One binary, no server. |
| **warren** (the network) | Invite your team and they're on a private network with exactly the access their role allows. No appliance, no exit nodes, no ACL files. |

**Differentiators:**
1. **Role-native access** — access is a consequence of who someone is, not hand-authored policy. (Tailscale makes you write ACL policy; hop derives it from roles.)
2. **No control plane** — membership lives in a replicated CRDT ([iroh-docs](../technical/warren-internals.md)), not a coordination server. The network keeps working even when no central service is up.
3. **Two depths, one invite** — join the full network, or just hop into one box. Same role, same token; the recipient chooses their footprint.

### Vocabulary

One consistent language across product, CLI, and marketing:

| Term | Meaning |
|------|---------|
| **hop** | The tool, and the verb — *hop into a machine*. |
| **warren** | A team's private network (the mesh / VPN). "Your warren." |
| **node** | A machine that lives in the warren — has a virtual IP, a name, is reachable. Runs the hop daemon. |
| **client** | A machine with just the `hop` CLI: can hop into permitted machines, but doesn't live in the warren (no virtual IP). |
| **role** | A named identity (`developer`, `ops`, …) that determines what a member can reach. |
| **invite** | A single-use token that admits a machine to the warren with a role. |

**Names (MagicDNS).** Each node is reachable as `<hostname>.<domain>`, using the
**bare host label** (the OS hostname with any DHCP-appended suffix like `.lan`
stripped, so `RexMundi.hop` works even when the machine reports `RexMundi.lan`).
The domain is **configurable per warren**, with a conventional default: a
**named** warren uses `<warren-name>.hop` (e.g. `web.acme.hop`); an unnamed
warren falls back to the flat `hop` domain (e.g. `web.hop`). The domain lives in
the warren document so every node resolves consistently. *(Today the resolver
hard-codes `.hop`; making it configurable is part of the role/onboarding work.)*

DNS is configured **automatically**: when a node's VPN comes up it points the OS
resolver for the warren domain at its own MagicDNS server (macOS
`/etc/resolver/<domain>`; Linux `resolvectl` with systemd-resolved) — split-DNS,
so only `.<domain>` lookups are affected and nothing else changes. No manual
`/etc/resolver` editing. Set `HOP_NO_AUTO_RESOLVER` to manage DNS yourself.

### The two paths: client vs node

The split is a **presence** axis, not a capability axis. *What* you can reach is
governed by your role; *how* you reach it is governed by which path you install.

| | `install.sh` → **hop client** | `join.sh` / `install.sh --join` → **hop node** *(Planned naming)* |
|---|---|---|
| Daemon / root | No | Yes |
| Virtual IP + MagicDNS name | No | Yes |
| `hop <host>` (shell/exec/transfer/MCP) | ✅ role-permitted hosts | ✅ |
| Reach services at IP:port (the VPN) | ❌ | ✅ ACL-gated |
| Network-doc replica | read-only (discovery + auth) *(Planned)* | read/write (full member) |

- A **client** is the lightweight "SSH-replacement" user — a contractor or CI
  runner who just needs into specific boxes. No root, no TUN.
- A **node** is a full warren member — engineer laptops and servers alike. A
  **server** is simply a node that others have a role to hop *into*; a laptop is
  a node nobody is authorized to reach inbound. Same daemon, governed by roles.

*(Planned)* The client will carry a **read-only replica** of the network
document so `hop ls` shows every host its role permits (no stale `known_hosts`) —
knowing the network without being on the fabric. *(Today only the `hop host`
daemon runs the netdoc stack; a plain client has no replica yet.)*

### Onboarding (zero-config)

All network administration collapses into **install + `hop invite`**. There are
no `net init`, `add-server`, `tag`, or `up` commands — the network self-forms
from the first daemon and grows through invites.

> **(Mostly shipped.)** The commands below are the *target* experience. Today
> `hop invite --role <named>` and the **warren VPN** are shipped; the VPN is
> **off by default** as of v0.6.37 (opt in with `--host` / `HOP_VPN=1` /
> `hop config set vpn on`) while the warren write model is hardened. Federation
> still joins via a namespace ticket (`HOP_VPN_JOIN_TICKET`) rather than a
> `--join` installer flag. See **Status**
> and **Roadmap** for what's shipped vs planned.

```
# Founder — install hop. The network ("warren") auto-creates; founder is Owner.
curl -fsSL https://hop.keikai.ai | bash

# Invite anyone (person or server) with a role:
hop invite --role developer
#  → prints a one-liner the recipient pastes:
#     curl -fsSL https://hop.keikai.ai | bash -s -- --join <token>
#     (drop --join for CLI-only client access)

# Recipient installs + redeems. They're on the warren with developer access —
# nothing else to configure.
```

#### Two install tiers, one command

`install.sh` is the only installer, and what a machine *is* comes from one choice:

| | **Connect from this machine** (client) | **A machine to reach** (node) |
|---|---|---|
| Command | `curl …/install.sh \| bash` *(no-arg default)* | `curl …/install.sh \| bash -s -- --host` |
| sudo / daemon | no | yes |
| Warren VPN / virtual IP / `name.hop` | no | yes (on by default) |
| Purpose | reach hosts you're invited to | be on the private network |

A client is a full **member** that simply hasn't lit up the VPN — upgrade anytime
with `hop warren join` (no re-invite). Node primers (forwarded by `install.sh
--host`):

| Flag | Effect | Maps to |
|---|---|---|
| `--invite <token>` | Redeem an invite (it carries the warren) → join | membership + `netdoc-join.ticket` |
| `--no-vpn` | Set up a host but disable the VPN | `vpn_enabled = false` |
| `--tag <a,b>` | Tag this host (role→tag reach + MagicDNS) | `tags` |
| `--default-role <name>` | Role for invites that don't specify one | `default_role` |

```bash
# A production web host that joins an existing warren from one invite:
curl -fsSL https://hop.keikai.ai/install.sh | bash -s -- \
  --host --tag production,web --invite <token>

# A laptop that just reaches the servers (no sudo, no VPN):
curl -fsSL https://hop.keikai.ai/install.sh | bash
```

Each primer is a wrapper over `hop config set <key> <value>` (or `hop warren
join`), so anything set at install can be changed at runtime. `install-daemon.sh`
remains as a back-compat alias of `install.sh --host`.

**How joining brings up the network (Shipped):** providing a warren join ticket
(the netdoc `DocTicket`, via `--join`, `HOP_VPN_JOIN_TICKET`, or
`<config>/netdoc-join.ticket`):
1. joins the network namespace (federation),
2. (node path) claims a virtual IP, brings up the TUN, registers the VPN endpoint,
3. resolves the role-derived ACL.

So the VPN comes up *as a side effect of joining* — there is no separate
"connect to VPN" step. Every member runs the hop daemon (the one-liner installs
it), exactly as Tailscale runs `tailscaled` everywhere.

> **(Remaining polish.)** Today membership (redeeming a `hop invite`) and the
> warren join ticket (`--join`) are two values. The planned refinement folds the
> join ticket *into* the invite token so a single redeem does both — the
> mechanism is shipped; only the one-token UX is pending.

### The role model

> **Unification (Shipped, with a compat shim):** hop is converging its two role
> concepts — `PeerRole` (`Peer`/`Creator`, the auth tier) and `RoleDefinition`
> (named roles with `host_tags`) — into **one named role**. Peer entries and
> invites now carry a role **name** (`role_name`), `member` is the seeded
> least-privilege default, and `hop invite --role` / `hop admin grant` operate on
> names. `PeerRole` survives as a migration shim for legacy peers; the named role
> is authoritative going forward.

A **role** defines:
- **Auth tier** — `member` vs `admin` (can it manage the warren?).
- **Reach** — which host **tags** it can access (`host_tags`).
- **Ports/services** — default all; tightenable.

#### Default roles

These are the **currently seeded** roles (`crates/hop-core/src/fleet`):

| Role | Reaches (tags) | Notes |
|------|----------------|-------|
| `member` *(the default)* | none | In the warren with an address; **default-deny** until granted. The safe default. |
| `developer` | `developer`, `staging` | Day-to-day engineering access. |
| `ops` | `*` | Infrastructure. |
| `ci` | `build` | Build/deploy targets. |
| `security` | `production`, `staging` | Audit-oriented. |
| `admin` | `*` | Full reach + manages the warren. |

*(Today these roles drive fleet aggregate-invite access; the warren extends the
same role→tag model to VPN reach. The exact tag sets are tunable — the table
reflects the seed defaults, not a fixed contract.)*

#### The default role (Shipped)

`hop invite` with no `--role` assigns the **org default role** (`HostConfig.default_role`),
which starts as `member` (least-privilege, default-deny reach). The founder can
re-point it with `hop config set default_role <name>` (e.g. to `developer` for a
small all-engineer team). Naming a role on the invite always overrides it.

This closes the old footgun where a forgotten flag silently granted broad access:
the default role now reaches **nothing** until a role grants it, so the safe
outcome is the one you get by default.

#### Role → ACL derivation (Shipped, the keystone)

The VPN ACL is **not authored** — it is the projection of the role model:

> A member with role `R` may reach hosts whose tags intersect `R`'s `host_tags`,
> on `R`'s permitted ports. Everything else is denied.

Rules are expressed as **role→tag**, resolved at enforcement time against the
replicated membership doc (packet src IP → member → role; dst IP → host → tags).
They're stable as people join and leave — no per-IP rule regeneration. When a new
developer joins, the existing `developer → dev` rule already covers them.

#### Two layers of access control: reach vs confinement

hop has **two** access-control systems that serve different, non-overlapping
purposes. They are not redundant and neither can do the other's job:

| Layer | Answers | Scope | Modeled on |
|-------|---------|-------|------------|
| **Reach** (the ACL) | *Can I connect to it?* | network — `member → host:port` | corporate network / security groups |
| **Confinement** (the sandbox) | *What can a hop session do once it's open?* | host — commands, paths, network egress inside a hop shell/exec/agent | least-privilege; the agentic read-only model (e.g. a monitor cron that may look but not touch) |

- **Reach** decides whether a connection is permitted at all — covering both the
  `hop <host>` session path and IP-level VPN service access (both derived from the
  same role tags, so they always agree).
- **Confinement** decides what a hop-spawned *session* may do once running. It
  applies to hop shells/exec/agents — **not** to a raw VPN connection to a
  service like Postgres, whose own auth governs that.

**They compose, they don't collide.** Each is an independent gate at a different
point, AND-ed together: an action is allowed only if it passes every applicable
layer, and where they touch the more-restrictive one wins (a `no_network`
sandbox session simply won't use the VPN even if the ACL would allow it — correct,
not a conflict). Neither layer ever overrides the other.

**The role sets both, so they stay coherent.** A `RoleDefinition` already carries
`host_tags` (→ reach) *and* a `sandbox` (→ confinement). You never configure two
systems: you assign a role, and reach + confinement are set together. `--role
monitor` → reaches the monitored hosts *and* gets a read-only, no-network
session. One decision, two layers, no contradiction.

#### Changing a role after invite (Shipped)

Members are elevated/demoted without re-inviting:

```
hop admin <host> grant <peer> ops       # elevate
hop admin <host> grant <peer> member    # demote / reset
```

This updates the member's role in the membership doc, which replicates to every
node and triggers ACL re-resolution — the member's reach changes within seconds,
no token re-issue.

### Status

#### Shipped
- **Decentralized membership** (iroh-docs) with doc-authoritative auth + a
  `peers.json` fallback that guarantees no lockout. *(0.6.26)*
- **Virtual IP allocation** — every node claims a stable `100.64.0.0/10`
  address. *(0.6.27)*

#### Shipped — VPN data plane *(opt-in; off by default since 0.6.37)*
- **VPN data plane** — `hop/vpn/1` QUIC-datagram forwarding over a TUN device,
  federation via write ticket. *(0.6.28)*
- **MagicDNS** resolver, configurable per-warren domain. *(0.6.28, 0.6.30)*
- **Role-based warren MVP — Steps 1-7** *(0.6.29, 0.6.30)*: unified role model
  (`role_name` on peers/invites; least-privilege `member` default;
  `HostConfig.default_role`); `hop invite --role <name>`; host tags
  (`HostConfig.tags`); **role→tag→ACL reach** enforced on the forwarding path
  (replaces the static default-deny policy); role elevation
  (`hop admin <host> grant <peer> <role>`); federation safety (additive-only
  reconcile when joined to a shared namespace).
- **Step 8 — live multi-node TUN e2e** *(0.6.31)*: two federated nodes route real
  ICMP over the TUN, role-gated, 0% loss (`tests/e2e/vpn-e2e.sh`). Joiners become
  role-bearing members by redeeming an invite; the namespace owner self-registers
  as `admin` so it can originate/return traffic (M4a).
- **Ingress authentication** *(0.6.37)*: inbound `hop/vpn/1` datagrams are
  accepted only from a registered peer, with a source vIP matching that peer's
  registration (anti-spoof) and a destination of this host's own vIP.
- **Opt-in / off by default** *(0.6.37)*: the VPN was default-on in
  0.6.32–0.6.36; the default was reverted to **off** while the warren write
  model is hardened (see [security.md](security.md) and C1 in
  [../technical/security.md](../technical/security.md)). Enable with
  `--host`, `HOP_VPN=1`, or `hop config set vpn on`. `HostConfig.vpn_enabled`
  (default `false`) and the `HOP_VPN` env var (`1`=force-on past the conflict
  guard, `0`=off) control it. Bringup is best-effort: a TUN-creation failure or a
  `100.64.0.0/10` conflict (e.g. a host already running Tailscale) only skips the
  VPN — **core access is never affected**.

Validated by unit/integration tests (role-reach, role-derived reach via doc,
federation replication, federated additive reconcile, ACL, DNS codec, config
vpn-default-off), the **live multi-node TUN e2e** (including reboot
reconvergence), and the 53-test regression e2e — which runs in TUN-less
containers, so its green run is the standing proof that core access is unaffected
whether or not the VPN is up. The live multi-node TUN packet flow is exercised by
`tests/e2e/vpn-e2e.sh` (real ICMP over `hop/vpn/1`, role-gated, 0% loss).

#### Planned (the warren product)
See the roadmap below.

### Roadmap

| Milestone | Status | Scope |
|-----------|--------|-------|
| **Role cleanup** | ✅ Shipped (compat shim) | Converge `PeerRole` + `RoleDefinition` into one named role. Configurable least-privilege **org-default role** (`member`). **`hop admin <host> grant`** for post-invite elevation. |
| **M1 — Invisible ACL** | ✅ Shipped | Role→tag→ACL derivation, resolved at enforcement time. Host tagging via role/invite. Turns the VPN from "default-deny, no way to open it" into "opens automatically by role." |
| **M2 — Network membership** | ◑ Mostly | Invite-to-network-with-a-role, doc-replicated membership every node reads, receiver-side ACL enforcement, and **data-plane ingress authentication** (source-vIP anti-spoof, v0.6.37) — **shipped**. Write-isolation is **shipped** — `node`/`warren-only` members hold a *read* ticket and write only their own write-isolated self-doc; the shared admin doc is admin-authored. Still **deferred**: flipping per-author validation from observe to **enforce** by default, and the full cryptographic Owner/Admin write *capability* (see C1 in [../technical/security.md](../technical/security.md) and [../technical/warren-internals.md](../technical/warren-internals.md)). |
| **M3 — Usable end to end** | ◑ Mostly | `--join` brings up the VPN + the **live multi-node TUN e2e** (Cedar reach + reboot reconvergence) — shipped. The VPN is **off by default** (opt in via `--host`/`HOP_VPN=1`/`hop config set vpn on`) while M2's write model is hardened. Client-vs-node redemption polish and MagicDNS OS auto-config (split-DNS) remain. |
| **M4 — One-line onboarding** | ◑ Partial | Installer `--join`/primer flags + the website command builder — **shipped**. Folding the warren ticket *into* the invite token, and the `install.sh`/node-installer rename, remain. |

The only command a founder ever types remains `hop invite --role X`. Everything
else is install-and-redeem.

### Legacy → warren reconciliation

hop's original design ("SSH without a server") baked in some assumptions that the
warren supersedes. The reconciling principle is **decentralization, not
minimalism** — hop's guarantee is *no central control plane / no third party*,
**not** *no daemon*. With that lens, each legacy piece has a clear destination:

| Concept | What it was (legacy) | Where it's going |
|---|---|---|
| **The guarantee** | "single binary, no background daemon" as the wedge | "fully P2P, no central coordination server, no third party" — a per-member daemon is fine |
| **Auth source of truth** | per-host `peers.json` ("who may connect to *me*") | replicated CRDT document (doc-authoritative; `peers.json` becomes a synced mirror/fallback) — *in progress, Phase 1* |
| **Roles** | two systems: `PeerRole` (`Peer`/`Creator`) + fleet `RoleDefinition` | one unified named role = auth tier + tags + access |
| **The fleet "orchestrator"** | a host that *owns* the member registry + `roles.json` + aggregate invites (soft centralization) | **no orchestrator** — the warren document *is* the shared registry, replicated to every node; write authority is a cryptographic **capability** (Owner/Admin-signed), not a server |
| **Fleet storage** | `fleet.json` / `fleet_registrations.json` / `aggregate_invites.json` (separate files on the orchestrator) | membership/tags/role-invites as entries in the warren document, replicated |
| **Invites** | host-scoped (authorize me to one host) | network-scoped (join the warren with a role); token carries the warren ticket |
| **`known_hosts`** | client-side cache of individual hosts | read-replica of the warren document (auto-discovery) |
| **Client model** | the only model: a rootless CLI that connects to hosts | one of **two tiers** — client (rootless CLI, kept first-class) and node (daemon, on the fabric) |

**On "no control plane" precisely:** the warren has **no central server** — the
document is fully replicated and any node can serve it. It is *not* anarchy:
membership/role/ACL **writes** require an Owner/Admin-signed capability, so
"Owner-managed" means *cryptographically authorized*, not *server-controlled*.
That is what reconciles "no control plane" with "the founder owns membership."
The old fleet **orchestrator** dissolves into this: its role definitions and
role-based invites are kept and extended; its position as the *authority that
holds the registry* is replaced by the replicated document.

### Design principles (the bar every feature meets)

1. **Zero-config by default** — there is always a sensible default; configuration is opt-in tuning, never required.
2. **Role is the access** — one source of truth drives both `hop`-shell access and VPN reach; no second ACL system.
3. **Additive, never regressive** — the VPN is a strict superset of the client; "just hop to a box" stays first-class forever.
4. **Safe by default** — least-privilege default role, default-deny ACL, no-lockout auth fallback.
5. **No control plane** — the network depends on no central service to keep running.


---

## Fleet Management

A fleet in hop is just your **[warren](warren.md)**, managed at scale. Any `hop host` can issue invites and define roles, but there is **no orchestrator and no master member list**: membership, roles, tags, and ACLs live in a **replicated network document** (iroh-docs) that every node holds its own copy of. Fleet features are integrated into `hop host` — there is no separate fleet server.

The warren federates across hosts via a join ticket (carried by `node`/`admin` invites; `--join` / `HOP_VPN_JOIN_TICKET`), with **additive-only reconcile** so no host can revoke another's entries. Roles drive both host access (RBAC) **and** warren VPN reach. Writes are gated by an admin/owner author binding (C1; see [Security Internals](../technical/security.md) and [Warren Internals](../technical/warren-internals.md)) — author validation ships in **observe** mode by default, with **enforce** opt-in (`HOP_NETDOC_VALIDATION`) pending a multi-node federated rollout.

### Architecture

Membership and policy live in the replicated warren document — every node sees the same view, with no central registry:

```
 Warren network document (iroh-docs, replicated to every node)
   peer/<node>        ─── members: node id, name, tags, vIP
   role/<name>        ─── RBAC role definitions (admin-authored)
   acl/ + tag/        ─── role→tag reach policy + host tags
   revocation/<node>  ─── tombstones (additive-only)

 Each member also owns a write-isolated self-doc
   (its own name / tag / posture / endpoint — see the Warren Internals doc)
```

- **No orchestrator of record.** Any host with admin rights issues invites and writes roles; the document replicates the result to every node. There is no master copy to keep in sync.
- **Members** are warren nodes — not "hosts registered with an orchestrator." A read-only mirror (`WarrenSnapshot`) is exported to `warren-members.json` so `hop fleet list/status` works without holding the store open or needing admin rights.
- Legacy `roles.json` is retained as a human-readable, git-committable source for role definitions (infrastructure-as-code). The old `fleet_registrations.json` is gone; `fleet.json` survives only behind legacy admin handlers.

### Fleet Members

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

#### Tag-Based Grouping

Members are organized by tags. Tags are free-form strings used for targeting fleet operations:

```bash
# Create a fleet invite with tags
hop admin <host> fleet-invite --tags web,production

# List members filtered by tag
hop admin <host> fleet-list --tag web

# Update tags on a member
hop admin <host> fleet-tag <node-id-prefix> --add staging --remove production
```

### Fleet Invites

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

### Aggregate Invites

Aggregate invites are role-based, reusable invites that grant access to all fleet members matching a role's host tags. They expire after 7 days.

Flow:
1. An admin host creates an aggregate invite for a role + peer name
2. The peer redeems the invite against that host
3. The host resolves matching members (whose tags match the role's `host_tags`)
4. Per-host invites are created for the peer

### CLI Commands

#### Host-side: `hop fleet`

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

#### Admin-side: `hop admin`

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

### RBAC System

Roles define what fleet members a peer can access and what capabilities they have on those hosts.

#### RoleDefinition Fields

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

#### Default Roles (5 built-in)

Seeded on first host startup via `roles.json`:

| Role | host_tags | sudo | admin | user_mode | groups | sandbox |
|---|---|---|---|---|---|---|
| `admin` | `*` | yes | yes | individual | `docker` | unrestricted |
| `ops` | `*` | yes | no | individual | `docker` | unrestricted |
| `developer` | `developer`, `staging` | no | no | individual | -- | unrestricted |
| `security` | `production`, `staging` | no | no | individual | -- | audit preset (read-only, no network) |
| `ci` | `build` | no | no | shared | -- | deploy preset (denied destructive commands) |

#### Role CLI

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

#### Infrastructure as Code

`roles.json` is designed to be human-readable (pretty-printed JSON) and git-committable, enabling infrastructure-as-code workflows.

*Last updated: v0.6.90*


---

## Warren — Gap Analysis (living)

Consistency review of the product docs against each other and the implementation,
updated after the **"decentralization, not minimalism"** decision (hop's
guarantee is *no central control plane / no third party*; a per-member daemon is
intentional). See [warren.md](warren.md) and
[../technical/warren-internals.md](../technical/warren-internals.md).

Status legend: ✅ resolved by decision · 📝 doc fix needed · 🔧 open technical work.

### ✅ Resolved by the decentralization decision

- ✅ **"No background daemons" contradiction.** *Was:* `overview.md` sold
  daemonlessness as the wedge vs Tailscale, while the warren needs a daemon on
  every member. *Now:* the guarantee is decentralization, not minimalism — a
  per-member daemon is in keeping with it. (`overview.md` reframed.)
- ✅ **"No control plane" vs "Owner-managed membership."** *Was:* these read as
  contradictory. *Now:* "no control plane" = **no central server** (the document
  is fully replicated); "Owner-managed" = **writes need an Owner/Admin-signed
  capability**. Authority is cryptographic, not infrastructural. (`warren.md`
  clarified.)
- ✅ **Root daemon on every laptop.** *Was:* flagged as an unstated cost. *Now:*
  accepted as intentional — same model as Tailscale, but with no coordination
  server. (Documented in the legacy→warren table.)
- ✅ **Fleet "orchestrator" as a soft central authority.** *Now:* dissolves into
  the replicated document + capability-based writes; its role definitions and
  role-based invites are kept and extended, not its authority-holding position.
- ✅ **Default-role behavior (confirmed).** `hop invite` with no role assigns the
  org default, which is **least-privilege `member`: in the warren with an address
  but default-deny — reaches nothing until a role grants it.** This replaces
  today's footgun (no-role → `Peer` = full unrestricted shell). The org default
  is re-pointable; implementation is part of the role-system merge.

### 📝 Doc honesty fixes — ✅ all addressed

*(All resolved as of the consistency pass: client read-replica + onboarding
`--role` flow marked Planned; default-role table corrected to seeded roles;
`hop ls` discovery marked Planned; MagicDNS domain decided (configurable);
`security.md` auth flow + role direction updated; `warren.md` cross-references the
warren evolution; the technical doc gained a "Federation safety" section. The
items below are kept for the record.)*

- 📝 **Client "carries a read-only replica."** Today only the `hop host` daemon
  runs the netdoc stack; a plain `hop` client has **no** replica. The
  legacy→warren table now lists this under "where it's going," but warren.md's
  capability table still states it as current — mark it Planned.
- 📝 **`hop invite --role developer` shown but unbuilt.** The basic invite only
  has `--creator` today (→ `Peer`/`Creator`). Named-role invites exist only on the
  fleet aggregate path. Mark the warren onboarding commands Planned; note the
  current syntax.
- 📝 **The default-role table is fictional.** Doc says `member` (default),
  `developer → dev,staging`, `security → *`. **Seeded reality:** there is no
  `member`; `developer → developer,staging` (not `dev`); `security →
  production,staging` (not `*`). Fix the table to match seeded roles and mark the
  new `member` default Planned.
- 📝 **`hop ls` scope.** It lists local `known_hosts`/peers, not a network-wide,
  role-filtered view. Correct the capability-table wording.
- ✅/🔧 **MagicDNS domain.** *Decided:* **configurable per-warren domain with
  conventional defaults** — named warren → `<warren-name>.hop` (`web.acme.hop`),
  unnamed → flat `hop` (`web.hop`); domain stored in the warren document. Docs
  updated. *Implementation* (live resolver currently hard-codes `.hop`) folds
  into the role/onboarding work.
- 📝 **`security.md` is stale.** Its auth flow still ends at "added to
  `peers.json`" with no mention of the netdoc / doc-authoritative auth / mirror
  from Phase 1. Update it.
- ✅ **Sandbox vs ACL — two access systems.** *Resolved:* they are complementary
  layers — **reach** (ACL: *can I connect?*, the corporate-network model) vs
  **confinement** (sandbox: *what may a hop session do?*, the agentic
  least-privilege model). They compose as independent AND-gates at different
  points (never override each other; more-restrictive wins where they touch), and
  the **role sets both** (`host_tags` → reach, `sandbox` → confinement) so they
  stay coherent. Documented in warren.md → "Two layers of access control."

### 🔧 Open technical work (now well-defined — this *is* the roadmap)

- ✅ **VPN traffic flows by role; ingress is authenticated.** *(0.6.31–0.6.37)*
  The ACL is derived from roles×tags and enforced on the forwarding path,
  validated by a live multi-node TUN e2e (real ICMP, role-gated, 0% loss, plus
  reboot reconvergence). Inbound datagrams are authenticated (source-vIP
  anti-spoof, v0.6.37). The VPN is **off by default** as of v0.6.37 (opt in via
  `--host` / `HOP_VPN=1` / `vpn_enabled=true`); a TUN failure or CGNAT conflict
  only skips it, never core access.
- 🔧 **Members get a *write* ticket → any member could rewrite membership/ACL/`vpn`/`name`.**
  Tracked as **C1** in [../technical/security.md](../technical/security.md).
  The reconciliation says writes must be Owner/Admin-capability-gated and members
  get a **read** replica. *Fix:* split read vs write capability in the
  invite/join path + per-author write validation on read. (Prerequisite for safe
  federation.) **Interim mitigation shipped (v0.6.37):** VPN off-by-default +
  data-plane ingress authentication.
- 🔧 **Federated membership reconcile would revoke other hosts' peers.**
  `reconcile` revokes "doc peers not in *my* peers.json" — safe per-host, breaks
  on a shared namespace (M2). The additive `ip`/`vpn`/`name` tables are
  federation-safe; membership needs **ownership scoping** before it can be shared.
- 🔧 **ACL enforced sender-side only.** A compromised member could decline to
  enforce. *Fix:* receiver-side enforcement (the design's intent).
- 🔧 **Fleet storage not yet in the document.** `fleet.json` /
  `fleet_registrations.json` / `aggregate_invites.json` still live as separate
  files; only `peers.json`/`roles.json` migrate into the netdoc today. Migrate
  fleet state into the document to complete decentralization.
- ✅ **Role-system merge.** *(shipped, compat shim)* Peers/invites carry a named
  role (`role_name`); the configurable least-privilege org-default (`member`) is
  seeded; `hop admin <host> grant` does post-invite elevation. `PeerRole` remains
  as a migration shim.

### Triage

1. ✅ **Already decided** (✅ block) — positioning, control-plane semantics,
   daemon/root model, default-role behavior, DNS domain. Doc edits landed.
2. ✅ **Docs made honest** (📝 block) — every present-tense overclaim is now marked
   Planned or corrected; `security.md`/`warren.md` updated; cross-refs added.
3. 🔧 **Build next** — the only remaining work is engineering. It is now planned
   in detail: see **[../technical/warren-internals.md](../technical/warren-internals.md) →
   "Next-stage build plan — the role-based warren MVP"** (role unification +
   federation safety + role→ACL derivation + live multi-node TUN e2e). The open
   🔧 items above (inert VPN, write-ticket, federated reconcile, receiver-side
   ACL, fleet-state migration, role-system merge) are all steps of that plan.

**Status: product/technical docs are internally consistent and consistent with
the implementation. All gaps are either resolved-by-decision, doc-corrected, or
captured as sequenced steps in the build plan.**
