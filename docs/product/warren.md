# Warren — hop's Private Network (Product Design)

> **Status:** This document is the product vision and roadmap for hop's
> peer-to-peer private network. Some of it ships today (clearly marked
> **Shipped** / **Experimental**); the rest is **Planned**. The technical
> implementation lives in [`../technical/p2p-network.md`](../technical/p2p-network.md).

## Vision

hop has always been "SSH without a server" — one binary, reach any machine
you're invited to, no port-forwarding, no VPN appliance. The **warren** extends
that into a full private network for a team, with one defining principle:

> **The role *is* the access.** You never write ACLs. You invite someone as a
> `developer` and the network already knows what a developer can reach.

The target customer is a **small, globally-distributed startup** doing remote
work: a founder, a handful of engineers, a few servers. They should never touch
a VPN config, an exit node, or a firewall rule. They install hop, invite their
team by role, and the network configures itself.

### Positioning

| Layer | Pitch |
|-------|-------|
| **hop** (the tool) | Reach any machine you're invited to. One binary, no server. |
| **warren** (the network) | Invite your team and they're on a private network with exactly the access their role allows. No appliance, no exit nodes, no ACL files. |

**Differentiators:**
1. **Role-native access** — access is a consequence of who someone is, not hand-authored policy. (Tailscale makes you write ACL policy; hop derives it from roles.)
2. **No control plane** — membership lives in a replicated CRDT ([iroh-docs](../technical/p2p-network.md)), not a coordination server. The network keeps working even when no central service is up.
3. **Two depths, one invite** — join the full network, or just hop into one box. Same role, same token; the recipient chooses their footprint.

## Vocabulary

One consistent language across product, CLI, and marketing:

| Term | Meaning |
|------|---------|
| **hop** | The tool, and the verb — *hop into a machine*. |
| **warren** | A team's private network (the mesh / VPN). "Your warren." |
| **node** | A machine that lives in the warren — has a virtual IP, a name, is reachable. Runs the hop daemon. |
| **client** | A machine with just the `hop` CLI: can hop into permitted machines, but doesn't live in the warren (no virtual IP). |
| **role** | A named identity (`developer`, `ops`, …) that determines what a member can reach. |
| **invite** | A single-use token that admits a machine to the warren with a role. |

**Names (MagicDNS).** Each node is reachable as `<hostname>.<domain>`. The domain
is **configurable per warren**, with a conventional default: a **named** warren
uses `<warren-name>.hop` (e.g. `web.acme.hop`); an unnamed warren falls back to
the flat `hop` domain (e.g. `web.hop`). The domain lives in the warren document
so every node resolves consistently. *(Today the resolver hard-codes `.hop`;
making it configurable is part of the role/onboarding work.)*

## The two paths: client vs node

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

## Onboarding (zero-config)

All network administration collapses into **install + `hop invite`**. There are
no `net init`, `add-server`, `tag`, or `up` commands — the network self-forms
from the first daemon and grows through invites.

> **(Mostly shipped.)** The commands below are the *target* experience. Today
> `hop invite --role <named>` and the **default-on VPN** are shipped (opt out with
> `HOP_VPN=0`); federation still joins via a namespace ticket
> (`HOP_VPN_JOIN_TICKET`) rather than a `--join` installer flag. See **Status**
> and **Roadmap** for what's shipped vs planned.

```
# Founder — install hop. The network ("warren") auto-creates; founder is Owner.
curl -fsSL https://hop.keik.ai | bash

# Invite anyone (person or server) with a role:
hop invite --role developer
#  → prints a one-liner the recipient pastes:
#     curl -fsSL https://hop.keik.ai | bash -s -- --join <token>
#     (drop --join for CLI-only client access)

# Recipient installs + redeems. They're on the warren with developer access —
# nothing else to configure.
```

### Install-time configuration (primers)

The installer can prime the host config at install time, so a machine comes up
exactly how you want with no follow-up commands. The website's **install command
builder** composes these flags from toggles; they work on both `install.sh` and
`install-daemon.sh` (and are forwarded by `install.sh --daemon`):

| Flag | Effect | Maps to |
|---|---|---|
| `--no-vpn` | Disable the warren VPN data plane | `vpn_enabled = false` |
| `--tag <a,b>` | Tag this host (role→tag reach + MagicDNS) | `tags` |
| `--default-role <name>` | Role for invites that don't specify one | `default_role` |
| `--join <ticket>` | Federate into an existing warren | `<config>/netdoc-join.ticket` |

```bash
# A production web host, VPN on, joined to an existing warren:
curl -fsSL https://hop.keikai.ai/install-daemon.sh | bash -s -- \
  --tag production,web --join <ticket>

# A client box that should never bring up the VPN:
curl -fsSL https://hop.keikai.ai/install.sh | bash -s -- --no-vpn
```

Each primer is just a wrapper over `hop config set <key> <value>` (or the join
ticket file), so anything set at install can be changed later at runtime.

**How the invite carries the network (Planned):** the invite token embeds the
warren's join ticket (the netdoc `DocTicket`). Redeeming it:
1. joins the network namespace (federation),
2. (node path) claims a virtual IP, brings up the TUN, writes split-DNS config,
3. applies the role-derived ACL.

So the VPN comes up *as a side effect of joining* — there is no separate
"connect to VPN" step. Every member runs the hop daemon (the one-liner installs
it), exactly as Tailscale runs `tailscaled` everywhere.

## The role model

> **Cleanup (Planned):** today hop has *two* role concepts — `PeerRole`
> (`Peer`/`Creator`, the auth tier) and `RoleDefinition` (named fleet roles with
> `host_tags`). These merge into **one conventional role model**: a named role
> that carries both the auth tier and the network access.

A **role** defines:
- **Auth tier** — `member` vs `admin` (can it manage the warren?).
- **Reach** — which host **tags** it can access (`host_tags`).
- **Ports/services** — default all; tightenable.

### Default roles

These are the **currently seeded** roles (`crates/hop-core/src/fleet`), plus the
planned `member` default:

| Role | Reaches (tags) | Notes |
|------|----------------|-------|
| `member` *(Planned — the new default)* | none | In the warren with an address; **default-deny** until granted. The safe default. |
| `developer` | `developer`, `staging` | Day-to-day engineering access. |
| `ops` | `*` | Infrastructure. |
| `ci` | `build` | Build/deploy targets. |
| `security` | `production`, `staging` | Audit-oriented. |
| `admin` | `*` | Full reach + manages the warren. |

*(Today these roles drive fleet aggregate-invite access; the warren extends the
same role→tag model to VPN reach. The exact tag sets are tunable — the table
reflects the seed defaults, not a fixed contract.)*

### The default role (Planned)

`hop invite` with no `--role` assigns the **org default role**, which starts as
`member` (least-privilege, default-deny). The founder can re-point the org
default (e.g. to `developer` for a small all-engineer team). Naming a role on
the invite always overrides it.

This fixes today's footgun: currently no-role defaults to `Peer` = **full
unrestricted shell** to the host. In a network where the role is the firewall,
silently granting full shell on a forgotten flag is exactly what we design out —
the default must be safe.

### Role → ACL derivation (Planned, the keystone)

The VPN ACL is **not authored** — it is the projection of the role model:

> A member with role `R` may reach hosts whose tags intersect `R`'s `host_tags`,
> on `R`'s permitted ports. Everything else is denied.

Rules are expressed as **role→tag**, resolved at enforcement time against the
replicated membership doc (packet src IP → member → role; dst IP → host → tags).
They're stable as people join and leave — no per-IP rule regeneration. When a new
developer joins, the existing `developer → dev` rule already covers them.

### Two layers of access control: reach vs confinement

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

### Changing a role after invite (Planned)

Members are elevated/demoted without re-inviting:

```
hop role grant <peer> ops      # elevate
hop role set   <peer> member   # demote / reset
```

This updates the member's role in the membership doc, which replicates to every
node and triggers ACL re-resolution — the member's reach changes within seconds,
no token re-issue. (Today the only path is `remove-peer` + re-invite; the
elevation command is new.)

## Status

### Shipped (default-on)
- **Decentralized membership** (iroh-docs) with doc-authoritative auth + a
  `peers.json` fallback that guarantees no lockout. *(0.6.26)*
- **Virtual IP allocation** — every node claims a stable `100.64.0.0/10`
  address. *(0.6.27)*

### Shipped — VPN default-on *(0.6.32)*
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
- **Default-on** *(0.6.32)*: the daemon brings up the VPN automatically.
  `HostConfig.vpn_enabled` (default `true`) and the `HOP_VPN` env var
  (`1`=force-on past the conflict guard, `0`=off) control it. Bringup is
  best-effort: a TUN-creation failure or a `100.64.0.0/10` conflict (e.g. a host
  already running Tailscale) only skips the VPN — **core access is never
  affected**.

Validated by unit/integration tests (role-reach, role-derived reach via doc,
federation replication, federated additive reconcile, ACL, DNS codec, config
default-on/opt-out), the **live multi-node TUN e2e**, and the 53-test regression
e2e — which runs in TUN-less containers, so its green run is the standing proof
that default-on degrades gracefully and the default daemon is unchanged.

Validated by unit/integration tests (routing, federation replication, ACL, DNS)
and the 53-test regression e2e. The live multi-node TUN packet flow is not yet in
an automated testbed — hence experimental.

### Planned (the warren product)
See the roadmap below.

## Roadmap

| Milestone | Scope |
|-----------|-------|
| **Role cleanup** | Merge `PeerRole` + `RoleDefinition` into one conventional role model. Add the configurable, least-privilege **org-default role**. Add **`hop role grant/set`** for post-invite elevation. |
| **M1 — Invisible ACL** | Role→tag→ACL derivation, resolved at enforcement time. Host tagging via role/invite. Turns the experimental VPN from "default-deny, no way to open it" into "opens automatically by role." |
| **M2 — Network membership** | Invite-to-network-with-a-role (not per-host); Owner/Admin-managed central membership every node reads; receiver-side ACL enforcement. The architectural shift from per-host to warren-wide access. |
| **M3 — Usable end to end** | Client vs node redemption branch; `--join` auto-brings-up the VPN; MagicDNS OS auto-config; the **live multi-node TUN e2e** that promotes the data plane to default-on. |
| **M4 — One-line onboarding** | Installer `--join`/`--invite` flags; invite token embeds the warren ticket; the founder narrative end to end. Script rename: `install.sh` = client, node installer reframed as "join the warren". |

The only command a founder ever types remains `hop invite --role X`. Everything
else is install-and-redeem.

## Legacy → warren reconciliation

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

## Design principles (the bar every feature meets)

1. **Zero-config by default** — there is always a sensible default; configuration is opt-in tuning, never required.
2. **Role is the access** — one source of truth drives both `hop`-shell access and VPN reach; no second ACL system.
3. **Additive, never regressive** — the VPN is a strict superset of the client; "just hop to a box" stays first-class forever.
4. **Safe by default** — least-privilege default role, default-deny ACL, no-lockout auth fallback.
5. **No control plane** — the network depends on no central service to keep running.
