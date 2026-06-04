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
> `hop invite --role <named>` and the **warren VPN** are shipped; the VPN is
> **off by default** as of v0.6.37 (opt in with `--host` / `HOP_VPN=1` /
> `hop config set vpn on`) while the warren write model is hardened. Federation
> still joins via a namespace ticket (`HOP_VPN_JOIN_TICKET`) rather than a
> `--join` installer flag. See **Status**
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

### Two install tiers, one command

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

## The role model

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

### Default roles

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

### The default role (Shipped)

`hop invite` with no `--role` assigns the **org default role** (`HostConfig.default_role`),
which starts as `member` (least-privilege, default-deny reach). The founder can
re-point it with `hop config set default_role <name>` (e.g. to `developer` for a
small all-engineer team). Naming a role on the invite always overrides it.

This closes the old footgun where a forgotten flag silently granted broad access:
the default role now reaches **nothing** until a role grants it, so the safe
outcome is the one you get by default.

### Role → ACL derivation (Shipped, the keystone)

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

### Changing a role after invite (Shipped)

Members are elevated/demoted without re-inviting:

```
hop admin <host> grant <peer> ops       # elevate
hop admin <host> grant <peer> member    # demote / reset
```

This updates the member's role in the membership doc, which replicates to every
node and triggers ACL re-resolution — the member's reach changes within seconds,
no token re-issue.

## Status

### Shipped
- **Decentralized membership** (iroh-docs) with doc-authoritative auth + a
  `peers.json` fallback that guarantees no lockout. *(0.6.26)*
- **Virtual IP allocation** — every node claims a stable `100.64.0.0/10`
  address. *(0.6.27)*

### Shipped — VPN data plane *(opt-in; off by default since 0.6.37)*
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
  [../technical/security-audit.md](../technical/security-audit.md)). Enable with
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

### Planned (the warren product)
See the roadmap below.

## Roadmap

| Milestone | Status | Scope |
|-----------|--------|-------|
| **Role cleanup** | ✅ Shipped (compat shim) | Converge `PeerRole` + `RoleDefinition` into one named role. Configurable least-privilege **org-default role** (`member`). **`hop admin <host> grant`** for post-invite elevation. |
| **M1 — Invisible ACL** | ✅ Shipped | Role→tag→ACL derivation, resolved at enforcement time. Host tagging via role/invite. Turns the VPN from "default-deny, no way to open it" into "opens automatically by role." |
| **M2 — Network membership** | ◑ Mostly | Invite-to-network-with-a-role, doc-replicated membership every node reads, receiver-side ACL enforcement, and **data-plane ingress authentication** (source-vIP anti-spoof, v0.6.37) — **shipped**. The cryptographic Owner/Admin write-capability is still **deferred** (every member currently holds a *write* ticket to the shared doc; per-author write validation ties to the trust root — see C1 in [../technical/security-audit.md](../technical/security-audit.md)). |
| **M3 — Usable end to end** | ◑ Mostly | `--join` brings up the VPN + the **live multi-node TUN e2e** (Cedar reach + reboot reconvergence) — shipped. The VPN is **off by default** (opt in via `--host`/`HOP_VPN=1`/`hop config set vpn on`) while M2's write model is hardened. Client-vs-node redemption polish and MagicDNS OS auto-config (split-DNS) remain. |
| **M4 — One-line onboarding** | ◑ Partial | Installer `--join`/primer flags + the website command builder — **shipped**. Folding the warren ticket *into* the invite token, and the `install.sh`/node-installer rename, remain. |

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
