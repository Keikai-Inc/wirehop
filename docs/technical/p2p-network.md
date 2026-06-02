# Peer-to-Peer Private Network (Design)

> **Status: MVP shipped — VPN default-on, as of v0.6.32.** The role-based warren
> MVP (all 8 build-plan steps below) is implemented and validated by a live
> multi-node TUN e2e (`tests/e2e/vpn-e2e.sh`) plus the 53-test regression suite.
> The VPN data plane is now **default-on**: the daemon brings up the TUN
> automatically, but bringup is **always best-effort** — if a TUN can't be
> created (no privilege / no `/dev/net/tun`) or `100.64.0.0/10` is already in use
> by another overlay (e.g. Tailscale), it degrades gracefully and keeps serving
> exec/shell/transfer untouched. Opt out with `HOP_VPN=0` or `vpn_enabled = false`
> in host config; `HOP_VPN=1` forces bringup past the conflict guard. Sections
> marked **(Commercial, deferred)** are planned for later phases and are
> documented here only so the schema and trust model don't have to be reworked
> when we get there.

## Goal

Turn hop's configured peers into a decentralized LAN-style VPN: every node gets
a stable virtual IP, can reach permitted services on other nodes over iroh P2P,
and resolves friendly names (`rexmundi.acme.hop`) — with **no orchestrator on the
data path**. Membership, roles, addressing, and access rules live in a shared,
replicated CRDT document rather than in any single host's local config.

The defining constraint: **the data plane stays orchestratorless in every mode.**
All commercial control-plane features (SSO, audit collection, network-lock,
key recovery) are additive and degrade gracefully when their central components
are offline — the network keeps routing on existing state.

## Architecture at a glance

```
        ┌─────────────────────── iroh-docs (replicated CRDT) ───────────────────────┐
        │  peers · roles · groups · tags · IP allocations · invites · revocations    │
        └───────────────┬──────────────────────────────┬────────────────────────────┘
                        │ replicates P2P (gossip)       │
                ┌───────┴────────┐              ┌────────┴───────┐
                │   Daemon A     │              │   Daemon B     │
                │ ┌────────────┐ │   QUIC       │ ┌────────────┐ │
   apps ──TUN──▶│ │ pkt filter │ │  datagrams   │ │ pkt filter │ │◀──TUN── apps
                │ │ (ACL)      │◀┼──────────────┼▶│ (ACL)      │ │
                │ └────────────┘ │  hop/vpn/v1  │ └────────────┘ │
                │ local DNS :53  │              │ local DNS :53  │
                └────────────────┘              └────────────────┘
```

- **Control plane:** one iroh-docs namespace per hop network ("the doc").
- **Data plane:** TUN device → daemon → QUIC datagrams (`hop/vpn/v1` ALPN) → peer daemon → TUN.
- **Names:** each daemon runs a small split-DNS resolver backed by the doc.
- **Access:** existing role/group/tag rules, enforced as a userspace packet filter at the *receiving* daemon, default-deny.

## Decisions

Each decision below records the chosen mechanism and the rationale. Forks that
were considered and rejected are noted so we don't relitigate them.

### 1. State sync — iroh-docs

A single iroh-docs namespace per network holds all control-plane state. Entries
are author-signed; replication is range-based set reconciliation plus gossip
over QUIC.

- **Why:** reuses the iroh investment, gives signed entries and P2P sync for
  free, no separate CRDT runtime to integrate.
- **Rejected:** custom CRDT (Automerge/Yjs) — more flexible schema but we'd
  reimplement sync; gossip-only — scales poorly past hundreds of peers.
- **Caveat to handle in code:** in iroh-docs any namespace writer can write any
  key. Key-uniqueness is *not* an authorization mechanism. Every entry's
  validity must be checked at read time against the role chain (see #9).

### 2. Virtual IP allocation — deterministic proposal + doc-coordinated claim

Addresses come from `100.64.0.0/10` (CGNAT range, familiar to Tailscale users).
Allocation is a hybrid:

1. **Deterministic proposal:** candidate IP = `hash(pubkey)` mapped into the
   range. Stable — the same key always re-derives the same "home" address.
2. **Doc is source of truth:** peer reads the allocation table
   (`ip/<addr> → pubkey`); if its candidate is free it claims it, else it
   linear-probes to the next free slot.
3. **Conflict resolution:** on a genuine concurrent claim (two peers, same slot,
   while partitioned), a deterministic tiebreak (lower pubkey wins) is applied
   at read time; the loser re-probes. Rare in a /10; the loser may change IP
   shortly after joining.

- **Why:** familiar IPv4 addresses + zero hard dependency on a central
  allocator (the doc *is* the allocator). Stable home IPs are a nice property.
- **Rejected:** pure `hash(pubkey)` into IPv4 — collision-prone and
  unrecoverable in a /10 (birthday paradox bites at a few thousand nodes);
  pure `hash(pubkey)` into IPv6 (Yggdrasil/CJDNS style) — collision-safe but
  commits us to IPv6 virtual addressing and loses the familiar look.
- **Note:** Tailscale itself allocates centrally via its coordination server;
  our doc-coordinated claim is the decentralized equivalent.

### 3. Invite token format — capability-token-into-doc (current scheme, lifted)

The existing single-use invite scheme, moved into the doc world. Token carries:
network (doc) ID, a bootstrap peer address, an ephemeral grant keypair, expiry,
and the issuer's signature. On redemption the new peer joins the doc, writes its
`peer/<pubkey>` entry under the grant, and the doc records `invite/<hash>` as
redeemed (replay-proof).

- **Why:** preserves the loved UX (single-use crypto token, no SSO, no account);
  works even when the inviter's daemon is offline (any peer with the doc can
  verify the invite).
- **Rejected:** **bearer + central revocation list** — a ticket anyone holding
  can use, cancellable only via an always-online server (defeats
  orchestratorless); **macaroons** — bearer tokens you can attenuate without the
  issuer (great for *delegated, narrowed* sub-invites), more machinery than v1
  needs. Macaroons are a good future option for "hand a contractor a narrower
  invite" and are noted here for that.

### 4. Revocation — eventual + sync-on-connect

Base model is eventual consistency: a revocation is a signed doc entry that
propagates via gossip (seconds-to-minutes when peers are online). The key
addition: **enforcement is on the receiving peer, so only the receiver's
freshness matters.**

- **Sync-on-connect:** before authorizing an inbound connection, the receiving
  daemon confirms its doc copy is fresh (triggers a sync if stale). This
  converts the exposure window from unbounded global propagation latency into
  the receiver's local sync latency — tight and controllable — with no
  credential-renewal churn and no compromise to the P2P model.
- **Why:** a revoked peer is harmless the moment any peer it contacts has a
  fresh doc; sync-on-connect guarantees that freshness cheaply.
- **Commercial upgrade (deferred):** short-lived peer credentials that must be
  periodically re-attested by an Admin. Converts "revocation must propagate"
  into "renewal must succeed," which fails safe and gives a hard bound. Purely
  additive — the doc carries revocations either way, so adopting this later is
  not a re-architecture.

### 5. Data plane — QUIC datagrams

VPN packets travel as QUIC unreliable datagrams (RFC 9221) over a dedicated
`hop/vpn/v1` ALPN.

- **Why:** IP packets are intrinsically unreliable; reliability/ordering for
  TCP-inside-the-tunnel is provided by the *inner* stack. QUIC streams would
  double-count reliability and cause head-of-line blocking (one lost packet
  stalls the whole stream).
- **MTU:** QUIC's effective datagram payload is ~1232 bytes after framing; set
  the TUN MTU to ~1280 to fit without fragmentation.
- **Rejected:** QUIC streams (HoL blocking); raw UDP via iroh-net (faster,
  WireGuard-like, but re-implements crypto/security primitives — too much
  review surface for v1).

### 6. TUN device — existing crate (candidates to evaluate)

Create the virtual interface via a maintained Rust crate rather than
hand-rolling per-OS `utun`/`tun` code. Candidates to evaluate at implementation
time: `tun`, `tun-rs`, and boringtun's tun module (reference for cross-platform
utun handling).

- **macOS:** utun via `socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` — no
  kext needed; requires root (daemon already runs as root via launchd).
- **Linux:** `/dev/net/tun` + `TUNSETIFF`; requires CAP_NET_ADMIN.
- **Windows:** Wintun — **(deferred, out of scope for v1).**

### 7. DNS — local split-DNS resolver (MagicDNS-style)

Each daemon runs a tiny DNS resolver bound to a magic address in the virtual
range. The OS is configured with **split-DNS** so only queries for the network's
domain go to that resolver; all other DNS is untouched. Name→IP mappings come
from the doc; the network's domain name is a configurable doc setting (e.g.
`acme.hop`).

- **Why:** exactly Tailscale's MagicDNS model. `hop RexMundi` and
  `ssh rexmundi.acme.hop` resolve the same doc entry. No system-resolver
  hijacking.
- **Rejected:** `/etc/hosts` rewriting (invasive, conflicts with manual edits,
  root for every change); mDNS over the VPN (finicky).
- **Client setup:** `/etc/resolver/<domain>` on macOS; systemd-resolved
  split-DNS on Linux.

### 8. Service ACL — doc rules, userspace filter at receiver, default-deny

Access rules reference **groups and tags, never individual peers**. Enforcement
is a userspace packet filter at the *receiving* daemon (packets already traverse
TUN → daemon → iroh, so the daemon is the natural choke point). Default policy is
**deny** — a peer joining gets zero service access until explicitly granted.

- **Why:** mirrors Tailscale's model (central policy, per-node userspace filter,
  deny-by-default) and reuses hop's existing role/group access rules rather than
  inventing a new system. No kernel firewall management required.
- **Rejected:** kernel firewall (iptables/pf) generation — faster but invasive
  and risky to manage on the user's behalf; default-allow — wrong for hop's
  threat model.

### 9. Trust root — peer-to-peer now, pluggable org-key later

v1 keeps the current fully-P2P trust model: the network Owner's keypair is the
root; roles flow from Owner → Admin → Peer as signed doc entries. Validity of
any entry is resolved by walking the role chain back to the Owner key.

- **Commercial (deferred):** make the trust root **pluggable**. The root becomes
  an **organization key** held in an HSM/KMS (never on a single daemon), which
  signs a small number of **Admin delegation certificates**; Admins sign peer
  and role entries. Same PKI shape as a corporate root CA → intermediate CAs →
  leaf certs, with the doc as the *replication layer for issued certificates*.
  Decentralized replication, centralized issuance authority. Adoption guide for
  large orgs to be written in the commercial phase.

### 10. Identity model — users *and* devices

Track both, separately:

| Entry | Meaning |
|-------|---------|
| `user/<id>` | A person (Bob). Belongs to groups. |
| `device/<pubkey>` | A machine. Owned by a `user/<id>`, or by the org (shared host). |
| group membership | `user/<id>` → groups (Bob ∈ `dev`). |
| tag | `device/<pubkey>` → tags (machine Z tagged `dev-machines`). |
| access rule | group → tag (group `dev` may reach tag `dev-machines`). |

Rules reference groups and tags only — that's what makes it scale:

- **Add machine Z** with tag `dev-machines` → *every* member of `dev` can reach
  it instantly, no per-user edits.
- **Remove Bob from `dev`** → he fails the ACL check on his next connection.
- **Lost laptop:** revoke one `device/<pubkey>`; Bob's other devices keep working.
- **Fire Bob:** revoke `user/bob`; all his devices lose access.

### 11. IdP integration — (Commercial, deferred)

A thin **identity bridge** holds an Admin cert and watches the customer's IdP
(Okta/Entra/Google Workspace) via SCIM/OIDC. IdP group change → bridge writes
the corresponding doc entry (provision/role/revoke).

- **Critically off the data path:** the bridge is automation that translates IdP
  events into signed doc entries. If it's down, the network keeps running on
  existing credentials; only onboarding/offboarding via SSO pauses.
- Roughly Tailscale's SSO mapping, except optional, self-hostable, and not a
  routing dependency.
- **Schema note for now:** because we model `user/<id>` separately (#10), adding
  the bridge later requires no schema change — the bridge just populates the
  same `user`/group entries a human Admin would.

### 12. Audit model — (Commercial, deferred; shape decided)

Two layers, built independently:

- **Control-plane audit (free):** the doc is already an append-only, signed log
  of every invite/grant/role-change/revocation — tamper-evident, answers "who
  was granted/revoked what, when, by whom." Covers most access-review
  compliance with no extra infrastructure.
- **Data-plane audit (opt-in):** "who connected to what service, when, how
  much." In true P2P only the two endpoints see this. Collecting it requires
  daemons to emit connection records to a sink — options: local signed logs
  pulled on demand, an optional collector peer, or export to the customer's SIEM
  (syslog/OTel). A *passive* collection component, not a routing dependency —
  the network still works if it's down. Built when a customer needs SOC 2.

### 13. Admin separation-of-duties — root-like now, network-lock later

v1: Admin is root-like (can manage ACLs, devices, users) — simple and matches
how small teams expect it to work.

- **Commercial (deferred) — "network lock":** modeled on Tailscale's *Tailnet
  Lock*. When enabled, the highest-privilege operations — **admitting a new
  device** and **promoting an Admin** — must be **co-signed by multiple trusted
  signing keys** held on existing nodes. No single compromised Admin key (and no
  compromised central component) can silently add a backdoor peer or escalate
  privilege. Scoped narrowly to the operations that matter, so it doesn't burden
  everyday admin work. This folds together the separation-of-duties (#13) and
  key-custody (#14) concerns.

### 14. Org key custody / recovery — (Commercial, deferred)

The org key (#9) is the root of trust; commercial customers *will* lose it
without help. Planned mechanisms (to be designed in the commercial phase):

- HSM/KMS-backed storage as the default.
- A documented multi-party recovery ceremony (threshold key shares).
- Key rotation that re-issues Admin certs without disrupting the data plane.

## Doc schema sketch

Entry keys (namespace = the network). Values are signed by the author; validity
is resolved against the role chain (#9) at read time.

| Key | Value | Written by |
|-----|-------|-----------|
| `network/config` | domain name, address range, flags (network-lock on/off) | Owner |
| `peer/<pubkey>` | hostname, advertised services, joined_at | self (under invite grant) / Admin |
| `device/<pubkey>` | owned-by `user/<id>` or `org`, tags | Admin |
| `user/<id>` | display name, groups | Admin / IdP bridge |
| `role/<pubkey>` | Owner / Admin / Peer, granted_by, granted_at | granter (Admin+) |
| `ip/<addr>` | pubkey (allocation table, #2) | self (claim) |
| `acl/<group>/<tag>` | scope (ports/protocols) | Admin |
| `invite/<token-hash>` | scope, expiry, redeemed_by | issuer |
| `revocation/<pubkey or user-id>` | reason, revoked_at | revoker (Admin+) |

## Phased rollout

Each phase stands on its own and ships independently. Personal-mode first; it's
the proving ground for the doc and addressing before any commercial work.

| Phase | Scope | Independent value |
|-------|-------|-------------------|
| **1. Decentralize state** ✅ *(per-host)* | Replace `peers.json`/`roles.json` with an iroh-docs replica. Migrate existing JSON on first start. Keep all current features (shell, exec, transfer, fleet, MCP). | Invites work even when the inviter is offline. |
| **2. Virtual IPs** ✅ | Deterministic-proposal + doc-claim allocation (#2). Claimed per host on startup. | Tests conflict resolution without TUN complexity. |
| **3. VPN packet plane** ✅ *(default-on, best-effort)* | TUN/utun (#6), `hop/vpn/1` over QUIC datagrams (#5), daemon-to-daemon forwarding, federation via write ticket. Default-on; skips gracefully on TUN failure / CGNAT conflict (`HOP_VPN=0` to opt out, `HOP_VPN=1` to force). | Actual P2P LAN reachability. |
| **4. DNS + ACL** ✅ *(default-on)* | MagicDNS resolver for `*.hop` (#7); role→tag→ACL filter on the forwarding path (#8, default-deny). Active with the default-on VPN. | Friendly names + safe service exposure. |
| **5. Commercial control plane** | Pluggable org-key trust root (#9), short-lived credentials (#4), user/device split already in place (#10), group/tag ACLs (#8/#10). | Strict, provable revocation for businesses. |
| **6. Enterprise integration** | IdP bridge (#11), data-plane audit export (#12), network-lock co-signing (#13), key custody/recovery (#14). | SSO, SOC 2, key safety. |

### Role-model unification (Planned — prerequisite for the warren)

The product layer ([`../product/warren.md`](../product/warren.md)) requires
collapsing hop's two role concepts into one:

- **Today:** `PeerRole` (`Peer`/`Creator`, the auth tier, used by the basic
  invite) and `RoleDefinition` (named fleet roles with `host_tags`, used by
  aggregate invites) are separate. The basic invite's no-role default is
  `PeerRole::Peer` = unrestricted shell, no admin.
- **Target:** one named-role model carrying auth tier + `host_tags` + ports. A
  configurable, least-privilege **org-default role** (`member`, default-deny) so
  `hop invite` with no `--role` is safe rather than granting full shell.
- **Elevation:** `hop role grant/set` updates a member's role entry in the
  document; replication + ACL re-resolution apply the change network-wide without
  re-issuing an invite. (Today the only path is `remove_peer` + re-invite.)
- **ACL derivation:** rules are stored/evaluated as role→tag (not per-IP) and
  resolved against the membership doc at enforcement time, so they're stable
  across join/leave. This supersedes hand-authored `acl/policy` for the default
  case.

### Federation safety (Planned — required before sharing a namespace)

Cross-host federation (one shared namespace) needs two safeguards the per-host
model doesn't:

- **Read vs write capability.** Today the join/`enable_vpn` path hands out a
  **write** ticket — any member could rewrite membership/roles/ACL. Members must
  instead get a **read** replica; membership/role/ACL **writes** require an
  Owner/Admin-signed capability (consistent with the trust-root chain, #9). This
  is what makes "Owner-managed membership" hold without a central server.
- **Ownership-scoped reconcile.** `reconcile` revokes "doc peers not in *my*
  `peers.json`" — safe per-host, but on a shared namespace it would revoke other
  hosts' members. Reconcile must be scoped to entries this host owns. The
  additive `ip`/`vpn`/`name` tables are already federation-safe (each host writes
  only its own); membership/roles need this scoping first.

### Phase 1 implementation status

**Shipped (per-host model):** the iroh-docs stack runs on a dedicated, isolated
endpoint (`net::create_netdoc_endpoint`, derived key → stable NodeId). On startup
the daemon opens-or-creates its network namespace (id persisted to `netdoc.json`)
and **reconciles** it against `peers.json`/`roles.json`; it reconciles again after
every admin mutation, so the document is a complete, self-healing, authoritative-
wired store. Auth is doc-aware: a peer in `peers.json` is **always** allowed
(local truth is never overridden by doc state — no lockout path), and the doc is
consulted only for peers *not* locally known, with a revocation gate. `peers.json`
remains a continuously-synced mirror for back-compat, downgrade safety, and
inspection. netdoc spawn/reconcile are **non-fatal** — any failure leaves the
daemon serving on `peers.json` exactly as before.

**Deliberately deferred — cross-host federation / network-wide membership.** The
"inviter offline" win across *multiple* hosts requires a shared namespace where a
peer admitted on host A is authorized on host B. That is a **network-wide
membership** model (a peer reaches *any* host), which is a security expansion over
today's per-host isolation. Shipping it without per-service access control would
let any network member reach every host's shell — so it is intentionally **coupled
to Phase 4's default-deny ACLs (#8)** rather than shipped in Phase 1. The
federation primitives exist (`NetDoc::read_ticket`, `Bootstrap::Import`,
`reconcile`'s per-host-ownership caveat) and are ready for that phase.

## Next-stage build plan — the role-based warren MVP ✅ *(shipped; default-on v0.6.32)*

All 8 steps below are implemented and validated (live multi-node TUN e2e
`tests/e2e/vpn-e2e.sh` — real ICMP over `hop/vpn/1`, role-gated, 0% loss — plus
the 53-test regression suite green). As of v0.6.32 the VPN data plane is
**default-on** with best-effort bringup: a TUN-creation failure or a
`100.64.0.0/10` conflict (e.g. a host already running Tailscale) only skips the
VPN — core access (exec/shell/transfer) is never affected. Opt out with
`HOP_VPN=0` / `vpn_enabled = false`; `HOP_VPN=1` forces past the conflict guard.
The 53-test regression suite runs in TUN-less containers, so its green run is the
standing proof that default-on degrades gracefully.

The next stage turns today's inert, opt-in VPN into a working role-driven warren:
**role unification + federation safety + role→ACL derivation + a live multi-node
TUN e2e.** These are interdependent (a member's reach across hosts needs both the
unified role and a safely-shared namespace), so they ship as one coherent stage,
sequenced so each step compiles and tests.

1. **Canonical role** (`hop-core`). Make `RoleDefinition` the one role type: add
   `ports` (default all) for reach; `admin: bool` is the auth tier (subsumes
   `Creator`). Seed a least-privilege **`member`** role (no tags, default-deny).
   Add `default_role` to the warren config (doc `network/config`, default
   `member`). Peer entries carry a role **name**; `PeerRole` becomes a thin compat
   shim (`Creator`↔admin, `Peer`↔default) during migration.
2. **Invite by role** (`hop-cli` + proto). `hop invite --role <name>`; `--creator`
   = sugar for `--role admin`; no `--role` → org default. Redeem stores the role
   name in the peer entry + doc.
3. **Host tags in the doc** (`hop-core`). Each host publishes its tags
   (`tag/<host_id>`); source from config / an install `--tag` flag; default
   untagged.
4. **Federation safety** (`hop-core`) — prerequisite for multi-node. Split **read
   vs write** capability (members get a read replica; membership/role/ACL writes
   need an Owner/Admin-signed capability), and make `reconcile`
   **ownership-scoped** (only revoke entries this host owns) so a shared namespace
   doesn't cross-revoke.
5. **Role→tag→ACL resolver** (`vpn::acl` + `netdoc`). Replace static `acl/policy`
   evaluation with: src IP → member → role → permitted tags+ports; dst IP → host →
   tags; allow iff dst tag ∈ role tags ∧ port permitted; default-deny. Reads
   membership/roles/tags from the replicated doc.
6. **Role elevation** (`hop-cli` + admin proto). `hop role grant/set <peer>
   <role>` updates the peer's role entry (peers.json + doc) → reconcile → ACL
   re-resolves network-wide, no re-invite.
7. **Configurable MagicDNS domain** (`hop-core`). Resolver reads the warren domain
   from `network/config` (default `<warren-name>.hop`, else `hop`) instead of the
   hard-coded `.hop`.
8. **Validation.** ✅ Unit: role→ACL resolution covers the deny path
   (`role_reaches` — wildcard, tag intersection, empty-role denies all;
   `role_derived_reach_via_doc`). **Live multi-node TUN e2e**
   (`tests/e2e/vpn-e2e.sh`, `NET_ADMIN` + `/dev/net/tun`): two federated nodes
   join one warren (host-b imports host-a's namespace ticket + redeems the admin
   creator invite); both enable the opt-in VPN; host-b pings host-a's virtual IP
   over the real `hop/vpn/1` TUN — role-gated forwarding (admin/`*` reach both
   directions), **0% packet loss**. The live harness exercises the allow path +
   the full data plane (TUN bringup, `100.64.0.0/10` routing, federation
   replication, MagicDNS vIPs); the tag-based deny path is covered by the unit
   tests above. Plus the existing 53-test regression suite green. Remaining
   follow-up: promote Phase 3-4 from experimental to default-on.

**Rollout order within the stage:** role unification + `member` default first
(auth-semantics change, guarded by the `peers.json` fallback so existing peers
are unaffected) → federation safety → ACL derivation (only affects the opt-in
VPN) → e2e → flip the VPN default-on once the live e2e is green.

## What stays the same

- iroh as transport; relay for NAT traversal (unchanged).
- ALPN-versioned protocols — add `hop/vpn/v1`, retain `hop/0..3`.
- Roles (Owner/Admin/Peer) and the capability/access-rule model.
- Single-use invite-token UX.
- All existing CLI commands and behaviors.

## Open risks

- **Doc-write spam** by a misbehaving authorized peer — rate-limit per author in
  replication; reject entries from non-role authors at *read/verify* time, not
  just write time (follows from #1's caveat).
- **Performance vs WireGuard/Tailscale** — per-packet QUIC overhead is real;
  fine at LAN-scale flows, noticeable at 10 Gbps. Set expectations; the
  differentiator is "works without central infrastructure," not raw throughput.
- **Accidental service exposure** — default-deny (#8) plus loud documentation;
  the ACL must fail closed.
- **Owner/org key loss** — addressed by #14, but must be a real product feature,
  not an afterthought; it's a deal-breaker for enterprise if hand-wavy.
