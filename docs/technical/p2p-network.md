# Peer-to-Peer Private Network (Design)

> **Status: Design / Planned.** Nothing in this document is implemented yet. It
> captures the agreed architecture and the decisions behind it so implementation
> can proceed in phases. Sections marked **(Commercial, deferred)** are planned
> for later phases and are documented here only so the schema and trust model
> don't have to be reworked when we get there.

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
| **3. VPN packet plane** ⚙️ *(opt-in/experimental)* | TUN/utun (#6), `hop/vpn/1` over QUIC datagrams (#5), daemon-to-daemon forwarding, federation via write ticket. Off by default (`HOP_VPN=1`). | Actual P2P LAN reachability. |
| **4. DNS + ACL** ⚙️ *(opt-in/experimental)* | MagicDNS resolver for `*.hop` (#7); default-deny userspace ACL filter on the forwarding path (#8). Active only with the opt-in VPN. | Friendly names + safe service exposure. |
| **5. Commercial control plane** | Pluggable org-key trust root (#9), short-lived credentials (#4), user/device split already in place (#10), group/tag ACLs (#8/#10). | Strict, provable revocation for businesses. |
| **6. Enterprise integration** | IdP bridge (#11), data-plane audit export (#12), network-lock co-signing (#13), key custody/recovery (#14). | SSO, SOC 2, key safety. |

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
