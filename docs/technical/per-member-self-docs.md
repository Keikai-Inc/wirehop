# Per-Member Self-Documents (Warren write-isolation, C1)

> **Status: design + in-progress.** This is the chosen remediation for the
> warren's write-open trust model (C1) — see
> [install-and-invite-tiers.md §10](install-and-invite-tiers.md) Phase 0b. It
> supersedes the "read-ticket members + admin-writes-on-behalf" approach.

## Motivation

Today the warren is **one iroh-docs namespace every member can write** (members
hold a *write* `DocTicket`). So any member can forge any entry — another member's
`vpn/`/`ip/`/`name/` registration (traffic interception, vIP theft, MagicDNS
spoof), or a `peer/`/`role/` membership grant. The shipped C1 *enforce* model
validates reads after the fact (author must match a vouched binding), which works
but is detect-and-reject, not prevent.

Two ways to actually prevent it were considered:

1. **Read-ticket members + admin-writes-on-behalf.** Members get read tickets and
   can't write; an admin writes their state for them. **Rejected** — it couples a
   member's VPN-reachability to an admin being online (a member's endpoint is
   dynamic; every change needs an admin to write it).
2. **Per-member self-documents** (this design). Each member owns its own
   namespace and is the *only* writer. Forgery is **physically impossible** (no
   write key for anyone else's doc) and there is **no admin-online coupling**.

## Model

Two document classes:

| Doc | Writers | Holds | Others get |
|---|---|---|---|
| **Admin doc** (today's namespace) | founder + vouched co-admins | `peer/ role/ acl/ revocation/ network/` + `peer/N.self_doc` | **read** ticket |
| **Per-member self-doc** (one namespace per member) | that member only | `ip/ vpn/ name/ tag/ posture/` | **read** ticket |

Capability = write scope (the tier split done physically, not by policy):
- **admin** → write the admin doc.
- **node / warren-only** → write only your own self-doc.
- **client** → no warren docs at all.

## Trust + discovery (reuses the shipped announce)

1. A member creates its self-doc namespace at first run and persists its id.
2. On `hop host` startup it announces its self-doc **read ticket** to an admin
   over the authenticated session — the `AnnounceNetdocAuthor` channel
   (`crates/hop-cli/src/main.rs`) generalized to also carry `self_doc`.
3. The admin (trust anchor / vouched admin) records `peer/N.self_doc =
   <read_ticket>` in the **admin** doc — admin-authored, so it's trusted, exactly
   like the existing `peer/N.netdoc_author` binding (`record_peer_author` →
   `record_peer_self_doc`).
4. Every node reads `peer/N.self_doc` from the (trusted) admin doc and imports N's
   self-doc **read-only** to learn N's vIP/endpoint/name/tags.

Because the self-doc ticket is recorded by an admin and the self-doc is writable
only by N (cryptographic namespace key), no other member can publish or alter N's
self-state. The C1 self-key *enforce* logic stays as defense-in-depth for the
shared-doc fallback during migration.

## Sync — lazy / on-demand (decision)

Each node always syncs the **admin doc**. It imports + syncs a **member's
self-doc on first need** (the first time it must resolve that member's
endpoint/vIP), then caches the open `Doc`; eviction on revoke. Cost is
O(peers-you-actually-reach), not O(warren) — reach is sparse.

## Global lookups across per-member docs

Per-addr / per-node reads are easy (you know which member you're reaching →
import their self-doc). The one reverse lookup is **MagicDNS `name → addr`**:
resolve `<name>.hop` by finding the admin-doc `peer/` whose host name matches →
that peer's `self_doc` → its `vpn/`/`ip/` → the vIP. (The admin doc already
carries each peer's name, so no extra index is needed.) During migration, fall
back to the shared-doc `name/` table (author-validated) when a member has no
self-doc yet.

## Migration (additive — decision)

- A member writes self-state to its **self-doc** once it has one; readers prefer
  the self-doc and **fall back** to the shared-doc self-keys when absent.
- The shipped self-key *enforce* (`refresh_vpn_peer_ips`, `lookup_name`) stays on
  for shared-doc entries during the overlap. Remove it only once self-docs are
  universal.
- No flag-day: old warrens keep routing on shared-doc self-keys; self-docs take
  over as nodes upgrade.

## Implementation status

**Shipped (infrastructure + mechanism):**
1. ✅ **Retain `Docs`** in `NetDoc` (`spawn`/`spawn_inner`) for runtime
   `create`/`open`/`import` of namespaces.
2. ✅ **Self-doc lifecycle**: each node creates-or-opens its own self-doc;
   namespace id persisted in `NetDocMeta.self_namespace`.
3. ✅ **Dual-write** (`put_self`): self-state (`vpn/ name/ tag/ posture/`) is
   written to the self-doc AND the shared doc, so the unchanged shared-doc read
   path keeps routing while the self-doc path goes live (migration-safe).
4. ✅ **Announce + record**: `AnnounceNetdocAuthor` extended with `self_doc`
   (serde-default, back-compatible); the daemon announces its self-doc read
   ticket; `record_peer_self_doc` records `peer/N.self_doc` (trust-anchor-only,
   idempotent). Unit-tested (`member_self_doc_roundtrips`) + asserted in vpn-e2e.
5. ✅ **Lazy import + cache**: `member_self_doc(node_id)` resolves
   `peer/N.self_doc`, imports read-only on first reach, caches; `evict_member_self_doc`.

6. ✅ **Data-plane read override**: `refresh_vpn_peer_ips` now resolves each
   member's **endpoint** from its own self-doc, keyed by the addr it owns per the
   validated `ip/` table (so a member can only set its own endpoint — the
   addr→owner authority stays the validated `ip/` table, not the self-doc). The
   shared-doc scan remains the base for not-yet-upgraded members. Unit-tested by
   `refresh_prefers_self_doc_endpoint` (resolves an endpoint present ONLY in a
   self-doc); vpn-e2e still routes under enforce with the override live.

### The addr→owner authority (the key #3b decision)

Dropping *all* shared self-state writes (required so `node`/`warren-only` members
can hold **read-only** admin-doc tickets) means the **addr→owner authority** must
leave the shared `ip/` table too. Two options:

- **Admin-allocated vIP (recommended).** When the admin admits a member it runs
  `claim_virtual_ip` (which probes + resolves collisions) and records
  `peer/N.vip` in the admin doc (admin-authored ⇒ trusted, validated under
  enforce). Readers take addr→owner from `peer/N.vip`; the member self-writes
  only its *endpoint* (`vpn/<peer.vip>`) in its self-doc. The vIP is **static**
  (allocated once at admission) so there's no ongoing admin-online coupling — the
  member still self-updates its dynamic endpoint with no admin involved.
- **Deterministic vIP.** Readers compute `deterministic_ip(node_id)`. Simple, no
  authority entry — but it **breaks under collisions** that today's probing
  resolves (two node_ids → same /10 slot), so a member's actual vIP can differ
  from the deterministic guess. Rejected unless paired with a collision registry.

`peer/N.vip` (admin-allocated) is the chosen direction: it preserves collision
handling, keeps the authority admin-validated (no interception — a member can't
claim another's addr), and adds no runtime coupling.

### ✅ The "convergence blocker" — root cause found (debug instrumentation)

Dropping the shared `vpn/` write initially **broke live 2-node routing** in
`vpn-e2e` and was twice halted by the gate. Debug-level instrumentation
(ingress-drop, refresh-override, egress-resolution, and self-doc-import markers)
showed it was **never a sync problem**: the founder imported the member's
self-doc, `start_sync` succeeded, content replicated, and the **ingress** map
converged. The break was **egress asymmetry**:

- `lookup_vpn_endpoint`'s self-doc path keyed *only* off `peer.vip`, and
  **redemption-admitted members never got a `vip`** — the auth path mirrored the
  peer with a direct `put_peer`, bypassing `reconcile` (the only place Phase 1
  allocated). The founder's own entry *did* have a `vip`, so member→founder
  resolved while founder→member returned UNRESOLVED — the founder received
  pings but could never address its replies.

**Fixes (all shipped together with the drop):**
1. `admit_peer` — one admission choke point (auth redemption **and** reconcile)
   that allocates `peer/N.vip` on the trust anchor.
2. `vip_owner` falls back to the **author-validated** shared `ip/` claim for
   legacy members with no `vip` (same rule as the refresh path — unforgeable).
3. Admin-authored `ip/` claims are accepted (the anchor claims on behalf at
   admission — that *is* the allocation mechanism).
4. `resume_sync` now derives its sync-peer list from `peer/N.self_doc` ticket
   addresses (membership), since the shared `vpn/` table no longer carries
   endpoints; the old `vpn/`-scan stays as a legacy source.

The earlier **active-sync hardening is kept** (`member_self_doc` always
`start_sync`s; `resync_member_self_docs` on both keepalives) — it's what makes
imported self-docs stay fresh; the vip gap was simply sitting in front of it.

A second break surfaced once egress resolved: the QUIC **datagram pump ran only
on the accept side**, so replies sent back over the connection a peer *dialed*
were silently discarded (no reader). Fixed by extracting `pump_vpn_datagrams`
and running it on dialed connections too, and by sharing live inbound
connections (`VpnConns`) so the outbound forwarder prefers a peer's fresh
inbound connection over a silently-dead cached dial (no CLOSE frame ever arrives
from a rebooted peer until the QUIC idle timeout).

## ✅ Status: COMPLETE (shared write dropped; read-ticket members shipped)

The shared `vpn/` write is **dropped** — a node's endpoint lives only in its
isolated self-doc. `node`/`warren-only` invites carry the admin doc's **read**
ticket (write reserved for `admin`); `enable_vpn` waits for the admin-allocated
`peer/N.vip` instead of self-claiming (read members can't write `ip/`);
`put_self`'s shared mirror is best-effort (read members have no write cap).

Proven end-to-end by `tests/e2e/vpn-e2e.sh` under enforce:
- founder↔member routing + reboot reconvergence (shared write gone);
- **READ-SCOPE**: a `--tier node` invite carries the read ticket;
- **READ-MEMBER ROUTING**: a read-ticket member (host-c) routes under enforce;
- **NO-ADMIN-ONLINE**: host-c re-registers its endpoint and keeps routing to
  host-b with the founder (host-a) stopped — the no-admin-coupling guarantee.

Remaining tidy-ups (non-blocking): `name/ tag/ posture/` still dual-write (their
read paths — MagicDNS, Cedar reach — haven't migrated to self-docs yet); the
shared-doc self-key *enforce* can be removed once self-docs are universal.

**Remaining (the final isolation flip):**
7. **Harden imported-self-doc sync** (active sync for `member_self_doc` docs), then
   **drop the shared-doc `vpn/` write** (`register_vpn_endpoint` → self-doc only)
   so the endpoint is physically isolated; migrate `lookup_vpn_endpoint` (egress
   resolution) to the self-doc; and rewrite the `vpn/` forgery tests
   (`enforce_rejects_forged_vpn_entry`, federation) for the self-doc model (a
   member can't intercept another's addr — the override ignores `vpn/<other>` in
   a member's self-doc). `name/ tag/ posture/` and `ip/` follow the same pattern
   (`ip/` stays shared for cross-node vIP-dedup until deterministic allocation).
8. **Tier ticket scope (#3b)**: `node`/`warren-only` invites carry the admin doc's
   **read** ticket (not write); `admin` carries write — safe once members write
   only their own self-doc.

> **Test note:** the eager per-node self-doc namespace adds gossip load that can
> make single-process, many-`NetDoc` replication tests flaky (>30s). Production
> (separate processes) converges fast (vpn-e2e). A clean fix is **lazy** self-doc
> creation — a pure client / non-VPN node shouldn't mint one. Tracked as a
> follow-up.
