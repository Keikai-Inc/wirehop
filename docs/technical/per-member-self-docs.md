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

**Remaining (the final isolation flip):**
7. **Drop the shared-doc `vpn/` write** (`register_vpn_endpoint` → self-doc only)
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
