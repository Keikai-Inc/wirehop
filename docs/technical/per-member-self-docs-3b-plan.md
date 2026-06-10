# #3b Execution Plan — Read-Ticket Members + Full Self-State Isolation

> **For a fresh-context session.** Read `per-member-self-docs.md` (the design)
> first, then this (the execution). This is the final isolation flip for the C1
> write-isolation work. It touches the **auth/redeem path and the VPN data
> plane** — failure modes are **lockout** and **traffic interception** — so every
> phase must stay green on `bash tests/e2e/vpn-e2e.sh` (real packets under
> enforce) before committing, and the risky steps (write-drop, read tickets)
> come **last**, each behind a green e2e.

## Where things stand (shipped through 0.6.53)

- Per-member **self-doc** per node, created lazily, namespace persisted in
  `NetDocMeta.self_namespace` (`crates/hop-core/src/netdoc/mod.rs`). Sole writer
  is that node.
- **Announce**: `ClientMessage::AnnounceNetdocAuthor { author, self_doc }` →
  founder records `peer/N.netdoc_author` + `peer/N.self_doc` (read ticket).
  `Peer.self_doc` field exists (`config/mod.rs`). `member_self_doc(node_id)`
  lazily imports + caches a member's read-only self-doc.
- **Dual-write** (`put_self`): self-state (`vpn/ name/ tag/ posture/`) is written
  to BOTH the self-doc and the shared doc. `ip/` (`claim_virtual_ip`) is
  shared-only. So today the shared doc still holds everything (members hold
  **write** tickets).
- **Data-plane read override** (`refresh_vpn_peer_ips`): endpoint is read from the
  owner's self-doc, keyed by addr→owner from the **shared `ip/` table**. Proven by
  `refresh_prefers_self_doc_endpoint` + vpn-e2e.
- C1 enforce (author validation) remains as defense-in-depth.

**The gap:** members still write the shared doc, so they can't hold read-only
tickets, and the addr→owner authority is still the shared `ip/` table.

## Target model

- **Admin doc** (today's namespace): `peer/ role/ acl/ revocation/ network/` +
  **`peer/N.vip`** (admin-allocated, see below). Members hold a **read** ticket.
- **Per-member self-doc**: `vpn/ name/ tag/ posture/` (and the member's endpoint),
  member is sole writer; everyone else read-only.
- **addr→owner authority = `peer/N.vip`** (admin-allocated at admission, recorded
  in the admin doc, admin-authored ⇒ validated under enforce). A member can only
  set its own endpoint *for the addr the admin gave it* — it cannot claim
  another's addr. The vIP is **static** (allocated once) so the member still
  self-updates its dynamic endpoint with **no admin online**.

## ✅ EXECUTION COMPLETE

All four phases shipped; the shared `vpn/` write is dropped and read-ticket
members route end-to-end under enforce, including the no-admin-online guarantee
(`vpn-e2e` green: VPN E2E + REBOOT + READ-SCOPE + READ-MEMBER ROUTING +
NO-ADMIN-ONLINE; 53/53 regression; full unit suite + clippy clean). The
"convergence blocker" turned out to be two concrete bugs, not a sync problem —
see `per-member-self-docs.md` for the root-cause story (missing vip on
redemption-admitted members; accept-only datagram pump). History below retained
for reference.

## Execution status (historical)

- **Phase 1 — DONE** (commit `#3b Phase 1`): `Peer.vip` + trust-anchor allocates
  in `reconcile` + founder self-reg vip. Inert; unit-tested; vpn-e2e green.
- **Phase 2 — DONE** (`#3b Phase 2`): `refresh_vpn_peer_ips` + `lookup_vpn_endpoint`
  use `peer/N.vip` (addr→owner) + the owner's self-doc for the endpoint, shared
  fallback. Behavior-identical; egress unit test; vpn-e2e green.
- **Phase 3 — DONE except the physical drop** (`#3b Phase 3`): the model is
  interception-resistant + the `vpn/` forgery tests are rewritten for the
  self-doc model (incl. a 3-node adversarial `self_doc_blocks_endpoint_interception`).
  **The e2e gate caught that dropping the shared `vpn/` write outright BROKE live
  2-node routing** — the founder didn't converge on a member's endpoint from the
  imported self-doc. So the endpoint stays dual-written (self-doc preferred +
  shared fallback); interception is still blocked, only physical isolation defers.
- **⚠️ BLOCKER (gates the Phase 3 drop AND Phase 4):** harden **imported
  member-self-doc sync**. Symptom: founder→member self-doc content doesn't
  converge in time (the reverse works). Suspect: stale ticket addresses /
  imported self-docs aren't actively re-synced like the admin doc's
  `resume_sync(self.doc.start_sync(peers))`. Likely fix: a self-doc keepalive
  that `start_sync`s each imported member self-doc with the owner's current
  endpoint address (from discovery / the admin doc), and/or re-share the self-doc
  ticket after addresses stabilize. **Validate with vpn-e2e after dropping the
  shared write** (Phase 3 step 7) — only then is Phase 4 (read-ticket members,
  who can't write the shared fallback) safe.

## Phased execution (each phase: compile → unit tests → vpn-e2e → commit → release)

### Phase 1 — `peer/N.vip` allocation (additive, inert)
- Add `vip: Option<String>` to `config::Peer` (serde default; `self_doc:None`-style).
  Add `Peer { … }` literal updates (grep `self_doc: None` → mirror).
- In `NetDoc::reconcile` (netdoc:612) and the founder self-registration
  (netdoc:~1232, the `me` peer): when the trust anchor admits a peer, call
  `claim_virtual_ip(node_id)` (which probes + resolves collisions in the shared
  `ip/` table — keep that) and set `peer.vip`. Only the trust anchor allocates.
- Nothing reads `peer.vip` yet. Pure groundwork. **Gate:** unit test that the
  founder records `peer/N.vip` for an admitted member; vpn-e2e unchanged.

### Phase 2 — readers prefer `peer/N.vip` + self-doc (additive, behavior-identical)
- `refresh_vpn_peer_ips`: build `ip_owner` from **`peer/N.vip`** (admin doc) as
  the primary authority, *falling back* to the shared `ip/` scan for peers without
  a `vip` (old members). The self-doc endpoint override already keys off
  `ip_owner` — it now works off `peer.vip`.
- `lookup_vpn_endpoint(dst)` (netdoc:1377, the **egress** path): resolve
  `dst → owner` via `peer/N.vip`, then read the endpoint from that owner's
  **self-doc** (`member_self_doc`), falling back to the shared `vpn/` entry.
- Keep dual-write, so base and override agree → routing identical. **Gate:**
  vpn-e2e green (proves the new read path carries egress too); add a unit test
  resolving egress via a self-doc-only endpoint.

### Phase 3 — drop the shared self-state writes (the isolation; security-sensitive)
- `register_vpn_endpoint`, `register_name`, `register_host_tags`,
  `register_posture` → write **self-doc only** (drop the `self.doc` half of
  `put_self`; or make `put_self` self-doc-only). `claim_virtual_ip` stays
  shared **only on the admin** (it's the allocator); members no longer call it.
- **Rewrite the VPN forgery security tests** for the self-doc model and ADD
  adversarial interception tests:
  - `enforce_rejects_forged_vpn_entry`, `enforce_rejects_forgery_against_vouched_member`,
    `federation_replicates_vpn_registration` (netdoc tests) now set up the
    self-doc flow (member writes self-doc; founder records `peer/N.self_doc` +
    `peer/N.vip`; reader imports).
  - **New**: a member M cannot intercept victim V — M writing `vpn/<V.vip>` in
    M's OWN self-doc is ignored (reader reads `vpn/<V.vip>` from V's self-doc,
    owner from `peer/V.vip`); M cannot forge `peer/V.vip` (admin-owned, enforce).
- **Gate:** vpn-e2e green (routing carried solely by self-docs) + all interception
  tests pass. This is the step where a bug = interception; do not skip the
  adversarial tests.

### Phase 4 — node/warren-only invites carry READ tickets (#3b proper)
- The daemon currently embeds `net.write_ticket()` as the warren ticket
  (`main.rs:410`, `generate_invite_with_role` reads `netdoc.ticket`). For
  `InviteTier::Node`/`WarrenOnly`, embed `net.read_ticket()` instead; `Admin`
  keeps write. Persist a read ticket file alongside `netdoc.ticket`, or branch in
  `cmd_invite`/`stamp_invite_tier` by tier.
- A read-ticket member: imports the admin doc read-only, redeems (founder records
  `peer/N` + allocates `peer/N.vip`), announces its self-doc ticket, self-writes
  its endpoint. It never writes the admin doc.
- **Gate — new multi-node e2e** (extend `vpn-e2e.sh` or a new script): a
  read-ticket member joins, routes under enforce, and **updates its endpoint with
  no admin/founder online** and stays reachable (the whole point — no admin
  coupling). Plus: the member cannot write the admin doc (verify a forged
  membership write from the member is rejected/ignored).

## Migration / back-compat (must hold)
- **Additive**: old (write-ticket, shared-doc) members keep working via the
  shared-doc fallbacks in Phases 2–3 until they upgrade. New members use
  self-docs + read tickets. Mixed-version warrens converge as nodes upgrade.
- **No lockout**: auth still falls back to local `peers.json`; the admin-doc read
  ticket still lets a member read membership. Never gate redemption on the vIP
  allocation succeeding (best-effort + retry, like the announce).

## Gates & rollback
- Per phase: `cargo test --workspace` + `cargo clippy --workspace` clean, then
  `bash tests/e2e/vpn-e2e.sh` (enforce + reboot) green, then the 53-test
  `REBUILD=1 ./tests/e2e/run.sh` for any proto/auth change (Phase 1, 4).
- Commit per phase; release per phase or per 2 phases. If a phase's e2e fails,
  the dual-write fallback (Phases ≤2) means reverting that phase restores routing.
- The dangerous phases are **3 (write-drop)** and **4 (read tickets + auth/redeem
  + the no-admin-online e2e)** — do them with fresh context, not at a session tail.

## Key files
- `crates/hop-core/src/netdoc/mod.rs` — `reconcile`, `claim_virtual_ip`,
  `register_vpn_endpoint`/`register_name`/`register_host_tags`/`register_posture`,
  `put_self`, `refresh_vpn_peer_ips`, `lookup_vpn_endpoint`, `member_self_doc`,
  the founder self-registration (`me` peer), and the netdoc tests.
- `crates/hop-core/src/config/mod.rs` — `Peer` (`+ vip`).
- `crates/hop-cli/src/main.rs` — `cmd_invite`/`stamp_invite_tier` (read vs write
  ticket by tier), creator-invite augmentation (`main.rs:410`).
- `crates/hop-core/src/invite/mod.rs` — `generate_invite_with_role` (ticket).
- `tests/e2e/vpn-e2e.sh` — extend for the read-ticket / no-admin-online case.
