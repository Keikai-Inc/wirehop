# Warren-First Fleet (Design)

> **Status: design.** Fleet management predates the warren (decentralized
> netdoc) model. The warren makes the **replicated document the control plane**,
> so most of fleet's central-orchestrator machinery is already superseded. This
> doc inventories what to delete, what to salvage, and a phased plan to reframe
> "fleet" as thin operations over the warren doc. Sequenced after the
> install/upgrade convention (`install-and-invite-tiers.md`).

## 1. The shift

Fleet was a **soft central control plane**: a "soft orchestrator" host
(`PeerRole::Creator`) holds the member registry (`fleet.json`), issues aggregate
invites (`aggregate_invites.json`), and hosts register *with* it
(`fleet_registrations.json`). Authority and state live on one host.

The warren inverts this: the **netdoc** (one replicated iroh-docs namespace per
warren) holds membership/roles/reach, every node has a full local replica, and
writes are **cryptographically capability-gated** by the founder anchor (C1).
There is no orchestrator and no master copy. `warren-gaps.md` already recorded
the decision: *"the orchestrator dissolves into the replicated document +
capability-based writes; its role definitions and role-based invites are kept
and extended, not its authority-holding position."*

So **fleet management stops being a subsystem** and becomes views + operations
over the warren doc, plus one issuer-local provisioning capability.

## 2. Already superseded — delete, don't port

| Fleet artifact | Warren replacement | State |
|---|---|---|
| `fleet.json` member registry (`FleetStore`, `fleet/mod.rs:33`) | `peer/<node>` entries, `NetDoc::list_peers()` — replicated to every node | shipped |
| `roles.json` role defs (`RolesStore`) | `role/<name>` entries, admin-authored, `list_roles()` | shipped (reconcile migrates) |
| role→tag reach ACL | Cedar `reach_engine()` / `vpn_reach_allowed()` from the doc | shipped |
| host naming / tags / posture | `name/`, `tag/`, `posture/` (per-member self-docs) | shipped |
| revocation, vIP allocation | `revocation/<node>`, admin-allocated `peer/N.vip` | shipped |
| `fleet_registrations.json` (host→orchestrator binding) | **obsolete** — a host is a warren node, not "registered with" an orchestrator | delete |
| `FleetMember.online` / `last_heartbeat` (`fleet/mod.rs:21`) | **dead** (no keeper code writes them); liveness derives from `peer.last_seen` / gossip | delete |
| orchestrator as authority | founder/admin author capability (C1 enforce) | shipped |

The 1,356-line `fleet/mod.rs` is mostly this superseded machinery.

## 3. Salvageable — the three things worth keeping

1. **The role model — the crown jewel.** `RoleDefinition` (`proto/mod.rs`)
   cleanly separates **reach** (`host_tags` → which hosts), **confinement**
   (`sandbox`, `network_only`), and **unix identity** (`sudo`, `groups`,
   `shell`, `user_mode`). It is already a netdoc citizen (`role/<name>`,
   admin-authored, replicated). Keep verbatim — it drives both VPN reach and
   session confinement and is the most valuable fleet artifact.

2. **Reusable / multi-use invites — the one capability warren invites lack.**
   Warren invites are single-use; fleet's genuinely useful idea is *one token →
   N hosts join with role X + tags*. Salvage the aggregate-invite design
   (Argon2-hashed reusable secret, max-uses, expiry; `fleet/mod.rs:237`) but make
   it **warren-scoped**: the token carries the warren ticket + role + tier; the
   reuse-count/expiry is tracked **on the issuer** (issuer-local provisioning
   state, *not* warren-replicated — redemptions aren't a warren-wide concern).
   This also completes the per-host issuance currently stubbed at
   `fleet/mod.rs:780` (`install-and-invite-tiers.md` Phase 2).

3. **Bulk operations — `fleet exec` / `fleet list`.** Fan-out-to-a-group and
   filtered views are real operator value. Reframe as **selectors over the
   netdoc**: choose peers by tag/role from the replicated doc, fan out exec
   gated by the reach ACL. No orchestrator, no `fleet.json`.

## 4. Plan — `hop fleet` as verbs over the warren doc

Keep `hop fleet` as the namespace for multi-host operations (a good mental
model: *the set of warren hosts I can reach*), backed entirely by the netdoc.

- **P1 — Views as netdoc reads (✅ shipped first).** `hop fleet list` /
  `hop fleet status` show the replicated warren membership — no `fleet.json`, no
  orchestrator. **Mechanism:** the netdoc store is held exclusively by the
  daemon, and a *read* shouldn't require admin rights (membership is replicated
  to every node), so the daemon **exports a read-only snapshot**
  (`warren-members.json`, group-readable) every 30s + after each admin mutation
  (`fleet::export_warren_snapshot`, joining `list_peers` + `list_roles` +
  `list_virtual_ips` + `list_host_tags`). The CLI reads that file directly —
  the same pattern as the daemon already publishing `netdoc.ticket`/`relay_url`
  to files. Every node shows the same view. `hop ls` (Planned in warren-gaps)
  becomes this network-wide, role-filtered view.
- **P2 — Warren-native bulk exec.** `hop fleet exec <tag|role> -- <cmd>` selects
  peers from the doc and fans out over the existing exec path
  (`cmd_exec`/agent), reach-ACL gated. Replaces today's `KnownHostsStore.groups`
  fan-out (`main.rs` `fleet exec`) with doc-derived selection.
- **P3 — Reusable warren invites.** `hop invite --role ci --tier node
  --max-uses N --expiry 24h` → one token N hosts redeem to join the warren as
  nodes with role `ci`. Completes the stubbed aggregate issuance; this is
  "provision a fleet," warren-first. Issuer tracks redemptions in a small
  local store (successor to `aggregate_invites.json`, but warren-scoped).
- **P4 — Retire the orchestrator files.** Delete `fleet_registrations.json`,
  demote `fleet.json` to removed/fallback, drop the dead heartbeat fields. The
  orchestrator authority is already gone (C1). Keep `roles.json` as the
  git-committable IaC source that reconciles into the doc.

## 5. Liveness without heartbeats

Fleet's `online`/`last_heartbeat` were never wired. In a warren, liveness is
cheap and local: a peer's `last_seen` (already in the netdoc peer entry) plus
iroh gossip/sync liveliness. `hop fleet status` can mark a peer "active" from
the most recent of (self-doc update, sync activity) without any heartbeat
keeper or central collector.

## 6. Files

- **Reuse:** `netdoc/mod.rs` reads (`list_peers`, `list_roles`,
  `list_virtual_ips`, `list_host_tags`, `list_posture`, `reach_engine`,
  `lookup_name`); `RoleDefinition` (`proto/mod.rs`); the role seeds
  (`fleet/mod.rs::seed_defaults`).
- **Rewrite:** the `hop fleet` command handlers (`main.rs`) to read the doc;
  `FleetAction` / admin `fleet-*` in `cli.rs`.
- **New (P3):** a reusable-invite issuer store (warren-scoped, issuer-local),
  successor to `AggregateInvitesStore`; extend `InviteToken` reuse semantics.
- **Delete (P4):** `FleetStore` / `FleetMember` registry, `FleetRegistrationsStore`,
  the dead online/heartbeat fields.

## 7. Migration & safety

- P1/P2 are additive reads — no data migration, no lockout risk.
- P3 keeps single-use invites working; reusable is opt-in via `--max-uses`.
- P4 removes files only after their data has a doc-backed replacement; keep
  `roles.json` as the human-authored reconcile source. Gate any removal behind a
  version so a mixed-version warren doesn't lose `hop fleet` reads.
