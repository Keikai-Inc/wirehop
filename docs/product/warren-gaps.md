# Warren — Gap Analysis (living)

Consistency review of the product docs against each other and the implementation,
updated after the **"decentralization, not minimalism"** decision (hop's
guarantee is *no central control plane / no third party*; a per-member daemon is
intentional). See [warren.md](warren.md) and
[../technical/p2p-network.md](../technical/p2p-network.md).

Status legend: ✅ resolved by decision · 📝 doc fix needed · 🔧 open technical work.

## ✅ Resolved by the decentralization decision

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

## 📝 Doc honesty fixes still needed (warren.md describes unbuilt things in present tense)

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

## 🔧 Open technical work (now well-defined — this *is* the roadmap)

- 🔧 **The experimental VPN passes zero traffic.** ACL is default-deny and there
  is no way to set a policy (Rust method only). *Fix:* derive the ACL from
  roles×tags (M1) so it opens automatically by role. Until then `HOP_VPN=1` = on
  the fabric, everything blocked.
- 🔧 **Members get a *write* ticket → any member could rewrite membership/ACL.**
  The reconciliation says writes must be Owner/Admin-capability-gated and members
  get a **read** replica. *Fix:* split read vs write capability in the
  invite/join path. (Prerequisite for safe federation.)
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
- 🔧 **Role-system merge.** Collapse `PeerRole` + `RoleDefinition` into one named
  role; add the configurable least-privilege org-default (`member`); add
  `hop role grant/set` for post-invite elevation. Prerequisite for M1.

## Triage

1. **Already decided (just land the doc edits):** the ✅ block — positioning,
   control-plane semantics, daemon/root model.
2. **Make the docs honest (small edits):** the 📝 block — so warren.md describes a
   buildable system and matches seeded roles + live DNS.
3. **Build, in order:** role-system merge → M1 (role→ACL derivation) → read/write
   capability split + ownership-scoped reconcile (M2) → receiver-side ACL +
   fleet-state migration. These are the genuine engineering items, now with their
   sharp edges named.
