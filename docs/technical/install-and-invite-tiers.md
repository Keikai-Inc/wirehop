# Install Model & Invite Capability Tiers (Design)

> **Status: in progress, shipping incrementally.** This specifies a unified
> install convention and an explicit invite-capability model. Decisions are
> resolved in [§8](#8-decisions-resolved); the file-level build plan is in
> [§9](#9-implementation-plan-code-level); **what has actually shipped (and what
> is deferred, with rationale) is tracked in [§10](#10-implementation-status-shipped-incrementally)**.
> As of 0.6.45: the C1 trust anchor + admin+self-key enforce (flag-gated, proven by a forged-entry test), the
> warren-only tier, the InviteTier model, and the self-upgrade consent flow are
> shipped; the embedded daemon installer, C1 self-key binding/read-ticket
> members, and signing remain dedicated follow-ups. Sequenced against the C1
> work in [security-audit.md](security-audit.md) (Phase 0).

## 1. Problem

Two things are tangled today:

1. **The website forces a client-vs-server guess.** The install page asks the
   user to decide up front whether this machine is a "client" or "on the
   warren" — a decision most users can't make before they understand the
   product, and one that isn't final anyway (a client that later wants to host
   re-runs the installer with `sudo`).
2. **Invites have only two effective tiers, and the wrong things are fused.**
   The only production site that attaches a `warren_ticket` is the **creator
   invite** (`crates/hop-cli/src/main.rs`, host-startup augmentation). So:
   - a regular `hop invite --role X` → **reach-only** (no warren ticket), and
   - a creator invite → **admin + warren node**, where the warren ticket is a
     **write** ticket (security-audit **C1**).

   The common "put this server on the mesh, but it is **not** an admin" case is
   inexpressible: the only thing carrying warren membership is the
   admin/write-capable creator invite. "Can join the warren" is fused to "can
   rewrite the whole warren."

## 2. Capability model — four tiers

Three orthogonal axes (plus confinement/identity modifiers that already exist):

| Axis | Grants | Needs the daemon (root)? |
|---|---|---|
| **session reach** | `hop <host>` shell / exec / transfer into a host | No — a pure client only initiates outbound sessions |
| **warren membership** | virtual IP, MagicDNS, L3 reach to services (role→tag ACL) | **Yes** — creating a TUN needs root (same as Tailscale/WireGuard) |
| **admin** | mint invites, grant roles, write warren state | Yes |

These are already separate gates in code: VPN L3 reach is `vpn_reach_allowed`
(Cedar), session access is peer-authorization in `auth/`. The model just makes
the split explicit and names the useful combinations:

| Tier | session reach | warren | admin | Daemon / sudo | Warren ticket |
|---|---|---|---|---|---|
| **client** (default) | ✅ (to invited hosts) | — | — | **No** | none |
| **warren-only** | — | ✅ (L3 to services per role) | — | Yes | **read** |
| **node** | ✅ | ✅ | — | Yes | **read** |
| **admin** | ✅ | ✅ | ✅ | Yes | **write** |

- **client** — the laptop/phone/CI that *connects to* hosts. No TUN, no daemon,
  no sudo. Reach scoped by the role's tags; confinement by the role's sandbox.
- **warren-only** — a corporate-VPN user: on the mesh, can reach
  `wiki.hop`/`jenkins.hop` per role, but **cannot** open a hop session into any
  box. Needs root locally only to make the tunnel.
- **node** — a server: on the mesh *and* reachable/hostable, but not an admin.
  This is the missing middle tier and the most common server case.
- **admin** — founds/administers the warren. The only tier with a **write**
  ticket.

The `read` vs `write` ticket distinction is the C1 remediation — see §7.

## 3. Personas → tiers

| Persona | Tier(s) |
|---|---|
| Founder / solo homelab | **admin** for themselves; **node** for their servers |
| Fleet operator | **admin** for self; **node** (aggregate) for servers; **client** for teammates |
| Teammate / contractor | **client**, scoped sandbox, optional TTL |
| AI agent / automation | **client**, tight sandbox |
| Worker / appliance box | **node** (mesh + reachable, not admin) |
| Corporate VPN user | **warren-only** |

Every persona maps to exactly one tier. That is the simple convention.

## 4. Invite encoding

Today the tier is *inferred* (warren_ticket presence + `PeerRole::Creator`).
Make it **explicit and minted by the inviter**, who knows the trust level.

Proposed `InviteToken` change (`crates/hop-core/src/invite/mod.rs`):

```rust
pub struct InviteToken {
    // … existing: node_id, secret, relay_url, username, host_name,
    //              role, role_name, sandbox …
    /// Explicit capability tier. Replaces inferring from warren_ticket/role.
    #[serde(default)]              // old invites → Client via Default
    pub tier: InviteTier,
    /// Warren join ticket. Scope follows the tier: a read-scoped membership
    /// ticket for Warren/Node, a write ticket only for Admin. `None` = Client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warren_ticket: Option<String>,
}

#[derive(Default)]
pub enum InviteTier { #[default] Client, WarrenOnly, Node, Admin }
```

`hop invite` flags (extend `cli.rs` `Invite`):

| Flag | Tier |
|---|---|
| *(none)* | `client` (reach-only — current default behavior) |
| `--warren` | `node` (mesh + session reach) |
| `--warren-only` | `warren-only` (mesh, no host sessions) |
| `--admin` | `admin` |

Flag names confirmed (decision 2): `--warren` / `--warren-only` / `--admin`.
`--creator` is kept as a **deprecated, hidden alias** for `--admin` so existing
scripts and the auto-generated `creator_invite` keep working.

`--role`, `--user`, `--read-only`, `--no-network`, `--scope`, `--allow-command`,
`--preset` continue to apply orthogonally (they shape reach/confinement/identity
*within* a tier).

**Backward compatibility:** old invites have no `tier` field → `Default` =
`Client`, but a decoder infers the effective tier for legacy tokens: `warren_ticket`
present + `PeerRole::Creator` → `Admin`; `warren_ticket` present → `Node`; else
`Client`. So existing creator invites keep working.

## 5. Install model — one install, self-upgrade

**There is one install.** Everyone runs the same command; it installs the binary
as a **client** into a **user-writable** dir (`~/.local/bin`) with **zero sudo**
(decision 7). A pure client only ever runs as the user, so a user-owned binary
has no escalation surface:

```
curl -fsSL https://hop.keikai.ai/install.sh | bash
```

"Server / warren / admin" is **not a separate install** — it's an **upgrade a
client performs on demand**, when it gains a capability that needs the daemon.

### Upgrade triggers
- Redeeming a `warren` / `warren-only` / `admin` invite.
- Running `hop host` (explicitly wanting to be reachable / on the mesh).

A **reach-only (client) invite never triggers an upgrade** — you redeem it and
stay a client.

### Self-upgrade flow (the important part — also the H10 fix)
1. **Decode + validate the invite as the unprivileged user.** No root yet.
   Verify the host identity, show the human-readable host name + the tier +
   which warren it joins.
2. **Reach-only?** Record the host in `known_hosts` / peer state. Done. **No sudo.**
3. **Node / warren / admin?** Prompt with concrete context:
   > `This will make <machine> a <tier> on warren "<name>" (<node-id prefix>).`
   > `That requires installing a system daemon (root). Continue? [y/N]`
   - **Yes** → escalate: install the system daemon under `sudo`, passing the
     already-validated ticket + role + tier. Bring up the daemon configured for
     the tier (VPN on for warren+, session-hosting for node+, admin role for
     admin).
   - **No / non-interactive** → **stay a client**, stash the validated join
     ticket (`netdoc-join.ticket`, `0600`), and print the exact command to
     finish later. Graceful — never a half-broken state.

This is precisely the **H10** remediation: the invite is decoded and the trust
decision is shown **before** any root is acquired, instead of today's
`sudo hop warren join <attacker-influenceable-invite>` which dials out as root.

### Binary location — the root-owned invariant (decision 7 security)

> **A root daemon must only ever execute a root-owned, root-only-writable
> binary. It must never run one from a user-writable path** (`~/.local/bin`,
> `~/bin`, …).

If the always-on root daemon ran a user-writable file, anything in that user's
account (a bug, a bad dependency, malware) could overwrite it and execute
arbitrary code **as root** on the next start — a privilege-escalation hole.

`~/.local/bin/hop` (zero-sudo) is fine for a **pure client** — it only ever runs
as the user. But the self-upgrade to a root daemon must **verify-then-promote**:

1. **Verify** the binary against the published release checksum/signature (this
   is the natural home for artifact signing, security-audit H9).
2. **Promote** the verified bytes into a root-owned path (`/usr/local/bin/hop`,
   `root:wheel`, `0755`) under the one upgrade-time `sudo`.
3. Point the LaunchDaemon/systemd unit at **that** path — never at `~/.local/bin`.

The upgrade never `sudo`s the user-writable binary; it verifies a clean copy and
lays it down root-owned. "Become a server" is a sudo moment anyway, so zero-sudo
applies only to the pure-client lifetime — which is correct.

### How the binary performs the privileged install
**Decision 1 — embedded.** A hidden `hop __install-daemon` subcommand drops the
LaunchDaemon plist / systemd unit from **embedded templates** and registers the
service. It runs from the **promoted, root-owned** `/usr/local/bin/hop` (per the
invariant above), invoked under the upgrade `sudo`. Rationale:
- No network round-trip for the *setup logic* (works offline / air-gapped).
- Runs a verified, root-owned binary — not the user-writable one.
- Testable in-process; one code path for macOS (launchd) and Linux (systemd).

(The verify-and-promote step in the invariant may fetch a fresh verified binary
from the CDN, or verify the local binary against the published `.sha256` and copy
it — either is fine; the small checksum fetch avoids re-downloading the whole
binary.)

### Keep the up-front path for automation
`--host` and the fleet `--register` (aggregate-invite) paths stay as the
**explicit, non-interactive** way to provision a known server in one shot —
that's the one place up-front sudo earns its keep (CI/provisioning can't answer
an interactive prompt). The website's old "Server" type becomes this shortcut,
not the default.

## 6. Website builder

- **Default: one command**, the client install. No client/server choice.
- **Optional "Paste your invite" field.** The command stays the same (client
  install); `hop` self-upgrades on redeem per the invite's tier. Nicety: the
  page can client-side decode the invite (base64 JSON) and *preview* the tier —
  "this invite will make this machine a **node** on warren *acme*."
- **Advanced disclosure:** "Provision as a server now (sudo)" → the explicit
  `install.sh --host …` / `--register` command for automation/known servers.
- **Copy fixes (do regardless):** remove every "VPN on by default" — the builder
  VPN label (`index.html:627`), the node hint (`:881`), the warren section
  (`:341`), and "joins your warren with its own virtual IP" (`:534`). The VPN is
  opt-in/off-by-default since 0.6.37.

## 7. Sequencing

**Security first (decision 5).** The C1 trust-model fix is Phase 0 — the tiers
are *born* on the read/write split, so we never ship an over-powered interim
"node" running on a write ticket.

- **Phase 0 — Close C1 (the keystone).** Read-scoped membership tickets vs. a
  write ticket reserved for admin; the doc enforces **author-validated writes**
  (a read replica cannot rewrite another node's `vpn`/`name`/`ip`/role entries).
  After this the warren is trustworthy and a "node, not admin" membership is a
  real, safe thing to grant. (Subsumes the deferred C1 work in
  [security-audit.md](security-audit.md); H1/H2/M6 collapse with it.)
- **Phase 1 — Tiers + unified install + self-upgrade (built on the secure base).**
  Add `InviteTier` to `InviteToken` (+ back-compat inference) and the `hop
  invite` flags; node/warren tiers issue **read** tickets, admin issues **write**.
  One-command zero-sudo client install; the self-upgrade flow with the
  verify-then-promote root-owned-binary invariant (§5) and `hop __install-daemon`
  (delivers the **H10** fix: decode-as-user → consent → escalate). Website
  rebuild: one command + optional invite-paste **tier preview** (decision 3) +
  the advanced "provision now" disclosure. **warren-only ships in this phase**
  (decision 4), including the role flag that **denies host sessions** while
  allowing L3 reach.
- **Phase 2 — Fleet + polish.** Aggregate/fleet invites carry an explicit tier;
  artifact signing wired into verify-then-promote (H9); any remaining
  warren-only / capability-preview refinements.

**Can land anytime (no trust-model change):** the website **copy fixes** — delete
every "VPN on by default" (`index.html:627/881/341/534`); the VPN has been
opt-in/off-by-default since 0.6.37.

## 8. Decisions (resolved)

| # | Decision | Resolution |
|---|---|---|
| 1 | Daemon-install mechanism | **Embedded** `hop __install-daemon` (offline-capable, runs the verified root-owned binary). |
| 2 | Invite flag names | **`--warren` / `--warren-only` / `--admin`**; `--creator` kept as a deprecated hidden alias. |
| 3 | Website previews the invite tier? | **Yes** — decode the token **in-browser only** (no network, read-only). |
| 4 | Ship `warren-only` in v1? | **Yes** — in Phase 1, with the session-deny role enforcement. |
| 5 | Order vs. the C1 security fix | **Security first** — C1 is Phase 0; tiers/install build on it. |
| 6 | Self-upgrade default + keep up-front for automation | **Confirmed** — client-first for humans; `--host`/`--register` stay for non-interactive provisioning. |
| 7 | Client binary location | **`~/.local/bin`, zero sudo** for the pure client — **but** the root daemon must run a **verified, root-owned** binary, so self-upgrade *verifies-then-promotes* to `/usr/local/bin` (§5 invariant). |

Remaining to confirm before building Phase 1: exact `InviteTier` wire shape and
whether the verify-then-promote step re-fetches the binary or checksum-verifies
the local one (both acceptable; pick when artifact signing lands).

---

## 9. Implementation plan (code-level)

Grounding facts from the current code (`crates/hop-core/src/netdoc/mod.rs` unless
noted):
- `read_ticket()` (`ShareMode::Read`) and `write_ticket()` (`ShareMode::Write`)
  **already exist**; today every invite ships the **write** ticket.
- The doc author is **per-host** (`docs.author_default()`, stored as
  `NetDoc::author`); the netdoc endpoint key is derived from the host secret
  (`net::derive_netdoc_secret_key`), so it's stable across restarts.
- `iroh_docs::Entry` exposes `.author()` (iroh-docs 0.97) but the read path
  (`decode_entry`/`list_prefix`, `reconcile`, `resume_sync`,
  `refresh_vpn_peer_ips`, `list_virtual_ips`, `lookup_*`, `vpn_reach_allowed`,
  `get_peer`, `is_revoked`) **never checks it**.
- Doc keys: admin-owned → `peer/<node>`, `role/<name>`, `revocation/<node>`,
  `acl/cedar`, `network/domain`; self-owned → `vpn/<addr>`, `ip/<addr>`,
  `tag/<node>`, `posture/<node>`, `name/<n>`.
- Federated joiners already **don't** self-write `peer/<node>` — the inviter
  writes it (`enable_vpn` self-registers only when `!self.federated`).

### Phase 0 — Close C1

The exploit (a member forging `vpn/<victim>` etc.) is closed by **validating the
author on read**; read-only tickets are the follow-on hardening.

**0a — Author-validated reads (closes the exploit; keep write tickets for now).**
1. *Identity binding.* Add `netdoc_author: Option<String>` (and `netdoc_node`)
   to the `Peer` doc entry (`config`/`proto` Peer type) and to the redeem
   handshake. The redeem already runs (`cmd_warren` → `cmd_exec` to the inviting
   host, consumed in `auth/mod.rs`); extend the client→host auth message to carry
   the joiner's **netdoc** NodeId/author, and have the inviting host record it
   when it writes the admin-authored `peer/<node>` (`put_peer`). The admin is
   vouching: "node N's doc author is A_N."
2. *Admin author set.* The namespace **creator's** author is the root admin
   (it created the namespace). Persist the admin author set in an admin-authored
   `admin/<author>` entry; v1 = just the founder, with room to promote co-admins
   later. Expose `NetDoc::is_admin_author(&AuthorId)`.
3. *Central validator.* Add `fn entry_author_ok(key: &[u8], value_node: Option<&str>, author: &AuthorId) -> bool`:
   - admin keys (`peer/ role/ revocation/ acl/ network/ admin/`) → `is_admin_author`.
   - self keys (`vpn/ ip/ tag/ posture/ name/`) → `author == vouched_author_for(owning_node)` **and** the owning node matches the admin-authored ownership (`ip/<addr>`→node, `peer/<node>` exists). Unknown/unbound author → reject.
   Call it in `decode_entry`/`list_prefix` and each consume site listed above;
   **ignore** (don't act on) entries that fail. Log at `debug`.
4. *Tests* (netdoc, two authors): a `vpn/<victim>` written by a non-owner author
   is ignored; a legit self-entry passes; a `peer/`/`role/` from a non-admin
   author is ignored; revocation by a non-admin is ignored.

**0b — Read-ticket members (remove the write capability).**
5. Invites for the **node / warren-only** tiers carry `read_ticket()`; **admin**
   carries `write_ticket()`. (Change the `main.rs` creator-invite augmentation +
   `generate_invite_with_role` to pick the ticket by tier — depends on 1a.)
6. Members can no longer self-write `vpn/ ip/ tag/ posture/ name/`. Replace with a
   **node-announce**: on join and periodically, the member sends its endpoint /
   desired tags / posture / name to an admin over an authenticated RPC; an admin
   writes the (now author-valid) entries. vIP allocation moves admin-side
   (`claim_virtual_ip` keyed by the member's node, written by admin). This is the
   larger change; 0a already makes the warren safe, so 0b can land second.

**Migration (important):** existing warrens have self-authored entries with no
admin-vouched binding. On upgrade, run a one-time **founder re-vouch**: the admin
writes `netdoc_author` bindings for every current `peer/<node>`, and a bounded
**grace window** accepts unbound self-entries (with a warning) until bindings
replicate. Gate the strict-reject behavior behind a version flag in
`network/config` so a half-upgraded warren doesn't partition.

Files: `netdoc/mod.rs` (validator + read sites + ticket selection + announce
writes), `proto/mod.rs` + `config/mod.rs` (Peer binding fields, announce msg),
`auth/mod.rs` (record binding on consume), `main.rs` (ticket-by-tier).

### Phase 1 — Tiers + unified install + self-upgrade + warren-only + website

**1a — `InviteTier` in the wire model.** Add to `invite/mod.rs`:
```rust
#[derive(Default, Serialize, Deserialize)]
pub enum InviteTier { #[default] Client, WarrenOnly, Node, Admin }
```
field `tier: InviteTier` on `InviteToken` (`#[serde(default)]`); legacy decode
inference (`decode_invite`): warren_ticket+Creator→Admin, warren_ticket→Node,
else Client. `hop invite` flags (`cli.rs` + `cmd_invite`): `--warren`,
`--warren-only`, `--admin` (+ hidden `--creator` alias → Admin). Ticket scope
follows tier (read vs write, from 0b).

**1b — Self-upgrade install.**
- New hidden subcommand `hop __install-daemon` (`cli.rs` + `main.rs`): embed the
  LaunchDaemon plist (`pkg/com.hop.daemon.plist`) and systemd unit
  (`pkg/hop.service`) as templates via `include_str!`; write/`chown`/enable the
  service; apply primers (`vpn on/off`, tags, default_role); write
  `netdoc-join.ticket`; start. One Rust path replacing `install-daemon.sh`'s
  platform logic.
- **Verify-then-promote** (the §5 invariant): before installing the service,
  verify the running binary against the published checksum and copy it to
  root-owned `/usr/local/bin/hop` (`root:wheel 0755`); point the unit there.
- Redeem/`hop host` self-upgrade (`cmd_warren`, `cmd_host`): decode the invite
  **as the user**, show host identity + tier + warren; if the tier needs the
  daemon, prompt and run `sudo hop __install-daemon …`; on decline/non-interactive,
  stash `netdoc-join.ticket` (0600) + print the finish-later command. (This is
  the **H10** fix.)
- `install.sh`: default `INSTALL_DIR=~/.local/bin` (zero sudo, decision 7); keep
  `--host`/`--register` as the explicit up-front path (now invoking
  `hop __install-daemon` after the binary lands).

**1c — warren-only enforcement.** Add `network_only: bool` to `RoleDefinition`
(`proto/mod.rs`); when set, `auth/mod.rs` refuses `RequestShell*/Exec*/Transfer`
for that role (returns a clear error) while the VPN L3 ACL (`vpn_reach_allowed`)
still applies. Seed a `warren-only` default role (`fleet/mod.rs::seed_defaults`).

**1d — Website** (`site/index.html`): default to one client command; optional
invite paste → **in-browser** `decode_invite` (base64 JSON) → preview tier;
"Advanced: provision as a server now (sudo)" disclosure; **delete** the "VPN on
by default" copy at lines 341, 534, 627, 695, 881.

Files: `invite/mod.rs`, `cli.rs`, `main.rs`, `proto/mod.rs`, `auth/mod.rs`,
`fleet/mod.rs`, `install.sh`, `pkg/*` (templates), `site/index.html`.

### Phase 2 — Fleet + signing

- Aggregate invites carry an explicit `tier`; complete the per-host invite
  issuance the redemption handler currently stubs (`fleet/mod.rs`
  `RedeemAggregateInvite`). `--register` maps to the Node tier.
- Wire **artifact signing** (minisign/cosign) into verify-then-promote and the
  release script (closes H9); the self-upgrade then checks a signature, not just
  a co-located hash.

### Test & rollout

- **Unit:** author-validator (forged vs legit, admin vs non-admin); `InviteTier`
  inference + encode/decode round-trip; `hop __install-daemon` templating
  (render plist/unit to a temp dir, assert contents); `network_only` session
  refusal.
- **e2e (`tests/e2e/`):** extend `vpn-e2e.sh` with (a) a **forged-entry** test —
  a second node writes `vpn/<victim>` and the victim/others must ignore it; (b) a
  **warren-only** node that can ping a service vIP but is refused a shell; (c) a
  **self-upgrade** smoke. Add a **macOS** run for the daemon-install path — the
  one combination today's Linux-container e2e doesn't cover.
- **Back-compat:** old invites → Client; old creator invites → Admin; the
  migration grace window (above) keeps existing warrens from partitioning during
  the Phase 0 rollout.

### Risk register

| Risk | Mitigation |
|---|---|
| Author-binding migration partitions an existing warren | Version flag in `network/config` + bounded grace window accepting unbound entries with a warning; founder re-vouch on upgrade |
| `hop __install-daemon` is new platform code (launchd/systemd) | Port from the proven `install-daemon.sh`; unit-test template rendering; macOS + Linux e2e before release |
| Self-upgrade interactive sudo / half-states | Graceful client fallback (stash ticket, print finish command); never leave a partial daemon |
| 0b node-announce adds an RPC + admin write loop | Land 0a first (already closes the exploit); 0b can iterate without re-opening the hole |
| Read-validation in the per-packet path adds cost | Validate at reconcile/refresh time and cache the vouched-author map (reuse the existing reach-cache pattern), not per datagram |

## 10. Implementation status (shipped incrementally)

Built in safe, individually-released increments, security-first per decision 5.

| Piece | Status | Released |
|---|---|---|
| **Phase 1a** — `InviteTier` enum + field + legacy inference | ✅ shipped (inert; ticket-scope still legacy) | 0.6.40 |
| **Phase 0a** — C1 observe-mode author-stability detector | ✅ shipped (default `Observe`, log-only) | 0.6.40 |
| **Phase 0a** — C1 founder-author anchor (`founder_author` pinned in invites; persisted on join; recorded in `NetDoc`) | ✅ shipped | 0.6.41 |
| **Phase 0a** — C1 **admin-key enforce** (`peer/ role/ revocation/ acl/ network/` honored only from the founder author; complete across `list_prefix` + `get_peer`/`is_revoked`/`get_authored_policy`) | ✅ shipped, behind `HOP_NETDOC_VALIDATION=enforce` (default Observe) | 0.6.42 |
| **Phase 1c** — warren-only tier (`network_only` role flag + session-dispatch refusal + seeded `warren-only` role) | ✅ shipped | 0.6.42 |
| **Phase 0a** — C1 **self-key enforce LOGIC** (`Peer.netdoc_author` binding + `vouched_authors` + `vpn/`/`ip/` validated against the owner's vouched author in `refresh_vpn_peer_ips`; `self_entry_author_ok` unit-tested) | ✅ logic shipped, flag-gated; founder self-vouches | 0.6.44 |
| **Phase 0a** — C1 **member-node binding** (`AnnounceNetdocAuthor` daemon-outbound announce → founder records `peer/N.netdoc_author`; `record_peer_author` trust-anchor-only + idempotent; unit-tested by `enforce_rejects_forgery_against_vouched_member`; **multi-node enforce e2e** runs both nodes under `HOP_NETDOC_VALIDATION=enforce` + asserts the binding) | ✅ shipped | 0.6.46 |
| **Phase 0a** — C1 **vouched-admin-authors** (`admin_authors` = founder ∪ founder-vouched co-admin authors; `validate_entry` honors admin keys from any vouched admin; refreshed at startup / on vouch / on keepalive; unit-tested by `enforce_honors_vouched_co_admin_peer_entry`). Makes opt-in enforce safe for federated multi-admin warrens | ✅ shipped, flag-gated | 0.6.47 |
| **Phase 1b** — self-upgrade **consent** on `hop warren join` (decode-as-user → consent → reuse proven installer; the **H10** fix) | ✅ shipped | 0.6.43 |
| **Phase 1 (decision 7)** — `install.sh` default client install → `~/.local/bin` (zero-sudo); existing `/usr/local/bin/hop` updated in place; `--host` promotes to root-owned `/usr/local/bin`. `--site-only` now redeploys `install.sh` too | ✅ shipped | site deploy |
| **Phase 1d** — website builder **invite tier-preview** (client-side base64url-JSON decode → "joins host X as a node/admin/warren-only", auto-selects the node tier) | ✅ live | site deploy |
| **Phase 1a** — `hop invite --tier client\|warren-only\|node\|admin` (sets explicit `InviteTier`: client strips warren ticket, warren-only pins `network_only` role, admin → creator; warren tiers pin founder anchor). Ticket *scope* split still pending (Phase 0b) | ✅ shipped (capability tier) | 0.6.48 |
| **Phase 0a** — C1 `name/` self-key enforce (`lookup_name` drops a MagicDNS name authored by a non-owner; migration grace for unbound owners; `enforce_rejects_spoofed_name`) + 20 s co-admin-author refresh (`spawn_admin_author_refresh`) | ✅ shipped, flag-gated | 0.6.49 |
| Website "VPN opt-in" copy fixes | ✅ live | site deploy |

### Deferred — major subsystems needing dedicated, validated passes

Consistent with the rock-solid mandate (and how C1-full/H8/H10 were deferred
earlier): these are big enough that rushing them would risk lockout, data loss,
or a privilege-escalation hole. Each needs test infrastructure we don't have yet.

- **C1 enforce — production flip.** Both admin-key *and* self-key (`vpn/`/`ip/`)
  enforce **logic** is implemented, unit-tested, **and proven end-to-end by a
  two-NetDoc forged-entry test** (`enforce_rejects_forged_vpn_entry`: a member's
  forged `vpn/<founder_addr>` is honored in Observe, dropped in Enforce). Shipped
  flag-gated (default Observe). The founder self-vouches, so **the founder is
  fully protected under enforce today**.
  - **Member-node binding — SHIPPED (0.6.46).** `ClientMessage::AnnounceNetdocAuthor
    { author }`: on `hop host` startup (after `enable_vpn`, once it has its
    author) a federated node opens an authenticated session to the founder —
    whose main NodeId is persisted from the invite as `netdoc-founder.node` —
    over the **main** hop endpoint and announces its doc author. The founder,
    receiving it from authenticated peer N, calls `record_peer_author` which
    (trust-anchor-only, member-must-exist, idempotent) writes
    `peer/N.netdoc_author`. Best-effort with exponential backoff. The chosen
    design needs **no author-derivation migration**, so it can't break a live
    warren's membership. The multi-node e2e (`tests/e2e/vpn-e2e.sh`) now runs
    both nodes under `HOP_NETDOC_VALIDATION=enforce` and asserts host-a records
    the binding — bind → enforce → reconverge on a real warren. Until the
    announce lands a member's self-owned `ip/`/`vpn/` entries pass under
    migration *grace* (unbound owner), so enforce never partitions a fresh join.
  - `name/` self-keys are **enforced (0.6.49)**: `lookup_name` drops a MagicDNS
    name whose author isn't the vouched author of the node owning the vIP it
    points to (spoof), with migration grace for unbound owners. Unit-tested
    (`enforce_rejects_spoofed_name`).
  - **Vouched-admin-authors — SHIPPED (0.6.47).** `reconcile` runs on every node
    and writes `peer/`/`role/` entries authored by *that* node; on a federated
    multi-admin warren a co-admin legitimately authors admin keys. `validate_entry`
    now honors admin keys from the founder **or any founder-vouched co-admin
    author**: `admin_authors` = the founder ∪ the `netdoc_author` of every
    **founder-authored** `peer/` entry with the Creator role. Only the founder
    confers admin authority (the set is built from founder-authored entries
    only — no elevation, no validation cycle), refreshed at startup, on the
    founder's own vouch, and on each sync keepalive. Unit-proven by
    `enforce_honors_vouched_co_admin_peer_entry` (a co-admin's `peer/C` is
    rejected under enforce until B is vouched, then honored). Legacy warrens with
    no founder anchor honor admin keys unconditionally (never partitioned).
  - **The global default flip is the last, deliberately-gated step.** Opt-in
    enforce (`HOP_NETDOC_VALIDATION=enforce`) is now production-safe for **all**
    topologies: single-admin, federated multi-admin (vouched), and anchor-less
    legacy (honored). What still gates flipping `ValidationMode::default()` to
    `Enforce` globally is a *mixed-version* propagation window: on a warren where
    co-admins run pre-0.6.46 builds (can't announce) the founder can't yet vouch
    them, so during the upgrade their federated `peer/` entries would be rejected
    until every node is upgraded + announced (auth still falls back to local
    `peers.json`, so this is a transient loss of *federated* reach, never local
    access or a lockout). Prereqs for the flip: (a) a 3-node federated e2e
    (founder + vouched co-admin + a peer the co-admin invited, all under enforce);
    (b) the co-admin-author refresh is now **20 s** (0.6.49,
    `spawn_admin_author_refresh`, decoupled from the 300 s sync keepalive) so the
    window closes fast. The 3-node federated e2e is folded into the per-member
    self-doc migration harness (Phase 0b below).
- **Phase 0b — per-member self-documents: ✅ COMPLETE.** Each member owns its own
  iroh-docs namespace (sole write key) and self-writes its VPN endpoint there; the
  admin doc (write-restricted to vouched admins) keeps `peer/ role/ acl/
  revocation/ network/` + the admin-allocated `peer/N.vip` (addr→owner authority)
  and `peer/N.self_doc` read ticket. The shared `vpn/` write is **dropped** — the
  endpoint is now physically isolated (no shared copy any member could forge).
  `node`/`warren-only` invites carry the admin doc's **read** ticket (write
  reserved for `admin`); a read-ticket member self-writes only its own self-doc
  and waits for its admin-allocated `peer/N.vip` at bringup. **No admin-online
  coupling**: a member re-registers its endpoint with no admin up. Endpoint
  resolution (`refresh_vpn_peer_ips` ingress + `lookup_vpn_endpoint` egress) reads
  from the owner's self-doc keyed by `peer/N.vip`, with an author-validated `ip/`
  fallback for legacy members. Proven end-to-end under enforce (`vpn-e2e`):
  founder↔member + reboot with the shared write gone, read-ticket member routing,
  and the no-admin-online guarantee (founder stopped, member re-registers + still
  routes). Full details + the root-cause debug story in
  `docs/technical/per-member-self-docs.md`. Tidy-ups (non-blocking): `name/ tag/
  posture/` still dual-write until their read paths (MagicDNS, Cedar) migrate.
- **Phase 1b — embedded `hop __install-daemon` SHIPPED inert (0.6.53).** A hidden
  subcommand installs + starts the daemon from **embedded** launchd/systemd
  templates (`include_str!` of `pkg/com.hop.daemon.plist` / `pkg/hop.service`),
  root-required, no network round-trip. Template validity is unit-tested
  (`embedded_daemon_templates_present`). **Not yet wired into the self-upgrade**
  — `hop warren join` still uses the proven shell installer (`install.sh --host`)
  — because invoking this privileged path needs a **macOS daemon-install e2e**
  that doesn't exist on the dev host. Inert until that harness exists, then the
  upgrade flow swaps to it (verify-then-promote → `__install-daemon`).
- **Phase 1a — tier *capability* flag SHIPPED (0.6.48); read/write ticket
  *scope* still pending.** `hop invite --tier client|warren-only|node|admin` now
  sets the explicit `InviteTier`: `client` strips the warren ticket (can't
  self-upgrade), `warren-only` pins the `network_only` role, `admin` redeems as
  creator, and warren tiers pin the founder anchor. The read/write ticket *scope*
  split is now **done** (Phase 0b ✅): `node`/`warren-only` carry the admin doc's
  **read** ticket, `admin` keeps write.
- **Phase 2 — artifact signing (H9): plumbing SHIPPED, inert until keyed.**
  `release.sh` signs each artifact with a detached `openssl dgst -sha256`
  signature when `HOP_SIGNING_KEY` is set; `install.sh` verifies it against an
  embedded `HOP_PUBKEY`, failing closed. RSA-via-openssl (not ed25519) so the
  stock `openssl` on macOS LibreSSL can verify with no extra dependency.
  `scripts/gen-signing-key.sh` mints the keypair. **Inert until the operator
  generates a key, embeds the public key in `install.sh`, and releases with
  `HOP_SIGNING_KEY` set** — `HOP_PUBKEY` empty ⇒ checksum-only (today's
  behaviour, unchanged). Once the pubkey is embedded, every release must be
  signed (install fails closed on a missing/bad signature).
- **Phase 2 — fleet-invite tiers SHIPPED (0.6.52).** `hop admin <host>
  fleet-invite --tier client|warren-only|node|admin` carries an explicit
  `InviteTier` (default `admin` = legacy Creator behaviour, back-compatible via a
  serde-default `tier` field on `AdminRequest::CreateFleetInvite`). The handler
  maps tier→role before storing the pending invite and stamps the tier + founder
  anchor (+ client-tier warren strip), mirroring `hop invite --tier`. Unit-tested
  (`fleet_invite_tier_stamping`).

*Last updated: 0.6.49 (signing plumbing shipped unkeyed)*
