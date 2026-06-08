# Install Model & Invite Capability Tiers (Design)

> **Status: Design / Planned.** This specifies a unified install convention and
> an explicit invite-capability model. None of it is implemented yet. It is
> sequenced against the C1 warren write-authorization work in
> [security-audit.md](security-audit.md); see [§7 Sequencing](#7-sequencing).

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
