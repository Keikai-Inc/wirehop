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
| `--admin` (replaces/aliases `--creator`) | `admin` |

`--role`, `--user`, `--read-only`, `--no-network`, `--scope`, `--allow-command`,
`--preset` continue to apply orthogonally (they shape reach/confinement/identity
*within* a tier).

**Backward compatibility:** old invites have no `tier` field → `Default` =
`Client`, but a decoder infers the effective tier for legacy tokens: `warren_ticket`
present + `PeerRole::Creator` → `Admin`; `warren_ticket` present → `Node`; else
`Client`. So existing creator invites keep working.

## 5. Install model — one install, self-upgrade

**There is one install.** Everyone runs the same command; it installs the binary
as a **client** (no sudo — one-time `sudo` only to write `/usr/local/bin`, or
none with `--dir ~/.local/bin`):

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

### How the binary performs the privileged install
**Recommended:** a hidden `hop __install-daemon` subcommand that drops the
LaunchDaemon plist / systemd unit from **embedded templates** and registers the
service, invoked by the parent `hop` via `sudo`. Rationale:
- No network round-trip at upgrade time (works offline / air-gapped).
- Uses the already-trusted local binary — no re-fetch of `install-daemon.sh`
  (avoids a fresh supply-chain + TOCTOU surface mid-upgrade).
- Testable in-process; one code path for macOS (launchd) and Linux (systemd).

**Lighter alternative (interim):** `hop` shells out to
`sudo bash <(curl … install-daemon.sh) …`. Less new Rust, but re-downloads and
depends on the network + CDN integrity at the worst moment. Use only as a
stop-gap.

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

Ordered so each phase ships independent value and the security-critical work is
isolated:

- **Phase 0 — Install UX + tier scaffolding (no security change).**
  One-command install + copy fixes on the site. Add `InviteTier` to
  `InviteToken` (back-compat inference for old invites) and the `hop invite`
  flags. Implement the self-upgrade flow + `hop __install-daemon` (this alone
  delivers the **H10** improvement: decode-as-user → consent → escalate). Node
  invites still carry today's write ticket for now.
- **Phase 1 — C1 read/write ticket split.** `node`/`warren-only` invites carry a
  **read-scoped** membership ticket; **write** is reserved for `admin`; the doc
  enforces author-validated writes (read replicas can't rewrite `vpn`/`name`/
  `ip`/role entries). This is what makes "node, not admin" *trustworthy* and
  closes C1 — building the tier system and fixing C1 are the same work.
- **Phase 2 — warren-only enforcement + fleet.** A role flag that **denies host
  sessions** while still allowing L3 reach (so `warren-only` truly can't `hop`
  into a box). Aggregate/fleet invites carry an explicit tier.

Rationale: Phase 0 is pure UX + a security *improvement* (H10) with no risky
trust-model change; Phase 1 carries the security weight (C1) and unlocks the
node-without-admin tier; Phase 2 completes warren-only and fleet coverage.

## 8. Open decisions

- Final CLI flag spelling (`--warren` vs `--node`; keep `--creator` as an alias
  for `--admin`?).
- Whether the website decodes the invite to preview the tier (nice, but the page
  then parses a token — keep it read-only/no-network).
- Whether `warren-only` ships in v1 or waits for Phase 2 (it needs the
  session-deny role enforcement to be meaningful).
- `hop __install-daemon` embedded templates vs. shelling to the installer — the
  spec recommends embedded; confirm before building.
