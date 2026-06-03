# Access Control: hop's warren vs. Tailscale

A technical comparison of how **hop** (the warren) and **Tailscale** decide who
can reach what — and, specifically, how each handles **capabilities**. Written
against hop's code (`crates/hop-core/src/vpn/acl.rs`, `netdoc/mod.rs`,
`fleet/mod.rs`) and Tailscale's current grants/ACL docs (linked at the end).

> **Terminology note.** "Capability" means two different things here. In
> Tailscale it means **application-layer capability grants** — structured JSON
> permission blobs handed to applications (the `app` field of a grant). In hop,
> `hop cap` is an unrelated **built-in automation** system (email triage, health
> monitors). hop has **no** equivalent of Tailscale's app-capability grants
> today; this document treats that as the headline difference.

## TL;DR

| Axis | hop (warren) | Tailscale |
|---|---|---|
| Policy location | **Decentralized** — in the replicated iroh-docs document; no coordinator | **Centralized** — one HuJSON tailnet policy file compiled + pushed by the coordination server |
| Unit of authorization | **Role** (named; carries reach + auth tier + OS sandbox) | **Rule** (`src → dst:port`) over users/groups/tags |
| Reach model | role `host_tags` → host `tags`, wildcard `*` or tag intersection | `src` list → `dst` list, per-port, per-proto |
| Default | **Default-deny** | **Default-deny** |
| Granularity | role↔tag (coarse) + optional static port-range rules | per-port/proto, autogroups, **device posture**, per-app capabilities |
| App-layer capabilities | **None** (gates at L3 + hop-session auth) | **Yes** — `app` capability grants delivered to apps (WhoIs / header) |
| Process confinement | **OS sandbox** (Seatbelt/Landlock) bound to the role | none (network-only; app capabilities are advisory to the app) |
| Identity source | invite-issued role (no IdP yet) | SSO/IdP users + synced groups |
| Enforcement | per-node, on the L3 VPN forwarding path | per-node packet filter (WireGuard), compiled centrally |

## hop's model — role → tag → reach, default-deny

**The role is the unit.** A `RoleDefinition` (`crates/hop-core/src/proto/mod.rs`)
carries everything about what a member is:

```rust
struct RoleDefinition {
    name: String,
    host_tags: Vec<String>,   // → network reach
    user_mode: UserMode,      // individual vs shared Unix account
    sudo: bool,
    admin: bool,              // can manage the warren
    groups: Vec<String>,      // Unix groups
    shell: Option<String>,
    sandbox: SandboxPolicy,   // → OS-level confinement of hop sessions
}
```

A **peer** carries a `role_name`; a **host** carries `tags`. Both live in the
replicated network document (`peer/`, `role/`, `tag/` keys).

**Reach is derived, not authored** (`vpn_reach_allowed` in `netdoc/mod.rs`). For
a packet `src_ip → dst_ip` on the VPN:

1. resolve `src_ip` → owning node → peer → `role_name` → `RoleDefinition`;
2. resolve `dst_ip` → owning host → its `tags`;
3. allow iff `role_reaches(role.host_tags, dst_tags)`:

```rust
pub fn role_reaches(role_tags: &[String], host_tags: &[String]) -> bool {
    if role_tags.iter().any(|t| t == "*") { return true; }      // wildcard
    role_tags.iter().any(|rt| host_tags.iter().any(|ht| ht == rt)) // intersection
}
```

Empty role tags → reaches nothing (the least-privilege `member` default).
Enforced **per packet on the forwarding path**, default-deny.

**Low-level primitive (not yet on the live path).** `vpn/acl.rs` also defines an
`AclPolicy` — an ordered, first-match-wins packet filter (`src`/`dst`/port-range/
`action` + a `default`), with `get_acl_policy`/`set_acl_policy` persisting it at
`acl/policy` in the doc. The design intent is that higher-level role→tag rules
compile down to this filter. **Today it is not consulted during forwarding** —
the live reach decision (`vpn_reach_allowed`, called per packet in the VPN
forwarding loop) evaluates `role_reaches` directly. So `AclPolicy` is a built,
replicable primitive awaiting wiring, not an active enforcement path.

**Two layers, set by one role.** hop separates:
- **Reach** (the network ACL above) — *can I connect at all?*
- **Confinement** (the OS sandbox — Seatbelt/Landlock) — *what may a hop
  session do once open?* (read-only, no-network, scoped paths).

A role carries both `host_tags` and a `sandbox`, so assigning one role sets reach
*and* confinement coherently. Tailscale has no analogue to the confinement layer.

**No coordinator.** The whole policy (roles, tags, membership, ACL) is CRDT state
replicated to every node and enforced locally. There is no central server
compiling or distributing it.

## Tailscale's model — central policy, src→dst, grants + capabilities

**One central policy file** (HuJSON), edited in the admin console / via GitOps,
compiled by the **coordination server** into a per-node packet filter and pushed
to every device.

**Building blocks:** `groups` (sets of SSO users), `tags` + `tagOwners` (non-human
device identities and who may assign them), `hosts`, and `autogroups`
(`autogroup:members`, `autogroup:admin`, `autogroup:self`, …). Identities come
from an **IdP** (users/groups synced via SSO).

**Classic ACLs** — network layer only:

```json
{ "action": "accept", "src": ["group:eng"], "proto": "tcp",
  "dst": ["tag:frontend:443"] }
```

**Grants (GA, the modern syntax)** — combine network *and* application layers in
one rule. Every grant has `src`, `dst`, and at least one of `ip` (network) or
`app` (capabilities):

```json
{
  "src": ["group:engineers"],
  "dst": ["tag:fileserver"],
  "ip":  [{ "action": "accept", "ports": ["443"] }],
  "app": {
    "tailscale.com/cap/drive": [
      { "shares": ["projects"], "access": "rw" },
      { "shares": ["archives"], "access": "ro" }
    ]
  }
}
```

**Application capabilities** are the key feature hop lacks. A capability is named
`{domain}/{path}` (e.g. `example.com/cap/billing`); its value is an **array of
arbitrary JSON config objects**. They're delivered to the destination
application via `tailscale whois`, the LocalAPI, or the `Tailscale-App-Capabilities`
HTTP header (through `tailscale serve`). The application then self-authorizes
using that structured grant — so authorization can be **fine-grained and
app-defined** (which file shares, which actions, which tenant) rather than only
"can this IP reach this port."

**Other gates Tailscale has:** per-proto rules, Tailscale SSH ACLs, and **device
posture** conditions (OS, client version, custom attributes) usable in `src`/`dst`.

## Side-by-side

**Distribution & trust.** This is the deepest difference. Tailscale's model
*depends on* a central coordination server to compile and authoritatively push
the policy — that's also its single trust root. hop's policy is **decentralized
CRDT state** with no coordinator; the trade-off is that hop has no central place
to atomically compile/validate a global policy, and (today) write-capability
gating is still the planned trust-root hardening.

**Expressiveness.** Tailscale is markedly more expressive: per-port/proto,
autogroups, posture, SSH rules, and especially **app-capability grants** for
application-layer authorization. hop's reach is coarse (role↔tag intersection,
plus optional static port ranges) and stops at L3 — services behind hop's VPN
authenticate their own clients; hop doesn't pass them a capability blob.

**The confinement axis is hop's, not Tailscale's.** hop binds an **OS-enforced
sandbox** (Seatbelt/Landlock) to the role, governing what a hop *session* can do
on the host. Tailscale's "app capabilities" are advisory data handed to an app;
hop's sandbox is kernel-enforced isolation of the process. They solve different
problems and could be complementary.

**Identity.** Tailscale derives identity from SSO/IdP (users + synced groups).
hop derives it from an invite that pins a role; there's no IdP integration yet
(it's on the commercial roadmap, tied to the trust root).

## What hop could borrow (gaps)

- **Application-capability grants.** A `role`/grant could carry a typed JSON
  capability map surfaced to services hop fronts (analogous to
  `Tailscale-App-Capabilities`), enabling app-level authorization instead of only
  L3 reach. This is the single biggest capability gap.
- **Port/proto in the derived path.** Reach is currently tag-level; folding the
  `AclPolicy` port ranges into the role→tag derivation would match Tailscale's
  per-port granularity without hand-authoring rules.
- **Autogroups & posture.** `autogroup:self`-style conveniences and device-posture
  conditions (OS/version/health) are absent.

## Where hop is structurally different (by design)

- **No coordinator / no central control plane** — the whole policy is replicated
  CRDT state. This is hop's defining guarantee; Tailscale's central compiler is
  exactly what hop omits.
- **Role = one decision for reach + auth tier + OS confinement** — Tailscale needs
  separate ACL rules, SSH rules, and (advisory) app capabilities; hop folds reach
  and kernel-enforced confinement into a single role.
- **Default-deny least-privilege member** out of the box, with reach that's stable
  across membership churn (role↔tag, not per-IP).

## Sources

- hop: `crates/hop-core/src/vpn/acl.rs`, `crates/hop-core/src/netdoc/mod.rs`
  (`vpn_reach_allowed`), `crates/hop-core/src/proto/mod.rs` (`RoleDefinition`),
  [warren.md](../product/warren.md), [p2p-network.md](p2p-network.md).
- Tailscale: [ACLs](https://tailscale.com/kb/1018/acls),
  [Grants](https://tailscale.com/kb/1324/grants),
  [Grants syntax](https://tailscale.com/docs/reference/syntax/grants),
  [Application capabilities](https://tailscale.com/docs/features/access-control/grants/grants-app-capabilities),
  [Policy file syntax](https://tailscale.com/docs/reference/syntax/policy-file),
  [Device posture](https://tailscale.com/blog/device-posture).

*Last updated: v0.6.35*
