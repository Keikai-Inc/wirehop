# Device posture — gate reach on machine health

hop lets you require that a machine is **healthy** (disk encrypted, up to date,
firewall on) before it reaches sensitive parts of your network. Each host publishes
a signed "health card"; you write a policy that gates reach on it. Nothing central
is involved, and the default stays open until you opt in.

## What's collected

Every host self-attests these attributes on startup (best-effort on macOS + Linux;
a probe that can't run yields `unknown`, never an error):

| Attribute | Meaning | Values |
|---|---|---|
| `os` | operating system | `macos` / `linux` |
| `os_version` | OS version | e.g. `14.5`, `24.04` |
| `hop_version` | hop version | e.g. `0.9.17` |
| `disk_encrypted` | FileVault (macOS) / LUKS (Linux) on | `true` / `false` / `unknown` |
| `firewall` | application/host firewall on | `true` / `false` / `unknown` |
| `screen_lock` | password-on-wake configured | `true` / `false` / `unknown` |

These are published to the warren as **tamper-evident** records: posture is a
self-owned key, and C1 author-validation (on by default) honors a node's posture
only if it was authored by that node's admin-vouched identity, so a member can't
forge another's health card.

## Gate reach on posture

The reach policy is **Cedar**, default-open (members reach the warren), tightened by
the rules you author. A posture gate reads an attribute on the principal:

```cedar
permit ( principal, action == Action::"connect", resource )
when { resource.tags.contains("production") && principal.disk_encrypted == "true" };
```

Author and roll it out (admin only; published on the next daemon restart):

```bash
# Save the policy (from a file or stdin); validated before saving.
hop acl policy set ./prod.cedar

# See it.
hop acl policy show

# Dry-run a principal against it BEFORE rolling out — offline, no daemon:
hop acl policy test --role ops --tag production --posture disk_encrypted=true   # ALLOW
hop acl policy test --role ops --tag production --posture disk_encrypted=false  # DENY
```

`hop acl policy test` evaluates the real Cedar engine with a mock principal, so you
can confirm "in policy is allowed, out of policy is denied" without touching a live
host.

## How it fits the bigger picture

Posture is the first rung of **progressive hardening**: open by default, then
roles + tags, then posture gates, then approvals/JIT. The same signed-attribute +
Cedar machinery underpins all of them. See
[strategy/next-paths-explained.md](../strategy/next-paths-explained.md) (Path D) for
the design, and [cli-reference.md](cli-reference.md#hop-acl-policy-setshowtest) for
the commands.

## Notes

- **Default is open.** With no authored policy, members reach the warren as before;
  posture only matters once a policy references it.
- **Best-effort.** `firewall` and `screen_lock` are `unknown` on systems where the
  probe can't run (no privilege, headless, unusual distro); gate on `disk_encrypted`
  and `os_version` for the most reliable signals.
- **macOS / Linux.** The collector targets these; other platforms report `unknown`.
