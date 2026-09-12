# Security

hop provides defense-in-depth through sandboxing, invite-based authentication, role-based access control, and privilege separation.

## Sandbox System

A `SandboxPolicy` restricts what a connecting peer can do on the host. Enforced server-side when spawning processes.

### SandboxPolicy Fields

| Field | Type | Default | Description |
|---|---|---|---|
| `read_only` | bool | `false` | Prevent all filesystem writes, deletes, and modifications |
| `no_network` | bool | `false` | Block outbound network access from spawned commands |
| `allowed_paths` | vec | `[]` | Restrict filesystem visibility to these paths (empty = unrestricted) |
| `allowed_commands` | vec | `[]` | Only these command basenames may be executed (empty = allow all) |
| `denied_commands` | vec | `[]` | Deny these commands even if not using an allowlist |

An empty (default) policy is unrestricted. Any non-default field activates the sandbox.

### Presets

Three built-in presets for common access patterns:

#### `monitor` -- read-only system monitoring

| Field | Value |
|---|---|
| `read_only` | `true` |
| `no_network` | `true` |
| `allowed_paths` | `/proc`, `/sys`, `/var/log`, `/etc` |
| `allowed_commands` | `ps`, `top`, `htop`, `free`, `df`, `du`, `uptime`, `lsof`, `netstat`, `ss`, `cat`, `grep`, `tail`, `head`, `journalctl`, `dmesg`, `ls`, `wc`, `sort`, `uniq`, `awk`, `sed` |
| `denied_commands` | (none) |

#### `audit` -- full read-only access

| Field | Value |
|---|---|
| `read_only` | `true` |
| `no_network` | `true` |
| `allowed_paths` | (unrestricted) |
| `allowed_commands` | (allow all) |
| `denied_commands` | `rm`, `rmdir`, `mkfs`, `dd`, `shutdown`, `reboot`, `poweroff`, `halt`, `init`, `telinit`, `fdisk`, `parted`, `mkswap`, `swapon`, `swapoff`, `mount`, `umount` |

#### `deploy` -- write access with destructive command blocking

| Field | Value |
|---|---|
| `read_only` | `false` |
| `no_network` | `false` |
| `allowed_paths` | (caller should set) |
| `allowed_commands` | (allow all) |
| `denied_commands` | `rm`, `rmdir`, `mkfs`, `dd`, `shutdown`, `reboot`, `poweroff`, `halt`, `init`, `telinit`, `fdisk`, `parted`, `mkswap`, `swapon`, `swapoff`, `mount`, `umount` |

### Policy Composition: `merge_stricter()`

When a host has a stored sandbox policy and a client requests additional restrictions, policies are merged using the **stricter** of each constraint:

| Field | Merge rule |
|---|---|
| `read_only` | OR -- if either says restricted, result is restricted |
| `no_network` | OR -- same |
| `allowed_paths` | Intersection (when both non-empty); if one is empty, use the other |
| `allowed_commands` | Intersection (when both non-empty); if one is empty, use the other |
| `denied_commands` | Union -- deny anything either side denies |

Key property: **a client can never weaken the host's policy**. The merge is symmetric and idempotent.

### CLI Flags

Sandbox flags are available on `hop invite`, `hop connect`, `hop exec`, and `hop admin invite`:

| Flag | Description |
|---|---|
| `--read-only` | Prevent filesystem writes |
| `--no-network` | Block outbound network |
| `--scope <PATH>` | Restrict filesystem to this path (repeatable) |
| `--allow-command <CMD>` | Only allow this command (repeatable) |
| `--preset <name>` | Use a preset: `monitor`, `audit`, `deploy` |

Flags can be combined with presets -- CLI flags override preset defaults via `with_overrides()`:

```bash
# Monitor preset but allow network
hop invite --preset monitor --no-network=false

# Deploy preset scoped to a directory
hop invite --preset deploy --scope /var/www
```

---

## Authentication

### Invite Tokens

hop uses one-time invite tokens for initial authentication. An invite encodes the host's identity and a shared secret.

#### InviteToken payload

| Field | Type | Description |
|---|---|---|
| `node_id` | string | Host's PublicKey (hex) |
| `secret` | string | 32-byte random secret (hex) |
| `relay_url` | string? | Relay URL hint |
| `tier` | InviteTier | `client`, `warren-only`, `node`, or `admin` |
| `host_name` | string? | Only when the operator passed `--name` (a label, not a capability) |

That is the whole token. The Unix username, role and sandbox policy stay in
the host's pending-invite store; the warren ticket and founder trust anchor
are delivered to the client **after** the secret verifies (`AuthResultV2`,
hop/4). A used or expired token is therefore inert. Tokens minted by hop
≤ 0.9.37 also carried `username`, `host_name`, `role`, `sandbox`,
`warren_ticket` and `founder_author`; they still decode and redeem.

#### Security properties

- **One-time**: consumed on first use and removed from the pending store
- **Expiry**: regular invites expire after 15 minutes; creator invites after 1 hour
- **Inert after use**: nothing in the token outlives the secret; the warren grant is only ever sent over the authenticated connection
- **Hashed at rest**: the host stores `sha256:<hex>` of the secret (256 bits of CSPRNG output need no password stretching); entries written by older versions (`$argon2id$…`) are still verified until they expire
- **Metered**: redemption attempts are rate-limited per connecting node id (burst of 5, then 5 per minute, 60-second cool-off) before the store is touched
- **Revocable**: `hop invite list` / `hop invite revoke <id>` manage pending invites
- **Base64url encoding**: the token is JSON serialized and base64url-encoded for safe transport

#### Flow

```
Host:   hop invite [--user alice] [--tier node] [--preset monitor]
          -> stores {sha256(secret), tier, user, role, sandbox}; prints token

Client: hop connect <invite-token>
          -> decodes token, connects to host (hop/4), presents secret
          -> host meters the attempt, verifies the hash, consumes the invite
          -> host answers AuthResultV2 { tier, warren ticket, founder anchor, host name }
          -> peer is added to authorized peers (peers.json)
          -> peer is also mirrored into the network document (iroh-docs)
          -> for node/admin tiers the client joins the warren with the granted ticket
```

Since Phase 1 (0.6.26), authorization is **doc-aware**: membership lives in a
replicated network document, with `peers.json` kept as a synced mirror and
fallback. A peer in `peers.json` is always allowed (no lockout); the document is
consulted for peers not locally known. See
[../technical/warren-internals.md](../technical/warren-internals.md) and
[warren.md](warren.md).

### Peer Roles

Every peer and invite now carries a **named role** (`role_name`). The auth tier
(`PeerRole`) is kept as a compatibility shim for legacy peers:

| Tier (`PeerRole`) | Description |
|---|---|
| `Peer` | Standard access; bound to a Unix user |
| `Creator` | Administrative access; can create invites, manage peers, fleet operations |

Creator-tier is required for `hop admin` commands. Named roles (e.g. `member`,
`developer`, `admin`) layer on top and decide **warren reach** (below). The
no-role default is the least-privilege `member` (default-deny reach), set via
`HostConfig.default_role`; elevate later with `hop admin <host> grant <peer>
<role>` — no re-invite.

### Two layers of access control: reach vs confinement

A role sets **two independent gates**, AND-ed together (the more-restrictive
wins where they touch — they never override each other):

| Layer | Answers | Mechanism |
|-------|---------|-----------|
| **Reach** (network ACL) | *Can this member connect to that host/service at all?* | role→tag rule resolved at enforcement time against the membership doc (`vpn_reach_allowed`); **default-deny** |
| **Confinement** (sandbox) | *What may a hop session do once open?* | macOS Seatbelt / Linux Landlock; commands, paths, network egress |

- **Reach** gates the warren VPN data plane: a packet is forwarded only if the
  source member's role tags reach the destination host's tags (`role_reaches`,
  wildcard `*` or tag intersection). A role with no tags (`member`) reaches
  nothing.
- **Confinement** governs what a hop-spawned shell/exec/agent can do; it does not
  govern a raw VPN connection to a service (that service's own auth does).

Because a role carries both `host_tags` (reach) and a `sandbox` (confinement),
you assign one role and both are set coherently. See
[warren.md](warren.md) for the full model.

### Warren VPN security posture

The VPN data plane is **on by default for a new host** (since v0.9.16) and
**fail-safe**. Opt out with `--host --no-vpn` or `hop config set vpn off`. A
config file that predates the `vpn_enabled` field deserializes to **off**, so
upgrading an existing host never silently brings up a VPN — only brand-new
configs default on. Bringup is best-effort, so a TUN-creation failure or a
`100.64.0.0/10` conflict (e.g. a host already running Tailscale) only skips the
VPN — `hop exec`/shell/transfer over the existing authenticated channels are
never affected. `HOP_VPN=1` forces bringup past the conflict guard; `HOP_VPN=0`
is a recovery escape hatch.

**Why it is safe to default on.** The VPN was off by default in v0.6.37–0.9.15
as an interim mitigation: the warren's shared document was a *write-open* trust
model, where every member held a `ShareMode::Write` ticket and per-author write
authorization was not enforced (tracked as **C1**). That gap is now closed by
**anchor-conditional author-validation enforce** — a founder-anchored warren
rejects forged `vpn`/`ip`/`name` bindings (see `netdoc::ValidationMode` and C1 in
[../technical/security.md](../technical/security.md)). With the
condition the old default was mitigating removed, the default was restored.

**Ingress is authenticated (v0.6.37).** Independent of the write model, inbound
`hop/vpn/1` datagrams are dropped unless (a) the connecting node is a registered
VPN peer, (b) the packet's source virtual IP matches *that node's* registered
vIP (anti-spoofing), and (c) the destination is this host's own vIP. This blocks
source-vIP spoofing and traffic interception even if a `vpn/` registration is
tampered with. Forwarding remains default-deny: nothing flows until a role grants
reach (`role_reaches` / the Cedar engine).

---

## Privilege Separation

When the hop daemon runs as root:

- **Shell sessions**: PTY is spawned as the target user (the username bound in the invite)
- **File transfers**: a helper process (`__transfer-helper`) runs as the target user, enforcing kernel-level file permission checks
- **Remote exec**: commands execute as the target user

This ensures that even though the daemon listens as root, all user-facing operations run with minimal privileges. The username binding is set at invite time and cannot be changed by the connecting peer.

*Last updated: v0.6.33*

---

## Everything an invite can restrict

Set these when you mint the token. They travel with it and cannot be widened by
the recipient; a client can only ask for *more* restriction at connect time.

| Flag | Effect |
|---|---|
| `--tier client` | Reach this one machine only. No membership in the warren. |
| `--tier warren-only` | On the warren (virtual IP and name), but refused a shell on the host. |
| `--tier node` | Full member: reachable, with a virtual address and a name. |
| `--tier admin` | Member, plus the ability to mint invites and grant roles. Give this sparingly. |
| `--role <name>` | The named role, which decides which tags (machines) the peer can reach. |
| `--user <name>` | The Unix user every session runs as. Fixed at mint time. |
| `--read-only` | No writes, deletes, or modifications to the filesystem. |
| `--no-network` | No outbound network from anything the session runs. |
| `--scope <path>` | Only these paths are visible. Repeatable. |
| `--allow-command <cmd>` | Only these commands may run. Repeatable. |
| `--preset monitor\|audit\|deploy` | Ready-made bundles of the above for common jobs. |
| `--expiry <secs>` | How long the token stays redeemable. Default 900 (15 minutes). |
| `--max-uses <n>` | How many machines may redeem it. Default 1. |

## Identity, transport, and the binary itself

**Identity is a keypair.** Each machine has an Ed25519 key generated on first
run and stored with owner-only permissions. There is no account to phish and no
password to reuse. Losing the key is losing the identity, which is the point.

**Encrypted end to end.** Connections are QUIC with TLS 1.3 between your
machines. When a direct path can't be punched through NAT, a relay forwards
*encrypted* packets it cannot read. The default relays are run by Keikai, the
company behind WireHop; `hop host --relay` runs a relay of your own that admits
only your machines (see [run-your-own-relay.md](run-your-own-relay.md)). A relay
sees that two machines are talking, never what they say.

**Signed releases.** Every published binary carries a SHA-256 checksum and an
RSA signature. The installer verifies both against a key embedded in it and
refuses to install on a mismatch. macOS packages are signed and notarized with
Apple. To check a download by hand, the key is published at
<https://wirehop.org/wirehop-release.pub>.

Invite secrets are hashed before storage, so the host keeps a verifier rather
than the secret, and a used invite token grants nothing. Stored secrets are
encrypted with ChaCha20-Poly1305. The implementation is public and permissively
licensed, so none of this has to be taken on faith.

## What this does not protect you from

- **An agent acting badly within its limits.** Scoping bounds the blast radius;
  it does not make an agent's judgment good. If you grant write access to a
  directory, an agent that decides to delete the wrong file in that directory
  can. Scope to what the job needs and read the audit log.
- **A compromised machine.** If an attacker already has root on one of your
  machines, they have that machine's identity, and WireHop will treat them as
  that machine. Revoke it with `hop fleet prune` or an admin revoke.
- **An invite you hand to the wrong party.** A token is a bearer credential
  until it is redeemed or expires. Short expiries and single use limit the
  window; they do not close it. Treat an unredeemed invite like a password.
- **Sharing with people outside your control.** WireHop is built for machines
  you own. It has no multi-tenant model, no per-customer isolation, and no SSO.
  If you need those, it is the wrong tool.
- **Traffic analysis at a relay.** A relay cannot read your traffic, but it can
  observe that two nodes exchanged packets and roughly how much. If that
  matters to you, run your own relay.
- **An unaudited codebase.** WireHop has not had a third-party security audit.
  The code is public and the threat model is written down, which is not the
  same thing as an audit. The standing source-level self-audit is in
  [../technical/security.md](../technical/security.md).

Found something? Report it privately through GitHub's security advisories on
the repository (see [SECURITY.md](../../SECURITY.md)). We aim to acknowledge
within 72 hours and will credit you in the release notes unless you'd rather we
didn't.
