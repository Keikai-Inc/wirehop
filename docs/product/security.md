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
| `username` | string? | Unix user the peer logs in as |
| `host_name` | string? | Human-readable host identifier |
| `role` | PeerRole | `peer` (default) or `creator` |
| `sandbox` | SandboxPolicy | Sandbox restrictions for this invite |

#### Security properties

- **One-time**: consumed on first use and removed from the pending store
- **Expiry**: regular invites expire after 15 minutes; creator invites after 1 hour
- **Argon2 hashing**: the secret is Argon2-hashed before storage; only the hash is persisted
- **Base64url encoding**: the token is JSON serialized and base64url-encoded for safe transport

#### Flow

```
Host:   hop invite [--user alice] [--preset monitor]
          -> prints invite token

Client: hop connect <invite-token>
          -> decodes token, connects to host, presents secret
          -> host verifies Argon2 hash, consumes invite
          -> peer is added to authorized peers (peers.json)
          -> peer is also mirrored into the network document (iroh-docs)
```

Since Phase 1 (0.6.26), authorization is **doc-aware**: membership lives in a
replicated network document, with `peers.json` kept as a synced mirror and
fallback. A peer in `peers.json` is always allowed (no lockout); the document is
consulted for peers not locally known. See
[../technical/p2p-network.md](../technical/p2p-network.md) and
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

The VPN data plane is **default-on** but **fail-safe**: bringup is best-effort,
so a TUN-creation failure or a `100.64.0.0/10` conflict (e.g. a host already
running Tailscale) only skips the VPN — `hop exec`/shell/transfer over the
existing authenticated channels are never affected. The VPN can be disabled with
`HOP_VPN=0`, `vpn_enabled = false`, or the installer `--no-vpn`; `HOP_VPN=1`
forces bringup past the conflict guard. Forwarding is default-deny: nothing flows
until a role grants reach.

---

## Privilege Separation

When the hop daemon runs as root:

- **Shell sessions**: PTY is spawned as the target user (the username bound in the invite)
- **File transfers**: a helper process (`__transfer-helper`) runs as the target user, enforcing kernel-level file permission checks
- **Remote exec**: commands execute as the target user

This ensures that even though the daemon listens as root, all user-facing operations run with minimal privileges. The username binding is set at invite time and cannot be changed by the connecting peer.

*Last updated: v0.6.33*
