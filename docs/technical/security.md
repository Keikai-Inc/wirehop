# Security Internals

hop's security implementation: cryptographic identity and secrets, the sandbox (validator/broker, macOS Seatbelt, Linux Landlock), privilege separation (monitor/worker), and the standing source-level security audit with remediation status.


---

## Cryptography

### Ed25519 Identity

Each hop node (host or client) has a persistent Ed25519 keypair that serves as its identity. The keypair is used by iroh for QUIC/TLS 1.3 mutual authentication -- all connections are end-to-end encrypted.

#### Generation and Storage

On first run, `load_or_generate_identity()` generates a new keypair and persists it to `identity.json`:

```rust
struct IdentityFile {
    secret_key: String,  // 32-byte Ed25519 secret, base64url-encoded (URL_SAFE_NO_PAD)
    node_id: String,     // Ed25519 public key, hex-encoded
}
```

Storage location:
- macOS system daemon: `/Library/Application Support/hop/identity.json`
- Linux system daemon: `/etc/hop/identity.json`
- User config: `~/.config/hop/identity.json` (via `directories::ProjectDirs`)

#### File Permissions

`identity.json` is written with `write_secret_file()` which sets **mode 0600** (owner read/write only) on Unix. The containing config directory is set to **mode 0700** unless the setgid bit (0o2000) is set, which indicates shared daemon/CLI access configured by the macOS .pkg postinstall script.

#### Resolution Priority

`resolve_host_config_dir()` resolves the config directory in order:
1. `--config` CLI override
2. System config dir if `identity.json` exists there
3. User config dir (`~/.config/hop/`)

#### Read-Only Access

`load_identity()` reads an existing identity without generating one. Used by `hop invite` to read the daemon's identity. Errors if the file does not exist.

### Invite Authentication

Invite tokens authenticate new peers to a host. The secret is 256 bits of
CSPRNG output, so the stored verifier is a plain SHA-256 (there is nothing for
a password-stretching function to defend; Argon2, used before hop/4, only made
every bogus attempt expensive for the host). Offline brute force is bounded by
the secret's entropy, and online attempts are metered per node id.

#### Invite Generation

`generate_invite_with_tier()` in `crates/hop-core/src/invite/mod.rs`:

1. Generate 32 bytes of random secret via `rand::rng().fill_bytes()`
2. Hex-encode the secret (64 hex characters)
3. Store `sha256:<hex of sha256(secret)>` as the verifier and the first 8 hex chars as the invite `id`
4. Store `PendingInvite { secret_hash, id, tier, created_at, username, role, role_name, sandbox, max_uses, expiry_secs }` in `pending_invites.json`
5. Build the minimal `InviteToken` (node id, secret, relay hint, tier, optional `--name`), JSON-encode, base64url-encode

```rust
pub struct InviteToken {
    pub node_id: String,              // Host's public key (hex)
    pub secret: String,               // 32-byte random secret (hex)
    pub relay_url: Option<String>,    // Host's relay URL hint
    pub tier: InviteTier,             // client | warren-only | node | admin
    pub host_name: Option<String>,    // only with `--name`
    // Legacy fields (hop <= 0.9.37 tokens), decoded but never emitted:
    // username, role, role_name, sandbox, warren_ticket, founder_author
}
```

Everything else about the invite (username, role, sandbox, and which warren
ticket to grant) lives in the host's `pending_invites.json` entry, keyed by the
secret's hash. The grant is resolved by `invite::grant_for_tier` only after
the secret verifies and is sent in `HostMessage::AuthResultV2` (hop/4).

#### Verification

When a client connects with `ClientMessage::AuthResponse { secret }`:

0. `auth::auth_attempt_allowed(remote_node_id)` meters the attempt (token bucket per node id: burst 5, refill 5/min, 60 s ban when spent). A refused attempt gets `authorized: false` without touching the store.
1. `PendingInvitesStore::try_consume()` computes `sha256(secret)` once
2. Each pending entry is compared in constant time against its `sha256:<hex>` hash; a `$argon2id$…` entry written by an older binary is verified with Argon2 until it expires
3. On match: **removes** the invite from the store (single-use), returns `ConsumedInvite { id, username, role, role_name, sandbox, tier }`
4. `invite::grant_for_tier(tier)` reads the read ticket (`node`/`warren-only`) or write ticket (`admin`) and the founder author; on hop/4 they go back in `AuthResultV2`

#### TOCTOU Safety

The invite is atomically consumed -- `invites.remove(idx)` is called in the same operation as verification. The `PendingInvitesStore` is re-loaded from disk on each connection attempt, and saved after mutation. There is no window where two clients can consume the same invite.

#### Expiry

`prune_expired(max_age_secs)` removes invites older than the threshold before checking. Default expiry:
- Regular invites: 15 minutes (900 seconds)
- Creator invites: 1 hour (3600 seconds)

#### Transport Security

The invite secret is sent as plaintext in `AuthResponse` because the QUIC/TLS 1.3 transport is end-to-end encrypted. The secret never traverses the network in cleartext.

### ChaCha20-Poly1305 Secrets

The datastore's secrets subsystem provides at-rest encryption for sensitive values (API keys, tokens, credentials).

#### SealedSecret Struct

```rust
pub struct SealedSecret {
    pub ciphertext: Vec<u8>,    // ChaCha20-Poly1305 ciphertext (plaintext + 16-byte auth tag)
    pub nonce: [u8; 12],        // 12-byte random nonce
    pub updated_at: u64,        // Unix timestamp in milliseconds
}
```

Stored in the redb `secrets` table as bincode-encoded bytes, keyed by secret name.

#### Encryption

`encrypt(key, plaintext)` in `crates/hop-core/src/datastore/secrets.rs`:

1. Create `ChaCha20Poly1305` cipher from the 32-byte key
2. Generate 12 random bytes for the nonce via `rand::fill()`
3. Encrypt: `cipher.encrypt(nonce, plaintext)` -- produces ciphertext with appended 16-byte Poly1305 auth tag
4. Return `SealedSecret { ciphertext, nonce, updated_at: now_ms() }`

#### Decryption

`decrypt(key, sealed)`:

1. Create `ChaCha20Poly1305` cipher from the 32-byte key
2. Decrypt: `cipher.decrypt(nonce, ciphertext)` -- verifies auth tag and returns plaintext
3. On auth tag mismatch (wrong key or tampered data): returns error

#### Remote Mode

When the datastore is in Remote mode (MCP process connecting to daemon), secrets operations are proxied via `DsRequest::SecretsGet/Set/Delete/List` over the Unix domain socket. The daemon handles encryption/decryption locally -- plaintext secrets travel over the IPC socket but never leave the machine.

### Key Derivation

The AEAD encryption key is derived from the Ed25519 identity secret key using SHA-256 with a domain separator:

```rust
pub fn derive_secrets_key(identity_key: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"hop-secrets-v1");    // Domain separator
    hasher.update(identity_key);          // Ed25519 secret key bytes
    hasher.finalize().into()              // 32-byte SHA-256 output = AEAD key
}
```

#### Design Rationale

- **Domain separator** (`"hop-secrets-v1"`): prevents cross-protocol key reuse. If the same Ed25519 key were used for a different purpose, the derived key would differ.
- **SHA-256 output**: 256 bits matches ChaCha20-Poly1305's key size exactly.
- **Deterministic**: the same identity always derives the same secrets key, so secrets survive daemon restarts without storing the AEAD key separately.
- **Version tag**: the `v1` suffix allows future key derivation scheme upgrades without breaking existing secrets.

> **Known limitation (security-audit H8, deferred).** This is a single SHA-256
> pass — not an HKDF — with no per-store salt, so the same identity derives the
> same key on every host. A move to HKDF-SHA256 + random per-store salt is
> **deferred**: it would change the output key and so require a key-rotation
> migration (risking unreadable secrets on upgrade), and it adds little against
> the real threat — an attacker who can read the ciphertext db can also read
> `identity.json` and re-derive the key under any KDF. The actual at-rest
> protection is filesystem permissions: the datastore is `0600` and
> `identity.json` is re-tightened to `0600` on load (v0.6.37). See
> [Security Audit](#security--code-health-audit--2026-06-03).

#### Key Lifecycle

1. Daemon starts, loads `identity.json` (Ed25519 secret key)
2. Calls `derive_secrets_key(&secret_key_bytes)` to get the 32-byte AEAD key
3. Opens datastore with `Datastore::open_with_secrets(path, secrets_key)`
4. All `secrets_get/set/delete/list` operations use this key for the session

*Last updated: v0.6.33*


---

## Sandbox

### Architecture

The sandbox enforces restrictions on what connected peers can do. It has three defense-in-depth layers:

1. **Application-layer validator** (`validator.rs`): catches obvious violations before process spawn.
2. **OS-native kernel sandbox**: the real security boundary.
   - macOS: Apple Seatbelt / `sandbox-exec` with SBPL profiles (paths escaped against profile injection — security-audit H4)
   - Linux: Landlock filesystem ACL + Landlock TCP rules for `no_network` (ABI v4) + `PR_SET_NO_NEW_PRIVS`; enforcement is fatal-when-restricted (H5/H6)
3. **Hardcoded safety net**: `PR_SET_NO_NEW_PRIVS` on Linux to prevent privilege escalation.

The policy is enforced on **every peer-driven surface**, not just shell/exec:
remote `exec`/shell and `hop.local()` (OS sandbox), **file transfer** (`hop cp`/`sync`
honor `read_only` + `allowed_paths`; security-audit C3), and the **MCP JS bindings**
(`hop.readFile`/`hop.writeFile` confined to `allowed_paths`; `hop.http` SSRF-blocked
for restricted peers; C4). See [../product/remote-access.md](../product/remote-access.md) and
[../product/ai-and-scripting.md](../product/ai-and-scripting.md).

### SandboxPolicy Struct

```rust
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq)]
pub struct SandboxPolicy {
    pub read_only: bool,              // Prevent all filesystem writes
    pub no_network: bool,             // Block outbound network access
    pub allowed_paths: Vec<PathBuf>,  // Restrict filesystem to these paths (empty = unrestricted)
    pub allowed_commands: Vec<String>, // Allowlist of command basenames (empty = allow all)
    pub denied_commands: Vec<String>,  // Denylist of command basenames (always enforced)
}
```

A default `SandboxPolicy` is unrestricted (all fields false/empty). The `is_restricted()` method returns `true` if any field has a non-default value.

### Presets

Three built-in presets via `SandboxPolicy::from_preset(name)`:

#### monitor

Read-only monitoring access with scoped paths and a strict command allowlist.

```rust
SandboxPolicy {
    read_only: true,
    no_network: true,
    allowed_paths: ["/proc", "/sys", "/var/log", "/etc"],
    allowed_commands: [
        "ps", "top", "htop", "free", "df", "du", "uptime", "lsof",
        "netstat", "ss", "cat", "grep", "tail", "head", "journalctl",
        "dmesg", "ls", "wc", "sort", "uniq", "awk", "sed"
    ],
    denied_commands: [],
}
```

#### audit

Read-only, no network, full filesystem read access, with dangerous commands denied.

```rust
SandboxPolicy {
    read_only: true,
    no_network: true,
    allowed_paths: [],        // Unrestricted read
    allowed_commands: [],     // Allow all read-safe commands
    denied_commands: [
        "rm", "rmdir", "mkfs", "dd", "shutdown", "reboot", "poweroff",
        "halt", "init", "telinit", "fdisk", "parted", "mkswap",
        "swapon", "swapoff", "mount", "umount"
    ],
}
```

#### deploy

Write-enabled, network-enabled, with dangerous commands denied. The caller should set `allowed_paths` to scope writes.

```rust
SandboxPolicy {
    read_only: false,
    no_network: false,
    allowed_paths: [],        // Caller should set
    allowed_commands: [],
    denied_commands: [/* same as audit */],
}
```

### Policy Composition: merge_stricter()

When both the host and client specify sandbox policies, `merge_stricter()` produces the intersection -- never looser than either input.

```rust
pub fn merge_stricter(&self, other: &Self) -> Self
```

**Algorithm:**

| Field | Merge Rule | Rationale |
|---|---|---|
| `read_only` | `self \|\| other` (OR) | If either restricts, restrict |
| `no_network` | `self \|\| other` (OR) | If either restricts, restrict |
| `allowed_paths` | Intersection when both non-empty; take non-empty side if one is empty | Empty = unrestricted |
| `allowed_commands` | Intersection when both non-empty; take non-empty side if one is empty | Empty = unrestricted |
| `denied_commands` | Union (deduplicated) | Deny anything either side denies |

**Properties:**
- **Symmetric**: `a.merge_stricter(&b)` has the same restrictions as `b.merge_stricter(&a)` (element order may differ)
- **Idempotent**: `a.merge_stricter(&a) == a`
- **Client cannot weaken host**: a client trying to set `read_only: false` when the host has `read_only: true` still gets `read_only: true`

### Validator

The application-layer validator in `crates/hop-core/src/sandbox/validator.rs` is defense-in-depth -- it catches obvious violations before any process is spawned. The OS kernel sandbox is the actual security boundary.

#### validate_command()

```rust
pub fn validate_command(cmd: &str, policy: &SandboxPolicy) -> Result<(), ValidationError>
```

Validation steps:

1. **Empty check**: reject empty or whitespace-only commands.
2. **Metacharacter rejection**: when `read_only` or `allowed_commands` is active, reject shell metacharacters outside single quotes: `;`, `|`, `&`, `>`, `<`, `` ` ``, `$(`.
3. **Shell split**: tokenize the command respecting single/double quotes and backslash escaping. Unbalanced quotes return `InvalidCommand`.
4. **Basename extraction**: `Path::new(binary).file_name()` to handle `/usr/bin/ls` -> `ls`.
5. **Denylist check**: case-insensitive match against `denied_commands`. Always enforced, even with an allowlist.
6. **Allowlist check**: if `allowed_commands` is non-empty, the basename must match (case-insensitive). Denylist takes priority over allowlist.

#### shell_split()

Minimal shell-like word splitting that respects quotes:

- Single quotes: everything inside is literal (no escaping)
- Double quotes: backslash escaping is honored
- Backslash outside quotes: escapes the next character
- Returns `None` for unbalanced quotes

#### Metacharacter Detection

Tracked characters (outside single quotes): `;`, `|`, `&`, `>`, `<`, `` ` ``, `$(` (two-character sequence). The scanner tracks quoting state (`in_single`, `in_double`) character by character.

**Note**: Backslash-escaped metacharacters (e.g., `\;`) are still rejected. This is intentional -- the validator is conservative.

### Broker

The broker in `crates/hop-core/src/sandbox/broker.rs` solves a macOS-specific problem: `sandbox-exec` blocks ALL setuid binaries (including `ps`, `top`, `netstat`) even with `(allow default)`.

#### Architecture

```
User types "ps aux" in sandboxed shell
  -> Shell finds <broker_dir>/bin/ps (symlink -> /usr/local/bin/hop)
  -> hop detects argv[0]="ps", enters broker client mode
  -> Connects to <broker_dir>/broker.sock (Unix domain socket)
  -> Sends BrokerRequest::Exec { command: "ps", args: ["aux"] }
  -> Daemon validates command against policy + broker-safe list
  -> Daemon spawns real /bin/ps aux UNSANDBOXED as session user
  -> Streams stdout/stderr back over socket
  -> Shim writes output to its stdout, exits with same code
```

#### Broker-Safe Commands

Read-only system tools that are setuid on macOS:

```rust
const BROKER_SAFE_COMMANDS: &[&str] = &[
    "ps", "w", "who", "last", "lastlog", "uptime", "netstat", "lsof",
    "iostat", "vm_stat", "sysctl", "sw_vers", "system_profiler",
    "diskutil", "ifconfig", "finger", "top",
];
```

#### Protocol

```rust
pub enum BrokerRequest {
    Exec { command: String, args: Vec<String>, rows: u16, cols: u16 },
    Input(Vec<u8>),
    Resize { rows: u16, cols: u16 },
}

pub enum BrokerResponse {
    Output(Vec<u8>),
    Exit(i32),
    Denied(String),
}
```

#### Shim Setup

`setup_shim_dir()` creates `<config_dir>/broker/<session_id>/bin/` with symlinks for each broker-safe command pointing to the hop binary. The shim directory is prepended to PATH via a custom ZDOTDIR (for zsh) so symlinks take precedence.

`setup_zdotdir()` creates a custom zsh dotfile directory that:
1. Sources the user's real dotfiles (`$HOME/.zshenv`, `.zprofile`, `.zshrc`, `.zlogin`)
2. Prepends the shim bin directory to PATH after `/etc/zprofile` runs (which resets PATH via `path_helper` on macOS)
3. Sets `HOP_BROKER_SOCK` environment variable
4. Unsets `HISTFILE` to prevent writes in read-only sandboxes

### macOS Enforcement: Seatbelt Profiles

`crates/hop-core/src/sandbox/macos.rs` generates SBPL (Sandbox Profile Language) profiles for `sandbox-exec`.

#### Profile Generation

```rust
pub fn generate_sbpl_profile(policy: &SandboxPolicy) -> String
```

The profile starts with `(allow default)` -- a permissive base -- then adds targeted deny rules:

**Read restrictions** (when `allowed_paths` is non-empty):
- `(deny file-read*)` -- deny all reads
- Re-allow system paths: `/usr`, `/bin`, `/sbin`, `/lib`, `/dev`, `/private/var/db`, `/private/var/run`, `/private/var/folders`, `/private/etc`, `/System`, `/Applications/Utilities`, `/Library/Preferences`, `/var/select`, `/var/db`, `/etc`, `/private/tmp`, `/tmp`
- Re-allow each path in `allowed_paths` (canonicalized)
- Re-allow broker directory if provided

**Write restrictions** (when `read_only`):
- `(deny file-write*)` -- deny all writes
- Re-allow PTY devices: `/dev/null`, `/dev/dfd`, `/dev/ttys*`, `/dev/pty*`
- Re-allow temp: `/private/var/folders`, `/private/tmp`, `/tmp`

**Network restrictions** (when `no_network`):
- `(deny network-outbound (remote ip "*:*"))` -- block TCP/UDP outbound
- `(deny network-inbound (local ip "*:*"))` -- block TCP/UDP inbound
- Unix domain sockets are preserved (needed for broker IPC)

#### Shell Wrapping

For PTY sessions with a user, the command chain is:
```
login -fp <user> /usr/bin/sandbox-exec -p <profile> <shell> -l
```
`login` is setuid and must run before `sandbox-exec` (which strips setuid).

Without a user:
```
/usr/bin/sandbox-exec -p <profile> <shell> -l
```

### Linux Enforcement: Landlock

`crates/hop-core/src/sandbox/linux.rs` uses Landlock (Linux 5.13+) for unprivileged filesystem sandboxing.

#### apply_sandbox()

Applied in the child process after fork, before exec. **Returns `Result`** — and
for a restricted policy a failure to enforce is **fatal** (the session is
refused rather than running unsandboxed; security-audit H6):

1. **`PR_SET_NO_NEW_PRIVS`**: prevents privilege escalation via setuid/setgid binaries. Always set via `prctl()`.
2. **Landlock filesystem rules**: filesystem access control. If the kernel
   doesn't support Landlock (< 5.13) and the policy is restricted, the
   `RulesetStatus::NotEnforced` result is treated as fatal.
3. **Landlock network rules** (when `no_network`): denies all TCP `bind`/`connect`
   via Landlock ABI v4 (Linux 6.7+), best-effort. **Limitation:** Landlock can't
   restrict UDP, so DNS and QUIC still function — this blocks TCP egress only.
   On kernels without ABI v4 the restriction is unenforceable and is logged
   loudly (not silently ignored). This replaced the prior **false** "seccomp-BPF"
   claim, under which `no_network` was unenforced on Linux (security-audit H5).

#### Landlock Rules

```rust
fn apply_landlock(policy: &SandboxPolicy) -> Result<(), String>
```

Access flags:
- **Read access**: `Execute | ReadFile | ReadDir`
- **Write access**: `WriteFile | RemoveDir | RemoveFile | MakeChar | MakeDir | MakeReg | MakeSock | MakeFifo | MakeBlock | MakeSym`

System paths always get read+execute: `/usr`, `/bin`, `/sbin`, `/lib`, `/lib64`, `/dev`, `/proc`, `/sys`, `/etc`, `/tmp`, `/run`, `/var/run`, `/var/lib`.

| Mode | Allowed Paths | Effect |
|---|---|---|
| `read_only`, paths empty | `/` gets read access; `/tmp`, `/var/tmp` get all access | Full read, write only to temp |
| `read_only`, paths set | Each path gets read; `/tmp`, `/var/tmp` get all access | Scoped read, write only to temp |
| Not read_only, paths empty | Skipped (no restrictions) | No Landlock applied |
| Not read_only, paths set | `/` gets read; each path gets all access | Global read, write to scoped paths |

#### Shell Wrapping (Linux)

Since `portable_pty::CommandBuilder` does not support `pre_exec` hooks, Linux uses a self-exec wrapper:

```
hop __sandbox-shell --policy <json> -- <shell> -l
```

The hop binary re-invokes itself with the `__sandbox-shell` subcommand, applies Landlock + no_new_privs in-process, then execs the real shell. The policy is serialized as JSON in the command arguments.

For users: `hop __sandbox-shell --policy <json> -- su - <username>`

*Last updated: v0.6.33*


---

## Privilege-Separated Warren Node (Design)

> **Status: Phases 1–3 implemented & Linux-validated (flag-gated); Phase 4 ACL +
> persistent-shell + macOS gate remain.** Behind `HOP_PRIVSEP` (off by default)
> and `HOP_PRIVSEP_DROP`:
> - **Phase 1** (monitor/worker split, `SCM_RIGHTS` fd-passing, control protocol +
>   validation, passed-fd TUN wrapper) — shipped in 0.6.60; `privsep-e2e.sh` routes
>   real packets over the monitor-passed fd.
> - **Phase 2** (`_hop`/`hop` service user, config ownership migration,
>   `initgroups`→`setgid`→`setuid` worker drop) — e2e-validated.
> - **Phase 3** — all three privileged-spawn primitives implemented:
>   `SpawnSession` (PTY, interactive shell), `SpawnExec` (pipes + status-fd exit
>   code), `SpawnHelper` (transfer). **The full 53-test e2e passes with both hosts
>   under `HOP_PRIVSEP_DROP`** — the worker runs as non-root `hop` and the monitor
>   serves every exec (`SpawnExec`) and transfer (`SpawnHelper`) as the bound user.
>   The interactive-shell `SpawnSession` is implemented + unit-tested + proven not
>   to regress the non-privsep path, though no e2e opens an interactive shell.
>   **Persistent shells** are explicitly refused under drop (a clean error) pending
>   relocation of the detached-session machinery.
>
> Phase 4 **receiver-side ACL is done** to the trust model's ceiling: the monitor
> refuses system/service accounts (uid < 500 macOS / 1000 Linux) and, if the
> operator provides a root-owned `privsep-users` allowlist, restricts spawns to
> exactly those accounts. A fully-automatic peer-binding sync is *not possible*
> (the worker owns `peers.json`, so only operator-set root-owned config is
> trustworthy) — operator-maintained allowlist is the inherent limit, not a gap.
>
> **Persistent (interactive) shells now work under drop too** — `spawn_persistent_pty`
> acquires its PTY via the monitor's `SpawnSession`, validated by the
> `interactive_shell` e2e under `HOP_PRIVSEP_DROP` (54/54). So all four session
> surfaces (shell, persistent-shell, exec, transfer) run under privsep.
>
> **macOS feasibility gate (§8.1): ✅ PASSED (2026-06-13)** — `hop __privsep-probe`
> ran as root and a non-root child read/wrote the passed utun fd → **B-full is
> viable on macOS.** macOS **activation** is implemented: the `.pkg` postinstall
> creates the `_hop` service account, and the LaunchDaemon plist sets
> `HOP_PRIVSEP` + `HOP_PRIVSEP_DROP` (default-on for new macOS installs). An
> **anti-lockout crash-loop fallback** is in `run_monitor`: if the worker keeps
> exiting fast, the monitor re-execs the daemon as a plain root process so the host
> stays reachable. macOS note: the full worker-as-`_hop` daemon isn't e2e-tested on
> macOS (no macOS CI), so validate on a test Mac before production hosts.
>
> **Worker-liveness invariant (the worker never outlives its monitor).** The
> monitor passes the worker the read end of a **liveness pipe**
> (`HOP_PRIVSEP_ALIVE_FD`) and holds the write end. A worker thread blocks reading
> it; if the monitor dies for *any* reason — even `SIGKILL` — the kernel closes
> the write end, the read hits EOF, and the worker `raise(SIGTERM)`s itself (with
> a hard-`_exit` backstop). Without this, a stranded worker keeps the
> `datastore.redb` lock + the TUN, and every restart — including the crash-loop
> fallback — wedges. This is the OpenSSH model: monitor and child are bound for
> life. (Found via the privsep-drop vpn-e2e: `pkill` of the daemon left an
> orphaned worker that defeated even the root fallback.)
>
> **Operator IPC (§6) is implemented.** Under drop the config is `_hop`-owned, but
> `hop invite` / `hop id` no longer need root: the daemon binds `daemon.sock`
> group-owned by the **operator group** (`admin` on macOS, `hop` on Linux, via the
> monitor's setgid config dir), and the CLI sends an `AdminRequest` over it — the
> daemon, which holds identity + netdoc, does the privileged part and returns the
> token/id. Operators read no `_hop` secrets and never `sudo`. Validated by
> `privsep-e2e.sh` (a non-root operator mints an invite + reads the host id, and is
> confirmed *unable* to read `identity.json` directly).
>
> Goal: shrink the warren node's root attack surface from
> "the entire daemon" to a minimal, non-network-facing privileged monitor, while
> the large, attackable, network-facing daemon (QUIC, protocol parsing, the
> netdoc replication stack, the VPN data plane, DNS logic) runs as an
> unprivileged service user. This is the OpenSSH privilege-separation model
> applied to `hop host`. It preserves all node capabilities (addressable vIP,
> full mesh, kernel-TUN performance, MagicDNS, host sessions) while making a
> remote code-execution bug in the network-facing code a compromise of an
> unprivileged service account, **not root**.
>
> This is the chosen direction (option **B** from the user-level-reach
> discussion): full node capability with a minimal root surface, as opposed to a
> userspace netstack (option A, zero-root but non-transparent / slower).

### 1. Why the daemon is root today, and why that's too much

`hop host` runs entirely as root. But root is needed for only **three** narrow
operations; everything else is the unprivileged-capable bulk:

| Privileged operation | Where | Why root |
|---|---|---|
| **TUN create + addr/MTU/route** | `vpn/mod.rs:102` `create_tun` (the `tun` crate sets `.address/.netmask/.mtu/.up`); kernel auto-installs the `100.64.0.0/10` route | creating a network interface + writing the route table needs root / `CAP_NET_ADMIN` |
| **Bind `:53` on the vIP (MagicDNS)** | `enable_vpn` spawns `vpn_dns_loop` (`netdoc/mod.rs:1464`) which binds the vIP UDP `:53` | port < 1024 is privileged |
| **Spawn a session as the bound unix user** | `plain_shell` / `sandboxed_shell` → `login -fp <user>` (macOS) / `su - <user>` / setuid+`initgroups` (Linux) — `sandbox/mod.rs:236`, `transfer/helper.rs:60-91` | only root can become an arbitrary user |

Everything else — and it is the overwhelming majority of the code, and **all of
the remotely-reachable attack surface** — needs no privilege:

- The iroh QUIC endpoints (main + the derived netdoc endpoint, `net/mod.rs:131`),
  `accept` loops, ALPN dispatch, protocol decoding (`proto/`), auth handshake.
- The entire netdoc replication stack (iroh-docs/gossip/blobs), reconcile, C1
  author validation, the Cedar reach engine (`vpn/cedar.rs`).
- The VPN data plane: `vpn_outbound_loop` (`netdoc/mod.rs:1570`), the inbound
  `pump_vpn_datagrams` + ingress anti-spoof (`vpn/mod.rs:137`), vIP→endpoint
  resolution, the per-packet parse (`parse_dest_ipv4` etc., `vpn/mod.rs:25`).
- Reading the node's own secret (`identity.json`) and writing its self-doc.

So today a memory-safety bug or logic flaw anywhere in the QUIC/protocol/netdoc/
packet-parsing surface — all of it fed by untrusted remote input — yields
**root**. The privilege the daemon actually needs is three small, well-defined
sysc90l clusters. That mismatch is the whole motivation.

### 2. Threat model

- **T1 — Remote RCE in network-facing code.** An attacker who can reach the
  node's QUIC endpoint (any warren peer, or anyone who can send to the relay/
  direct path) exploits a bug in QUIC, ALPN dispatch, protocol decode, the
  netdoc/iroh-docs stack, or the VPN packet path. *Today → root. Goal → an
  unprivileged service account.*
- **T2 — Local non-service user reads node secrets.** Another local account
  tries to read `identity.json` / the netdoc store to clone the node's identity.
  *Must stay denied (today: 0600 root; after: 0600 `_hop`).*
- **T3 — Compromised worker escalates.** Having popped the unprivileged worker
  (T1), the attacker tries to use the privileged monitor to regain root.
  *The monitor must expose only a fixed, validated set of primitives — never a
  general "run as root".*
- **T4 — Worker abuses the TUN.** The worker holds the TUN fd, so it can inject/
  read warren L3 packets. *This is inherent to any data plane; reach is still
  ACL-gated, and the worker cannot reconfigure interfaces/routes (monitor-only).*

Out of scope: a root-level local compromise (already game over); HSM-backed key
custody (a later evolution — see §9 residual risk).

### 3. Target architecture — monitor + worker

```
              launchd / systemd  (RunAtLoad, KeepAlive)
                        │  starts as root
                        ▼
            ┌───────────────────────────┐
            │  hop-monitor  (root)       │   tiny, NON-network-facing
            │  - owns the canonical TUN  │   only talks to its own child
            │  - holds priv-port :53 fd  │   over an inherited socketpair
            │  - performs the 3 prims    │   no untrusted input
            │  - supervises the worker   │
            └─────────────┬─────────────┘
                          │ AF_UNIX socketpair (SCM_RIGHTS) — private, inherited
                          │ drops privilege → execs worker as _hop
                          ▼
            ┌───────────────────────────┐
            │  hop host  (user _hop)     │   the entire existing daemon
            │  - iroh endpoints, accept  │   MINUS the 3 privileged prims
            │  - netdoc stack, C1, Cedar │   ← all remote attack surface
            │  - VPN data plane (TUN I/O)│   ← runs unprivileged
            │  - DNS logic (on passed fd)│
            │  - reads _hop-owned secret │
            └───────────────────────────┘
```

- The **monitor** is a few hundred lines: create the socketpair, do the three
  privileged primitives on validated request, hold the canonical TUN/`:53` fds
  (so the interface survives worker restarts), supervise + restart the worker.
  It takes **no network input** and never execs anything but the known worker and
  the validated session-spawn helper.
- The **worker** is the current `hop host` codebase, with the three privileged
  call-sites replaced by requests to the monitor. It runs as a dedicated service
  user (`_hop`) and holds the node identity (now `_hop`-owned, 0600).

This is structurally identical to OpenSSH's `sshd` privsep (unprivileged
net-facing child + privileged monitor exposing a small validated API), which is
the canonical precedent for "don't run the parser as root."

### 4. The privileged-primitive protocol (the security crux)

The monitor↔worker channel is a single inherited `AF_UNIX` `SOCK_SEQPACKET`
socketpair (no on-disk path → no other process can connect; created before the
worker drops privilege so the worker inherits one end). The protocol is a
**fixed, closed** set of requests; the monitor validates each and refuses
anything else. Minimality here is the entire security argument for §T3.

**P1 — `CreateTun { vip: Ipv4Addr }` → `fd`.**
- Monitor asserts `vip ∈ 100.64.0.0/10`. Creates the utun (macOS
  `SYSPROTO_CONTROL`) / `/dev/net/tun` (Linux `TUNSETIFF`, `IFF_NO_PI`), sets
  address = `vip`, netmask `255.192.0.0`, MTU `1280`, `up`; kernel installs the
  `/10` route. Sends the fd via `SCM_RIGHTS`. Monitor **retains the canonical
  fd** so the interface + route persist across worker restarts.
- Returned once at worker start. A second `CreateTun` for a *different* vip is
  the multi-home path (§8.7); for the same vip it's idempotent.

**P2 — `BindPrivPort { addr: Ipv4Addr, port: u16 }` → `fd`.**
- Monitor asserts `addr == vip` and `port == 53` (the only privileged port hop
  binds). Binds a UDP socket, sends the fd. Worker runs `vpn_dns_loop` on it.
- Hard-allowlisted to `(vip, 53)` — not a general "bind any port as root".
- Worker side is `privsep::acquire_priv_port` (mirrors `acquire_tun`): routes
  through the monitor under privsep, binds directly otherwise.

**P2b — `ConfigureResolver { domain: String, vip: Ipv4Addr }` → `Ok`.**
- Points the OS resolver for the warren `domain` at the local MagicDNS server on
  `vip:53` (split-DNS) so `<host>.<domain>` resolves with no manual setup —
  privileged because it writes root-owned `/etc/resolver/<domain>` (macOS) or
  runs `resolvectl` (Linux/systemd-resolved). The monitor sanitizes `domain` (a
  plain DNS label path — it becomes a filename / CLI arg), applies it, and
  **remembers it to revert on exit** so a stale entry never outlives the daemon.
  Returns `MonitorReply::Ok` (no fd). Worker side: `privsep::configure_resolver`.
  Opt out with `HOP_NO_AUTO_RESOLVER`.

**P3 — `SpawnSession { user, kind, pty_size, argv… }` → `pty_fd`/streams.**
- The worker authenticates the peer and decides the bound unix user (existing
  auth path). It then asks the monitor to *become that user* and exec the
  shell/exec/transfer helper — i.e. the existing `login -fp` / `su -` /
  setuid+`initgroups` logic (`sandbox/mod.rs`, `transfer/helper.rs`) **moves into
  the monitor**. The monitor re-validates: `validate_username` (`unix_user.rs`:
  format, **not root**, exists), the sandbox policy, the command class — then
  spawns and hands back the PTY/stdio fds. The worker proxies bytes over QUIC as
  it does today.
- This is the part people miss: making the daemon non-root is *not* just the
  TUN — the daemon's core feature (sessions as the bound user) is itself a root
  operation, and it must be brokered, not held.

Everything else the worker does itself (no monitor round-trip): open QUIC
endpoints, replicate the netdoc, resolve vIPs, parse/forward packets on the TUN
fd, enforce the Cedar ACL, write its self-doc.

### 5. File-descriptor passing

hop does **not** pass fds today (grep: no `SCM_RIGHTS`/`sendmsg`/`recvmsg` cmsg
in non-vendor code). We add it on the monitor socketpair using `nix`'s cmsg
helpers (`nix` is already a dependency with the `net` feature). A `SEQPACKET`
socketpair gives message framing for the small control protocol; fds ride as
ancillary data. Because the socketpair is created in the monitor and one end is
inherited across the privilege-dropping exec, there is **no named socket** for a
third party to reach — the channel is private to the monitor/worker pair.

Worker-side TUN I/O does **not** use the `tun` crate's `create_as_async` (that
makes a *new* device). It wraps the *passed* fd: `tokio::io::unix::AsyncFd` over
the raw fd, with manual handling of the macOS utun **4-byte address-family
prefix** (`AF_INET`/`AF_INET6` prepended on write, stripped on read) — on Linux
with `IFF_NO_PI` there is no prefix. This is a small, well-understood amount of
raw I/O code; correctness is covered by a loopback unit test.

### 6. Service user & secret ownership

Introduce a dedicated **`_hop`** service account (created at install; macOS
`dscl`/`sysadminctl` hidden uid < 500, Linux `useradd --system`). Re-own:

| Path | Today | After |
|---|---|---|
| `identity.json` | `root:wheel 0600` | `_hop:_hop 0600` |
| `netdoc/` store (+ self-doc keys, iroh-docs-managed) | root | `_hop` `0700` |
| `netdoc-read.ticket`, `netdoc-founder.*` | root `0600` | `_hop 0600` |
| `peers.json`, `host_config.json`, `roles.json`, `warren-members.json` | `root:admin 0660` | `_hop:hop 0660` (group-readable for the operator's CLI) |
| **`netdoc.ticket` (warren WRITE)** | root `0600` | `_hop 0600` *only if this node is the founder/admin* |

The worker (as `_hop`) reads `identity.json` directly — **no root, no permission
papercut** (this is the same class of bug as the earlier `hop warren status` /
`hop invite` EACCES: those resolve to a root-owned file). The host secret is
still protected from *other* local users (0600 `_hop`).

This composes with the host-admin permission model discussed separately: the
human operator's CLI ops that need the secret/ticket go through the worker's
group-readable `daemon.sock` IPC (or self-escalate via `sudo` for genuinely
root operations), never by reading `_hop`'s 0600 files.

**Key fact (from the audit) that makes this clean:** a plain *node* never needs
the warren **write** ticket or any *other* node's secret. It holds only its own
identity, the admin-doc **read** ticket, and its own self-doc (whose write key
iroh-docs manages inside the `_hop`-owned store). So moving the node's custody
from root to `_hop` exposes only the node's own identity to the `_hop`
account — which is exactly the account that must use it. No admin/founder
authority moves.

### 7. macOS vs Linux specifics

| | macOS | Linux |
|---|---|---|
| TUN | `socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` + connect `UTUN_CONTROL_NAME`; **4-byte AF prefix** on each frame | `/dev/net/tun` + `TUNSETIFF`, `IFF_TUN\|IFF_NO_PI` (no prefix) |
| addr/route | `ioctl` `SIOCSIFADDR`/`SIOCSIFNETMASK` + `PF_ROUTE` socket (root) | `ioctl` / `rtnetlink` (root or `CAP_NET_ADMIN`) |
| become-user | `login -fpq <user> …` — establishes a fresh **audit session** (without it, a bare setuid from launchd's root audit session can't touch user-owned files — `transfer/helper.rs:60`) | setuid+setgid+`initgroups` in `pre_exec`; `su -` for login env |
| `:53` bind | privileged-port, needs root | `CAP_NET_BIND_SERVICE` (the monitor can hold just this cap, not full root) |
| monitor privilege | root (no fine-grained caps) | could be reduced to `CAP_NET_ADMIN`+`CAP_NET_BIND_SERVICE`+`CAP_SETUID/SETGID` ambient — strictly less than full root |

On Linux the monitor can be *capability-bounded* (it never needs full root),
tightening §T3 further. On macOS it must be root, so the monitor's minimality is
the only lever — hence the fixed 3-primitive protocol.

### 8. Edge cases

**8.1 — macOS utun fd usable by a non-root process? (THE feasibility gate.) ✅
PASSED (2026-06-13).** The entire design assumes that after the monitor (root)
creates+configures the utun, a *passed* fd can be `read`/`write`n by the
unprivileged worker. `hop __privsep-probe` ran as root on macOS and reported
`probe child: non-root I/O on the passed TUN fd is PERMITTED` → **PASS**. So the
privilege checks are at socket *creation* (`SYSPROTO_CONTROL` connect) and
*interface configuration* (`SIOCSIF*`), not per-I/O, exactly as on Linux —
**B-full is viable on macOS.** No B-lite pivot needed. (Linux had already proven
this via `privsep-e2e.sh`.)

**8.2 — Worker crash / restart.** The monitor holds the **canonical** TUN/`:53`
fds, so the interface, address, and route **persist** across worker restarts
(no flap). On worker exit the monitor re-spawns it and passes fresh `dup`s. The
worker is otherwise stateless w.r.t. the interface. (The monitor is the launchd/
systemd-supervised top process; it supervises the worker, not the reverse.)

**8.3 — Clean teardown.** On monitor exit (or system shutdown) the canonical fds
close → the kernel removes the interface + its `/10` route automatically. No
stale routes. (`KeepAlive` restarts the monitor; a deliberate stop tears down.)

**8.4 — vIP reallocation.** The vIP is admin-allocated and static
(`peer/N.vip`), so reconfiguration is rare. If it changes, the worker sends a new
validated `CreateTun{vip}`; the monitor reconfigures the interface it owns.
Never the worker (no `CAP_NET_ADMIN`).

**8.5 — Privileged-port `:53`.** Covered by P2; hard-allowlisted to `(vip, 53)`.
If we later add more listeners, each privileged port is an explicit allowlist
entry, not a general capability.

**8.6 — Sessions need root (the non-obvious one).** Covered by P3 — the
setuid-to-bound-user logic moves into the monitor. The worker never holds
setuid. macOS `login -fpq` (audit session) still happens, in the monitor.

**8.7 — Multi-home (future).** Multiple warren memberships → multiple vIPs/TUNs:
the monitor creates N interfaces (N `CreateTun`), passes N fds. The protocol and
ownership model extend unchanged.

**8.8 — Migration on upgrade.** A one-time step re-owns the existing root-owned
config dir to `_hop` (`chown -R _hop`), creates the `_hop` user if absent, and
rewrites the launchd plist / systemd unit to launch the monitor. Must be
idempotent and reversible (back up before chown). The current
`hop __install-daemon` is the natural home for this.

**8.9 — Reboot ordering.** The monitor starts at boot (root), creates the TUN,
spawns the worker (`_hop`); the worker's netdoc/relay reconnect is unchanged
from today (and is the subject of the separate "reachable only after SSH"
investigation — privsep neither helps nor hurts it). The worker starting before
the network is up is the same race as today.

**8.10 — Argument / path injection into the monitor.** Every `SpawnSession`
argument is validated (`validate_username`, allowlisted command classes, no
shell interpolation — exec argv directly, never `sh -c` on attacker strings).
`CreateTun`/`BindPrivPort` take only typed `Ipv4Addr`/`u16` with range checks.
The monitor never reflects worker-supplied paths into privileged exec.

**8.11 — `_hop` compromise blast radius.** If the worker is popped (T1), the
attacker is `_hop`: they can act as **this node's identity** on the warren
(the key is necessarily usable by the data plane), sniff/inject this node's
warren packets, and read `_hop`-owned files. They **cannot**: become root, read
other users' files, reconfigure interfaces/routes, become other unix users
(P3 is monitor-validated and refuses `root`), or obtain admin/founder authority
(a node never holds the write ticket). Reach stays ACL-bounded. Recovery =
revoke the node (`revocation/<node>`), rotate its key.

### 9. Security analysis

**Attack-surface reduction (the headline).** Every byte of untrusted remote
input — QUIC frames, ALPN, the wire protocol, iroh-docs sync, VPN datagrams — is
parsed by the **worker (`_hop`)**. A memory-safety or logic bug there yields an
unprivileged account, not root. The monitor parses only its own child's fixed
3-primitive protocol over a private socketpair; it has **no network surface**.

**Monitor soundness.** The monitor's power is exactly: make-`100.64/10`-iface,
bind-`(vip,53)`, become-a-validated-non-root-user-and-exec-a-known-helper. There
is no primitive that runs attacker-chosen code as root. Each primitive has a
narrow, typed, range/allowlist-checked input. This is the §T3 argument.

**Comparison.**

| Capability if the network code is compromised | Today (all-root daemon) | Privsep (monitor + `_hop` worker) |
|---|---|---|
| Execute as root | ✅ | ❌ |
| Read any local user's files | ✅ | ❌ (only `_hop`'s) |
| Reconfigure host network / routes | ✅ | ❌ (monitor-only, fixed `/10`) |
| Become arbitrary unix users | ✅ | ❌ (P3 validates, refuses root) |
| Act as this node on the warren | ✅ | ✅ (irreducible — the data plane needs the key) |
| Obtain warren admin/founder authority | only if this node is admin | only if this node is admin (unchanged) |

**Residual risk — the node key must be online.** A data plane that forwards
warren traffic inherently needs a usable node key, so an `_hop` compromise can
impersonate *this node*. This is irreducible without an HSM/Secure-Enclave-backed
key with per-operation user-presence (a possible future evolution: keep the key
in the Secure Enclave and have the monitor or a separate signer mediate). The
mitigation today is least privilege (it's only the node's *own* key, never
admin/founder) + fast revocation. Privsep does not make this worse than today;
it makes *everything else* better.

**Receiver-side ACL becomes more important.** Today reach is enforced
sender-side only (`vpn_outbound_loop`, `netdoc/mod.rs:1590`); `warren.md`
already flags receiver-side enforcement as the intent. With the data plane
unprivileged and the node key potentially reachable via T1, **receiver-side ACL
enforcement** (the receiving worker dropping packets its ACL forbids, regardless
of what a compromised sender does) should land alongside this work — it's the
defense that doesn't depend on every peer's worker being honest.

### 10. Phased plan

- **Phase 0 — Feasibility gate.** Prove a passed TUN fd survives I/O by a
  different uid (§8.1). **Linux: PROVEN** — `privsep-e2e.sh` routes packets over a
  monitor-passed TUN fd, and a TUN fd is uid-agnostic on Linux. **macOS: still
  unrun** — `hop __privsep-probe` (built) must run as root to decide whether a
  passed *utun* fd survives non-root I/O. If it fails on macOS, pivot to B-lite
  (packet I/O stays in the monitor) or option A. macOS activation is contingent on
  this passing.
- **Phase 1 — fd-passing + the monitor skeleton. ✅ DONE (flag-gated, Linux-validated).**
  Stream socketpair (macOS AF_UNIX has no `SEQPACKET`), the `CreateTun`/`BindPrivPort`
  primitives + their validation boundary (warren-range vIP only, `:53` only),
  `SCM_RIGHTS` send/recv (nix cmsg), and the worker-side passed-fd TUN wrapper
  (`tun::Configuration::raw_fd`, wrap-only). `run_monitor` spawns the worker
  (`HOP_PRIVSEP_WORKER` + the control fd) and serves the primitives, holding the
  devices alive for the worker's lifetime. `enable_vpn` calls `acquire_tun` (the
  single integration point); the non-privsep path is byte-equivalent. **The worker
  still runs as root here** — the only change is *who creates the TUN* and that the
  fd crosses the control channel; the privilege drop is Phase 2.
- **Phase 2 — `_hop` service user + ownership migration.** Create `_hop`,
  re-own the config dir, run the worker as `_hop`, plist/unit launches the
  monitor. This is where the EACCES papercuts (`hop invite`/`id`/…) dissolve,
  because the worker reads its own `_hop`-owned secret and the operator's CLI
  goes through the group-readable IPC.
- **Phase 3 — Move privileged session/exec/transfer spawns into the monitor. ✅
  DONE (except persistent shell).** All three primitives ship and the full 53-test
  e2e passes with both hosts under `HOP_PRIVSEP_DROP`: `SpawnSession` (PTY shell),
  `SpawnExec` (pipes + status-fd exit code, sync std exec builder applying the
  Linux `pre_exec` sandbox), `SpawnHelper` (transfer, `login`/uid-drop). The worker
  routes through the monitor whenever it's the unprivileged worker with a bound
  user. **Persistent shells** are refused under drop pending relocation of the
  detached-session machinery (resize task owning the master, pid-based registry
  kill, cancellable reader). Original design notes for reference:

  The privileged **primitive**: `MonitorRequest::SpawnSession` (worker
  sends a concrete `argv` with its embedded `login`/`su`, so the monitor needs no
  sandbox policy), `monitor_spawn_session` (validate → `openpty` → spawn as root →
  pass the master fd → reap the child off-thread), `validate_spawn_session` (argv[0]
  allowlist + username), and `worker_spawn_session`. The **interactive-shell
  surface is integrated**: a `SessionPty` (Local vs monitor-Passed) abstraction in
  `host_shell_session`, `acquire_session_pty` (monitor path iff bound-user +
  non-root + privsep worker), and `check_shell_security` now admits the non-root
  privsep worker. Non-privsep path proven unchanged (full 53-test e2e green).
  **Remaining surfaces** (each its own change, gated by a privsep-drop e2e):
  - **exec** (`host_exec_session`) — pipe-based, not PTY, and harder than shell:
    on Linux the sandbox is an in-process `pre_exec` landlock closure
    (`sandbox/mod.rs:112`), not an argv wrapper, so the monitor (not the worker)
    must apply it. Design (plumbing already in place — `send_fds`/`recv_fds`
    multi-fd passing is built + unit-tested):
    `MonitorRequest::SpawnExec { cmd, policy, username }` (`SandboxPolicy` is
    serde, so it serializes); the monitor builds a **`std::process::Command`**
    (a sync sibling of the tokio `build_exec_command`) with `Stdio::piped()` and
    the platform sandbox (Linux `pre_exec` apply, macOS argv `sandbox-exec`),
    spawns as root, and `send_fds` returns **four** fds — child stdin (write),
    stdout (read), stderr (read), and a **status pipe** (read). A reaper thread
    `wait()`s the child and writes the 4-byte exit code to the status pipe, so
    the worker gets the exit code out-of-band without a control-channel reply.
    The worker wraps the three I/O fds with `tokio::net::unix::pipe` and bridges
    them exactly as today, reading the exit code from the status fd on EOF.
  - **file transfer** (`transfer/helper.rs`) — ✅ done (`SpawnHelper`; all four
    copy/sync arms route through the monitor for the privsep worker).

  - **persistent shell** (`spawn_persistent_pty`) — ✅ done. Acquires its PTY via
    `acquire_session_pty` → `SessionPty` (Local or monitor-Passed). The cancellable
    reader takes the master raw fd from `SessionPty::as_raw_fd` and reports exit on
    EOF when there's no local child (privsep); removal relies on master-close SIGHUP
    (the worker holds the only master fd, since the monitor drops its copy).

  All four surfaces are validated by the 54-test e2e under `HOP_PRIVSEP_DROP`,
  including the `interactive_shell` round-trip, with the non-privsep path byte-preserved.
- **Phase 4 — Hardening + receiver ACL. ✅ ACL done.** The monitor authorizes the
  spawn *target* (`validate_spawn_user`) in two layers: (1) refuse system/service
  accounts (uid < `MIN_SPAWNABLE_UID`), so a compromised worker can't reach
  `root`/`daemon`/`_hop`; (2) if a **root-owned `privsep-users`** file exists in the
  config dir, restrict spawns to exactly those accounts. `load_allowlist` rejects a
  non-root or group/other-writable file (the worker mustn't be able to forge the
  allowlist). Wired into all three spawn validators; uid threshold + parser
  unit-tested; e2e-green under drop. A fully-automatic peer-binding sync is
  impossible under the trust model (the worker owns `peers.json`), so the
  operator-maintained root-owned allowlist is the ceiling, not a TODO.
  **Still open (the only remaining item):** the macOS feasibility gate (§8.1) —
  `sudo hop __privsep-probe` must pass before privsep is activated on macOS. A
  macOS daemon-install e2e (asserting monitor=root / worker=`_hop` / sessions+VPN)
  is the natural follow-up once the gate is run. All Linux surfaces are done.

### 11. Reused components (don't rebuild)

- **Spawn-as-user** (`sandbox/mod.rs:236` `plain_shell`, `sandbox/macos.rs:165`,
  `sandbox/linux.rs:223`, `transfer/helper.rs:36`) → becomes the monitor's P3.
- **`unix_user`** (`is_running_as_root`, `validate_username`, uid/gid lookup,
  `initgroups`) → monitor's validation.
- **Data-plane loops** (`vpn_outbound_loop` `netdoc/mod.rs:1570`,
  `pump_vpn_datagrams` `vpn/mod.rs:137`) → move verbatim into the worker; only
  `create_tun` is replaced by "use the passed fd".
- **launchd plist / systemd unit** (`pkg/com.hop.daemon.plist`, `pkg/hop.service`,
  the embedded `hop __install-daemon`) → launch the monitor; add the `_hop` user.
- **`nix`** (already a dep) for the cmsg/`SCM_RIGHTS` plumbing.

### 12. Open questions (resolve during Phase 0/1)

1. macOS: does a passed utun fd survive I/O by a different uid? (§8.1 — the gate.)
2. macOS: can the worker bind `:53` on the vIP via a *passed* socket fd, or must
   the monitor also own the socket for the lifetime? (Likely pass-and-use, mirror
   the TUN.)
3. Linux: reduce the monitor from full root to ambient
   `CAP_NET_ADMIN`+`CAP_NET_BIND_SERVICE`+`CAP_SETUID/SETGID`? (Strictly better;
   confirm systemd `AmbientCapabilities` covers the setuid-spawn path.)
4. Does any current code assume the daemon euid==0 beyond the 3 primitives (e.g.
   reading other root-owned files, the datastore IPC socket perms)? Audit before
   flipping the worker to `_hop`.


---

## Security & Code-Health Audit — 2026-06-03

A source-level audit of hop (v0.6.36) across five areas: auth/invite/secrets,
warren/VPN/ACL, sandbox/transfer/exec/MCP, installers/release/ops, and
vestigial/dead code. Every finding cites `file:line` and a fix. **This is a
working report to act on**, not a sign-off.

> **Status:** the findings below describe the state at audit time (v0.6.36). Most
> were remediated in **v0.6.37** — see [Remediation status](#remediation-status--v0637-2026-06-03)
> at the end for exactly what shipped and what was deliberately **deferred** (C1
> write-authorization, H8 secrets KDF, H10 root redeem) with the reasoning.

> **Headline.** The cryptographic transport (iroh/QUIC, node-key auth), the
> invite primitives (CSPRNG secret, constant-time hash compare, atomic single-use), and
> the Cedar policy engine are sound *in isolation*. The serious problems are in
> the **trust model around them**, and they matter more because the warren VPN is
> **default-on** (`crates/hop-cli/src/main.rs:424`), despite module docs still
> calling it "experimental / opt-in." Two architectural flaws dominate and should
> gate any default-on posture.

### P0 — Critical (fix before the VPN stays default-on)

#### C1. Every invite embeds a **write-capable** warren ticket → any member can rewrite the whole warren
*Flagged independently by the warren and installer audits.*
- `crates/hop-core/src/netdoc/mod.rs` (`write_ticket` = `ShareMode::Write`), embedded into every invite by `crates/hop-core/src/invite/mod.rs` (reads `<config>/netdoc.ticket`), redeemed by `hop warren join` (`crates/hop-cli/src/main.rs` ~4098-4141).
- iroh-docs write capability is **namespace-wide** — there is no per-key/per-author ACL on the CRDT. So **any** joined member can `put_peer` (self-promote to `role_name:"admin"`), `put_role`, `revoke`/tombstone any peer (DoS/eviction), `set_authored_policy` (author a Cedar `permit` granting itself universal reach), `register_host_tags` (re-tag a target to a tag it reaches), and overwrite `ip/`/`vpn/`/`name/` claims. The Cedar engine faithfully evaluates attacker-controlled inputs. **Per-invite role/sandbox auth is meaningless at the doc layer.**
- **Fix:** embed the **read** ticket (`read_ticket()` already exists but is never used) in member invites; gate write/federation behind an explicit, separately-authorized admin step; validate per-entry author capability on read (reject `acl/*`, `role/*`, `peer/*` not authored by an admin key). This is the root trust fix and is the prerequisite for C-series #2/#3 below to mean anything.

#### C2. VPN data plane has **no ingress authentication**; source-vIP is spoofable → ACL bypass + impersonation
- `crates/hop-core/src/vpn/mod.rs` `VpnInbound::accept` writes any received datagram straight to the TUN with **no check** of `conn.remote_node_id()`, the source vIP, or the destination. Reach (`vpn_reach_allowed`, `netdoc/mod.rs`) is enforced **only on the sender**, keyed on the packet's self-declared source IPv4 (`parse_src_ipv4`, bytes 12-16).
- A malicious member crafts a packet with `src = <victim/admin vIP>` — its own sender check passes (it controls its daemon), and the receiver injects it into the local TUN with a spoofed trusted source. Full ACL bypass + source impersonation to local services. The receiver also applies no `is_virtual_addr`/ownership/dst filtering on ingress.
- **Fix:** enforce on **receive**. In `accept`, resolve `conn.remote_node_id()` → its authorized vIP, drop datagrams whose `parse_src_ipv4` ≠ that vIP; verify `dst` is the local host's vIP; re-run `vpn_reach_allowed(src, dst, port)` on ingress (defense in depth).

#### C3. File transfer (`hop cp`/`sync`) bypasses the sandbox **entirely**
- `crates/hop-core/src/transfer/mod.rs` `host_transfer_session` takes `username` + `protocol_version` but **no `SandboxPolicy`**; `RequestTransfer` is dispatched (`crates/hop-cli/src/main.rs` ~902) without merging the peer's stored policy; `resolve_host_path` accepts any absolute `remote_path` with no `allowed_paths`/`read_only` check.
- A peer pinned to `monitor`/`audit` (read-only, scoped) can read **any** file the bound user can read (`~/.ssh/id_rsa`) and **write/delete any path** (`sync --delete`). Nullifies read-only + path-scope for every restricted peer.
- **Fix:** thread the merged effective `SandboxPolicy` into `host_transfer_session`; reject writes when `read_only`; validate canonicalized `base_path` ⊆ `allowed_paths` for both read and write.

#### C4. MCP JS `readFile`/`writeFile` ignore the sandbox; `hop.http` is an SSRF
- `crates/hop-mcp/src/js/bindings.rs:105-125` — `hop.readFile`/`hop.writeFile` call `std::fs` on arbitrary absolute paths inside the un-sandboxed QuickJS process, regardless of `read_only`/`allowed_paths` (asymmetry: `hop.local` *does* honor the policy).
- `crates/hop-mcp/src/js/bindings.rs:782-847` — `hop.http` gates only on `no_network`; when network is allowed it reaches **any** URL incl. `http://169.254.169.254/...` (cloud IMDS → IAM credential theft), loopback, RFC1918; `reqwest::blocking` follows redirects by default (an allowlisted URL can 302 into IMDS).
- **Fix:** gate `readFile`/`writeFile` on the policy (or route through the sandboxed mechanism); for `hop.http`, reject loopback/link-local/private/IMDS ranges, restrict to http/https, disable or re-validate redirects.

### P1 — High

| # | Location | Issue | Fix |
|---|---|---|---|
| H1 | `netdoc/mod.rs` `claim_virtual_ip` / `register_vpn_endpoint` / `register_name` | Any member can overwrite another node's `ip/`/`vpn/`/`name/` entry → traffic interception (point `vpn/<victim>` at self), MagicDNS spoofing, vIP theft. LWW tie-break only resolves honest races. | Bind these keys to the owning author/node identity; reject replicated updates whose author ≠ claimed node. |
| H2 | `netdoc/mod.rs` `register_posture` + `enable_vpn` self-admin | Posture (`os`/`version`) is self-attested → a node lies (`os:"linux"`) to satisfy posture-gated `permit`s. Owner vs member boundary is the locally-controlled `federated` bool in `netdoc.json`. | Cryptographic posture attestation; derive admin from an owner-signed record, not a local flag. |
| H3 | `netdoc/mod.rs:119-126` reach cache | `invalidate_reach_cache` fires only on **local** writes; a revocation/ACL-tightening arriving via **replication** isn't applied until the 3s TTL lapses (plus unbounded gossip latency). Revoked peer still reachable in the window. | Subscribe to doc change events; invalidate on any reach-affecting replicated key; document the revocation SLA. |
| H4 | `sandbox/macos.rs:67-74` | SBPL profile injection: `allowed_paths` interpolated into the Scheme profile unescaped, and `merge_stricter` takes the **client's** `allowed_paths` when the host list is empty → a crafted path with `")` can append arbitrary SBPL rules = sandbox escape. | Reject paths with `"`/`\`/newline (or escape) before emitting; validate path shapes. |
| H5 | `sandbox/linux.rs:20-130` | `no_network` is **silently unenforced** on Linux (no seccomp/netns/Landlock-net); the module doc falsely advertises "seccomp-BPF". `monitor`/`audit` give zero network isolation. | Landlock ABI≥4 net rules and/or a seccomp `socket()` filter, or a netns; at minimum fail-closed + document. |
| H6 | `sandbox/linux.rs:25-27,120` | Landlock failures are non-fatal (`let _ =`, warn-and-continue); on kernels <5.13 a restricted peer runs unsandboxed with no signal to the client. | When `policy.is_restricted()`, treat Landlock unavailability as fatal (refuse the session). |
| H7 | `crates/hop-cli/src/main.rs:392` + `install.sh:216-221` + `cmd_warren` join | The warren **write** ticket (`netdoc.ticket`, `netdoc-join.ticket`, `warren-ticket`) is written with default `std::fs::write` (umask → typically 0644) on per-user installs → any local user reads it and gains warren write. | Use `write_secret_file` (0600) everywhere these tickets are written; `chmod 600` in install.sh. |
| H8 | `datastore/mod.rs:41-47` | Secrets-at-rest AEAD key = `SHA256("hop-secrets-v1" ‖ identity_secret)` — single pass, no KDF, no salt, **shared across all users**. Confidentiality of all secrets reduces to `identity.json` perms; user-scoping is non-cryptographic. | HKDF-SHA256 with a random per-store salt + domain-separated subkey distinct from the networking identity. |
| H9 | `install.sh:135-144` / `install-daemon.sh:192-201` | Checksum verification silently no-ops when no `sha256sum`/`shasum` (sets `ACTUAL=EXPECTED`). And artifacts are **unsigned** — the `.sha256` sidecar sits beside the binary in the same mutable bucket, so an origin/bucket compromise controls both. | `die` instead of warn-and-skip; sign artifacts with an offline key (minisign/cosign) and verify a signature, not a co-located hash. |
| H10 | `install-daemon.sh:43-48` | `sudo hop warren join "$INVITE"` redeems an **attacker-controlled** invite as **root** — the root daemon dials an attacker relay/node and imports a foreign namespace as root. | Redeem invites as the unprivileged user; confirm host identity before a root daemon imports a foreign namespace. |

### P2 — Medium

| # | Location | Issue | Fix |
|---|---|---|---|
| M1 | `sandbox/validator.rs:34-40` + `policy.rs:55-91` | `allowed_commands`/`denied_commands` are enforced **nowhere** (OS sandbox restricts files/net, not which binary runs). `monitor`'s 22-command allowlist and the deny-list (`rm`,`dd`,…) are decorative → false restriction. | Enforce argv[0] basename at spawn, or remove the fields/presets' reliance so the policy doesn't misrepresent guarantees. |
| M2 | `sandbox/broker.rs:336-376,524-568` | Broker runs `is_broker_safe` commands **unsandboxed** with arbitrary args; some take dangerous flags (`sysctl -w` writes kernel params, defeating read-only; `lsof`/`netstat` leak host-wide state). | Pass only known-safe argv / block write flags; run under the policy where feasible. |
| M3 | `transfer/receiver.rs:53,82-99,130,600-614` | Symlink-assisted write escape + TOCTOU: a session can create an in-tree symlink then write through it; `safe_join` skips the `starts_with(base)` check when the path/parent don't yet exist, and `rename` follows symlinks. Bounded (targets confined to base) but fragile. | Resolve each component against `base` at write time (`openat2(RESOLVE_BENEATH)`/`O_NOFOLLOW`); never follow same-session symlinks. |
| M4 | `invite/mod.rs:204-209` + `admin/mod.rs:126-157` | Creator invites skip username validation at mint → a Creator invite bound to `root`/nonexistent user enters `peers.json` and only fails at session time. (Mitigated: `check_shell_security` hard-blocks root at runtime.) | Validate the username at generation for all roles (still allowing `None`). |
| M5 | `auth/mod.rs:177-197` | The "peers.json always wins" no-lockout fallback never consults doc revocation for a locally-authorized peer → a doc-only revocation (another Creator revokes) doesn't lock the peer out on this host until the local entry is also removed. | Check `is_revoked` (doc tombstone) before the unconditional local allow. |
| M6 | `netdoc/mod.rs` `vpn_dns_loop` + member-writable `name/` | MagicDNS answers from the member-writable `name/` table → name→IP spoofing redirects victim connections. No rate limiting. | Author-bind `name/` (H1); restrict DNS to local queries. |
| M7 | `netdoc/mod.rs` `lookup_host_tags`/`list_posture` etc. | `serde_json::from_slice(...).unwrap_or_default()` on replicated entries → a hostile/corrupt posture entry silently becomes empty (policy behavior depends on attacker-supplied malformed data). | Log + hard-deny/ignore nodes with undecodable security-relevant entries. |
| M8 | `admin/mod.rs:444-463` | `log_admin_action` builds audit JSON via raw `format!` interpolation → log injection / forged entries from role names / node-id prefixes containing `"`/`\`. | Serialize with `serde_json`. |
| M9 | `pkg/com.hop.daemon.plist` + `pkg/hop.service` | Default `--host` install = root, `KeepAlive`, network-listening daemon with **no** systemd hardening (`NoNewPrivileges`/`ProtectSystem`/`User=` absent). | Add systemd hardening; run the data plane as a dedicated unprivileged user where possible. |
| M10 | `CLAUDE.md` relay one-liner | Production relay re-provisioned by `curl|bash` as root (unverified + degradable checksum). Bucket/CDN compromise → root on the relay. | Pull a signed artifact by digest; avoid root SSH. |
| M11 | `datastore/mod.rs:85-114` | `datastore.redb` (encrypted secrets) created with default umask, relaxed to `0o660` group-writable when parent is setgid → ciphertext+nonces group-readable. | Create 0600 when daemon-owned; widen only when genuinely shared. |
| M12 | `config/mod.rs:115-145` | `load_or_generate_identity` writes new keys 0600 but never re-tightens a pre-existing `identity.json` with looser perms (it's the secrets-encryption root). | On load, stat + `set_permissions(0o600)` if owned and wider. |

### P3 — Low / Info (condensed)

- **`scripts/release.sh` ~322** — pushes the **current branch** + tags unconditionally, no clean-tree/branch guard (repo is on `p2p-network`). Add a `main` + clean-worktree assertion. *(Low)*
- **`scripts/release.sh`** — the `latest` plain-text marker (read by every installer to pick the version) is unsigned; a bucket write flips all fresh installs. Sign the version manifest. *(Low)*
- **`hop-mcp/src/js/bindings.rs:1441-1446`** — `__hop_kv_get` builds JSON by string interpolation; serialize via `serde_json`. *(Low)*
- **`hop-mcp/src/js/mod.rs:164-166`** — JS deadline is cooperative (native blocking calls aren't preempted); chained calls can exceed `timeout_secs`. *(Info)*
- **`hop-cli/src/main.rs:1589`** — `hop exec` joins args with spaces and runs through `sh -lc`; shell-evaluated by design but worth documenting (no argv-vector mode). *(Info)*
- **`install.sh:228`** — client auto-redeem `hop exec <invite> -- true 2>/dev/null` hides identity/MITM failures behind a generic fallback. Surface verification failures distinctly. *(Low)*
- **`install-daemon.sh:35` vs `install.sh:64`** — daemon installer only *warns* on unknown flags (a typo'd `--no-vpn` is silently dropped → VPN unexpectedly on); install.sh `die`s. Make them consistent (die). *(Info)*
- **Good:** `setup-aws.sh` blocks public bucket access, scopes the policy to one distribution, forces HTTPS. DNS/HuJSON parsers are bounds-checked (no panic/OOM). ChaCha20 nonces are fresh-random per write. Session-resume is bound to the authenticated `PublicKey`. Admin requests are correctly gated to Creator.

### Vestigial / dead code (separate from security)

**Remove (DEAD):**
- `crates/hop-core/src/vpn/acl.rs:57-99` — `AclPolicy` + `evaluate`/`permits` (+ its tests): replaced by the Cedar engine; not on any live path.
- `crates/hop-core/src/netdoc/mod.rs` — `get_acl_policy`/`set_acl_policy`: zero callers (read/write the dead `AclPolicy`).
- `crates/hop-core/src/invite/mod.rs:50` — `suggested_tier` on `InviteToken`: write-only, only ever set to `None` in prod; never read for a decision. (`#[serde(default)]` → removal is wire-compatible.)
- `crates/hop-core/src/netdoc/mod.rs:1085` — `test_endpoint_with_key`: unused test helper (the only real dead-code build warning).
- `crates/hop-cli/src/oauth.rs` — the `#![allow(dead_code)]` legacy `detect_claude_credentials*` / `parse_claude_oauth` / `ClaudeCredentials` family: never called (live path uses `oauth_provider`/`run_oauth_flow`). Remove + drop the blanket allow.
- `crates/hop-core/src/extensions/registry.rs:147` — `#[allow(dead_code)] manifest_dir` field: stored, unused.

**Wire up (UNWIRED — currently inert):**
- `set_authored_policy` (`netdoc/mod.rs`) — **no CLI sets it**, so `get_authored_policy` can only ever return `None`; authored Cedar policies are unreachable. Wire `hop acl set-policy` (needs the daemon↔netdoc IPC channel) or remove until then.
- `RoleDefinition.capabilities` — populated by the importer + shown by `hop acl caps`, but **never delivered** to any service (no `HOP_APP_CAPS`/`hop whois`). Wire delivery or document as import-only metadata.
- `admin/mod.rs:440` — `active_sessions: 0 // TODO`: hardcoded; wire the session registry or drop the field.

**Keep (verified FINE):** `role_reaches` (live in `hop acl check` + Cedar's test oracle); `PeerRole`/`Creator` (load-bearing — gates admin auth, invite TTL, root mapping); all dependencies (no unused deps found, incl. the iroh-docs/gossip/blobs stack); the `eprintln!` logging (intentional, not debug leftovers).

**Doc drift (all since resolved):** the drift found here has been corrected — the
`acl-cedar-plan` doc has been retired as a completed plan (the Cedar engine
shipped), `data-and-automation.md`'s `hop auth` "(Planned)" marker was dropped, and the
VPN module docstrings now match reality: the VPN was reverted to **off by
default** (P0a below), so "opt-in / off by default" is accurate.

### Prioritized remediation plan

1. **P0a — Close the warren trust model (C1).** Read-ticket member invites + gate write/federation behind an explicit admin step + per-entry author validation on read. This is the keystone; H1, H2 (admin self-claim), M6 all collapse once writes are authorized. Until done, **disable the VPN default-on** (flip `vpn_enabled` default to false / require `--host` opt-in) and fix the stale "opt-in" docstrings to match reality.
2. **P0b — Authenticate the data plane (C2).** Ingress check: `remote_node_id()` → authorized vIP; drop spoofed source/foreign dst.
3. **P0c — Make the sandbox a real boundary (C3, C4).** Thread the policy into transfer; gate JS file bindings; block SSRF in `hop.http`.
4. **P1 — Harden:** ticket/identity/secrets file perms (H7, H8, M11, M12), SBPL injection (H4), Linux no_network + fatal Landlock (H5, H6), revocation latency (H3), artifact signing + die-on-no-checksum (H9), un-root the redeem (H10).
5. **P2/P3 — Consistency & hygiene:** enforce or drop command allow/deny lists (M1), broker arg restrictions (M2), symlink/TOCTOU (M3), doc-revocation override (M5), audit-log JSON (M8), systemd hardening (M9), release branch guard, dead-code removals, doc-drift fixes.

### Remediation status — v0.6.37 (2026-06-03)

**Fixed:**
- **P0a** — VPN flipped off-by-default (`vpn_enabled` default false; `--host` /
  `HOP_VPN=1` / `hop config set vpn on` opt in); docstrings corrected; installer
  primers opt a node back in only on explicit `--host`/node install.
- **P0b** — VPN data-plane ingress authentication: `VpnInbound` delivers a
  datagram only when the connecting node is a registered peer, the source vIP
  matches that node's registered vIP, and the destination is our own vIP.
- **P0c (C3/C4)** — transfer now enforces the peer's `SandboxPolicy`
  (read-only + `allowed_paths`); JS `readFile`/`writeFile` confined to scope and
  read-only-aware; `hop.http` blocks SSRF (loopback/private/link-local/CGNAT/
  IMDS + v6 equivalents) and disables redirects for restricted peers.
- **P1/P2** — H4 (SBPL escaping), H5/H6 (Landlock fatal-when-restricted +
  no_network via Landlock TCP rules + honest docs), H7 (ticket files 0600),
  H9 (install.sh die-on-no-checksum + ticket umask 077), M5 (doc-revocation
  overrides a local allow), M8 (audit-log via serde_json), M9 (systemd note +
  LockPersonality; heavier sandboxing intentionally omitted — sessions are
  children of the unit), M11/M12 (datastore 0600, identity re-tighten),
  release branch guard.
- **Dead code** — removed `AclPolicy`/`Action`/`Rule` + `get/set_acl_policy`,
  `suggested_tier`+`Tier`, `test_endpoint_with_key`, `manifest_dir`, and the
  legacy `oauth.rs` credential-detection family (+ blanket `allow(dead_code)`).
- **Doc drift** — `data-and-automation.md` `hop auth` marked Shipped; README already
  Shipped; VPN docstrings now accurate (off-by-default again).

#### Deferred items — why, and what mitigates them now

Three findings were deliberately **not** fixed in v0.6.37. In each case the
*correct* fix is a structural change with a credible way to break legitimate
access or destroy data, while a cheaper interim mitigation already shrinks the
exposure materially. hop's operating constraint — *it may be the only way into a
system* — means a fix that risks lockout or data loss is worse than a documented,
mitigated gap. Each is tracked here so the next pass starts with the context
intact.

##### C1 — Warren trust model (the keystone)

**Finding.** Every invite embeds a `ShareMode::Write` iroh-docs `DocTicket` for
the shared warren document. That document holds *all* security-relevant warren
state: virtual-IP claims (`ip/`), VPN endpoint registrations (`vpn/`), MagicDNS
names (`name/`), device posture, and peer/role records. Because every member
holds a **write** ticket, any member can rewrite any of it — repoint
`vpn/<victim>` at their own node to intercept traffic, spoof a MagicDNS name,
claim another node's vIP, or forge posture to satisfy a posture-gated policy.
Last-writer-wins conflict resolution only arbitrates *honest* races; it offers
nothing against a malicious writer.

**Why it's the keystone.** H1 (key overwrite), H2 (self-attested posture/admin),
and M6 (DNS spoofing) are all *symptoms* of C1 — they collapse the moment writes
are authorized per author.

**Why deferred.** The real fix is structural and multi-layer: issue members
**read-only** tickets, gate write/federation behind an explicit admin action,
and validate on read that each entry's author matches the identity it claims to
speak for (`vpn/<node>` is writable only by `<node>`). That touches ticket
issuance, the replication-read path, admin gating, and migration of existing
warrens. Landing it half-right could either lock legitimate nodes out of their
own warren or silently leave the hole open; it needs its own focused pass with
its own e2e coverage. (`set_authored_policy`/`get_authored_policy` are the
inert scaffolding for the authored-policy half of this — see UNWIRED below.)

**Mitigation shipped.** This is *why* P0a flipped the VPN off-by-default. With
the warren/VPN dormant unless explicitly enabled (`--host` / `HOP_VPN=1` /
`hop config set vpn on`), a bare `hop host` no longer joins a writable shared
document at all — the blast radius shrinks to nodes that have deliberately
opted in. P0b (ingress auth) independently blocks the *traffic-interception*
exploitation path even when `vpn/` is tampered with: a forged registration
still can't produce correctly-sourced, authenticated packets.

##### H8 — Secrets-at-rest KDF

**Finding.** The AEAD key for the encrypted secrets store is
`SHA256("hop-secrets-v1" ‖ identity_secret)` — a single hash pass, no HKDF, no
per-store salt, identical derivation for every user on the box. The recommended
shape was HKDF-SHA256 with a random per-store salt and a domain-separated
subkey.

**Why deferred — two independent reasons:**
1. **The fix risks destroying data.** Any change to the derivation changes the
   *output* key, rendering every already-encrypted secret on every deployed host
   undecryptable on upgrade. The only safe path is a key-rotation migration
   (decrypt-with-old → re-encrypt-with-new → versioned marker) — real surface
   that can't be validated against live field stores in this pass, and whose
   failure mode is *permanently unreadable secrets*. That is the precise
   opposite of "rock solid."
2. **The benefit is near-zero against the real threat.** The threat is an
   attacker who can read the filesystem. The key derives from `identity.json`,
   so anyone who can read the ciphertext db can also read `identity.json` and
   re-derive the key under *any* KDF. A per-store salt doesn't help either — it
   would live in the same db the attacker is already reading. Domain separation,
   the one property that genuinely matters here, is *already* present via the
   `"hop-secrets-v1"` label.

So: high risk of data loss, negligible security gain. Revisit only alongside a
proven migration path. The actual protection for secrets-at-rest is filesystem
permissions, which *were* hardened this pass — M11 pins the datastore to `0600`,
M12 re-tightens `identity.json` to `0600` on load.

##### H10 — Root invite redeem

**Finding.** `install-daemon.sh` runs `sudo hop warren join "$INVITE"` — the
root daemon redeems an operator-supplied invite, dials the inviting node, and
imports a foreign namespace **as root**. A malicious invite points the root
daemon at an attacker's relay/node.

**Why deferred.** This is inherent to the install *model*, not a discrete bug.
The daemon runs as root because it must `su` to arbitrary users, create the TUN
device, and write `/etc/hop` — and the join ticket has to land in that
root-owned config dir. A real fix means redesigning `warren join`'s privilege
split: redeem as an unprivileged user, confirm host identity, then hand only the
validated ticket to the daemon. And critically: an operator pasting `--invite`
into a root install command *is* the authorization — a malicious invite here is
a social-engineering vector that exists for any "paste this to join" UX, root or
not.

**Mitigation shipped.** Same lever as C1 — VPN off-by-default. A bare daemon
install no longer auto-joins a warren; the foreign-namespace import happens only
when the operator explicitly passes `--invite`/`--join`, making the trust
decision explicit rather than implicit.

##### Lower-severity / inert (next pass)
- **H1 / H2 / H3 / M6** — all collapse into C1 (author-bound keys); revisit with C1.
- **M1 / M2 / M3** — command allow/deny enforcement, broker argument
  restrictions, transfer symlink/TOCTOU hardening: real but lower-severity.
- **UNWIRED (not security bugs)** — `set_authored_policy` /
  `RoleDefinition.capabilities` / `active_sessions` remain inert; wire or remove
  in a later pass.

*Last updated: v0.6.37*
