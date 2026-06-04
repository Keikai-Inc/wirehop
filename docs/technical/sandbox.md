# Sandbox

## Architecture

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
for restricted peers; C4). See [../product/transfer.md](../product/transfer.md) and
[../product/js-api.md](../product/js-api.md).

## SandboxPolicy Struct

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

## Presets

Three built-in presets via `SandboxPolicy::from_preset(name)`:

### monitor

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

### audit

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

### deploy

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

## Policy Composition: merge_stricter()

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

## Validator

The application-layer validator in `crates/hop-core/src/sandbox/validator.rs` is defense-in-depth -- it catches obvious violations before any process is spawned. The OS kernel sandbox is the actual security boundary.

### validate_command()

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

### shell_split()

Minimal shell-like word splitting that respects quotes:

- Single quotes: everything inside is literal (no escaping)
- Double quotes: backslash escaping is honored
- Backslash outside quotes: escapes the next character
- Returns `None` for unbalanced quotes

### Metacharacter Detection

Tracked characters (outside single quotes): `;`, `|`, `&`, `>`, `<`, `` ` ``, `$(` (two-character sequence). The scanner tracks quoting state (`in_single`, `in_double`) character by character.

**Note**: Backslash-escaped metacharacters (e.g., `\;`) are still rejected. This is intentional -- the validator is conservative.

## Broker

The broker in `crates/hop-core/src/sandbox/broker.rs` solves a macOS-specific problem: `sandbox-exec` blocks ALL setuid binaries (including `ps`, `top`, `netstat`) even with `(allow default)`.

### Architecture

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

### Broker-Safe Commands

Read-only system tools that are setuid on macOS:

```rust
const BROKER_SAFE_COMMANDS: &[&str] = &[
    "ps", "w", "who", "last", "lastlog", "uptime", "netstat", "lsof",
    "iostat", "vm_stat", "sysctl", "sw_vers", "system_profiler",
    "diskutil", "ifconfig", "finger", "top",
];
```

### Protocol

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

### Shim Setup

`setup_shim_dir()` creates `<config_dir>/broker/<session_id>/bin/` with symlinks for each broker-safe command pointing to the hop binary. The shim directory is prepended to PATH via a custom ZDOTDIR (for zsh) so symlinks take precedence.

`setup_zdotdir()` creates a custom zsh dotfile directory that:
1. Sources the user's real dotfiles (`$HOME/.zshenv`, `.zprofile`, `.zshrc`, `.zlogin`)
2. Prepends the shim bin directory to PATH after `/etc/zprofile` runs (which resets PATH via `path_helper` on macOS)
3. Sets `HOP_BROKER_SOCK` environment variable
4. Unsets `HISTFILE` to prevent writes in read-only sandboxes

## macOS Enforcement: Seatbelt Profiles

`crates/hop-core/src/sandbox/macos.rs` generates SBPL (Sandbox Profile Language) profiles for `sandbox-exec`.

### Profile Generation

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

### Shell Wrapping

For PTY sessions with a user, the command chain is:
```
login -fp <user> /usr/bin/sandbox-exec -p <profile> <shell> -l
```
`login` is setuid and must run before `sandbox-exec` (which strips setuid).

Without a user:
```
/usr/bin/sandbox-exec -p <profile> <shell> -l
```

## Linux Enforcement: Landlock

`crates/hop-core/src/sandbox/linux.rs` uses Landlock (Linux 5.13+) for unprivileged filesystem sandboxing.

### apply_sandbox()

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

### Landlock Rules

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

### Shell Wrapping (Linux)

Since `portable_pty::CommandBuilder` does not support `pre_exec` hooks, Linux uses a self-exec wrapper:

```
hop __sandbox-shell --policy <json> -- <shell> -l
```

The hop binary re-invokes itself with the `__sandbox-shell` subcommand, applies Landlock + no_new_privs in-process, then execs the real shell. The policy is serialized as JSON in the command arguments.

For users: `hop __sandbox-shell --policy <json> -- su - <username>`

*Last updated: v0.6.33*
