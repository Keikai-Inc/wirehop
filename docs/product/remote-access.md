# Remote Access — Sessions & Transfer

Interactive shell sessions (persistence, reconnection, the connection agent) and file transfer (`hop cp`, `hop sync`, delta + compression).


---

## Sessions

hop supports persistent PTY sessions that survive client disconnects, automatic reconnection, and a connection multiplexer agent for efficient multi-session management.

### Session Persistence

When a client disconnects (network drop, laptop close, etc.), the PTY session on the host stays alive. The shell process continues running and every output byte is absorbed by an off-screen virtual terminal so that on reconnect the host can repaint the current screen state.

#### Behavior

- Sessions are identified by a random 16-byte hex session ID
- A detached session keeps its shell process running in the background
- Default timeout: **24 hours** after disconnect (configurable)
- Sessions with exited child processes are reaped automatically
- All PTY output is fed through a `VtScreen` (alacritty terminal grid). On reconnect the host renders the current grid to bytes and sends those — not a ring of historic bytes.

#### Session Lifecycle

```
connect         -> new PTY spawned, session registered, VtScreen seeded
disconnect      -> session enters "detached" state, timer starts
reconnect       -> session re-attached, VtScreen repainted to client
timeout/exit    -> session reaped, PTY closed (sends SIGHUP to shell)
```

### Recovery latency (session-recovery-parity)

Interactive sessions are engineered to recover on the VPN's heels after a
network event:

- **Zombie detection**: the connection agent watches each pooled QUIC
  connection's receive counters; 15s without a datagram (3 missed 5s
  keepalives) closes the connection as a zombie instead of waiting out QUIC's
  60s idle timeout, so the reconnect flow engages within seconds of a silent
  path death.
- **Fail-fast dials**: reconnect dials time out at 10s, and the hop/2 ALPN
  fallback is skipped when hop/3 *timed out* (a dead path would hang it
  identically) — the old worst case serialized 60s of dialing that every
  "retry now" queued behind.
- **Network-change reset**: an interface change resets the anti-flap backoff
  (the flaps were the old network's fault) and re-enables the instant quick
  reconnect tier.
- During any reconnect state: `Enter` retries immediately, `q`/`Ctrl+C`
  quits — including after stray keypresses (typed input is distinguished from
  pasted input by bracketed-paste state).

Set `HOP_SESSION_DEBUG=1` to print a one-line timing summary on every
recovery. The release gate `tests/e2e/session-resilience.sh` enforces SRT
(session-recovery-time) budgets per perturbation, including a silent-stall
scenario, and reports the parity delta against the VPN's own recovery in the
same event (artifact: `tests/e2e/session-results.md`).

---

### Listing Sessions

```bash
hop sessions                 # sessions on this machine's daemon
hop sessions myserver        # sessions on one host
hop sessions --all           # every reachable warren member and known host
hop sessions --all --json
```

One line per session: a short session id, the Unix user it runs as, its
state (`attached`, `detached`, or `exited N`), how long it has been detached,
a `*N` in BELL if it rang the bell N times since anyone last attached, and
the captured app's window title (whatever it set with OSC 0/2, so a Claude
Code session shows what it is working on). Attaching acknowledges the bells.

The host answers from its session registry; nothing is stored. Over the
network this is `PeerRequest::ListSessions` (hop/4), so a host older than
0.9.38 reports "unexpected request" rather than a list.

### Attention

When a session rings the bell (BEL, OSC 9, or OSC 777) while nobody is
attached to it, the host tells every client that *is* attached to one of its
other sessions, and that client raises a terminal notification (OSC 9, which
iTerm2, kitty, ghostty, WezTerm, foot, VS Code and Windows Terminal show on
the desktop; OSC 777 for urxvt-style terminals). So a long-running agent that
finishes, or asks a question, reaches you in whichever window you are working
in. One event per session per 30 seconds.

- Off on the host: `hop config set notify off` (applies to sessions started
  afterwards).
- Off on a client: `HOP_NOTIFY=off`.
- Attached nowhere: `hop sessions --all --watch` polls every host and raises
  a desktop notification (`osascript` on macOS, `notify-send` on Linux) when a
  detached session rings the bell. `--interval <secs>` sets the poll (default 15).

### Multi-Session Support

Each peer can have multiple concurrent sessions. Sessions are keyed by session ID (not by peer+username), so multiple `hop connect` invocations create independent PTYs.

#### Capacity and Eviction

| Setting | Default | Description |
|---|---|---|
| `max_sessions` | `10` | Maximum total detached PTY sessions |
| `session_timeout_secs` | `86400` (24h) | How long a detached session stays alive |

When the session limit is reached, the **oldest detached** (non-attached) session is evicted to make room. Attached sessions are never evicted.

#### Eviction Priority

1. Exited + detached sessions are reaped first (periodic reap cycle)
2. Timed-out detached sessions are reaped next
3. If still at capacity, the oldest detached session is evicted on new insertion

---

### Reconnection

When a connection drops, hop attempts automatic reconnection with a two-tier strategy:

#### Tier 1: Quick Reconnect

- Prints a single-line inline banner: `[hop] Connection lost. Reconnecting...`
- Attempts reconnection within a short timeout
- On success: host repaints the current screen, then live output resumes
- On failure: escalates to Tier 2

#### Tier 2: TUI Reconnect

- Enters an alternate-screen TUI (ratatui-based)
- Shows connection status and retry attempts
- User can press a key to quit instead of waiting
- On success: host repaints the current screen, then live output resumes

#### Resume Repaint

Each session owns an off-screen virtual terminal (`hop_vt::VtScreen`) — an alacritty grid fed by a vt parser. Every PTY output byte advances this grid on the host as it's read; the grid is the canonical session state.

On resume, the host calls `screen.render_full_repaint()` which emits:

- SGR reset and `\x1b[2J\x1b[H` (clear + home)
- `\x1b[?1049h` if the captured app is in the alternate screen — so vim/htop/less land on the matching screen mode regardless of the client's prior state
- One `\x1b[r;1H` cursor-move per row plus SGR-grouped UTF-8 cells
- Final cursor restore at the captured app's logical position

Because the bytes come from grid state and not a byte stream:

- **No truncated escape sequences** — a 64 KB ring could bisect a long OSC/CSI/DCS; the grid only holds complete cells
- **No stale mode bits** — alt-screen, scroll regions, cursor style follow the captured app's *current* state, not a historical sequence that may have been evicted
- **No late query responses** — captured-app queries like `\x1b[c` (DA1) or `\x1b]11;?` are consumed by the parser, never replayed (a common source of `:3838/0c0c` color-leak artefacts in vim under naïve byte replay)
- **No "long-inactivity blank screen"** — the grid contains whatever's on screen now, regardless of how long the session has been idle

Scrollback is not preserved by the host; the captured app's PTY/shell don't maintain scrollback either. Pre-disconnect scrollback lives in the client's local terminal emulator, which preserves it through the `\x1b[2J` repaint by pushing the cleared viewport into its own scrollback.

---

### Connection Agent

The connection agent is a singleton background process that owns a single iroh `Endpoint` and multiplexes all sessions over QUIC bi-streams. This avoids the overhead of creating a new QUIC endpoint per `hop connect`.

#### Architecture

```
hop connect myhost  ─── IPC (Unix socket) ───> hop agent ─── QUIC ───> remote host
hop connect myhost  ─── IPC (Unix socket) ───┘
hop sync ...        ─── IPC (Unix socket) ───┘
```

- All client commands communicate with the agent via a Unix domain socket
- The agent maintains a pool of QUIC connections, one per remote host
- Each client session gets a dedicated QUIC bi-stream within the shared connection

#### Auto-Start

The agent starts automatically on the first `hop connect` if not already running. It can also be managed explicitly:

```bash
# Explicit management
hop agent                # start in foreground
hop agent --daemon       # start in background (writes PID file)
hop agent status         # check if running
hop agent stop           # stop via SIGTERM
```

#### Idle Timeout

The agent shuts down after **10 minutes** with no active sessions, freeing system resources.

#### IPC Protocol

| Direction | Message | Description |
|---|---|---|
| Client -> Agent | `MuxConnect { host_id, relay_url }` | Request connection to a host |
| Agent -> Client | `MuxResult::Ready` | Bi-stream open, start sending protocol messages |
| Agent -> Client | `MuxResult::Error(msg)` | Connection failed |

Messages are length-prefixed bincode over the Unix socket. After `Ready`, the socket becomes a transparent byte pipe to the remote host's QUIC bi-stream.

#### Files

| Path | Description |
|---|---|
| `<config>/agent.sock` | Unix domain socket for IPC |
| `<config>/agent.pid` | PID file for the daemon |
| `<config>/agent.log` | Log file |

---

### Configuration

Session settings are configured via `hop config`:

```bash
# Set session timeout to 1 hour (3600 seconds)
hop config set session_timeout 3600

# Set max sessions to 20
hop config set max_sessions 20
```

#### HostConfig Fields

| Key | Type | Default | Description |
|---|---|---|---|
| `session_timeout_secs` | u64 | `86400` | Detached session lifetime in seconds |
| `max_sessions` | usize | `10` | Max detached PTY sessions |

Configuration is stored in `host_config.json` in the config directory.

*Last updated: v0.6.33*


---

## File Transfer

hop provides two file transfer modes: `cp` for direct file copying and `sync` for rsync-style directory synchronization. Both operate over QUIC streams with automatic compression negotiation and privilege separation.

### hop cp

Copy files to/from a remote host. Uses `host:path` notation for remote paths.

#### Syntax

```bash
hop cp [-r] <source>... <dest>
```

#### Push and Pull

```bash
# Push: local -> remote
hop cp ./file.txt myhost:/tmp/file.txt
hop cp -r ./project/ myhost:/home/user/project/

# Pull: remote -> local
hop cp myhost:/var/log/app.log ./logs/
hop cp -r myhost:/etc/nginx/ ./backup/nginx/
```

#### Flags

| Flag | Description |
|---|---|
| `-r`, `--recursive` | Copy directories recursively (required for directories) |

#### Trailing-Slash Semantics

Trailing slashes on source paths follow rsync conventions:

```bash
# With trailing slash: copy CONTENTS of dir into dest
hop cp -r ./project/ myhost:/home/user/dest/
# Result: /home/user/dest/file1, /home/user/dest/file2, ...

# Without trailing slash: copy the dir itself into dest
hop cp -r ./project myhost:/home/user/dest/
# Result: /home/user/dest/project/file1, /home/user/dest/project/file2, ...
```

#### Path Resolution

| Input | Interpretation |
|---|---|
| `/absolute/path` | Local absolute path |
| `./relative/path` | Local relative path |
| `host:path` | Remote -- `host` is an alias, NodeId, or invite token |
| `host:` | Remote home directory (`~`) |

Windows drive letters (e.g. `C:\`) are recognized as local paths.

---

### hop sync

rsync-style directory synchronization with delta transfer. Only transfers changed file content.

#### Syntax

```bash
hop sync [flags] <source> <dest>
```

#### Examples

```bash
# Sync local to remote
hop sync ./dist/ myhost:/var/www/html/

# Sync remote to local
hop sync myhost:/var/www/html/ ./backup/

# Dry run -- show what would change
hop sync -n ./dist/ myhost:/var/www/html/

# Delete files on dest that don't exist on source
hop sync --delete ./dist/ myhost:/var/www/html/

# Itemized changes (show per-file status)
hop sync -i ./dist/ myhost:/var/www/html/

# Full stats report
hop sync --stats ./dist/ myhost:/var/www/html/
```

#### Flags

| Flag | Short | Description |
|---|---|---|
| `--delete` | | Delete extraneous files from destination not present in source |
| `--dry-run` | `-n` | Show what would be transferred without doing it |
| `--itemize-changes` | `-i` | Show itemized list of changes per file |
| `--stats` | | Show detailed transfer statistics |
| `--no-progress` | | Suppress per-file progress bars (show only filenames) |

The following flags are accepted for rsync compatibility but are no-ops (hidden from `--help`): `-a`/`--archive`, `-z`/`--compress`, `-P`, `--progress`, `-H`/`--human-readable`.

---

### Delta Transfer

Sync uses a block-level delta algorithm (rsync-style) to minimize data transfer for modified files:

1. **Receiver** computes rolling (Adler32-variant) + strong (xxh3-64) checksums per block of the existing file and sends them as block signatures
2. **Sender** rolls through the new file byte-by-byte, matching blocks via rolling hash then verifying with strong hash
3. **Sender** emits a stream of delta operations (`CopyBlock` or `Literal`) which the receiver applies to reconstruct the new file

This means only the changed portions of files are transferred, not entire files.

---

### Compression

Transfer sessions negotiate compression parameters at connection time.

| Protocol | Compression | Max Chunk Size |
|---|---|---|
| hop/0 (legacy) | None | 64 KiB |
| hop/1+ | zstd (default level 3) | 1 MiB |

Compression is negotiated automatically between sender and receiver. The zstd level and max chunk size are agreed upon during session setup.

---

### Progress Display

File transfers show real-time progress by default:

- Per-file progress bars with transfer speed and ETA
- `--no-progress` suppresses per-file bars and shows only filenames
- `--stats` prints a summary report after completion
- `--itemize-changes` shows a per-file change indicator (similar to rsync's `-i`)
- Dry-run mode (`-n`) lists changes without transferring data

---

### Privilege Separation

When the hop daemon runs as root and a session is bound to a Unix user, file transfers are executed via a privilege-separated helper process (`__transfer-helper`). The helper runs as the target user, ensuring all file I/O uses kernel-enforced user permissions. This applies to all transfer modes: copy push, copy pull, sync push, and sync pull.

### Sandbox enforcement

Transfers honor the connecting peer's `SandboxPolicy` (the same policy that
gates shell/exec). As of v0.6.37 the policy is enforced on the transfer data
plane itself — previously it was not, so a restricted peer could read or write
any path regardless of its role:

- **Read-only policy** (e.g. the `monitor`/`audit` presets) — a push (peer →
  host write) is rejected before any I/O; pulls are still allowed.
- **`allowed_paths` scope** — both directions are confined to the policy's
  allowed roots. The base path is canonicalized (resolving symlinks and `..`,
  including for not-yet-existing write targets) and must lie under an allowed
  root, so a transfer can't escape its scope.

Unrestricted peers (no policy / full-access roles) are unaffected. Rejections
are surfaced to the client as a transfer error.

*Last updated: v0.6.37*
