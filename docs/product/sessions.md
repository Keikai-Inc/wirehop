# Sessions

hop supports persistent PTY sessions that survive client disconnects, automatic reconnection, and a connection multiplexer agent for efficient multi-session management.

## Session Persistence

When a client disconnects (network drop, laptop close, etc.), the PTY session on the host stays alive. The shell process continues running and every output byte is absorbed by an off-screen virtual terminal so that on reconnect the host can repaint the current screen state.

### Behavior

- Sessions are identified by a random 16-byte hex session ID
- A detached session keeps its shell process running in the background
- Default timeout: **24 hours** after disconnect (configurable)
- Sessions with exited child processes are reaped automatically
- All PTY output is fed through a `VtScreen` (alacritty terminal grid). On reconnect the host renders the current grid to bytes and sends those — not a ring of historic bytes.

### Session Lifecycle

```
connect         -> new PTY spawned, session registered, VtScreen seeded
disconnect      -> session enters "detached" state, timer starts
reconnect       -> session re-attached, VtScreen repainted to client
timeout/exit    -> session reaped, PTY closed (sends SIGHUP to shell)
```

---

## Multi-Session Support

Each peer can have multiple concurrent sessions. Sessions are keyed by session ID (not by peer+username), so multiple `hop connect` invocations create independent PTYs.

### Capacity and Eviction

| Setting | Default | Description |
|---|---|---|
| `max_sessions` | `10` | Maximum total detached PTY sessions |
| `session_timeout_secs` | `86400` (24h) | How long a detached session stays alive |

When the session limit is reached, the **oldest detached** (non-attached) session is evicted to make room. Attached sessions are never evicted.

### Eviction Priority

1. Exited + detached sessions are reaped first (periodic reap cycle)
2. Timed-out detached sessions are reaped next
3. If still at capacity, the oldest detached session is evicted on new insertion

---

## Reconnection

When a connection drops, hop attempts automatic reconnection with a two-tier strategy:

### Tier 1: Quick Reconnect

- Prints a single-line inline banner: `[hop] Connection lost. Reconnecting...`
- Attempts reconnection within a short timeout
- On success: host repaints the current screen, then live output resumes
- On failure: escalates to Tier 2

### Tier 2: TUI Reconnect

- Enters an alternate-screen TUI (ratatui-based)
- Shows connection status and retry attempts
- User can press a key to quit instead of waiting
- On success: host repaints the current screen, then live output resumes

### Resume Repaint

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

## Connection Agent

The connection agent is a singleton background process that owns a single iroh `Endpoint` and multiplexes all sessions over QUIC bi-streams. This avoids the overhead of creating a new QUIC endpoint per `hop connect`.

### Architecture

```
hop connect myhost  ─── IPC (Unix socket) ───> hop agent ─── QUIC ───> remote host
hop connect myhost  ─── IPC (Unix socket) ───┘
hop sync ...        ─── IPC (Unix socket) ───┘
```

- All client commands communicate with the agent via a Unix domain socket
- The agent maintains a pool of QUIC connections, one per remote host
- Each client session gets a dedicated QUIC bi-stream within the shared connection

### Auto-Start

The agent starts automatically on the first `hop connect` if not already running. It can also be managed explicitly:

```bash
# Explicit management
hop agent                # start in foreground
hop agent --daemon       # start in background (writes PID file)
hop agent status         # check if running
hop agent stop           # stop via SIGTERM
```

### Idle Timeout

The agent shuts down after **10 minutes** with no active sessions, freeing system resources.

### IPC Protocol

| Direction | Message | Description |
|---|---|---|
| Client -> Agent | `MuxConnect { host_id, relay_url }` | Request connection to a host |
| Agent -> Client | `MuxResult::Ready` | Bi-stream open, start sending protocol messages |
| Agent -> Client | `MuxResult::Error(msg)` | Connection failed |

Messages are length-prefixed bincode over the Unix socket. After `Ready`, the socket becomes a transparent byte pipe to the remote host's QUIC bi-stream.

### Files

| Path | Description |
|---|---|
| `<config>/agent.sock` | Unix domain socket for IPC |
| `<config>/agent.pid` | PID file for the daemon |
| `<config>/agent.log` | Log file |

---

## Configuration

Session settings are configured via `hop config`:

```bash
# Set session timeout to 1 hour (3600 seconds)
hop config set session_timeout 3600

# Set max sessions to 20
hop config set max_sessions 20
```

### HostConfig Fields

| Key | Type | Default | Description |
|---|---|---|---|
| `session_timeout_secs` | u64 | `86400` | Detached session lifetime in seconds |
| `max_sessions` | usize | `10` | Max detached PTY sessions |

Configuration is stored in `host_config.json` in the config directory.

*Last updated: v0.4.3*
