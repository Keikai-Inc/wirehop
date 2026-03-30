# Sessions

hop supports persistent PTY sessions that survive client disconnects, automatic reconnection, and a connection multiplexer agent for efficient multi-session management.

## Session Persistence

When a client disconnects (network drop, laptop close, etc.), the PTY session on the host stays alive. The shell process continues running and output is buffered for replay on reconnect.

### Behavior

- Sessions are identified by a random 16-byte hex session ID
- A detached session keeps its shell process running in the background
- Default timeout: **24 hours** after disconnect (configurable)
- Sessions with exited child processes are reaped automatically
- Output generated while detached is captured in a replay buffer (64 KB ring buffer)

### Session Lifecycle

```
connect         -> new PTY spawned, session registered
disconnect      -> session enters "detached" state, timer starts
reconnect       -> session re-attached, replay buffer drained to client
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
- On success: resumes the session seamlessly (replay buffer is drained)
- On failure: escalates to Tier 2

### Tier 2: TUI Reconnect

- Enters an alternate-screen TUI (ratatui-based)
- Shows connection status and retry attempts
- User can press a key to quit instead of waiting
- On success: returns to the session with replay

### Replay Buffer

The `ReplayBuffer` is a 64 KB ring buffer attached to each session. It captures the most recent PTY output so that reconnecting clients see recent context (like mosh) instead of a blank screen.

```
disconnect -> output continues into ring buffer (old bytes evicted)
reconnect  -> buffer drained to client, then live output resumes
```

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
