# Host reachability and self-recovery

How a host notices that it cannot be reached, what it does about it, and what
the client does when a host stops answering. Written after the 2026-09-11
incident, in which a host stayed unreachable for about an hour while every
local signal (relay session, UDP endpoint, VPN, DNS, cron) was green.

Companion to [warren-internals.md](warren-internals.md) (endpoint, relay,
netmon) and [security.md](security.md) (privilege separation).

---

## The two failures with one symptom

| | Under memory pressure | After a pooled path died |
|---|---|---|
| Host log | `Incoming connection attempt` then `aborted by peer` 10 s later, repeatedly, then one `Connection from` | `Connection from: <peer> (protocol v3)` with **no** `Authorized peer` after it; nothing else for 20 min; then `read frame length: connection lost: closed by peer: 0` |
| Cause | The daemon was partly swapped out (1 GB free, 18 GB swap); the QUIC handshake was answered late and the client's 10 s dial timeout gave up | The client's agent reused a pooled QUIC connection whose path could no longer carry stream data. QUIC keepalives still flowed, so neither the transport's idle timeout (60 s) nor the agent's rx-stall watchdog fired |
| What the host could do | Nothing; it did not even log the slowness | Nothing; it waited for the auth message with no deadline, so the wedged connection was never closed and the client never re-dialed |
| What the client did | Retried, and eventually got through | Every `hop connect` was handed the same wedged connection: dial "succeeded", the session request went nowhere, and after 5 s the client continued into the shell loop anyway |

The one host-side event during the outage was macOS retiring a *temporary*
IPv6 address, which netmon counted as a network change (iroh re-discovery
plus a mux-pool flush). It was not the cause, but it is a state change that
happens daily and served nobody.

---

## Host-side guards

All in `crates/hop-cli/src/main.rs` (accept path) and
`crates/hop-core/src/net/health.rs` unless noted.

| Guard | Where | Behaviour |
|---|---|---|
| QUIC handshake deadline | `handle_incoming` | 30 s. A handshake still pending after that is dropped; counted as aborted. |
| Application handshake deadline | `handle_incoming_inner` | 20 s from QUIC completion to the auth message. On expiry: WARN naming the peer, connection closed, counted as timed out. The client sees the close and its next attempt re-dials. |
| First message on a multiplexed stream | `handle_incoming_inner` | Read inside the per-stream task with a 30 s deadline. A silent stream no longer stalls the connection's accept loop or holds a task forever. |
| Slow-handshake warning | both | A QUIC or auth handshake slower than 1 s logs `Slow QUIC handshake from …` / `Slow auth handshake from …`. This line alone names a memory-pressure episode. |
| Inbound counters | `net::health` | Every completed inbound handshake records `last_inbound_ok`; ok / aborted / timed-out counts are kept for the probe's log lines. |
| Inbound liveness probe | `net::health::spawn_inbound_probe` | See below. |
| Self-restart | `net::health::request_restart` | One channel; the accept loop exits cleanly on receipt (sessions checkpointed). Used by the probe and by `hop recover`. |
| Transient IPv6 filter | `net/netmon.rs` | Temporary (RFC 4941), deprecated, tentative, duplicated and detached IPv6 addresses are excluded from the interface set, so their rotation no longer triggers re-discovery or a pool flush. macOS: `SIOCGIFAFLAG_IN6`; Linux: `/proc/net/if_inet6` flags. |
| `hop/probe/1` ALPN | `proto`, `net::create_host_endpoint` | Accepted by the host endpoint; a connection carrying it is answered at the QUIC layer and closed. Never authenticated or dispatched. |

### The inbound liveness probe

The relay-health watcher proves the relay answers HTTPS. The probe proves
*this host* can be reached through it, the way a remote client would:

1. Every 5 min (`HOP_INBOUND_PROBE_SECS` overrides; first run after 2 min),
   unless a real inbound handshake completed within the last interval.
2. Precondition: the home relay answers HTTPS. If not, the round is skipped
   and not counted (the relay watcher owns that failure; a restart would not
   help).
3. Bind a throwaway endpoint: fresh random key, relay-only (`RelayMode::custom`
   with the home relay), no address lookup, no mDNS. Dial our own node id with
   the relay hint and `hop/probe/1`, 20 s budget. A completed handshake is a
   pass; the connection is closed immediately.
4. Escalation on consecutive failures: 2 → `endpoint.network_change()`
   (ERROR logged); 4 → `request_restart` (about 20 min of provable
   unreachability through a reachable relay). Any success resets the count.

Log lines to grep for: `Inbound liveness probe started`, `Inbound probe ok`,
`Inbound probe FAILED`, `Forcing iroh re-discovery`, `Requesting daemon
self-restart`.

### What a self-restart does

The worker exits with status 0 after checkpointing sessions. Under privilege
separation the monitor respawns it (a worker that ran ≥ 30 s is not a fast
failure); a plain root daemon is respawned by launchd `KeepAlive` or systemd
`Restart=`. The new worker binds a fresh iroh endpoint and relay session.
Persistent sessions come back through the checkpoint/restore path.

---

## `hop recover` without root

`DsRequest::Restart` on the daemon socket asks the daemon to restart itself.
The socket is owned by the operator group (`admin` on macOS, `hop` on Linux),
so any operator shell on the host can do it, including a shell reached over
hop when hop is the only way in.

```
hop recover                # non-root: kills stray user agents, then asks the
                           # daemon over its socket; prints
                           # "daemon asked to restart itself (over its socket, no root needed)"
sudo hop recover           # root: launchctl kickstart / systemctl restart, as before
hop --config DIR recover   # target a daemon serving DIR (tests, a second host)
```

A daemon older than this change closes the socket without a reply; `hop
recover` then prints the old `re-run with sudo hop recover` message. The
first upgrade onto a version with `Restart` therefore still needs one root
restart.

---

## Client-side guards

| Guard | Where | Behaviour |
|---|---|---|
| Pooled-connection liveness check | `agent.rs::check_pooled_liveness` | Before a *pooled* connection to a hop/4 host is handed to a session: open a bi-stream, send `ClientMessage::Ping`, expect `HostMessage::Pong` within 2 s. On failure the connection is force-evicted (live sessions or not, by `stable_id`, so a concurrent replacement is untouched) and the request dials fresh. |
| Session-setup deadline | `reconnect.rs::run_initial_connect` | After the dial, the host has 10 s to answer the session request (`SessionInfo`). Silence or a stream error is a failed attempt: the next attempt dials with `evict_first`, dropping the pooled connection. The spinner says so. |
| No silent fallthrough | `main.rs::cmd_connect` | The setup handshake now happens inside the connect loop, under its deadline; the interactive loop starts only with an answered session request. Previously a 5 s `SessionInfo` timeout was treated as "old host, continue". |

`Ping`/`Pong` are appended to the end of both wire enums (bincode variant
order) and used only on hop/4 connections; an older host never sees them.

---

## Resource leaks fixed in the same change

| Leak | Where | Fix |
|---|---|---|
| Session stuck `attached: true` | `shell/mod.rs::host_shell_session_persistent` | A `?` between `registry.attach`/`insert` and `run_attached_loop` (writing `SessionInfo` or the repaint) left the session attached with nobody behind it: unreapable, un-evictable, holding a PTY, a shell tree and three blocking threads. Setup failures now detach. |
| Exec stdin task outliving the exec | `shell/mod.rs::host_exec_session` | The stdin proxy task owned the QUIC recv stream and only ended when the client stopped sending; on a long-lived pooled connection one parked task per exec. Aborted when the exec ends. |
| Connection pinned by a peer that never speaks | `main.rs::handle_incoming_inner` | The deadlines above. |
| Zombie `claude` children | `hop-mcp/src/js/bindings.rs` | `kill()` without `wait()` on timeout left a `<defunct>` child for the daemon's lifetime (observed on RexMundi). Reaped now. |
| Unbounded audit queue | `audit.rs` | A reconnect storm records a `session.start` per resume (13k for one session in the incident log). The queue is bounded at 8192; overflow is dropped and counted (`audit::dropped`), logged once per power of two. |
| Per-host semaphore map | `agent.rs` | Cleared on pool flush. |

Still open, from the incident review: memory-pressure awareness in the
daemon, a `hop status` for hosts (the counters exist in `net::health`), and
`hop doctor`.
