# Networking

## iroh Endpoints

hop uses iroh (QUIC-based P2P networking) for all connections. Two endpoint types are created in `crates/hop-core/src/net/mod.rs`:

### Host Endpoint

```rust
pub async fn create_host_endpoint(secret_key: SecretKey) -> Result<Endpoint>
```

- Binds with ALPNs: `[hop/3, hop/2, hop/1, hop/0]` (newest first)
- Uses `hop_relay_mode()` (custom relay only)
- Uses `hop_transport_config()` (custom QUIC tuning)
- **Waits for online**: `endpoint.online().await` blocks until connected to relay and address is published to discovery. Without this, clients cannot find the host.

### Client Endpoint

```rust
pub async fn create_client_endpoint(secret_key: SecretKey) -> Result<Endpoint>
```

- No ALPNs (clients don't accept incoming connections)
- Same relay and transport config as host
- **5-second relay timeout**: if the relay does not come online within 5 seconds, proceeds anyway. Clients can still connect via discovery.

### QUIC Transport Configuration

```rust
fn hop_transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .max_idle_timeout(15s)     // Detect dead peers in 15s (iroh default: 30s)
        .keep_alive_interval(3s)   // ~40 bytes/3s, 5 missed probes = dead
        .initial_rtt(300ms)        // Cellular-friendly initial estimate
        .build()
}
```

Rationale:
- **15s idle timeout**: survives 10s cellular stalls while detecting dead peers in half the time of iroh's 30s default.
- **3s keepalive**: aggressive enough for responsive detection, light enough for metered links.
- **300ms initial RTT**: prevents aggressive retransmission on cellular before QUIC measures actual RTT.

## Relay URL

hop uses a single custom relay server:

```rust
pub const HOP_RELAY_URL: &str = "https://relay.keik.ai";
```

`hop_relay_mode()` returns `RelayMode::custom([hop_relay])`, which excludes iroh's public relays. This ensures all hop traffic flows through controlled infrastructure. If the relay is unreachable, iroh falls back to discovery-based direct connections.

### Relay Persistence

The relay URL is stored in several places:
- `known_hosts.json`: each `KnownHost` entry has an optional `relay_url` field
- Invite tokens: `InviteToken.relay_url` embeds the host's relay URL
- On connection, the cached relay URL is updated via `KnownHostsStore::update_relay_url()`

### Connection with Relay Hint

```rust
pub async fn connect_to_host(
    endpoint: &Endpoint,
    remote_id: PublicKey,
    relay_url: Option<&RelayUrl>,
) -> Result<(Connection, bool)>
```

When a relay URL is provided (from known_hosts or invite tokens), it is included as a hint in the `EndpointAddr`. This allows iroh to immediately relay traffic while also attempting direct paths via discovery. Without the hint, iroh must discover the relay URL via DNS/pkarr first, which can delay or fail.

The default ALPN for `connect_to_host` is `ALPN_V2`. Use `connect_to_host_with_alpn` for a specific version.

## Warren Network Document & VPN

The warren (P2P private network) runs on a **third, isolated iroh endpoint**,
separate from the host and client endpoints above.

### netdoc endpoint

`net::create_netdoc_endpoint` binds an endpoint keyed by `derive_netdoc_secret_key`
(a stable, derived NodeId distinct from the host identity). It runs the iroh-docs
replication stack — an `iroh::protocol::Router` hosting `Docs` (CRDT), `Gossip`,
and `Blobs` — which `crates/hop-core/src/netdoc/mod.rs` wraps as `NetDoc`. This
document holds membership, roles, revocations, virtual IPs, VPN endpoints, host
tags, and MagicDNS names (see [protocol.md](protocol.md#warren-protocols-vpn--netdoc)).
Like the host endpoint it waits for relay readiness before publishing, and it
re-publishes its VPN endpoint (NodeId + relay) into the document so peers can dial
it by virtual IP.

**Sync resumption (reboot resilience).** iroh-docs only starts live sync on the
first `import` (the ticket carries peer addresses); reopening a persisted
namespace — the path on every restart — does **not**. So on each daemon start
`NetDoc::resume_sync` rebuilds peer addresses from the replicated `vpn/` endpoint
table and calls `Doc::start_sync`, and `spawn_sync_keepalive` re-affirms it every
5 minutes. Without this a rebooted node would reopen a stale local replica and
never reconverge (membership/role/IP updates wouldn't propagate). The persisted
namespace id (`netdoc.json`), local replica, and deterministic virtual IP mean a
rebooted node rejoins the *same* warren with the *same* address.

### VPN data plane (`hop/vpn/1`)

When the VPN is enabled (off by default; see below), `NetDoc::enable_vpn`:

1. claims a stable virtual IP in `100.64.0.0/10` (deterministic hash + doc claim),
2. creates a TUN device (`vpn::create_tun`, utun on macOS / `/dev/net/tun` on
   Linux, MTU 1280, netmask `255.192.0.0` so the kernel routes the whole `/10`),
3. registers the VPN endpoint + host tags in the document, and records its own
   vIP + the peer-vIP map used for ingress authentication,
4. spawns an outbound loop (TUN → reach-check → QUIC datagram to the destination's
   VPN endpoint) and the `VpnInbound` handler (authenticated datagram → TUN).

**Ingress authentication (v0.6.37).** `VpnInbound` writes a received datagram to
the TUN only after three checks: (a) the connecting node (QUIC/TLS-verified
`remote_id`) is a registered VPN peer, (b) the datagram's *source* virtual IP
matches that node's registered vIP — anti-spoofing — and (c) the *destination* is
this host's own vIP. The peer→vIP map is read per datagram and refreshed from the
`vpn/` table every 5 s, plus on-demand (rate-limited) when a packet arrives from
an as-yet-unknown peer, so a node that just rebooted reconverges quickly. This
closes the prior gap where any node could inject packets with a spoofed source
vIP.

**Connection liveness — keepalive + stable redial.** The data plane runs on
QUIC datagrams, which return `Ok` on send even over a dead path, so
`close_reason()` alone never detects a silently-dead connection (a rebooted peer
sends no CLOSE frame). The outbound loop therefore:

- **Keepalive (every 5 s):** sends a `VPN_KEEPALIVE` heartbeat datagram (a
  non-IP marker — leading `0xFF`, so it can never be injected to the TUN even if
  the ingress marker check is bypassed) to every peer connection. This keeps the
  QUIC path validated/warm and the remote's `last_rx` fresh, so a *live-but-idle*
  connection is never mistaken for dead and redialed. It's also what makes a
  multipath failover land on an already-warm path rather than cold-validating a
  new one.
- **No teardown on transient send failure:** a `send_datagram` error drops the
  connection from the cache **only if `close_reason().is_some()`** (genuinely
  closed). A transient failure — no validated path yet on a freshly-dialed
  multipath connection, or an over-MTU packet — is kept. Tearing down on the
  first failed packet previously caused a redial storm (drop → next packet
  redials → drop → …) that prevented any cold connection from finishing
  establishment (the no-admin-online reconnect failure).
- **Liveness-gated reuse:** a connection is reused while it's open and either
  `last_rx` is fresh (within `STALE_AFTER` = 20 s, i.e. ≤4 missed heartbeats) or
  it was dialed within `DIAL_GRACE` = 30 s (the cold-reconnect window). Past
  that with no inbound datagram it's treated as silently-dead and redialed.
  Closed connections are reaped during the keepalive pass.

**Off by default, fail-safe.** As of v0.6.37 the VPN is off unless explicitly
enabled (`--host` / `HOP_VPN=1` / `hop config set vpn on`) — the default was
reverted while the warren's write-authorization trust model is hardened (see
[p2p-network.md](p2p-network.md) and `security-audit.md` C1). Bringup is
best-effort: if the TUN can't be created or `cgnat_range_in_use()` finds the
`100.64.0.0/10` range already claimed by another interface (e.g. Tailscale), the
VPN is skipped and the daemon serves normally. `HOP_VPN=1` forces past the
conflict guard; `HOP_VPN=0` is a recovery escape hatch.

## Network Monitoring

`crates/hop-core/src/net/netmon.rs` implements a lightweight interface poller that detects IP address changes and kicks iroh's re-discovery.

### Interface Polling

```rust
const POLL_INTERVAL: Duration = Duration::from_secs(5);

pub fn current_interface_addrs() -> BTreeSet<IpAddr>
```

Every 5 seconds, `current_interface_addrs()` enumerates all non-loopback, non-link-local IP addresses using `nix::ifaddrs::getifaddrs()`.

Filtered out:
- IPv4 loopback (`127.0.0.0/8`)
- IPv4 link-local (`169.254.0.0/16`)
- IPv6 loopback (`::1`)
- IPv6 link-local (`fe80::/10`)

### Change Detection

```rust
pub fn spawn_interface_watcher(
    endpoint: Endpoint,
    flush_tx: Option<mpsc::Sender<()>>,
) -> JoinHandle<()>
```

When the set of interface addresses changes:
1. Logs added/removed addresses at INFO level
2. Calls `endpoint.network_change().await` to force iroh to re-probe paths
3. If `flush_tx` is provided (agent side): waits 2 seconds for QUIC path migration, then signals the caller to flush pooled connections

This is a belt-and-suspenders layer over iroh's built-in `netwatch` -- catches interface changes that the OS-level socket monitor sometimes misses (e.g., plugging in Ethernet on macOS).

## Connection Agent

The agent process (`crates/hop-cli/src/agent.rs`) owns a single iroh Endpoint and multiplexes all client sessions over QUIC bi-streams. It uses the actor pattern for thread-safe mutable state management.

### Singleton Lifecycle

```
~/.config/hop/agent.pid    # PID file
~/.config/hop/agent.sock   # IPC Unix socket
~/.config/hop/agent.log    # stderr log
```

1. Client calls `ensure_agent(config_dir)`:
   - Try `UnixStream::connect(agent.sock)` -- if success, agent is running
   - If not, spawn `hop agent --daemon --config <dir>` with stderr redirected to `agent.log`
   - Retry connect with linear backoff: 50ms, 100ms, 150ms, ..., up to 20 attempts
2. Agent writes its PID to `agent.pid` on startup
3. Agent removes socket and PID file on shutdown

### Idle Timeout

The agent shuts down after 10 minutes (`IDLE_TIMEOUT = 600s`) with no active sessions. The `CheckIdle` command queries the actor for staleness.

### Actor Pattern

```rust
enum AgentCommand {
    GetConnection { host_id, relay_url, reply },   // Request/create connection
    ConnectDone { host_id, result },                // Connect task completed
    RemoveConnection { host_id },                   // Evict stale connection
    FlushAll,                                       // Flush after network change
    TouchActivity,                                  // Bump last_activity
    CheckIdle { reply },                            // Query idle status
}

struct AgentState {
    endpoint: Endpoint,
    connections: HashMap<PublicKey, Connection>,     // Pooled QUIC connections
    semaphores: HashMap<PublicKey, Arc<Semaphore>>,  // Per-host concurrency limit
    pending: HashMap<PublicKey, Vec<ConnectReply>>,  // In-flight connect waiters
    tx: mpsc::Sender<AgentCommand>,                 // Self-sender for spawned tasks
    last_activity: Instant,
}
```

All mutable state is owned by the actor task. External callers interact via `AgentHandle` which sends commands over an `mpsc::channel(64)`.

### Connection Pooling

When `GetConnection` arrives:
1. If a cached `Connection` exists: return it immediately
2. If a connect is in-flight for this host: queue the reply channel in `pending`
3. Otherwise: spawn a connect task, queue the reply

When `ConnectDone` arrives:
- On success: cache the connection, create a per-host `Semaphore`, reply to all waiters
- On failure: reply error to all waiters

## Mux Protocol

`crates/hop-cli/src/mux.rs` defines the IPC protocol between CLI processes and the agent.

### MuxConnect (Client -> Agent)

```rust
pub struct MuxConnect {
    pub host_id: [u8; 32],          // Target host's PublicKey
    pub relay_url: Option<String>,   // Relay URL hint
}
```

### MuxResult (Agent -> Client)

```rust
pub enum MuxResult {
    Ready,              // Bi-stream open, start sending hop protocol messages
    Error(String),      // Connection failed
}
```

### Stream Proxying

After `MuxResult::Ready`, the Unix socket becomes a transparent bidirectional pipe to a QUIC bi-stream. The client writes hop protocol messages (`ClientMessage`) and reads responses (`HostMessage`) directly through the IPC socket -- the agent just copies bytes.

### IPC Framing

Same 4-byte big-endian length-prefixed bincode as the hop protocol:

```rust
pub async fn write_ipc_message<T: Serialize>(stream, msg) -> Result<()>
pub async fn read_ipc_message<T: Deserialize>(stream) -> Result<T>
```

Max IPC frame: 16 MiB.

### Target Resolution

`mux::connect_to_host()` resolves the target string in order:
1. **Known host alias**: `KnownHostsStore::resolve_alias(target)` -- matches by name
2. **Invite token**: `invite::is_invite_token(target)` -- base64url decode, run auth flow
3. **Direct NodeId**: parse as hex PublicKey -- connect without auth

## Reconnection

`crates/hop-cli/src/reconnect.rs` implements a two-tier reconnection flow:

### Tier 1: Quick Inline Reconnect

```rust
pub async fn try_quick_reconnect(config_dir, resolved, session_request, timeout) -> Option<ReconnectAction>
```

Prints a single-line banner in the current terminal and attempts to reconnect within the timeout. On success, clears the banner and returns `ReconnectedViaAgent`. On failure, returns `None` so the caller escalates to Tier 2.

Retry loop with 5-second connect attempts within the overall timeout window. On success, sends the session request + setup messages (WindowSize, SetEnv) before reading SessionInfo.

### Tier 2: Full TUI

If quick reconnect fails, a full-screen ratatui TUI is shown with reconnection status, countdown, and option to quit.

### ReconnectAction

```rust
pub enum ReconnectAction {
    ReconnectedViaAgent { send, recv, new_session_id },
    Quit,
}
```

## MCP Audit Log

`crates/hop-mcp/src/audit.rs` logs every MCP tool invocation to `<config_dir>/mcp_audit.jsonl`.

### AuditEntry Format

Each line is a JSON object:

```rust
pub struct AuditEntry {
    pub timestamp: String,        // ISO 8601
    pub tool: String,             // Tool name (e.g., "exec", "fleet_exec")
    pub host: Option<String>,     // Target host (if applicable)
    pub arguments: Value,         // Tool arguments as JSON
    pub result_summary: String,   // Brief result description
    pub duration_ms: u64,         // Execution time
    pub success: bool,            // Whether the operation succeeded
}
```

Written as append-only JSONL (one JSON object per line). The file is opened with `O_CREAT | O_APPEND` for crash-safe writes. Serialization or file open failures are logged as warnings but do not fail the operation.

*Last updated: v0.6.33*
