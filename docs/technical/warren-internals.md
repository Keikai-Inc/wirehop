# Warren Internals — P2P Network, VPN & ACL

The full internal design of the warren: the iroh endpoint/relay/netmon networking layer and VPN data plane, the orchestratorless iroh-docs state model and its 13 design decisions, per-member write-isolated self-docs, the install/invite capability tiers, and the Cedar-based ACL (with a Tailscale comparison).


---

## Networking

### iroh Endpoints

hop uses iroh (QUIC-based P2P networking) for all connections. Two endpoint types are created in `crates/hop-core/src/net/mod.rs`:

#### Host Endpoint

```rust
pub async fn create_host_endpoint(secret_key: SecretKey) -> Result<Endpoint>
```

- Binds with ALPNs: `[hop/3, hop/2, hop/1, hop/0]` (newest first)
- Uses `hop_relay_mode()` (custom relay only)
- Uses `hop_transport_config()` (custom QUIC tuning)
- **Waits for online**: `endpoint.online().await` blocks until connected to relay and address is published to discovery. Without this, clients cannot find the host.

#### Client Endpoint

```rust
pub async fn create_client_endpoint(secret_key: SecretKey) -> Result<Endpoint>
```

- No ALPNs (clients don't accept incoming connections)
- Same relay and transport config as host
- **5-second relay timeout**: if the relay does not come online within 5 seconds, proceeds anyway. Clients can still connect via discovery.

#### QUIC Transport Configuration

```rust
fn hop_transport_config() -> QuicTransportConfig {
    QuicTransportConfig::builder()
        .max_idle_timeout(60s)               // survive WiFi/cellular handoffs; still detect dead peers in ~1 min
        .keep_alive_interval(5s)             // 12 missed probes before death; ~40 bytes/5s is negligible
        .initial_rtt(300ms)                  // cellular-friendly initial estimate
        .max_concurrent_multipath_paths(13)  // keep WiFi/cellular/relay paths warm for instant failover
        .default_path_keep_alive_interval(5s)
        .default_path_max_idle_timeout(20s)
        .build()
}
```

Rationale:
- **60s idle timeout**: survives WiFi handoffs (5-15s), cellular tower switches (10-30s), and brief relay hiccups, while still detecting a truly dead peer in ~1 minute.
- **5s keepalive**: 12 missed probes before death — responsive without being chatty on metered links.
- **300ms initial RTT**: prevents aggressive retransmission on cellular before QUIC measures the actual RTT.
- **Multipath (13 paths)**: keep several validated paths (WiFi, cellular, relay) alive at once so a network move is absorbed by an already-warm backup instead of a full reconnect. (This was briefly dropped to 1 to dodge a per-packet leak in the QUIC engine; that leak is fixed in the vendored `noq-proto`, so concurrent multipath is restored.)

#### Address filter — never advertise the VPN overlay IP

Every hop endpoint (host, client, netdoc) sets an iroh `addr_filter` (`hop_addr_filter`)
that **drops the VPN overlay range `100.64.0.0/10` from the addresses it publishes**.
The VPN virtual IP lives on the `utun`/TUN device — it is the *overlay*, reachable
only *through* the hop tunnel. If a node advertised it as an iroh direct address,
peers would try to hole-punch to each other through the tunnel itself — a routing
loop (the target IP routes straight back into `utun`). Those dead/loop paths pile up
against `max_concurrent_multipath_paths`, so after a network change iroh can't
establish the real new path (`maximum number of concurrent paths reached`) and the
connection can't migrate — which flapped the control/session (hop/3) connections.
Relays, real IPs, and custom transports pass through unchanged.

### Relay URL

hop uses a single custom relay server:

```rust
pub const HOP_RELAY_URL: &str = "https://relay.keik.ai";
```

`hop_relay_mode()` returns `RelayMode::custom([hop_relay])`, which excludes iroh's public relays. This ensures all hop traffic flows through controlled infrastructure. If the relay is unreachable, iroh falls back to discovery-based direct connections.

#### Relay Persistence

The relay URL is stored in several places:
- `known_hosts.json`: each `KnownHost` entry has an optional `relay_url` field
- Invite tokens: `InviteToken.relay_url` embeds the host's relay URL
- On connection, the cached relay URL is updated via `KnownHostsStore::update_relay_url()`

#### Connection with Relay Hint

```rust
pub async fn connect_to_host(
    endpoint: &Endpoint,
    remote_id: PublicKey,
    relay_url: Option<&RelayUrl>,
) -> Result<(Connection, bool)>
```

When a relay URL is provided (from known_hosts or invite tokens), it is included as a hint in the `EndpointAddr`. This allows iroh to immediately relay traffic while also attempting direct paths via discovery. Without the hint, iroh must discover the relay URL via DNS/pkarr first, which can delay or fail.

The default ALPN for `connect_to_host` is `ALPN_V2`. Use `connect_to_host_with_alpn` for a specific version.

### Warren Network Document & VPN

The warren (P2P private network) runs on a **third, isolated iroh endpoint**,
separate from the host and client endpoints above.

#### netdoc endpoint

`net::create_netdoc_endpoint` binds an endpoint keyed by `derive_netdoc_secret_key`
(a stable, derived NodeId distinct from the host identity). It runs the iroh-docs
replication stack — an `iroh::protocol::Router` hosting `Docs` (CRDT), `Gossip`,
and `Blobs` — which `crates/hop-core/src/netdoc/mod.rs` wraps as `NetDoc`. This
document holds membership, roles, revocations, virtual IPs, VPN endpoints, host
tags, and MagicDNS names (see [Architecture — Warren protocols](architecture.md#warren-protocols-vpn--netdoc)).
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

#### Membership lifecycle (admin mutations)

Every admin mutation that changes the roster — invite-redeem, `grant`/`SetPeerRole`,
`remove-peer`, `rename`, `create-user`, role create/update, fleet-tag — runs the
**same post-mutation reconcile** regardless of whether it arrived over the network
(`RequestAdmin` handler) or through the local datastore socket (`hop admin self …`):

1. **Local store write** — the handler updates `peers.json` / `roles.json`.
2. **Explicit revoke (removals only)** — `remove-peer` writes a
   `revocation/<id>` tombstone via `NetDoc::revoke`. This is required because
   `reconcile` is **additive-only** in a federated/shared namespace (it never
   deletes doc entries), so a removal that isn't tombstoned would never propagate.
3. **Reconcile (additions)** — `reconcile(peers, roles)` re-publishes any roster
   entries missing from the doc. It only *adds*, so it can't cross-revoke another
   host's members.
4. **Upsert (in-place updates)** — a `grant` or `rename` changes an **existing**
   peer, which reconcile skips. `NetDoc::put_peer` force-writes that one peer's
   `peer/<id>` blob so the new `role_name` / display name actually reach the doc
   (and therefore the warren snapshot).
5. **Refresh admin authors + re-export snapshot** — `refresh_admin_authors`
   re-resolves who may write admin entries; `export_warren_snapshot` rebuilds the
   member/role view that `hop fleet` reads.

`propagate_admin_mutation` (netdoc/mod.rs) encapsulates steps 2–5 and is invoked by
both paths.

**Roster hygiene (G25): liveness, name backfill, pruning.** The roster is
append-only — a member persists until explicitly revoked — so liveness and stale
removal are layered on top:

- **Liveness.** `last_seen` on a roster `Peer` refreshes only on a new authenticated
  *control-plane* connection (a VPN-only-but-idle member would look dead), so the
  daemon merges the **VPN data-plane** signal at snapshot-export time:
  `build_warren_snapshot` takes, per member, the later of `last_seen` and
  `vpn_last_rx` (the founder receives each active member's keepalive every ~5s, keyed
  by the member's `vpn_endpoint` id). `WarrenMemberInfo::is_online(now, window)`
  then drives `online`/`offline` in `hop fleet list` and the fan-out filter (the
  default 15-min window is `fleet::DEFAULT_LIVENESS_WINDOW_SECS`). `hop fleet
  exec`/`grep` skip offline members by default (`--include-offline` forces all).
- **Name backfill.** A member admitted without a bound username gets the
  `generate_peer_display_name` fallback `peer-<short_id>`. Each member self-registers
  `name/<hostname> = <vIP>` in its self-doc; the founder's periodic sweep
  (`NetDoc::backfill_peer_names`, on the snapshot tick) reverse-maps a `peer-XXXX`
  entry's vIP to that hostname (author-validated, same C1 binding as `lookup_name`)
  and rewrites `peer/<id>.name`. Idempotent; runs once the member's self-doc lands.
- **Pruning.** `NetDoc::stale_members(older_than, now)` dates each member by the
  merged liveness and returns those past the threshold — **never** this node, and
  never a member with no recorded contact at all (a fresh, never-connected invite).
  `prune_stale_members` revokes each (a replicated tombstone) and re-exports.
  `hop fleet prune` drives this over the local operator socket (admin-gated, like
  `hop admin self`), so the sole admin can prune its own warren; `--dry-run` returns
  the would-prune set without mutating. An optional `prune_after_secs` HostConfig
  TTL makes the founder's daemon auto-evict on its sweep.
- **Source of duplicates.** A *new* roster node-id is only ever admitted at invite
  redemption (`auth/mod.rs`, recording the redeemer's `remote_id`); there is no guard
  that it's a daemon vs a transient client endpoint. The protection is the unified
  machine identity (the CLI/agent and daemon share one on-disk key), which is what
  stops a client endpoint from being recorded as a second member; pruning + backfill
  clean up legacy residue from before that discipline.

**Reconcile never revokes self.** On a non-federated (single-owner) namespace
`reconcile`'s removal sweep revokes any netdoc peer absent from `peers.json`. The
founder's own `peer/<self>` is written straight to the netdoc by `enable_vpn` and
is *not* in `peers.json`, so the sweep must skip it — `NetDoc::set_host_node_id`
records the host's own id (before the startup reconcile, and again in `enable_vpn`)
and the sweep skips that id. Without this skip a runtime `propagate_admin_mutation`
tombstoned the founder out of its own roster (startup masked it because `enable_vpn`
re-creates the entry right after). `enable_vpn` also clears any stale founder
self-revocation on bringup (`clear_revocation` → `is_revoked` reads a content-empty
tombstone-over-tombstone as not-revoked), which is the general un-revoke / re-admit
primitive. The local-socket path is what lets a **sole-admin warren** self-admin:
the admin node can't mux-connect to itself, so `hop admin self …` resolves the
target as local (`admin_target_is_local`) and routes the mutation through
`DsRequest::Admin`, after which the daemon runs the identical reconcile — a revoke
on the admin node propagates a tombstone, drops the member from the snapshot, and
denies that peer's next session, with no second admin required.

#### VPN data plane (`hop/vpn/1`)

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

**Reliability under partial netdoc sync (degrade-don't-die).** The data plane
depends on the replicated roster, but iroh-docs syncs entry *keys* and *blob
content* separately — content can lag (or an interrupted sync can leave an entry
key present with its content missing, `entity not found`). Three layers keep a
transient gap from black-holing the tunnel rather than only degrading it:

- **Read-path resilience.** `list_prefix` skips a single entry whose content
  hasn't synced (or is malformed) instead of failing the whole read — one lagging
  blob never empties the roster. `refresh_vpn_peer_ips` keeps the
  last-known-good ingress map on a roster read error or an empty computed map
  (a transient gap can't wipe working routes). Egress resolution
  (`lookup_vpn_endpoint`) falls through to the vIP owner's **node-id** when no
  endpoint blob is available, and `vpn_reach_allowed` **fails open** on a roster
  read error — safe because delivery is still gated by endpoint resolution (an
  unknown vIP has no endpoint and is dropped there, so fail-open can't reach a
  non-member).
- **Active content heal.** `ensure_content_synced` (slow periodic sweep + on the
  unauthenticated-ingress signal) finds roster entries whose blob content is
  missing locally and re-fetches it from a current doc sync peer via the
  iroh-blobs `Downloader`. Plain re-sync won't do this (no entry diff once the
  key reconciled). Strictly best-effort: it only *adds* missing content, so it
  can never regress the data plane; a cheap no-op once everything is present.
- **One worker owns the node-id.** `cmd_host` acquires the datastore's exclusive
  lock **before** binding the iroh endpoint. A successor that can't get the lock
  (a predecessor is still alive — e.g. an overlapping restart/upgrade) exits
  *before* binding, so it can never put a second endpoint with this machine's
  node-id on the relay. Two endpoints sharing a node-id get prune-stormed by the
  relay, which is what interrupts sync and strands content in the first place;
  the lock is the guarantee that exactly one worker exists.

**Off by default, fail-safe.** As of v0.6.37 the VPN is off unless explicitly
enabled (`--host` / `HOP_VPN=1` / `hop config set vpn on`) — the default was
reverted while the warren's write-authorization trust model is hardened (see
[Peer-to-Peer Private Network](#peer-to-peer-private-network-design) and `security.md` C1). Bringup is
best-effort: if the TUN can't be created or `cgnat_range_in_use()` finds the
`100.64.0.0/10` range already claimed by another interface (e.g. Tailscale), the
VPN is skipped and the daemon serves normally. `HOP_VPN=1` forces past the
conflict guard; `HOP_VPN=0` is a recovery escape hatch.

#### 4via6 overlapping-subnet routing (Tier 3a)

Plain subnet routing (Tier 1) fails when the client's own LAN uses the **same**
IPv4 subnet as the remote LAN it wants to reach — e.g. a cabin and a home both on
`192.168.1.0/24`. **4via6** (after Tailscale's feature of the same name) solves it
by addressing each remote device through a unique **IPv6** that embeds
`(site_id, real_ipv4)`; the gateway translates it back to the real IPv4 on the far
LAN, so the same `192.168.1.50` at two sites is unambiguous in v6.

- **Address layout** (`vpn::via6_encode`): `fd68:6f70:7669:6136 : <32-bit site id>
  : <32-bit embedded IPv4>` — a ULA under `fc00::/7`. A client also gets a TUN
  source address in the sibling `…6135::/64` prefix (`vpn::client_v6`, derived from
  its vIP).
- **site_id** is admin-allocated exactly like the vIP: a deterministic candidate
  (`deterministic_site_id`) recorded on the admin-owned `peer/<n>.site_id`, with a
  shared `siteid/` collision table + self-claim offline fallback. Every member is
  assigned one at admission so any node can become an overlap gateway with no admin
  round-trip. MagicDNS resolves `<a>-<b>-<c>-<d>-via-<site>.hop` → the via6 IPv6
  (`AAAA`); the embedded IPv4 is never returned as an `A` record (that would hand
  the client the colliding address).
- **SIIT split** (the key design choice): hop does only the *stateless* IP/ICMP
  translation (RFC 6145 — `vpn::siit`), and the **host kernel does the v4 LAN NAT**
  (the shipped Tier-1 `ip_forward` + nftables masquerade). The translated source is
  a per-client address from the reserved SIIT pool `100.127.0.0/16` (the top /16 of
  the warren /10, excluded from vIP allocation), so it falls inside the range the
  gateway already masquerades and a reply routed back to it is recognized for the
  reverse translation. The coarse `client_v6 ↔ pooled_v4` map (`vpn::SiitState`) is
  the only per-client state hop holds; the kernel's conntrack handles per-flow NAT.
- **Data path**: client `via6(siteB,D)` → TUN (via6 `/64` route) → outbound loop
  decodes `siteB` → gateway B → QUIC datagram (carrying the v6 packet) → B's ingress
  reach-authorizes (the client's embedded vIP must reach `D` via an advertised
  route) → SIIT v6→v4 (dst `D`, src pooled) → TUN → kernel forwards + masquerades →
  `D`. The reply reverses: kernel reverse-masquerade → pooled → TUN → outbound loop
  recognizes the pool address → SIIT v4→v6 (src `via6(siteB,D)`, dst client_v6) →
  datagram → client.
- **Opt-in + inert by default**: a client enables via6 routing with `HOP_VIA6`
  (assigns its TUN v6 address + routes the via6 `/64`, delegated to the privsep
  monitor via `ConfigureTunV6`). Nothing forwards v6 until a gateway owns the site.
- **Scope**: Linux gateway first; full TCP/UDP/ICMP + path-MTU. macOS utun-v6 + pf
  NAT46 is a second-platform follow-up. Validated by `tests/e2e/via6-overlap-e2e.sh`
  (two sites both `192.168.1.0/24` + a client with a local `192.168.1.50` collision
  reaching the *remote* `192.168.1.50` via its via6 address).

### Network Monitoring

`crates/hop-core/src/net/netmon.rs` implements a lightweight interface poller that detects IP address changes and kicks iroh's re-discovery.

#### Interface Polling

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

#### Change Detection

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

### Connection Agent

The agent process (`crates/hop-cli/src/agent.rs`) owns a single iroh Endpoint and multiplexes all client sessions over QUIC bi-streams. It uses the actor pattern for thread-safe mutable state management.

#### Singleton Lifecycle

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

#### Idle Timeout

The agent shuts down after 10 minutes (`IDLE_TIMEOUT = 600s`) with no active sessions. The `CheckIdle` command queries the actor for staleness.

#### Actor Pattern

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

#### Connection Pooling

When `GetConnection` arrives:
1. If a cached `Connection` exists: return it immediately
2. If a connect is in-flight for this host: queue the reply channel in `pending`
3. Otherwise: spawn a connect task, queue the reply

When `ConnectDone` arrives:
- On success: cache the connection, create a per-host `Semaphore`, reply to all waiters
- On failure: reply error to all waiters

### Mux Protocol

`crates/hop-cli/src/mux.rs` defines the IPC protocol between CLI processes and the agent.

#### MuxConnect (Client -> Agent)

```rust
pub struct MuxConnect {
    pub host_id: [u8; 32],          // Target host's PublicKey
    pub relay_url: Option<String>,   // Relay URL hint
}
```

#### MuxResult (Agent -> Client)

```rust
pub enum MuxResult {
    Ready,              // Bi-stream open, start sending hop protocol messages
    Error(String),      // Connection failed
}
```

#### Stream Proxying

After `MuxResult::Ready`, the Unix socket becomes a transparent bidirectional pipe to a QUIC bi-stream. The client writes hop protocol messages (`ClientMessage`) and reads responses (`HostMessage`) directly through the IPC socket -- the agent just copies bytes.

#### IPC Framing

Same 4-byte big-endian length-prefixed bincode as the hop protocol:

```rust
pub async fn write_ipc_message<T: Serialize>(stream, msg) -> Result<()>
pub async fn read_ipc_message<T: Deserialize>(stream) -> Result<T>
```

Max IPC frame: 16 MiB.

#### Target Resolution

`mux::connect_to_host()` resolves the target string in order:
1. **Known host alias**: `KnownHostsStore::resolve_alias(target)` -- matches by name
2. **Invite token**: `invite::is_invite_token(target)` -- base64url decode, run auth flow
3. **Direct NodeId**: parse as hex PublicKey -- connect without auth

### Reconnection

`crates/hop-cli/src/reconnect.rs` implements a two-tier reconnection flow:

#### Tier 1: Quick Inline Reconnect

```rust
pub async fn try_quick_reconnect(config_dir, resolved, session_request, timeout) -> Option<ReconnectAction>
```

Prints a single-line banner in the current terminal and attempts to reconnect within the timeout. On success, clears the banner and returns `ReconnectedViaAgent`. On failure, returns `None` so the caller escalates to Tier 2.

Retry loop with 5-second connect attempts within the overall timeout window. On success, sends the session request + setup messages (WindowSize, SetEnv) before reading SessionInfo.

#### Tier 2: Full TUI

If quick reconnect fails, a full-screen ratatui TUI is shown with reconnection status, countdown, and option to quit.

#### ReconnectAction

```rust
pub enum ReconnectAction {
    ReconnectedViaAgent { send, recv, new_session_id },
    Quit,
}
```

### MCP Audit Log

`crates/hop-mcp/src/audit.rs` logs every MCP tool invocation to `<config_dir>/mcp_audit.jsonl`.

#### AuditEntry Format

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


---

## Peer-to-Peer Private Network (Design)

> **Status: MVP shipped — VPN off by default, as of v0.6.37.** The role-based
> warren MVP (all 8 build-plan steps below) is implemented and validated by a
> live multi-node TUN e2e (`tests/e2e/vpn-e2e.sh`, including reboot
> reconvergence) plus the 53-test regression suite. The VPN data plane was
> default-on in v0.6.32–0.6.36; **v0.6.37 reverted the default to off** while the
> warren's write-authorization trust model is hardened (see the **Trust model**
> note below and `security.md` C1). Enable it with `--host`, `HOP_VPN=1`,
> or `hop config set vpn on`. Bringup is **always best-effort** — if a TUN can't
> be created (no privilege / no `/dev/net/tun`) or `100.64.0.0/10` is already in
> use by another overlay (e.g. Tailscale), it degrades gracefully and keeps
> serving exec/shell/transfer untouched; `HOP_VPN=0` is a recovery escape hatch.
> Inbound `hop/vpn/1` datagrams are **ingress-authenticated** (source-vIP
> anti-spoof; v0.6.37). Sections marked **(Commercial, deferred)** are planned
> for later phases and are documented here only so the schema and trust model
> don't have to be reworked when we get there.

> **Trust model (C1).** Write-isolation is now **shipped**: `node`/`warren-only`
> invites carry a **read** ticket (not a write ticket), and each member writes
> only its own **write-isolated self-doc** — the shared admin doc (membership,
> roles, `peer/N.vip`/`.vpn_endpoint`) is admin-authored. Per-author write
> validation runs against the founder/admin author binding. What remains
> **deferred** is flipping that validation from **observe** to **enforce** by
> *default* (it's opt-in today via `HOP_NETDOC_VALIDATION`, pending a multi-node
> federated rollout so mixed-version co-admins aren't partitioned) and the full
> cryptographic Owner/Admin write *capability* (vs the current author binding).
> Defence-in-depth still applies: VPN off-by-default and data-plane ingress
> authentication (a forged registration can't source authenticated packets).
> See **C1** in [Security Audit](#security--code-health-audit--2026-06-03) and
> [Per-Member Self-Documents](#per-member-self-documents-warren-write-isolation-c1).

### Goal

Turn hop's configured peers into a decentralized LAN-style VPN: every node gets
a stable virtual IP, can reach permitted services on other nodes over iroh P2P,
and resolves friendly names (`rexmundi.acme.hop`) — with **no orchestrator on the
data path**. Membership, roles, addressing, and access rules live in a shared,
replicated CRDT document rather than in any single host's local config.

The defining constraint: **the data plane stays orchestratorless in every mode.**
All commercial control-plane features (SSO, audit collection, network-lock,
key recovery) are additive and degrade gracefully when their central components
are offline — the network keeps routing on existing state.

### Architecture at a glance

```
        ┌─────────────────────── iroh-docs (replicated CRDT) ───────────────────────┐
        │  peers · roles · groups · tags · IP allocations · invites · revocations    │
        └───────────────┬──────────────────────────────┬────────────────────────────┘
                        │ replicates P2P (gossip)       │
                ┌───────┴────────┐              ┌────────┴───────┐
                │   Daemon A     │              │   Daemon B     │
                │ ┌────────────┐ │   QUIC       │ ┌────────────┐ │
   apps ──TUN──▶│ │ pkt filter │ │  datagrams   │ │ pkt filter │ │◀──TUN── apps
                │ │ (ACL)      │◀┼──────────────┼▶│ (ACL)      │ │
                │ └────────────┘ │  hop/vpn/v1  │ └────────────┘ │
                │ local DNS :53  │              │ local DNS :53  │
                └────────────────┘              └────────────────┘
```

- **Control plane:** one iroh-docs namespace per hop network ("the doc").
- **Data plane:** TUN device → daemon → QUIC datagrams (`hop/vpn/v1` ALPN) → peer daemon → TUN.
- **Names:** each daemon runs a small split-DNS resolver backed by the doc.
- **Access:** existing role/group/tag rules, enforced as a userspace packet filter at the *receiving* daemon, default-deny.

### Decisions

Each decision below records the chosen mechanism and the rationale. Forks that
were considered and rejected are noted so we don't relitigate them.

#### 1. State sync — iroh-docs

A single iroh-docs namespace per network holds all control-plane state. Entries
are author-signed; replication is range-based set reconciliation plus gossip
over QUIC.

- **Why:** reuses the iroh investment, gives signed entries and P2P sync for
  free, no separate CRDT runtime to integrate.
- **Rejected:** custom CRDT (Automerge/Yjs) — more flexible schema but we'd
  reimplement sync; gossip-only — scales poorly past hundreds of peers.
- **Caveat to handle in code:** in iroh-docs any namespace writer can write any
  key. Key-uniqueness is *not* an authorization mechanism. Every entry's
  validity must be checked at read time against the role chain (see #9).

#### 2. Virtual IP allocation — deterministic proposal + doc-coordinated claim

Addresses come from `100.64.0.0/10` (CGNAT range, familiar to Tailscale users).
Allocation is a hybrid:

1. **Deterministic proposal:** candidate IP = `hash(pubkey)` mapped into the
   range. Stable — the same key always re-derives the same "home" address.
2. **Doc is source of truth:** peer reads the allocation table
   (`ip/<addr> → pubkey`); if its candidate is free it claims it, else it
   linear-probes to the next free slot.
3. **Conflict resolution:** on a genuine concurrent claim (two peers, same slot,
   while partitioned), a deterministic tiebreak (lower pubkey wins) is applied
   at read time; the loser re-probes. Rare in a /10; the loser may change IP
   shortly after joining.

- **Why:** familiar IPv4 addresses + zero hard dependency on a central
  allocator (the doc *is* the allocator). Stable home IPs are a nice property.
- **Rejected:** pure `hash(pubkey)` into IPv4 — collision-prone and
  unrecoverable in a /10 (birthday paradox bites at a few thousand nodes);
  pure `hash(pubkey)` into IPv6 (Yggdrasil/CJDNS style) — collision-safe but
  commits us to IPv6 virtual addressing and loses the familiar look.
- **Note:** Tailscale itself allocates centrally via its coordination server;
  our doc-coordinated claim is the decentralized equivalent.

#### 3. Invite token format — capability-token-into-doc (current scheme, lifted)

The existing single-use invite scheme, moved into the doc world. Token carries:
network (doc) ID, a bootstrap peer address, an ephemeral grant keypair, expiry,
and the issuer's signature. On redemption the new peer joins the doc, writes its
`peer/<pubkey>` entry under the grant, and the doc records `invite/<hash>` as
redeemed (replay-proof).

- **Why:** preserves the loved UX (single-use crypto token, no SSO, no account);
  works even when the inviter's daemon is offline (any peer with the doc can
  verify the invite).
- **Rejected:** **bearer + central revocation list** — a ticket anyone holding
  can use, cancellable only via an always-online server (defeats
  orchestratorless); **macaroons** — bearer tokens you can attenuate without the
  issuer (great for *delegated, narrowed* sub-invites), more machinery than v1
  needs. Macaroons are a good future option for "hand a contractor a narrower
  invite" and are noted here for that.

#### 4. Revocation — eventual + sync-on-connect

Base model is eventual consistency: a revocation is a signed doc entry that
propagates via gossip (seconds-to-minutes when peers are online). The key
addition: **enforcement is on the receiving peer, so only the receiver's
freshness matters.**

- **Sync-on-connect:** before authorizing an inbound connection, the receiving
  daemon confirms its doc copy is fresh (triggers a sync if stale). This
  converts the exposure window from unbounded global propagation latency into
  the receiver's local sync latency — tight and controllable — with no
  credential-renewal churn and no compromise to the P2P model.
- **Why:** a revoked peer is harmless the moment any peer it contacts has a
  fresh doc; sync-on-connect guarantees that freshness cheaply.
- **Commercial upgrade (deferred):** short-lived peer credentials that must be
  periodically re-attested by an Admin. Converts "revocation must propagate"
  into "renewal must succeed," which fails safe and gives a hard bound. Purely
  additive — the doc carries revocations either way, so adopting this later is
  not a re-architecture.

#### 5. Data plane — QUIC datagrams

VPN packets travel as QUIC unreliable datagrams (RFC 9221) over a dedicated
`hop/vpn/v1` ALPN.

- **Why:** IP packets are intrinsically unreliable; reliability/ordering for
  TCP-inside-the-tunnel is provided by the *inner* stack. QUIC streams would
  double-count reliability and cause head-of-line blocking (one lost packet
  stalls the whole stream).
- **MTU:** QUIC's effective datagram payload is ~1232 bytes after framing; set
  the TUN MTU to ~1280 to fit without fragmentation.
- **Rejected:** QUIC streams (HoL blocking); raw UDP via iroh-net (faster,
  WireGuard-like, but re-implements crypto/security primitives — too much
  review surface for v1).

#### 6. TUN device — existing crate (candidates to evaluate)

Create the virtual interface via a maintained Rust crate rather than
hand-rolling per-OS `utun`/`tun` code. Candidates to evaluate at implementation
time: `tun`, `tun-rs`, and boringtun's tun module (reference for cross-platform
utun handling).

- **macOS:** utun via `socket(AF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL)` — no
  kext needed; requires root (daemon already runs as root via launchd).
- **Linux:** `/dev/net/tun` + `TUNSETIFF`; requires CAP_NET_ADMIN.
- **Windows:** Wintun — **(deferred, out of scope for v1).**

#### 7. DNS — local split-DNS resolver (MagicDNS-style)

Each daemon runs a tiny DNS resolver bound to a magic address in the virtual
range. The OS is configured with **split-DNS** so only queries for the network's
domain go to that resolver; all other DNS is untouched. Name→IP mappings come
from the doc; the network's domain name is a configurable doc setting (e.g.
`acme.hop`).

- **Why:** exactly Tailscale's MagicDNS model. `hop RexMundi` and
  `ssh rexmundi.acme.hop` resolve the same doc entry. No system-resolver
  hijacking.
- **Rejected:** `/etc/hosts` rewriting (invasive, conflicts with manual edits,
  root for every change); mDNS over the VPN (finicky).
- **Names:** a node registers the **bare host label** (the OS hostname stripped
  of any DHCP-appended suffix like `.lan`/`.local`), so `RexMundi.hop` resolves
  even when `gethostname()` returns the FQDN `RexMundi.lan`.
- **The `:53` bind is privileged** (port < 1024). Under privsep the unprivileged
  worker can't bind it, so `enable_vpn` routes the bind through the root monitor
  (`BindPrivPort`) and receives the socket fd via `SCM_RIGHTS` — same mechanism
  as the TUN. See `privsep::acquire_priv_port`.
- **MagicDNS bind address is platform-specific** (`vpn::magicdns_bind_addr`).
  Linux serves on the node's vIP (the kernel delivers packets addressed to a
  local interface). macOS serves on **`127.0.0.1`**: a point-to-point utun routes
  a query to the node's *own* vIP back out the tunnel instead of to the bound
  socket, so MagicDNS would be unreachable from the same host on the vIP. Loopback
  is always locally deliverable. `validate_bind_priv_port` allows `127.0.0.1:53`
  in addition to the vIP for this.
- **Client setup is automatic.** `enable_vpn` points the OS resolver for the
  warren domain at this node's MagicDNS server with **zero manual steps**:
  macOS writes `/etc/resolver/<domain>` (`nameserver 127.0.0.1` + `port 53`);
  Linux uses `resolvectl` on the hop interface (vIP) when systemd-resolved is
  present. Both are split-DNS (only `.<domain>` is affected). Writing resolver
  config is privileged, so under privsep it runs in the monitor via the
  `ConfigureResolver` primitive; the monitor reverts it on exit. Opt out with
  `HOP_NO_AUTO_RESOLVER`. If systemd-resolved is absent on Linux, hop logs the
  manual step rather than editing `/etc/resolv.conf`. (`nslookup`/`dig` ignore
  `/etc/resolver/*` — they hit `/etc/resolv.conf`; the scoped resolver is used by
  `getaddrinfo`/`ping`. Verify with `scutil --dns`.)
- **Routing on macOS is installed + enforced** (`vpn::ensure_warren_route` +
  `spawn_route_enforcer`). A macOS p2p utun does NOT auto-install the
  `100.64.0.0/10` route from its netmask (Linux's kernel does), so the route is
  added explicitly when the TUN is created, and a 30s enforcer re-finds the hop
  utun and re-asserts the route after sleep/wake / network changes / restarts.

#### 8. Service ACL — doc rules, userspace filter at receiver, default-deny

Access rules reference **groups and tags, never individual peers**. Enforcement
is a userspace packet filter at the *receiving* daemon (packets already traverse
TUN → daemon → iroh, so the daemon is the natural choke point). Default policy is
**deny** — a peer joining gets zero service access until explicitly granted.

- **Why:** mirrors Tailscale's model (central policy, per-node userspace filter,
  deny-by-default) and reuses hop's existing role/group access rules rather than
  inventing a new system. No kernel firewall management required.
- **Rejected:** kernel firewall (iptables/pf) generation — faster but invasive
  and risky to manage on the user's behalf; default-allow — wrong for hop's
  threat model.

#### 9. Trust root — peer-to-peer now, pluggable org-key later

v1 keeps the current fully-P2P trust model: the network Owner's keypair is the
root; roles flow from Owner → Admin → Peer as signed doc entries. Validity of
any entry is resolved by walking the role chain back to the Owner key.

- **Commercial (deferred):** make the trust root **pluggable**. The root becomes
  an **organization key** held in an HSM/KMS (never on a single daemon), which
  signs a small number of **Admin delegation certificates**; Admins sign peer
  and role entries. Same PKI shape as a corporate root CA → intermediate CAs →
  leaf certs, with the doc as the *replication layer for issued certificates*.
  Decentralized replication, centralized issuance authority. Adoption guide for
  large orgs to be written in the commercial phase.

#### 10. Identity model — users *and* devices

Track both, separately:

| Entry | Meaning |
|-------|---------|
| `user/<id>` | A person (Bob). Belongs to groups. |
| `device/<pubkey>` | A machine. Owned by a `user/<id>`, or by the org (shared host). |
| group membership | `user/<id>` → groups (Bob ∈ `dev`). |
| tag | `device/<pubkey>` → tags (machine Z tagged `dev-machines`). |
| access rule | group → tag (group `dev` may reach tag `dev-machines`). |

Rules reference groups and tags only — that's what makes it scale:

- **Add machine Z** with tag `dev-machines` → *every* member of `dev` can reach
  it instantly, no per-user edits.
- **Remove Bob from `dev`** → he fails the ACL check on his next connection.
- **Lost laptop:** revoke one `device/<pubkey>`; Bob's other devices keep working.
- **Fire Bob:** revoke `user/bob`; all his devices lose access.

#### 11. IdP integration — (Commercial, deferred)

A thin **identity bridge** holds an Admin cert and watches the customer's IdP
(Okta/Entra/Google Workspace) via SCIM/OIDC. IdP group change → bridge writes
the corresponding doc entry (provision/role/revoke).

- **Critically off the data path:** the bridge is automation that translates IdP
  events into signed doc entries. If it's down, the network keeps running on
  existing credentials; only onboarding/offboarding via SSO pauses.
- Roughly Tailscale's SSO mapping, except optional, self-hostable, and not a
  routing dependency.
- **Schema note for now:** because we model `user/<id>` separately (#10), adding
  the bridge later requires no schema change — the bridge just populates the
  same `user`/group entries a human Admin would.

#### 12. Audit model — (Commercial, deferred; shape decided)

Two layers, built independently:

- **Control-plane audit (free):** the doc is already an append-only, signed log
  of every invite/grant/role-change/revocation — tamper-evident, answers "who
  was granted/revoked what, when, by whom." Covers most access-review
  compliance with no extra infrastructure.
- **Data-plane audit (opt-in):** "who connected to what service, when, how
  much." In true P2P only the two endpoints see this. Collecting it requires
  daemons to emit connection records to a sink — options: local signed logs
  pulled on demand, an optional collector peer, or export to the customer's SIEM
  (syslog/OTel). A *passive* collection component, not a routing dependency —
  the network still works if it's down. Built when a customer needs SOC 2.

#### 13. Admin separation-of-duties — root-like now, network-lock later

v1: Admin is root-like (can manage ACLs, devices, users) — simple and matches
how small teams expect it to work.

- **Commercial (deferred) — "network lock":** modeled on Tailscale's *Tailnet
  Lock*. When enabled, the highest-privilege operations — **admitting a new
  device** and **promoting an Admin** — must be **co-signed by multiple trusted
  signing keys** held on existing nodes. No single compromised Admin key (and no
  compromised central component) can silently add a backdoor peer or escalate
  privilege. Scoped narrowly to the operations that matter, so it doesn't burden
  everyday admin work. This folds together the separation-of-duties (#13) and
  key-custody (#14) concerns.

#### 14. Org key custody / recovery — (Commercial, deferred)

The org key (#9) is the root of trust; commercial customers *will* lose it
without help. Planned mechanisms (to be designed in the commercial phase):

- HSM/KMS-backed storage as the default.
- A documented multi-party recovery ceremony (threshold key shares).
- Key rotation that re-issues Admin certs without disrupting the data plane.

### Doc schema sketch

Entry keys (namespace = the network). Values are signed by the author; validity
is resolved against the role chain (#9) at read time.

| Key | Value | Written by |
|-----|-------|-----------|
| `network/config` | domain name, address range, flags (network-lock on/off) | Owner |
| `peer/<pubkey>` | hostname, advertised services, joined_at | self (under invite grant) / Admin |
| `device/<pubkey>` | owned-by `user/<id>` or `org`, tags | Admin |
| `user/<id>` | display name, groups | Admin / IdP bridge |
| `role/<pubkey>` | Owner / Admin / Peer, granted_by, granted_at | granter (Admin+) |
| `ip/<addr>` | pubkey (allocation table, #2) | self (claim) |
| `acl/<group>/<tag>` | scope (ports/protocols) | Admin |
| `invite/<token-hash>` | scope, expiry, redeemed_by | issuer |
| `revocation/<pubkey or user-id>` | reason, revoked_at | revoker (Admin+) |

### Phased rollout

Each phase stands on its own and ships independently. Personal-mode first; it's
the proving ground for the doc and addressing before any commercial work.

| Phase | Scope | Independent value |
|-------|-------|-------------------|
| **1. Decentralize state** ✅ *(per-host)* | Replace `peers.json`/`roles.json` with an iroh-docs replica. Migrate existing JSON on first start. Keep all current features (shell, exec, transfer, fleet, MCP). | Invites work even when the inviter is offline. |
| **2. Virtual IPs** ✅ | Deterministic-proposal + doc-claim allocation (#2). Claimed per host on startup. | Tests conflict resolution without TUN complexity. |
| **3. VPN packet plane** ✅ *(opt-in, best-effort)* | TUN/utun (#6), `hop/vpn/1` over QUIC datagrams (#5), daemon-to-daemon forwarding, federation via write ticket, **ingress authentication** (source-vIP anti-spoof, v0.6.37). Off by default (`--host`/`HOP_VPN=1`/`hop config set vpn on` to enable); skips gracefully on TUN failure / CGNAT conflict (`HOP_VPN=0` escape hatch). | Actual P2P LAN reachability. |
| **4. DNS + ACL** ✅ *(active when VPN enabled)* | MagicDNS resolver for `*.hop` (#7); role→tag→ACL filter on the forwarding path (#8, default-deny). Active whenever the VPN is enabled. | Friendly names + safe service exposure. |
| **5. Commercial control plane** | Pluggable org-key trust root (#9), short-lived credentials (#4), user/device split already in place (#10), group/tag ACLs (#8/#10). | Strict, provable revocation for businesses. |
| **6. Enterprise integration** | IdP bridge (#11), data-plane audit export (#12), network-lock co-signing (#13), key custody/recovery (#14). | SSO, SOC 2, key safety. |

#### Role-model unification (Shipped, with a compat shim)

The product layer ([`../product/warren.md`](../product/warren.md)) requires
collapsing hop's two role concepts into one. This is now shipped:

- **Named role on peers/invites.** Peer entries and invites carry a role
  **name** (`role_name`); `PeerRole` (`Peer`/`Creator`) survives only as a
  migration shim for legacy peers.
- **Safe org default.** A configurable, least-privilege **org-default role**
  (`member`, default-deny reach) is seeded; `HostConfig.default_role` (default
  `member`) is used when `hop invite` is run with no `--role`. `hop config set
  default_role <name>` re-points it.
- **Elevation:** `hop admin <host> grant <peer> <role>` (proto `SetPeerRole`)
  updates a member's role entry in the document; replication + ACL re-resolution
  apply the change network-wide without re-issuing an invite.
- **ACL derivation:** reach is stored/evaluated as role→tag (not per-IP) and
  resolved against the membership doc at enforcement time (`vpn_reach_allowed`),
  so it's stable across join/leave. This supersedes hand-authored `acl/policy`
  for the default case.

#### Federation safety (Partially shipped)

Cross-host federation (one shared namespace) needs two safeguards the per-host
model doesn't:

- **Ownership-scoped reconcile (Shipped).** On a shared namespace `reconcile`
  is **additive-only** — it no longer revokes "doc peers not in *my* `peers.json`",
  so one host can't cross-revoke another's members. The additive `ip`/`vpn`/`name`
  tables are federation-safe by construction (each host writes only its own).
- **Read vs write capability (Deferred — security-audit C1, ties to the
  commercial trust root, #9).** Today the join path hands out an iroh-docs
  **write** ticket, so a member can rewrite membership/roles/`vpn`/`name`/`ip`
  entries in the shared doc. Cryptographically gating writes behind an
  Owner/Admin-signed capability (members get a read replica) plus per-author
  write validation on read is the remaining hardening. It is **deferred**
  (tracked as C1) because it's a multi-layer change with a real risk of locking
  legitimate nodes out of their own warren; the interim mitigations shipped in
  v0.6.37 are **VPN off-by-default** (only opted-in nodes join the writable doc)
  and **data-plane ingress authentication** (a forged `vpn/` entry can't source
  authenticated packets). See `security.md` for the full rationale.

#### Phase 1 implementation status

**Shipped (per-host model):** the iroh-docs stack runs on a dedicated, isolated
endpoint (`net::create_netdoc_endpoint`, derived key → stable NodeId). On startup
the daemon opens-or-creates its network namespace (id persisted to `netdoc.json`)
and **reconciles** it against `peers.json`/`roles.json`; it reconciles again after
every admin mutation, so the document is a complete, self-healing, authoritative-
wired store. Auth is doc-aware: a peer in `peers.json` is **always** allowed
(local truth is never overridden by doc state — no lockout path), and the doc is
consulted only for peers *not* locally known, with a revocation gate. `peers.json`
remains a continuously-synced mirror for back-compat, downgrade safety, and
inspection. netdoc spawn/reconcile are **non-fatal** — any failure leaves the
daemon serving on `peers.json` exactly as before.

**Deliberately deferred — cross-host federation / network-wide membership.** The
"inviter offline" win across *multiple* hosts requires a shared namespace where a
peer admitted on host A is authorized on host B. That is a **network-wide
membership** model (a peer reaches *any* host), which is a security expansion over
today's per-host isolation. Shipping it without per-service access control would
let any network member reach every host's shell — so it is intentionally **coupled
to Phase 4's default-deny ACLs (#8)** rather than shipped in Phase 1. The
federation primitives exist (`NetDoc::read_ticket`, `Bootstrap::Import`,
`reconcile`'s per-host-ownership caveat) and are ready for that phase.

### Next-stage build plan — the role-based warren MVP ✅ *(shipped; VPN off-by-default since v0.6.37)*

All 8 steps below are implemented and validated (live multi-node TUN e2e
`tests/e2e/vpn-e2e.sh` — real ICMP over `hop/vpn/1`, role-gated, 0% loss, plus
reboot reconvergence — and the 53-test regression suite green). The VPN data
plane was **default-on** in v0.6.32–0.6.36; **v0.6.37 reverted it to off** (opt
in via `--host` / `HOP_VPN=1` / `hop config set vpn on`) while the warren write
model is hardened (Trust-model note at the top; C1 in `security.md`).
Bringup is best-effort: a TUN-creation failure or a `100.64.0.0/10` conflict
(e.g. a host already running Tailscale) only skips the VPN — core access
(exec/shell/transfer) is never affected. `HOP_VPN=1` forces past the conflict
guard; `HOP_VPN=0` is a recovery escape hatch. The 53-test regression suite runs
in TUN-less containers, so its green run is the standing proof that VPN bringup
(or its absence) never affects core access.

This stage turned the previously inert VPN into a working role-driven warren:
**role unification + federation safety + role→ACL derivation + a live multi-node
TUN e2e.** These are interdependent (a member's reach across hosts needs both the
unified role and a safely-shared namespace), so they shipped as one coherent
stage, sequenced so each step compiled and tested.

1. **Canonical role** (`hop-core`). Make `RoleDefinition` the one role type: add
   `ports` (default all) for reach; `admin: bool` is the auth tier (subsumes
   `Creator`). Seed a least-privilege **`member`** role (no tags, default-deny).
   Add `default_role` to the warren config (doc `network/config`, default
   `member`). Peer entries carry a role **name**; `PeerRole` becomes a thin compat
   shim (`Creator`↔admin, `Peer`↔default) during migration.
2. **Invite by role** (`hop-cli` + proto). `hop invite --role <name>`; `--creator`
   = sugar for `--role admin`; no `--role` → org default. Redeem stores the role
   name in the peer entry + doc.
3. **Host tags in the doc** (`hop-core`). Each host publishes its tags
   (`tag/<host_id>`); source from config / an install `--tag` flag; default
   untagged.
4. **Federation safety** (`hop-core`) — prerequisite for multi-node. Split **read
   vs write** capability (members get a read replica; membership/role/ACL writes
   need an Owner/Admin-signed capability), and make `reconcile`
   **ownership-scoped** (only revoke entries this host owns) so a shared namespace
   doesn't cross-revoke.
5. **Role→tag→ACL resolver** (`vpn::acl` + `netdoc`). Replace static `acl/policy`
   evaluation with: src IP → member → role → permitted tags+ports; dst IP → host →
   tags; allow iff dst tag ∈ role tags ∧ port permitted; default-deny. Reads
   membership/roles/tags from the replicated doc.
6. **Role elevation** (`hop-cli` + admin proto). `hop admin <host> grant <peer>
   <role>` updates the peer's role entry (peers.json + doc) → reconcile → ACL
   re-resolves network-wide, no re-invite.
7. **Configurable MagicDNS domain** (`hop-core`). Resolver reads the warren domain
   from `network/config` (default `<warren-name>.hop`, else `hop`) instead of the
   hard-coded `.hop`.
8. **Validation.** ✅ Unit: role→ACL resolution covers the deny path
   (`role_reaches` — wildcard, tag intersection, empty-role denies all;
   `role_derived_reach_via_doc`). **Live multi-node TUN e2e**
   (`tests/e2e/vpn-e2e.sh`, `NET_ADMIN` + `/dev/net/tun`): two federated nodes
   join one warren (host-b imports host-a's namespace ticket + redeems the admin
   creator invite); both run the VPN (enabled via `HOP_VPN=1` in the harness);
   host-b pings host-a's virtual IP over the real `hop/vpn/1` TUN — role-gated
   forwarding (admin/`*` reach both directions), **0% packet loss** — and the
   harness then restarts host-b and re-pings to prove reboot reconvergence. The
   live harness exercises the allow path + the full data plane (TUN bringup,
   `100.64.0.0/10` routing, ingress authentication, federation replication,
   MagicDNS vIPs); the tag-based deny path is covered by the unit tests above.
   Plus the existing 53-test regression suite green.
   ✅ Phase 3-4 was default-on in v0.6.32–0.6.36; **v0.6.37 reverted the default
   to off** (opt in via `--host` / `HOP_VPN=1` / `hop config set vpn on`) while
   the warren write model is hardened. `HOP_VPN=0` / `--no-vpn` / `vpn_enabled=false`
   keep it off.

**Rollout order within the stage (as executed):** role unification + `member`
default first (auth-semantics change, guarded by the `peers.json` fallback so
existing peers are unaffected) → federation safety → ACL derivation (affects only
the VPN data plane) → live e2e → flipped the VPN default-on once the e2e was
green (v0.6.32).

### Next-stage build plan — token unification + the two install tiers ✅ *(shipped v0.6.34)*

> **Status: Shipped (v0.6.34).** This stage reconciled two accidental dualities —
> (a) "regular invite" vs "warren join token", and (b) the install story — into
> one mental model. The invite now carries the warren (`warren_ticket` on
> `InviteToken`); the founder's creator invite is augmented with it once netdoc
> is ready; `hop warren join [invite]` redeems membership + joins the namespace;
> the installer is one `install.sh` (no-arg = client, `--host` = node) with a
> unified `--invite`. Validated by a live multi-node TUN e2e that joins the whole
> warren from one invite (0% loss) + the 53-test regression suite.

#### Product framing (what the user sees)

The category (Tailscale, ZeroTier, NetBird) installs a root daemon by default but
gates *joining the network* behind an explicit step (`up`/`join`), and resolves
"new vs existing network" from **identity via a coordinator**. hop has **no
coordinator**, so the only signal for "new vs join" is a **token** (or its
absence). hop is also more *asymmetric* than the symmetric mesh VPNs — it has a
real client-vs-host split, closer to `ssh`/`sshd`. Two install tiers fall out:

| Tier | sudo / daemon | VPN / virtual IP / `name.hop` | Has a warren? | Purpose |
|------|---------------|-------------------------------|---------------|---------|
| **Connect from this machine** (client) — *no-arg default* | no | no | no (member only) | reach hosts you're invited to, SSH-style, zero footprint |
| **A machine to reach** (node) — *explicit `--host`* | yes | yes | yes (its namespace) | be *on* the private network |

Two ways to reach a host, and only one is the VPN: **direct hop session**
(`hop host`, exec, cp — P2P, no VPN, works from a client) vs **warren IP
reachability** (services by virtual IP / `name.hop`, nodes only). That is why a
no-sudo client needs no VPN.

**One-warren default, no create/join prompt.** The "a machine to reach" path has
a single optional field: *paste your invite (leave blank to start your own)*.
Blank → anchor your own warren (founder / home server / company's first server).
Token → join. Joining while **trivial** (no members yet) silently adopts the
target warren (no island); joining once you **have members** becomes a gated
populated-warren merge (admin + two-sided consent — see Federation safety).

#### The unification: one token, one membership, tier = install

Today the daemon writes **two** artifacts — `creator_invite` (an `InviteToken`:
how to reach the host + role) and `netdoc.ticket` (a `DocTicket`: how to replicate
the namespace). Fold the second into the first:

- Add `warren_ticket: Option<String>` (the namespace `DocTicket`) and
  `suggested_tier: Option<Tier>` (`client` | `node`, for org-steering) to
  `InviteToken`. "Warren join token" disappears as a separate concept — there is
  only **an invite**.
- **Redeeming always = becoming a warren member with a role** (the host already
  dual-writes the peer entry into the doc). Tier decides what your *local* machine
  does with it:
  - **Node** (default, sudo): membership **+** joins the namespace via
    `warren_ticket` → virtual IP, MagicDNS, on the mesh.
  - **Client** (no sudo): membership **+** direct-session reach; `warren_ticket`
    stored **dormant** for a later upgrade.
- **Upgrade client → node** = re-run the node install; it detects the stored
  `warren-ticket` + existing membership and brings up the VPN. No re-invite.
- Single-use invite = invite a person; the existing multi-use **aggregate/fleet
  invite** (role + tags) = provision N servers. Both just carry `warren_ticket`.

**Capability decision (MVP):** the embedded `DocTicket` is **write-capable** — a
node must write to claim its virtual IP / register its endpoint, so a read-only
ticket can't power the node path with today's self-claim architecture. It inherits
the invite's protection (single-use, expiring, secret) and additive-only
reconcile. **This is the C1 limitation** (`security.md`): a write ticket
lets a member rewrite any doc entry, and per-author validation isn't yet enforced.
Cryptographic write-gating (members get read; writes need an Owner/Admin-signed
capability) remains the trust-root hardening (#9); until then v0.6.37 mitigates
with VPN off-by-default + data-plane ingress authentication.

**Main engineering risk / bridge:** redeeming is a client/connect action
(`hop connect`), but joining the namespace as a node is a `hop host` action
(reads `netdoc-join.ticket`). The **installer orchestrates the bridge** (redeem →
extract `warren_ticket` → hand to the daemon), since it knows the tier.

#### Phases (each compiles + is independently testable)

- **A — Unify the token.** `InviteToken` gains `warren_ticket` (`skip_if_none` →
  old invites parse, old clients ignore). Invite generation (`cmd_invite`, creator
  invite at `main.rs`, `admin::handle_create_invite`, aggregate/fleet) reads the
  existing `<config>/netdoc.ticket` and embeds it. `cmd_connect` redeem persists a
  present `warren_ticket` to `<config>/warren-ticket` (dormant). `netdoc.ticket`
  stays on disk for back-compat but is no longer the user-facing path.
- **C — Reconcile the installer.** One `install.sh`: **no-arg = client** (today's
  lightweight binary install, no sudo); **`--host` = node** (today's
  `install-daemon.sh` path — sudo, service, VPN on by default). Unify the join
  input as `--invite <token>` (node → extract ticket → `netdoc-join.ticket`;
  client → redeem + store). An invite's `suggested_tier` drives the default the
  install page presents. Keep `--no-vpn`/`--tag`/`--default-role`; `--join` and
  `--daemon` become hidden aliases (`--daemon`→`--host`). `install-daemon.sh` →
  thin alias of `install.sh --host`.
- **B — Join the warren VPN (the client's upgrade).** A client is already a warren
  *member* that simply hasn't lit up the VPN. Make the upgrade a first-class,
  product-named action rather than a re-install dance: **`hop warren join`** —
  "put this machine on the warren VPN." It takes sudo, sets up the host service,
  and brings up the VPN using the already-stored `<config>/warren-ticket` +
  existing membership (no re-invite). On success: "This machine is now part of
  your warren — virtual IP `100.64.x.x`, reachable as `name.hop`." Add
  `hop warren status` → "member of `<warren>`; VPN: off (client) — run
  `hop warren join` to join the network." The **client install surfaces this as
  the default next step** in its output (offered by default, discoverable), but it
  stays **opt-in**: no root daemon appears unless the user chooses to join the VPN.
  (Re-running `install.sh --host` is the equivalent path for scripted installs.)
- **D — Site + docs.** Install page: client vs node (node primary), one optional
  "paste your invite" field; builder controls show only for node. Retire
  "warren join token" vocabulary across warren.md / p2p-network.md / cli-reference
  / security.
- **E — Validate + release.** Unit (invite round-trips `warren_ticket`; redeem
  persists; old ticketless invite still authorizes). e2e: `vpn-e2e.sh` reworked so
  host-b joins as a node from the **single unified invite**; plus a client-redeems
  → reaches host by direct session → node-reinstall **upgrades** → pings case.
  53-test regression green. Release + sync branches.

**Execution order:** A → C → B → D → E.

#### Back-compat (rock-solid)

- Old invites (no `warren_ticket`) still authorize for direct-session access; they
  just can't make you a node. No breakage.
- `install-daemon.sh` URL is a permanent alias.
- Existing nodes/namespaces untouched; newly-minted invites simply gain the ticket.

#### Resolved product decision — laptops default to client

A developer's laptop defaults to **client** (reach servers, no root;
upgrade-to-node one re-install away). Rationale: it matches how startups and
larger orgs actually run — engineers get *access to servers*, not an addressable
mesh peer + root daemon on every laptop — and it plays to hop's differentiator
(the no-root client tier the symmetric mesh VPNs can't offer). Node-by-default
(Tailscale-like: every machine a reachable peer, root everywhere) was rejected as
too heavy for the common case.

**Org-steering lever.** Because the tier is otherwise a local choice (gated by
`sudo` availability), the **invite carries a suggested tier** (`suggested_tier:
client | node`) so a company's onboarding link sets the right expectation —
"this link gives you access to the servers (no sudo)" vs "this link puts your
machine on the network (needs admin)". The machine-local `sudo`/`--client`/`--host`
choice remains the real gate; the suggestion just drives the default + the
install-page copy.

This makes the **no-argument `curl … | bash` resolve to the client** (safe, no
surprise root); becoming a node is the explicit **"a machine to reach"** path
(`--host`), where the VPN is then on by default (opt out with `--no-vpn`). The
install page leads with the intent choice rather than burying either tier.

### What stays the same

- iroh as transport; relay for NAT traversal (unchanged).
- ALPN-versioned protocols — add `hop/vpn/v1`, retain `hop/0..3`.
- Roles (Owner/Admin/Peer) and the capability/access-rule model.
- Single-use invite-token UX.
- All existing CLI commands and behaviors.

### Open risks

- **Doc-write spam** by a misbehaving authorized peer — rate-limit per author in
  replication; reject entries from non-role authors at *read/verify* time, not
  just write time (follows from #1's caveat).
- **Performance vs WireGuard/Tailscale** — per-packet QUIC overhead is real;
  fine at LAN-scale flows, noticeable at 10 Gbps. Set expectations; the
  differentiator is "works without central infrastructure," not raw throughput.
- **Accidental service exposure** — default-deny (#8) plus loud documentation;
  the ACL must fail closed.
- **Owner/org key loss** — addressed by #14, but must be a real product feature,
  not an afterthought; it's a deal-breaker for enterprise if hand-wavy.


---

## Per-Member Self-Documents (Warren write-isolation, C1)

> **Status: design + in-progress.** This is the chosen remediation for the
> warren's write-open trust model (C1) — see
> [Install & Invite Tiers §10](#install-model--invite-capability-tiers-design) Phase 0b. It
> supersedes the "read-ticket members + admin-writes-on-behalf" approach.

### Motivation

Today the warren is **one iroh-docs namespace every member can write** (members
hold a *write* `DocTicket`). So any member can forge any entry — another member's
`vpn/`/`ip/`/`name/` registration (traffic interception, vIP theft, MagicDNS
spoof), or a `peer/`/`role/` membership grant. The shipped C1 *enforce* model
validates reads after the fact (author must match a vouched binding), which works
but is detect-and-reject, not prevent.

Two ways to actually prevent it were considered:

1. **Read-ticket members + admin-writes-on-behalf.** Members get read tickets and
   can't write; an admin writes their state for them. **Rejected** — it couples a
   member's VPN-reachability to an admin being online (a member's endpoint is
   dynamic; every change needs an admin to write it).
2. **Per-member self-documents** (this design). Each member owns its own
   namespace and is the *only* writer. Forgery is **physically impossible** (no
   write key for anyone else's doc) and there is **no admin-online coupling**.

### Routing via the roster (`peer/N.vpn_endpoint`) — data-plane robustness

> **Added 2026-06-16.** The endpoint is **static**, so routing does not need the
> per-member self-doc namespace at all — it reads the reliably-replicated admin
> doc instead. Self-docs stay for genuinely member-dynamic, non-routing state.

**The realization.** `register_vpn_endpoint` writes `"<endpoint_id> <relay>"`, and
*both halves are static*: the netdoc `endpoint_id` is derived from the persisted
host key (`derive_netdoc_secret_key`) and the `relay` is configured. iroh
discovers the live (dynamic) addresses itself at dial time — that never touches
the doc. So the premise that justified self-docs-for-routing — *"a member's
endpoint is dynamic; every change needs an admin to write it"* (the reason
"admin-writes-on-behalf" was rejected) — **is false for the endpoint**. There are
no dynamic updates to couple to an admin.

**Why it mattered.** Routing depended on importing each owner's **separate
iroh-docs self-doc namespace** and keeping it synced. That per-namespace sync is
fragile — it failed live with `NotFound`, churned on relay/address flaps (the
ticket embeds addresses), and orphaned on leave/rejoin — and a single gap
**black-holed the whole VPN** (`vpn_peer_ips` collapsed to the local entry only;
every egress dropped as `UNRESOLVED`). The **admin doc**, by contrast, replicates
reliably (every node holds the full roster).

**The fix.** Carry the endpoint in the roster beside `peer/N.vip`:
- New field **`peer/N.vpn_endpoint`** (`config::Peer.vpn_endpoint`), the same
  static `"<endpoint_id> <relay>"` value.
- Recorded by the trust anchor from the member's authenticated announce
  (`record_peer_vpn_endpoint`), exactly like `peer/N.self_doc` /
  `peer/N.netdoc_author`. `AnnounceNetdocAuthor` carries `vpn_endpoint`
  (`#[serde(default)]`); the founder self-heals its own on every bringup.
- `lookup_vpn_endpoint` resolves `peer/N.vpn_endpoint` **first**, then falls back
  to the self-doc / shared `vpn/` / owner-node-id paths (migration).
  `refresh_vpn_peer_ips` seeds the ingress map from it. **Zero per-member-namespace
  dependency on the data path.**

**MagicDNS names too.** `lookup_name` had the same fragility — it scanned the
`name/<name>` entry across the main doc + imported self-docs, so a peer's `*.hop`
name didn't resolve until its `name/` entry synced (the `vpn-e2e` MagicDNS-name
flake). The roster already carries each peer's **name** *and* **vip** (both
admin-authored), so `lookup_name` now resolves name→vip from the roster first
(bare-label, case-insensitive), `name/` scan as the legacy fallback. Verified by
`lookup_name_resolves_via_roster`.

**Security is unchanged.** A member can only set *its own* endpoint string
(the admin records it keyed to the member's authenticated node-id; addr→owner
stays the admin-allocated `peer/N.vip`) — the *same* property the self-doc model
gives, since a member could already write any endpoint string into its own
self-doc's `vpn/<its-own-vip>`. The one property dropped — "a malicious admin
can't forge a member's endpoint" — is redundant: the admin already controls
`peer/N.vip`, membership, and revocation, so it has strictly stronger levers over
a member's reachability. Verified by `lookup_vpn_endpoint_resolves_via_roster_endpoint`
(resolves with no self-doc, via an endpoint id distinct from the node-id).

### Model

Two document classes:

| Doc | Writers | Holds | Others get |
|---|---|---|---|
| **Admin doc** (today's namespace) | founder + vouched co-admins | `peer/ role/ acl/ revocation/ network/` + `peer/N.self_doc` | **read** ticket |
| **Per-member self-doc** (one namespace per member) | that member only | `ip/ vpn/ name/ tag/ posture/` | **read** ticket |

Capability = write scope (the tier split done physically, not by policy):
- **admin** → write the admin doc.
- **node / warren-only** → write only your own self-doc.
- **client** → no warren docs at all.

### Trust + discovery (reuses the shipped announce)

1. A member creates its self-doc namespace at first run and persists its id.
2. On `hop host` startup it announces its self-doc **read ticket** to an admin
   over the authenticated session — the `AnnounceNetdocAuthor` channel
   (`crates/hop-cli/src/main.rs`) generalized to also carry `self_doc`.
3. The admin (trust anchor / vouched admin) records `peer/N.self_doc =
   <read_ticket>` in the **admin** doc — admin-authored, so it's trusted, exactly
   like the existing `peer/N.netdoc_author` binding (`record_peer_author` →
   `record_peer_self_doc`).
4. Every node reads `peer/N.self_doc` from the (trusted) admin doc and imports N's
   self-doc **read-only** to learn N's vIP/endpoint/name/tags.

Because the self-doc ticket is recorded by an admin and the self-doc is writable
only by N (cryptographic namespace key), no other member can publish or alter N's
self-state. The C1 self-key *enforce* logic stays as defense-in-depth for the
shared-doc fallback during migration.

### Sync — lazy / on-demand (decision)

Each node always syncs the **admin doc**. It imports + syncs a **member's
self-doc on first need** (the first time it must resolve that member's
endpoint/vIP), then caches the open `Doc`; eviction on revoke. Cost is
O(peers-you-actually-reach), not O(warren) — reach is sparse.

### Global lookups across per-member docs

Per-addr / per-node reads are easy (you know which member you're reaching →
import their self-doc). The one reverse lookup is **MagicDNS `name → addr`**:
resolve `<name>.hop` by finding the admin-doc `peer/` whose host name matches →
that peer's `self_doc` → its `vpn/`/`ip/` → the vIP. (The admin doc already
carries each peer's name, so no extra index is needed.) During migration, fall
back to the shared-doc `name/` table (author-validated) when a member has no
self-doc yet.

### Migration (additive — decision)

- A member writes self-state to its **self-doc** once it has one; readers prefer
  the self-doc and **fall back** to the shared-doc self-keys when absent.
- The shipped self-key *enforce* (`refresh_vpn_peer_ips`, `lookup_name`) stays on
  for shared-doc entries during the overlap. Remove it only once self-docs are
  universal.
- No flag-day: old warrens keep routing on shared-doc self-keys; self-docs take
  over as nodes upgrade.

### Implementation status

**Shipped (infrastructure + mechanism):**
1. ✅ **Retain `Docs`** in `NetDoc` (`spawn`/`spawn_inner`) for runtime
   `create`/`open`/`import` of namespaces.
2. ✅ **Self-doc lifecycle**: each node creates-or-opens its own self-doc;
   namespace id persisted in `NetDocMeta.self_namespace`.
3. ✅ **Dual-write** (`put_self`): self-state (`vpn/ name/ tag/ posture/`) is
   written to the self-doc AND the shared doc, so the unchanged shared-doc read
   path keeps routing while the self-doc path goes live (migration-safe).
4. ✅ **Announce + record**: `AnnounceNetdocAuthor` extended with `self_doc`
   (serde-default, back-compatible); the daemon announces its self-doc read
   ticket; `record_peer_self_doc` records `peer/N.self_doc` (trust-anchor-only,
   idempotent). Unit-tested (`member_self_doc_roundtrips`) + asserted in vpn-e2e.
5. ✅ **Lazy import + cache**: `member_self_doc(node_id)` resolves
   `peer/N.self_doc`, imports read-only on first reach, caches; `evict_member_self_doc`.

6. ✅ **Data-plane read override**: `refresh_vpn_peer_ips` now resolves each
   member's **endpoint** from its own self-doc, keyed by the addr it owns per the
   validated `ip/` table (so a member can only set its own endpoint — the
   addr→owner authority stays the validated `ip/` table, not the self-doc). The
   shared-doc scan remains the base for not-yet-upgraded members. Unit-tested by
   `refresh_prefers_self_doc_endpoint` (resolves an endpoint present ONLY in a
   self-doc); vpn-e2e still routes under enforce with the override live.

#### The addr→owner authority (the key #3b decision)

Dropping *all* shared self-state writes (required so `node`/`warren-only` members
can hold **read-only** admin-doc tickets) means the **addr→owner authority** must
leave the shared `ip/` table too. Two options:

- **Admin-allocated vIP (recommended).** When the admin admits a member it runs
  `claim_virtual_ip` (which probes + resolves collisions) and records
  `peer/N.vip` in the admin doc (admin-authored ⇒ trusted, validated under
  enforce). Readers take addr→owner from `peer/N.vip`; the member self-writes
  only its *endpoint* (`vpn/<peer.vip>`) in its self-doc. The vIP is **static**
  (allocated once at admission) so there's no ongoing admin-online coupling — the
  member still self-updates its dynamic endpoint with no admin involved.
- **Deterministic vIP.** Readers compute `deterministic_ip(node_id)`. Simple, no
  authority entry — but it **breaks under collisions** that today's probing
  resolves (two node_ids → same /10 slot), so a member's actual vIP can differ
  from the deterministic guess. Rejected unless paired with a collision registry.

`peer/N.vip` (admin-allocated) is the chosen direction: it preserves collision
handling, keeps the authority admin-validated (no interception — a member can't
claim another's addr), and adds no runtime coupling.

#### ✅ The "convergence blocker" — root cause found (debug instrumentation)

Dropping the shared `vpn/` write initially **broke live 2-node routing** in
`vpn-e2e` and was twice halted by the gate. Debug-level instrumentation
(ingress-drop, refresh-override, egress-resolution, and self-doc-import markers)
showed it was **never a sync problem**: the founder imported the member's
self-doc, `start_sync` succeeded, content replicated, and the **ingress** map
converged. The break was **egress asymmetry**:

- `lookup_vpn_endpoint`'s self-doc path keyed *only* off `peer.vip`, and
  **redemption-admitted members never got a `vip`** — the auth path mirrored the
  peer with a direct `put_peer`, bypassing `reconcile` (the only place Phase 1
  allocated). The founder's own entry *did* have a `vip`, so member→founder
  resolved while founder→member returned UNRESOLVED — the founder received
  pings but could never address its replies.

**Fixes (all shipped together with the drop):**
1. `admit_peer` — one admission choke point (auth redemption **and** reconcile)
   that allocates `peer/N.vip` on the trust anchor.
2. `vip_owner` falls back to the **author-validated** shared `ip/` claim for
   legacy members with no `vip` (same rule as the refresh path — unforgeable).
3. Admin-authored `ip/` claims are accepted (the anchor claims on behalf at
   admission — that *is* the allocation mechanism).
4. `resume_sync` now derives its sync-peer list from `peer/N.self_doc` ticket
   addresses (membership), since the shared `vpn/` table no longer carries
   endpoints; the old `vpn/`-scan stays as a legacy source.

The earlier **active-sync hardening is kept** (`member_self_doc` always
`start_sync`s; `resync_member_self_docs` on both keepalives) — it's what makes
imported self-docs stay fresh; the vip gap was simply sitting in front of it.

A second break surfaced once egress resolved: the QUIC **datagram pump ran only
on the accept side**, so replies sent back over the connection a peer *dialed*
were silently discarded (no reader). Fixed by extracting `pump_vpn_datagrams`
and running it on dialed connections too, and by sharing live inbound
connections (`VpnConns`) so the outbound forwarder prefers a peer's fresh
inbound connection over a silently-dead cached dial (no CLOSE frame ever arrives
from a rebooted peer until the QUIC idle timeout).

### ✅ Status: COMPLETE (shared write dropped; read-ticket members shipped)

The shared `vpn/` write is **dropped** — a node's endpoint lives only in its
isolated self-doc. `node`/`warren-only` invites carry the admin doc's **read**
ticket (write reserved for `admin`); `enable_vpn` waits for the admin-allocated
`peer/N.vip` instead of self-claiming (read members can't write `ip/`);
`put_self`'s shared mirror is best-effort (read members have no write cap).

Proven end-to-end by `tests/e2e/vpn-e2e.sh` under enforce:
- founder↔member routing + reboot reconvergence (shared write gone);
- **READ-SCOPE**: a `--tier node` invite carries the read ticket;
- **READ-MEMBER ROUTING**: a read-ticket member (host-c) routes under enforce;
- **NO-ADMIN-ONLINE**: host-c re-registers its endpoint and keeps routing to
  host-b with the founder (host-a) stopped — the no-admin-coupling guarantee.

Remaining tidy-ups (non-blocking): `name/ tag/ posture/` still dual-write (their
read paths — MagicDNS, Cedar reach — haven't migrated to self-docs yet); the
shared-doc self-key *enforce* can be removed once self-docs are universal.

**Remaining (the final isolation flip):**
7. **Harden imported-self-doc sync** (active sync for `member_self_doc` docs), then
   **drop the shared-doc `vpn/` write** (`register_vpn_endpoint` → self-doc only)
   so the endpoint is physically isolated; migrate `lookup_vpn_endpoint` (egress
   resolution) to the self-doc; and rewrite the `vpn/` forgery tests
   (`enforce_rejects_forged_vpn_entry`, federation) for the self-doc model (a
   member can't intercept another's addr — the override ignores `vpn/<other>` in
   a member's self-doc). `name/ tag/ posture/` and `ip/` follow the same pattern
   (`ip/` stays shared for cross-node vIP-dedup until deterministic allocation).
8. **Tier ticket scope (#3b)**: `node`/`warren-only` invites carry the admin doc's
   **read** ticket (not write); `admin` carries write — safe once members write
   only their own self-doc.

> **Test note:** the eager per-node self-doc namespace adds gossip load that can
> make single-process, many-`NetDoc` replication tests flaky (>30s). Production
> (separate processes) converges fast (vpn-e2e). A clean fix is **lazy** self-doc
> creation — a pure client / non-VPN node shouldn't mint one. Tracked as a
> follow-up.


---

## Install Model & Invite Capability Tiers (Design)

> **Status: in progress, shipping incrementally.** This specifies a unified
> install convention and an explicit invite-capability model. Decisions are
> resolved in [§8](#8-decisions-resolved); the file-level build plan is in
> [§9](#9-implementation-plan-code-level); **what has actually shipped (and what
> is deferred, with rationale) is tracked in [§10](#10-implementation-status-shipped-incrementally)**.
> As of 0.6.45: the C1 trust anchor + admin+self-key enforce (flag-gated, proven by a forged-entry test), the
> warren-only tier, the InviteTier model, and the self-upgrade consent flow are
> shipped; the embedded daemon installer, C1 self-key binding/read-ticket
> members, and signing remain dedicated follow-ups. Sequenced against the C1
> work in [Security Audit](#security--code-health-audit--2026-06-03) (Phase 0).

### 1. Problem

Two things are tangled today:

1. **The website forces a client-vs-server guess.** The install page asks the
   user to decide up front whether this machine is a "client" or "on the
   warren" — a decision most users can't make before they understand the
   product, and one that isn't final anyway (a client that later wants to host
   re-runs the installer with `sudo`).
2. **Invites have only two effective tiers, and the wrong things are fused.**
   The only production site that attaches a `warren_ticket` is the **creator
   invite** (`crates/hop-cli/src/main.rs`, host-startup augmentation). So:
   - a regular `hop invite --role X` → **reach-only** (no warren ticket), and
   - a creator invite → **admin + warren node**, where the warren ticket is a
     **write** ticket (security-audit **C1**).

   The common "put this server on the mesh, but it is **not** an admin" case is
   inexpressible: the only thing carrying warren membership is the
   admin/write-capable creator invite. "Can join the warren" is fused to "can
   rewrite the whole warren."

### 2. Capability model — four tiers

Three orthogonal axes (plus confinement/identity modifiers that already exist):

| Axis | Grants | Needs the daemon (root)? |
|---|---|---|
| **session reach** | `hop <host>` shell / exec / transfer into a host | No — a pure client only initiates outbound sessions |
| **warren membership** | virtual IP, MagicDNS, L3 reach to services (role→tag ACL) | **Yes** — creating a TUN needs root (same as Tailscale/WireGuard) |
| **admin** | mint invites, grant roles, write warren state | Yes |

These are already separate gates in code: VPN L3 reach is `vpn_reach_allowed`
(Cedar), session access is peer-authorization in `auth/`. The model just makes
the split explicit and names the useful combinations:

| Tier | session reach | warren | admin | Daemon / sudo | Warren ticket |
|---|---|---|---|---|---|
| **client** (default) | ✅ (to invited hosts) | — | — | **No** | none |
| **warren-only** | — | ✅ (L3 to services per role) | — | Yes | **read** |
| **node** | ✅ | ✅ | — | Yes | **read** |
| **admin** | ✅ | ✅ | ✅ | Yes | **write** |

- **client** — the laptop/phone/CI that *connects to* hosts. No TUN, no daemon,
  no sudo. Reach scoped by the role's tags; confinement by the role's sandbox.
- **warren-only** — a corporate-VPN user: on the mesh, can reach
  `wiki.hop`/`jenkins.hop` per role, but **cannot** open a hop session into any
  box. Needs root locally only to make the tunnel.
- **node** — a server: on the mesh *and* reachable/hostable, but not an admin.
  This is the missing middle tier and the most common server case.
- **admin** — founds/administers the warren. The only tier with a **write**
  ticket.

The `read` vs `write` ticket distinction is the C1 remediation — see §7.

### 3. Personas → tiers

| Persona | Tier(s) |
|---|---|
| Founder / solo homelab | **admin** for themselves; **node** for their servers |
| Fleet operator | **admin** for self; **node** (aggregate) for servers; **client** for teammates |
| Teammate / contractor | **client**, scoped sandbox, optional TTL |
| AI agent / automation | **client**, tight sandbox |
| Worker / appliance box | **node** (mesh + reachable, not admin) |
| Corporate VPN user | **warren-only** |

Every persona maps to exactly one tier. That is the simple convention.

### 4. Invite encoding

Today the tier is *inferred* (warren_ticket presence + `PeerRole::Creator`).
Make it **explicit and minted by the inviter**, who knows the trust level.

Proposed `InviteToken` change (`crates/hop-core/src/invite/mod.rs`):

```rust
pub struct InviteToken {
    // … existing: node_id, secret, relay_url, username, host_name,
    //              role, role_name, sandbox …
    /// Explicit capability tier. Replaces inferring from warren_ticket/role.
    #[serde(default)]              // old invites → Client via Default
    pub tier: InviteTier,
    /// Warren join ticket. Scope follows the tier: a read-scoped membership
    /// ticket for Warren/Node, a write ticket only for Admin. `None` = Client.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub warren_ticket: Option<String>,
}

#[derive(Default)]
pub enum InviteTier { #[default] Client, WarrenOnly, Node, Admin }
```

`hop invite` flags (extend `cli.rs` `Invite`):

| Flag | Tier |
|---|---|
| *(none)* | `client` (reach-only — current default behavior) |
| `--warren` | `node` (mesh + session reach) |
| `--warren-only` | `warren-only` (mesh, no host sessions) |
| `--admin` | `admin` |

Flag names confirmed (decision 2): `--warren` / `--warren-only` / `--admin`.
`--creator` is kept as a **deprecated, hidden alias** for `--admin` so existing
scripts and the auto-generated `creator_invite` keep working.

`--role`, `--user`, `--read-only`, `--no-network`, `--scope`, `--allow-command`,
`--preset` continue to apply orthogonally (they shape reach/confinement/identity
*within* a tier).

**Backward compatibility:** old invites have no `tier` field → `Default` =
`Client`, but a decoder infers the effective tier for legacy tokens: `warren_ticket`
present + `PeerRole::Creator` → `Admin`; `warren_ticket` present → `Node`; else
`Client`. So existing creator invites keep working.

### 5. Install model — one install, self-upgrade

**There is one install.** Everyone runs the same command; it installs the binary
as a **client** into a **user-writable** dir (`~/.local/bin`) with **zero sudo**
(decision 7). A pure client only ever runs as the user, so a user-owned binary
has no escalation surface:

```
curl -fsSL https://hop.keikai.ai/install.sh | bash
```

"Server / warren / admin" is **not a separate install** — it's an **upgrade a
client performs on demand**, when it gains a capability that needs the daemon.

#### Upgrade triggers
- Redeeming a `warren` / `warren-only` / `admin` invite.
- Running `hop host` (explicitly wanting to be reachable / on the mesh).

A **reach-only (client) invite never triggers an upgrade** — you redeem it and
stay a client.

#### Self-upgrade flow (the important part — also the H10 fix)
1. **Decode + validate the invite as the unprivileged user.** No root yet.
   Verify the host identity, show the human-readable host name + the tier +
   which warren it joins.
2. **Reach-only?** Record the host in `known_hosts` / peer state. Done. **No sudo.**
3. **Node / warren / admin?** Prompt with concrete context:
   > `This will make <machine> a <tier> on warren "<name>" (<node-id prefix>).`
   > `That requires installing a system daemon (root). Continue? [y/N]`
   - **Yes** → escalate: install the system daemon under `sudo`, passing the
     already-validated ticket + role + tier. Bring up the daemon configured for
     the tier (VPN on for warren+, session-hosting for node+, admin role for
     admin).
   - **No / non-interactive** → **stay a client**, stash the validated join
     ticket (`netdoc-join.ticket`, `0600`), and print the exact command to
     finish later. Graceful — never a half-broken state.

This is precisely the **H10** remediation: the invite is decoded and the trust
decision is shown **before** any root is acquired, instead of today's
`sudo hop warren join <attacker-influenceable-invite>` which dials out as root.

#### Binary location — the root-owned invariant (decision 7 security)

> **A root daemon must only ever execute a root-owned, root-only-writable
> binary. It must never run one from a user-writable path** (`~/.local/bin`,
> `~/bin`, …).

If the always-on root daemon ran a user-writable file, anything in that user's
account (a bug, a bad dependency, malware) could overwrite it and execute
arbitrary code **as root** on the next start — a privilege-escalation hole.

`~/.local/bin/hop` (zero-sudo) is fine for a **pure client** — it only ever runs
as the user. But the self-upgrade to a root daemon must **verify-then-promote**:

1. **Verify** the binary against the published release checksum/signature (this
   is the natural home for artifact signing, security-audit H9).
2. **Promote** the verified bytes into a root-owned path (`/usr/local/bin/hop`,
   `root:wheel`, `0755`) under the one upgrade-time `sudo`.
3. Point the LaunchDaemon/systemd unit at **that** path — never at `~/.local/bin`.

The upgrade never `sudo`s the user-writable binary; it verifies a clean copy and
lays it down root-owned. "Become a server" is a sudo moment anyway, so zero-sudo
applies only to the pure-client lifetime — which is correct.

#### How the binary performs the privileged install
**Decision 1 — embedded.** A hidden `hop __install-daemon` subcommand drops the
LaunchDaemon plist / systemd unit from **embedded templates** and registers the
service. It runs from the **promoted, root-owned** `/usr/local/bin/hop` (per the
invariant above), invoked under the upgrade `sudo`. Rationale:
- No network round-trip for the *setup logic* (works offline / air-gapped).
- Runs a verified, root-owned binary — not the user-writable one.
- Testable in-process; one code path for macOS (launchd) and Linux (systemd).

(The verify-and-promote step in the invariant may fetch a fresh verified binary
from the CDN, or verify the local binary against the published `.sha256` and copy
it — either is fine; the small checksum fetch avoids re-downloading the whole
binary.)

#### Keep the up-front path for automation
`--host` and the fleet `--register` (aggregate-invite) paths stay as the
**explicit, non-interactive** way to provision a known server in one shot —
that's the one place up-front sudo earns its keep (CI/provisioning can't answer
an interactive prompt). The website's old "Server" type becomes this shortcut,
not the default.

### 6. Website builder

- **Default: one command**, the client install. No client/server choice.
- **Optional "Paste your invite" field.** The command stays the same (client
  install); `hop` self-upgrades on redeem per the invite's tier. Nicety: the
  page can client-side decode the invite (base64 JSON) and *preview* the tier —
  "this invite will make this machine a **node** on warren *acme*."
- **Advanced disclosure:** "Provision as a server now (sudo)" → the explicit
  `install.sh --host …` / `--register` command for automation/known servers.
- **Copy fixes (do regardless):** remove every "VPN on by default" — the builder
  VPN label (`index.html:627`), the node hint (`:881`), the warren section
  (`:341`), and "joins your warren with its own virtual IP" (`:534`). The VPN is
  opt-in/off-by-default since 0.6.37.

### 7. Sequencing

**Security first (decision 5).** The C1 trust-model fix is Phase 0 — the tiers
are *born* on the read/write split, so we never ship an over-powered interim
"node" running on a write ticket.

- **Phase 0 — Close C1 (the keystone).** Read-scoped membership tickets vs. a
  write ticket reserved for admin; the doc enforces **author-validated writes**
  (a read replica cannot rewrite another node's `vpn`/`name`/`ip`/role entries).
  After this the warren is trustworthy and a "node, not admin" membership is a
  real, safe thing to grant. (Subsumes the deferred C1 work in
  [Security Audit](#security--code-health-audit--2026-06-03); H1/H2/M6 collapse with it.)
- **Phase 1 — Tiers + unified install + self-upgrade (built on the secure base).**
  Add `InviteTier` to `InviteToken` (+ back-compat inference) and the `hop
  invite` flags; node/warren tiers issue **read** tickets, admin issues **write**.
  One-command zero-sudo client install; the self-upgrade flow with the
  verify-then-promote root-owned-binary invariant (§5) and `hop __install-daemon`
  (delivers the **H10** fix: decode-as-user → consent → escalate). Website
  rebuild: one command + optional invite-paste **tier preview** (decision 3) +
  the advanced "provision now" disclosure. **warren-only ships in this phase**
  (decision 4), including the role flag that **denies host sessions** while
  allowing L3 reach.
- **Phase 2 — Fleet + polish.** Aggregate/fleet invites carry an explicit tier;
  artifact signing wired into verify-then-promote (H9); any remaining
  warren-only / capability-preview refinements.

**Can land anytime (no trust-model change):** the website **copy fixes** — delete
every "VPN on by default" (`index.html:627/881/341/534`); the VPN has been
opt-in/off-by-default since 0.6.37.

### 8. Decisions (resolved)

| # | Decision | Resolution |
|---|---|---|
| 1 | Daemon-install mechanism | **Embedded** `hop __install-daemon` (offline-capable, runs the verified root-owned binary). |
| 2 | Invite flag names | **`--warren` / `--warren-only` / `--admin`**; `--creator` kept as a deprecated hidden alias. |
| 3 | Website previews the invite tier? | **Yes** — decode the token **in-browser only** (no network, read-only). |
| 4 | Ship `warren-only` in v1? | **Yes** — in Phase 1, with the session-deny role enforcement. |
| 5 | Order vs. the C1 security fix | **Security first** — C1 is Phase 0; tiers/install build on it. |
| 6 | Self-upgrade default + keep up-front for automation | **Confirmed** — client-first for humans; `--host`/`--register` stay for non-interactive provisioning. |
| 7 | Client binary location | **`~/.local/bin`, zero sudo** for the pure client — **but** the root daemon must run a **verified, root-owned** binary, so self-upgrade *verifies-then-promotes* to `/usr/local/bin` (§5 invariant). |

Remaining to confirm before building Phase 1: exact `InviteTier` wire shape and
whether the verify-then-promote step re-fetches the binary or checksum-verifies
the local one (both acceptable; pick when artifact signing lands).

---

### 9. Implementation plan (code-level)

Grounding facts from the current code (`crates/hop-core/src/netdoc/mod.rs` unless
noted):
- `read_ticket()` (`ShareMode::Read`) and `write_ticket()` (`ShareMode::Write`)
  **already exist**; today every invite ships the **write** ticket.
- The doc author is **per-host** (`docs.author_default()`, stored as
  `NetDoc::author`); the netdoc endpoint key is derived from the host secret
  (`net::derive_netdoc_secret_key`), so it's stable across restarts.
- `iroh_docs::Entry` exposes `.author()` (iroh-docs 0.97) but the read path
  (`decode_entry`/`list_prefix`, `reconcile`, `resume_sync`,
  `refresh_vpn_peer_ips`, `list_virtual_ips`, `lookup_*`, `vpn_reach_allowed`,
  `get_peer`, `is_revoked`) **never checks it**.
- Doc keys: admin-owned → `peer/<node>`, `role/<name>`, `revocation/<node>`,
  `acl/cedar`, `network/domain`; self-owned → `vpn/<addr>`, `ip/<addr>`,
  `tag/<node>`, `posture/<node>`, `name/<n>`.
- Federated joiners already **don't** self-write `peer/<node>` — the inviter
  writes it (`enable_vpn` self-registers only when `!self.federated`).

#### Phase 0 — Close C1

The exploit (a member forging `vpn/<victim>` etc.) is closed by **validating the
author on read**; read-only tickets are the follow-on hardening.

**0a — Author-validated reads (closes the exploit; keep write tickets for now).**
1. *Identity binding.* Add `netdoc_author: Option<String>` (and `netdoc_node`)
   to the `Peer` doc entry (`config`/`proto` Peer type) and to the redeem
   handshake. The redeem already runs (`cmd_warren` → `cmd_exec` to the inviting
   host, consumed in `auth/mod.rs`); extend the client→host auth message to carry
   the joiner's **netdoc** NodeId/author, and have the inviting host record it
   when it writes the admin-authored `peer/<node>` (`put_peer`). The admin is
   vouching: "node N's doc author is A_N."
2. *Admin author set.* The namespace **creator's** author is the root admin
   (it created the namespace). Persist the admin author set in an admin-authored
   `admin/<author>` entry; v1 = just the founder, with room to promote co-admins
   later. Expose `NetDoc::is_admin_author(&AuthorId)`.
3. *Central validator.* Add `fn entry_author_ok(key: &[u8], value_node: Option<&str>, author: &AuthorId) -> bool`:
   - admin keys (`peer/ role/ revocation/ acl/ network/ admin/`) → `is_admin_author`.
   - self keys (`vpn/ ip/ tag/ posture/ name/`) → `author == vouched_author_for(owning_node)` **and** the owning node matches the admin-authored ownership (`ip/<addr>`→node, `peer/<node>` exists). Unknown/unbound author → reject.
   Call it in `decode_entry`/`list_prefix` and each consume site listed above;
   **ignore** (don't act on) entries that fail. Log at `debug`.
4. *Tests* (netdoc, two authors): a `vpn/<victim>` written by a non-owner author
   is ignored; a legit self-entry passes; a `peer/`/`role/` from a non-admin
   author is ignored; revocation by a non-admin is ignored.

**0b — Read-ticket members (remove the write capability).**
5. Invites for the **node / warren-only** tiers carry `read_ticket()`; **admin**
   carries `write_ticket()`. (Change the `main.rs` creator-invite augmentation +
   `generate_invite_with_role` to pick the ticket by tier — depends on 1a.)
6. Members can no longer self-write `vpn/ ip/ tag/ posture/ name/`. Replace with a
   **node-announce**: on join and periodically, the member sends its endpoint /
   desired tags / posture / name to an admin over an authenticated RPC; an admin
   writes the (now author-valid) entries. vIP allocation moves admin-side
   (`claim_virtual_ip` keyed by the member's node, written by admin). This is the
   larger change; 0a already makes the warren safe, so 0b can land second.

**Migration (important):** existing warrens have self-authored entries with no
admin-vouched binding. On upgrade, run a one-time **founder re-vouch**: the admin
writes `netdoc_author` bindings for every current `peer/<node>`, and a bounded
**grace window** accepts unbound self-entries (with a warning) until bindings
replicate. Gate the strict-reject behavior behind a version flag in
`network/config` so a half-upgraded warren doesn't partition.

Files: `netdoc/mod.rs` (validator + read sites + ticket selection + announce
writes), `proto/mod.rs` + `config/mod.rs` (Peer binding fields, announce msg),
`auth/mod.rs` (record binding on consume), `main.rs` (ticket-by-tier).

#### Phase 1 — Tiers + unified install + self-upgrade + warren-only + website

**1a — `InviteTier` in the wire model.** Add to `invite/mod.rs`:
```rust
#[derive(Default, Serialize, Deserialize)]
pub enum InviteTier { #[default] Client, WarrenOnly, Node, Admin }
```
field `tier: InviteTier` on `InviteToken` (`#[serde(default)]`); legacy decode
inference (`decode_invite`): warren_ticket+Creator→Admin, warren_ticket→Node,
else Client. `hop invite` flags (`cli.rs` + `cmd_invite`): `--warren`,
`--warren-only`, `--admin` (+ hidden `--creator` alias → Admin). Ticket scope
follows tier (read vs write, from 0b).

**1b — Self-upgrade install.**
- New hidden subcommand `hop __install-daemon` (`cli.rs` + `main.rs`): embed the
  LaunchDaemon plist (`pkg/com.hop.daemon.plist`) and systemd unit
  (`pkg/hop.service`) as templates via `include_str!`; write/`chown`/enable the
  service; apply primers (`vpn on/off`, tags, default_role); write
  `netdoc-join.ticket`; start. One Rust path replacing `install-daemon.sh`'s
  platform logic.
- **Verify-then-promote** (the §5 invariant): before installing the service,
  verify the running binary against the published checksum and copy it to
  root-owned `/usr/local/bin/hop` (`root:wheel 0755`); point the unit there.
- Redeem/`hop host` self-upgrade (`cmd_warren`, `cmd_host`): decode the invite
  **as the user**, show host identity + tier + warren; if the tier needs the
  daemon, prompt and run `sudo hop __install-daemon …`; on decline/non-interactive,
  stash `netdoc-join.ticket` (0600) + print the finish-later command. (This is
  the **H10** fix.)
- `install.sh`: default `INSTALL_DIR=~/.local/bin` (zero sudo, decision 7); keep
  `--host`/`--register` as the explicit up-front path (now invoking
  `hop __install-daemon` after the binary lands).

**1c — warren-only enforcement.** Add `network_only: bool` to `RoleDefinition`
(`proto/mod.rs`); when set, `auth/mod.rs` refuses `RequestShell*/Exec*/Transfer`
for that role (returns a clear error) while the VPN L3 ACL (`vpn_reach_allowed`)
still applies. Seed a `warren-only` default role (`fleet/mod.rs::seed_defaults`).

**1d — Website** (`site/index.html`): default to one client command; optional
invite paste → **in-browser** `decode_invite` (base64 JSON) → preview tier;
"Advanced: provision as a server now (sudo)" disclosure; **delete** the "VPN on
by default" copy at lines 341, 534, 627, 695, 881.

Files: `invite/mod.rs`, `cli.rs`, `main.rs`, `proto/mod.rs`, `auth/mod.rs`,
`fleet/mod.rs`, `install.sh`, `pkg/*` (templates), `site/index.html`.

#### Phase 2 — Fleet + signing

- Aggregate invites carry an explicit `tier`; complete the per-host invite
  issuance the redemption handler currently stubs (`fleet/mod.rs`
  `RedeemAggregateInvite`). `--register` maps to the Node tier.
- Wire **artifact signing** (minisign/cosign) into verify-then-promote and the
  release script (closes H9); the self-upgrade then checks a signature, not just
  a co-located hash.

#### Test & rollout

- **Unit:** author-validator (forged vs legit, admin vs non-admin); `InviteTier`
  inference + encode/decode round-trip; `hop __install-daemon` templating
  (render plist/unit to a temp dir, assert contents); `network_only` session
  refusal.
- **e2e (`tests/e2e/`):** extend `vpn-e2e.sh` with (a) a **forged-entry** test —
  a second node writes `vpn/<victim>` and the victim/others must ignore it; (b) a
  **warren-only** node that can ping a service vIP but is refused a shell; (c) a
  **self-upgrade** smoke. Add a **macOS** run for the daemon-install path — the
  one combination today's Linux-container e2e doesn't cover.
- **Back-compat:** old invites → Client; old creator invites → Admin; the
  migration grace window (above) keeps existing warrens from partitioning during
  the Phase 0 rollout.

#### Risk register

| Risk | Mitigation |
|---|---|
| Author-binding migration partitions an existing warren | Version flag in `network/config` + bounded grace window accepting unbound entries with a warning; founder re-vouch on upgrade |
| `hop __install-daemon` is new platform code (launchd/systemd) | Port from the proven `install-daemon.sh`; unit-test template rendering; macOS + Linux e2e before release |
| Self-upgrade interactive sudo / half-states | Graceful client fallback (stash ticket, print finish command); never leave a partial daemon |
| 0b node-announce adds an RPC + admin write loop | Land 0a first (already closes the exploit); 0b can iterate without re-opening the hole |
| Read-validation in the per-packet path adds cost | Validate at reconcile/refresh time and cache the vouched-author map (reuse the existing reach-cache pattern), not per datagram |

### 10. Implementation status (shipped incrementally)

Built in safe, individually-released increments, security-first per decision 5.

| Piece | Status | Released |
|---|---|---|
| **Phase 1a** — `InviteTier` enum + field + legacy inference | ✅ shipped (inert; ticket-scope still legacy) | 0.6.40 |
| **Phase 0a** — C1 observe-mode author-stability detector | ✅ shipped (default `Observe`, log-only) | 0.6.40 |
| **Phase 0a** — C1 founder-author anchor (`founder_author` pinned in invites; persisted on join; recorded in `NetDoc`) | ✅ shipped | 0.6.41 |
| **Phase 0a** — C1 **admin-key enforce** (`peer/ role/ revocation/ acl/ network/` honored only from the founder author; complete across `list_prefix` + `get_peer`/`is_revoked`/`get_authored_policy`) | ✅ shipped, behind `HOP_NETDOC_VALIDATION=enforce` (default Observe) | 0.6.42 |
| **Phase 1c** — warren-only tier (`network_only` role flag + session-dispatch refusal + seeded `warren-only` role) | ✅ shipped | 0.6.42 |
| **Phase 0a** — C1 **self-key enforce LOGIC** (`Peer.netdoc_author` binding + `vouched_authors` + `vpn/`/`ip/` validated against the owner's vouched author in `refresh_vpn_peer_ips`; `self_entry_author_ok` unit-tested) | ✅ logic shipped, flag-gated; founder self-vouches | 0.6.44 |
| **Phase 0a** — C1 **member-node binding** (`AnnounceNetdocAuthor` daemon-outbound announce → founder records `peer/N.netdoc_author`; `record_peer_author` trust-anchor-only + idempotent; unit-tested by `enforce_rejects_forgery_against_vouched_member`; **multi-node enforce e2e** runs both nodes under `HOP_NETDOC_VALIDATION=enforce` + asserts the binding) | ✅ shipped | 0.6.46 |
| **Phase 0a** — C1 **vouched-admin-authors** (`admin_authors` = founder ∪ founder-vouched co-admin authors; `validate_entry` honors admin keys from any vouched admin; refreshed at startup / on vouch / on keepalive; unit-tested by `enforce_honors_vouched_co_admin_peer_entry`). Makes opt-in enforce safe for federated multi-admin warrens | ✅ shipped, flag-gated | 0.6.47 |
| **Phase 1b** — self-upgrade **consent** on `hop warren join` (decode-as-user → consent → reuse proven installer; the **H10** fix) | ✅ shipped | 0.6.43 |
| **Phase 1 (decision 7)** — `install.sh` default client install → `~/.local/bin` (zero-sudo); existing `/usr/local/bin/hop` updated in place; `--host` promotes to root-owned `/usr/local/bin`. `--site-only` now redeploys `install.sh` too | ✅ shipped | site deploy |
| **Phase 1d** — website builder **invite tier-preview** (client-side base64url-JSON decode → "joins host X as a node/admin/warren-only", auto-selects the node tier) | ✅ live | site deploy |
| **Phase 1a** — `hop invite --tier client\|warren-only\|node\|admin` (sets explicit `InviteTier`: client strips warren ticket, warren-only pins `network_only` role, admin → creator; warren tiers pin founder anchor). Ticket *scope* split still pending (Phase 0b) | ✅ shipped (capability tier) | 0.6.48 |
| **Phase 0a** — C1 `name/` self-key enforce (`lookup_name` drops a MagicDNS name authored by a non-owner; migration grace for unbound owners; `enforce_rejects_spoofed_name`) + 20 s co-admin-author refresh (`spawn_admin_author_refresh`) | ✅ shipped, flag-gated | 0.6.49 |
| Website "VPN opt-in" copy fixes | ✅ live | site deploy |

#### Deferred — major subsystems needing dedicated, validated passes

Consistent with the rock-solid mandate (and how C1-full/H8/H10 were deferred
earlier): these are big enough that rushing them would risk lockout, data loss,
or a privilege-escalation hole. Each needs test infrastructure we don't have yet.

- **C1 enforce — production flip.** Both admin-key *and* self-key (`vpn/`/`ip/`)
  enforce **logic** is implemented, unit-tested, **and proven end-to-end by a
  two-NetDoc forged-entry test** (`enforce_rejects_forged_vpn_entry`: a member's
  forged `vpn/<founder_addr>` is honored in Observe, dropped in Enforce). Shipped
  flag-gated (default Observe). The founder self-vouches, so **the founder is
  fully protected under enforce today**.
  - **Member-node binding — SHIPPED (0.6.46).** `ClientMessage::AnnounceNetdocAuthor
    { author }`: on `hop host` startup (after `enable_vpn`, once it has its
    author) a federated node opens an authenticated session to the founder —
    whose main NodeId is persisted from the invite as `netdoc-founder.node` —
    over the **main** hop endpoint and announces its doc author. The founder,
    receiving it from authenticated peer N, calls `record_peer_author` which
    (trust-anchor-only, member-must-exist, idempotent) writes
    `peer/N.netdoc_author`. Best-effort with exponential backoff. The chosen
    design needs **no author-derivation migration**, so it can't break a live
    warren's membership. The multi-node e2e (`tests/e2e/vpn-e2e.sh`) now runs
    both nodes under `HOP_NETDOC_VALIDATION=enforce` and asserts host-a records
    the binding — bind → enforce → reconverge on a real warren. Until the
    announce lands a member's self-owned `ip/`/`vpn/` entries pass under
    migration *grace* (unbound owner), so enforce never partitions a fresh join.
  - `name/` self-keys are **enforced (0.6.49)**: `lookup_name` drops a MagicDNS
    name whose author isn't the vouched author of the node owning the vIP it
    points to (spoof), with migration grace for unbound owners. Unit-tested
    (`enforce_rejects_spoofed_name`).
  - **Vouched-admin-authors — SHIPPED (0.6.47).** `reconcile` runs on every node
    and writes `peer/`/`role/` entries authored by *that* node; on a federated
    multi-admin warren a co-admin legitimately authors admin keys. `validate_entry`
    now honors admin keys from the founder **or any founder-vouched co-admin
    author**: `admin_authors` = the founder ∪ the `netdoc_author` of every
    **founder-authored** `peer/` entry with the Creator role. Only the founder
    confers admin authority (the set is built from founder-authored entries
    only — no elevation, no validation cycle), refreshed at startup, on the
    founder's own vouch, and on each sync keepalive. Unit-proven by
    `enforce_honors_vouched_co_admin_peer_entry` (a co-admin's `peer/C` is
    rejected under enforce until B is vouched, then honored). Legacy warrens with
    no founder anchor honor admin keys unconditionally (never partitioned).
  - **The global default flip is the last, deliberately-gated step.** Opt-in
    enforce (`HOP_NETDOC_VALIDATION=enforce`) is now production-safe for **all**
    topologies: single-admin, federated multi-admin (vouched), and anchor-less
    legacy (honored). What still gates flipping `ValidationMode::default()` to
    `Enforce` globally is a *mixed-version* propagation window: on a warren where
    co-admins run pre-0.6.46 builds (can't announce) the founder can't yet vouch
    them, so during the upgrade their federated `peer/` entries would be rejected
    until every node is upgraded + announced (auth still falls back to local
    `peers.json`, so this is a transient loss of *federated* reach, never local
    access or a lockout). Prereqs for the flip: (a) a 3-node federated e2e
    (founder + vouched co-admin + a peer the co-admin invited, all under enforce);
    (b) the co-admin-author refresh is now **20 s** (0.6.49,
    `spawn_admin_author_refresh`, decoupled from the 300 s sync keepalive) so the
    window closes fast. The 3-node federated e2e is folded into the per-member
    self-doc migration harness (Phase 0b below).
- **Phase 0b — per-member self-documents: ✅ COMPLETE.** Each member owns its own
  iroh-docs namespace (sole write key) and self-writes its VPN endpoint there; the
  admin doc (write-restricted to vouched admins) keeps `peer/ role/ acl/
  revocation/ network/` + the admin-allocated `peer/N.vip` (addr→owner authority)
  and `peer/N.self_doc` read ticket. The shared `vpn/` write is **dropped** — the
  endpoint is now physically isolated (no shared copy any member could forge).
  `node`/`warren-only` invites carry the admin doc's **read** ticket (write
  reserved for `admin`); a read-ticket member self-writes only its own self-doc
  and waits for its admin-allocated `peer/N.vip` at bringup. **No admin-online
  coupling**: a member re-registers its endpoint with no admin up. Endpoint
  resolution (`refresh_vpn_peer_ips` ingress + `lookup_vpn_endpoint` egress) reads
  from the owner's self-doc keyed by `peer/N.vip`, with an author-validated `ip/`
  fallback for legacy members. Proven end-to-end under enforce (`vpn-e2e`):
  founder↔member + reboot with the shared write gone, read-ticket member routing,
  and the no-admin-online guarantee (founder stopped, member re-registers + still
  routes). Full details + the root-cause debug story in
  `docs/technical/warren-internals.md`. Tidy-ups (non-blocking): `name/ tag/
  posture/` still dual-write until their read paths (MagicDNS, Cedar) migrate.
- **Phase 1b — embedded `hop __install-daemon` WIRED (flag-gated).** The hidden
  subcommand now does the full §5 privileged install in one Rust path:
  **verify-then-promote** the binary to root-owned `/usr/local/bin/hop`
  (`root:wheel 0755`), copy the staged primer files into the **system** config
  dir (`config::system_config_dir()`), apply vpn/tier/role primers in-process,
  write the embedded launchd/systemd template, and start the service. Flags:
  `--stage --vpn --tier --default-role --tags --promote-from --no-promote`.
  The unprivileged `verify_and_stage_binary` (sha256 vs the published `.sha256`,
  `HOP_PROMOTE_ALLOW_UNVERIFIED` dev escape) produces the verified bytes the
  privileged step promotes — so the user-writable binary is never run as root.
  `self_upgrade_to_node` wires it into both `hop warren join` **and** the
  `hop connect <invite>` auto-upgrade, behind **`HOP_NATIVE_DAEMON_INSTALL`**
  (the proven shell installer stays the default until the macOS e2e flips it).
  **e2e:** `tests/e2e/daemon-install-e2e.sh` (Linux/systemd, in CI — green) and
  `tests/e2e/macos-daemon-install.sh` (gated host script, snapshot-guarded
  teardown, refuses on a machine with a daemon already loaded). Flipping the
  default to native is gated on a green macOS run on a clean Mac/VM.
- **Connect-time auto-upgrade + multi-warren resolution (NEW).** `hop connect
  <warren-invite>` now puts the machine on the warren (consume → on the warren,
  no `--host`); a client-tier invite stays reach-only. When already on a
  *different* warren, the consume path offers **replace** (KISS default; a new
  `hop warren leave` tears down namespace/tickets/store/vIP after a timestamped
  backup, then joins the new one), with `--on-warren-conflict
  replace|merge|multi-home|abort` for headless and `--yes` to skip prompts.
  Conflict is detected via `netdoc::namespace_of_ticket` (decodes the incoming
  namespace from the ticket without joining) + `classify_warren_conflict`.
  **merge** (federation) and **multi-home** are designed extension points
  (enum variants present; bail "not yet available").
- **Phase 1a — tier *capability* flag SHIPPED (0.6.48); read/write ticket
  *scope* still pending.** `hop invite --tier client|warren-only|node|admin` now
  sets the explicit `InviteTier`: `client` strips the warren ticket (can't
  self-upgrade), `warren-only` pins the `network_only` role, `admin` redeems as
  creator, and warren tiers pin the founder anchor. The read/write ticket *scope*
  split is now **done** (Phase 0b ✅): `node`/`warren-only` carry the admin doc's
  **read** ticket, `admin` keeps write.
- **Phase 2 — artifact signing (H9): plumbing SHIPPED, inert until keyed.**
  `release.sh` signs each artifact with a detached `openssl dgst -sha256`
  signature when `HOP_SIGNING_KEY` is set; `install.sh` verifies it against an
  embedded `HOP_PUBKEY`, failing closed. RSA-via-openssl (not ed25519) so the
  stock `openssl` on macOS LibreSSL can verify with no extra dependency.
  `scripts/gen-signing-key.sh` mints the keypair. **Inert until the operator
  generates a key, embeds the public key in `install.sh`, and releases with
  `HOP_SIGNING_KEY` set** — `HOP_PUBKEY` empty ⇒ checksum-only (today's
  behaviour, unchanged). Once the pubkey is embedded, every release must be
  signed (install fails closed on a missing/bad signature).
- **Phase 2 — fleet-invite tiers SHIPPED (0.6.52).** `hop admin <host>
  fleet-invite --tier client|warren-only|node|admin` carries an explicit
  `InviteTier` (default `admin` = legacy Creator behaviour, back-compatible via a
  serde-default `tier` field on `AdminRequest::CreateFleetInvite`). The handler
  maps tier→role before storing the pending invite and stamps the tier + founder
  anchor (+ client-tier warren strip), mirroring `hop invite --tier`. Unit-tested
  (`fleet_invite_tier_stamping`).

*Last updated: 0.6.49 (signing plumbing shipped unkeyed)*


---

## Access Control: hop's warren vs. Tailscale

A technical comparison of how **hop** (the warren) and **Tailscale** decide who
can reach what — and, specifically, how each handles **capabilities**. Written
against hop's code (`crates/hop-core/src/vpn/acl.rs`, `netdoc/mod.rs`,
`fleet/mod.rs`) and Tailscale's current grants/ACL docs (linked at the end).

> **Terminology note.** "Capability" means two different things here. In
> Tailscale it means **application-layer capability grants** — structured JSON
> permission blobs handed to applications (the `app` field of a grant). In hop,
> `hop cap` is an unrelated **built-in automation** system (email triage, health
> monitors). hop has **no** equivalent of Tailscale's app-capability grants
> today; this document treats that as the headline difference.

### TL;DR

| Axis | hop (warren) | Tailscale |
|---|---|---|
| Policy location | **Decentralized** — in the replicated iroh-docs document; no coordinator | **Centralized** — one HuJSON tailnet policy file compiled + pushed by the coordination server |
| Unit of authorization | **Role** (named; carries reach + auth tier + OS sandbox) | **Rule** (`src → dst:port`) over users/groups/tags |
| Reach model | role `host_tags` → host `tags`, wildcard `*` or tag intersection | `src` list → `dst` list, per-port, per-proto |
| Default | **Default-deny** | **Default-deny** |
| Granularity | role↔tag (coarse) + optional static port-range rules | per-port/proto, autogroups, **device posture**, per-app capabilities |
| App-layer capabilities | **None** (gates at L3 + hop-session auth) | **Yes** — `app` capability grants delivered to apps (WhoIs / header) |
| Process confinement | **OS sandbox** (Seatbelt/Landlock) bound to the role | none (network-only; app capabilities are advisory to the app) |
| Identity source | invite-issued role (no IdP yet) | SSO/IdP users + synced groups |
| Enforcement | per-node, on the L3 VPN forwarding path | per-node packet filter (WireGuard), compiled centrally |

### hop's model — role → tag → reach, default-deny

**The role is the unit.** A `RoleDefinition` (`crates/hop-core/src/proto/mod.rs`)
carries everything about what a member is:

```rust
struct RoleDefinition {
    name: String,
    host_tags: Vec<String>,   // → network reach
    user_mode: UserMode,      // individual vs shared Unix account
    sudo: bool,
    admin: bool,              // can manage the warren
    groups: Vec<String>,      // Unix groups
    shell: Option<String>,
    sandbox: SandboxPolicy,   // → OS-level confinement of hop sessions
}
```

A **peer** carries a `role_name`; a **host** carries `tags`. Both live in the
replicated network document (`peer/`, `role/`, `tag/` keys).

**Reach is derived, not authored** (`vpn_reach_allowed` in `netdoc/mod.rs`). For
a packet `src_ip → dst_ip` on the VPN:

1. resolve `src_ip` → owning node → peer → `role_name` → `RoleDefinition`;
2. resolve `dst_ip` → owning host → its `tags`;
3. allow iff `role_reaches(role.host_tags, dst_tags)`:

```rust
pub fn role_reaches(role_tags: &[String], host_tags: &[String]) -> bool {
    if role_tags.iter().any(|t| t == "*") { return true; }      // wildcard
    role_tags.iter().any(|rt| host_tags.iter().any(|ht| ht == rt)) // intersection
}
```

Empty role tags → reaches nothing (the least-privilege `member` default).
Enforced **per packet on the forwarding path**, default-deny.

**Low-level primitive (not yet on the live path).** `vpn/acl.rs` also defines an
`AclPolicy` — an ordered, first-match-wins packet filter (`src`/`dst`/port-range/
`action` + a `default`), with `get_acl_policy`/`set_acl_policy` persisting it at
`acl/policy` in the doc. The design intent is that higher-level role→tag rules
compile down to this filter. **Today it is not consulted during forwarding** —
the live reach decision (`vpn_reach_allowed`, called per packet in the VPN
forwarding loop) evaluates `role_reaches` directly. So `AclPolicy` is a built,
replicable primitive awaiting wiring, not an active enforcement path.

**Two layers, set by one role.** hop separates:
- **Reach** (the network ACL above) — *can I connect at all?*
- **Confinement** (the OS sandbox — Seatbelt/Landlock) — *what may a hop
  session do once open?* (read-only, no-network, scoped paths).

A role carries both `host_tags` and a `sandbox`, so assigning one role sets reach
*and* confinement coherently. Tailscale has no analogue to the confinement layer.

**No coordinator.** The whole policy (roles, tags, membership, ACL) is CRDT state
replicated to every node and enforced locally. There is no central server
compiling or distributing it.

### Tailscale's model — central policy, src→dst, grants + capabilities

**One central policy file** (HuJSON), edited in the admin console / via GitOps,
compiled by the **coordination server** into a per-node packet filter and pushed
to every device.

**Building blocks:** `groups` (sets of SSO users), `tags` + `tagOwners` (non-human
device identities and who may assign them), `hosts`, and `autogroups`
(`autogroup:members`, `autogroup:admin`, `autogroup:self`, …). Identities come
from an **IdP** (users/groups synced via SSO).

**Classic ACLs** — network layer only:

```json
{ "action": "accept", "src": ["group:eng"], "proto": "tcp",
  "dst": ["tag:frontend:443"] }
```

**Grants (GA, the modern syntax)** — combine network *and* application layers in
one rule. Every grant has `src`, `dst`, and at least one of `ip` (network) or
`app` (capabilities):

```json
{
  "src": ["group:engineers"],
  "dst": ["tag:fileserver"],
  "ip":  [{ "action": "accept", "ports": ["443"] }],
  "app": {
    "tailscale.com/cap/drive": [
      { "shares": ["projects"], "access": "rw" },
      { "shares": ["archives"], "access": "ro" }
    ]
  }
}
```

**Application capabilities** are the key feature hop lacks. A capability is named
`{domain}/{path}` (e.g. `example.com/cap/billing`); its value is an **array of
arbitrary JSON config objects**. They're delivered to the destination
application via `tailscale whois`, the LocalAPI, or the `Tailscale-App-Capabilities`
HTTP header (through `tailscale serve`). The application then self-authorizes
using that structured grant — so authorization can be **fine-grained and
app-defined** (which file shares, which actions, which tenant) rather than only
"can this IP reach this port."

**Other gates Tailscale has:** per-proto rules, Tailscale SSH ACLs, and **device
posture** conditions (OS, client version, custom attributes) usable in `src`/`dst`.

### Side-by-side

**Distribution & trust.** This is the deepest difference. Tailscale's model
*depends on* a central coordination server to compile and authoritatively push
the policy — that's also its single trust root. hop's policy is **decentralized
CRDT state** with no coordinator; the trade-off is that hop has no central place
to atomically compile/validate a global policy, and (today) write-capability
gating is still the planned trust-root hardening.

**Expressiveness.** Tailscale is markedly more expressive: per-port/proto,
autogroups, posture, SSH rules, and especially **app-capability grants** for
application-layer authorization. hop's reach is coarse (role↔tag intersection,
plus optional static port ranges) and stops at L3 — services behind hop's VPN
authenticate their own clients; hop doesn't pass them a capability blob.

**The confinement axis is hop's, not Tailscale's.** hop binds an **OS-enforced
sandbox** (Seatbelt/Landlock) to the role, governing what a hop *session* can do
on the host. Tailscale's "app capabilities" are advisory data handed to an app;
hop's sandbox is kernel-enforced isolation of the process. They solve different
problems and could be complementary.

**Identity.** Tailscale derives identity from SSO/IdP (users + synced groups).
hop derives it from an invite that pins a role; there's no IdP integration yet
(it's on the commercial roadmap, tied to the trust root).

### What hop could borrow (gaps)

- **Application-capability grants.** A `role`/grant could carry a typed JSON
  capability map surfaced to services hop fronts (analogous to
  `Tailscale-App-Capabilities`), enabling app-level authorization instead of only
  L3 reach. This is the single biggest capability gap.
- **Port/proto in the derived path.** Reach is currently tag-level; folding the
  `AclPolicy` port ranges into the role→tag derivation would match Tailscale's
  per-port granularity without hand-authoring rules.
- **Autogroups & posture.** `autogroup:self`-style conveniences and device-posture
  conditions (OS/version/health) are absent.

### Where hop is structurally different (by design)

- **No coordinator / no central control plane** — the whole policy is replicated
  CRDT state. This is hop's defining guarantee; Tailscale's central compiler is
  exactly what hop omits.
- **Role = one decision for reach + auth tier + OS confinement** — Tailscale needs
  separate ACL rules, SSH rules, and (advisory) app capabilities; hop folds reach
  and kernel-enforced confinement into a single role.
- **Default-deny least-privilege member** out of the box, with reach that's stable
  across membership churn (role↔tag, not per-IP).

### Conventionality, open standards, and a migration path

**Is Tailscale's ACL conventional / standards-based?** Partly.

- **Format — open and conventional.** The policy file is **HuJSON / JWCC**
  ("JSON With Commas and Comments"), an extension of JSON ([RFC 8259]) that
  Tailscale open-sourced (`github.com/tailscale/hujson`). There's also a visual
  policy editor. So the *syntax* is just JSON-with-comments.
- **Basics are familiar.** `{ "action": "accept", "src": …, "dst": …, "proto": … }`
  reads like firewall / security-group rules — a model most operators know.
- **Semantics are bespoke.** The schema is **not** built on any authorization
  standard — not XACML, not Cedar, not OPA/Rego, not OpenFGA/Zanzibar. And the
  parts beyond the basics carry real learning curve: **tags + tagOwners** (which
  allow nested ownership hierarchies Tailscale itself flags as hard to track),
  **autogroups**, and the recent **ACLs → grants** migration.

So: an open *format* and firewall-like *basics*, but proprietary semantics with a
non-trivial learning curve. (There is no dominant open standard for *network
reach* policy specifically; the 5-tuple + tags is the de-facto lingua franca.)

**Open authorization standards** worth knowing for hop:

| Option | Shape | Fit for hop |
|---|---|---|
| **Cedar** (AWS, Apache-2.0) | IAM-like, human-readable, deny-by-default, formally verified/analyzable, **Rust crate `cedar-policy`**, ~40–60× faster than Rego | Strong — Rust-native, analyzable ("why denied?"), matches hop's rock-solid bar |
| **OPA / Rego** (CNCF) | Datalog-derived, infra-level, powerful but harder to read | Heavier; less readable |
| **OpenFGA / Zanzibar** | relationship-based (ReBAC) | App object graphs, not L3 reach |

**Recommendations to make hop's ACL conventional, understandable, and easy for a
Tailscale user to adopt** (independent moves, in priority order):

1. **Match the vocabulary + give it an editable surface** *(highest leverage)*.
   hop already has the primitives — `tags` and the `AclPolicy` `src`/`dst`/port
   filter. Surface a **human-editable policy in JWCC** using Tailscale's exact
   words — `accept`, `src`, `dst`, `tag:`, `group:`, default-deny — so a Tailscale
   user's mental model transfers 1:1. Add a `hop acl` view/edit command and worked
   examples. (This also finally wires `AclPolicy` onto the live path.)
2. **Ship a Tailscale-ACL importer.** Translate a pasted tailnet grant/ACL into
   hop roles/tags/rules: map what maps (`src`/`dst`/tags/ports), and clearly
   report what doesn't yet (app capabilities, device posture). "Paste your tailnet
   policy" is the most concrete possible on-ramp.
3. **Consider Cedar as the engine underneath.** Compiling hop's role→tag policy to
   **Cedar** would make hop's authz *standards-based, auditable, and analyzable*
   (e.g. `hop acl explain <src> <dst>` → "allowed because role `dev` reaches
   `tag:staging`"), arguably more principled than Tailscale's bespoke schema. It's
   a bigger lift and Cedar is app-authz-oriented, so treat it as a direction, not
   a mandate.

**Do not trade away** hop's differentiators for familiarity: the **decentralized
distribution** (no coordinator) and the **role = reach + OS-sandbox** model. The
goal is a *familiar surface and standards-based engine* over hop's existing
decentralized, role-centric core — not Tailscale's centralized architecture.

> The Cedar engine, the Tailscale-ACL importer, and the feature-gap closers
> described above are **shipped** — `crates/hop-core/src/vpn/cedar.rs` +
> `tailscale_import.rs`, surfaced via `hop acl check` / `hop acl import`.

[RFC 8259]: https://www.rfc-editor.org/rfc/rfc8259

### Sources

- hop: `crates/hop-core/src/vpn/acl.rs`, `crates/hop-core/src/netdoc/mod.rs`
  (`vpn_reach_allowed`), `crates/hop-core/src/proto/mod.rs` (`RoleDefinition`),
  [warren.md](../product/warren.md), [Peer-to-Peer Private Network](#peer-to-peer-private-network-design).
- Tailscale: [ACLs](https://tailscale.com/kb/1018/acls),
  [Grants](https://tailscale.com/kb/1324/grants),
  [Grants syntax](https://tailscale.com/docs/reference/syntax/grants),
  [Application capabilities](https://tailscale.com/docs/features/access-control/grants/grants-app-capabilities),
  [Policy file syntax](https://tailscale.com/docs/reference/syntax/policy-file),
  [Device posture](https://tailscale.com/blog/device-posture),
  [HuJSON / JWCC](https://github.com/tailscale/hujson),
  [visual policy editor](https://tailscale.com/docs/features/visual-editor).
- Standards: [Cedar policy language](https://www.cedarpolicy.com/) (Rust crate
  `cedar-policy`), [Open Policy Agent / Rego](https://www.openpolicyagent.org/),
  [JSON / RFC 8259](https://www.rfc-editor.org/rfc/rfc8259).

*Last updated: v0.6.35*
