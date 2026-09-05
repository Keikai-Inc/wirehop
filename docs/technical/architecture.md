# Architecture & Protocol

hop's crate/module layout and dependency flow, plus the on-the-wire protocol (ALPN versions, message types, the admin protocol).


---

## Architecture

### Workspace Layout

hop is a Cargo workspace with three crates:

```
Cargo.toml              # workspace root
crates/
  hop-cli/              # Binary crate (binary name: "hop")
  hop-core/             # Library crate (networking, PTY, auth, config, protocol)
  hop-mcp/              # MCP server + JS runtime for orchestration
```

Workspace-level settings in the root `Cargo.toml`:

```toml
[workspace.package]
version = "0.6.33"
edition = "2024"
license = "LicenseRef-Proprietary"
```

### Dependency Flow

```
hop-cli ──depends-on──> hop-core
hop-cli ──depends-on──> hop-mcp
hop-mcp ──depends-on──> hop-core
```

`hop-core` is the foundation. Both `hop-cli` and `hop-mcp` depend on it. `hop-cli` also depends on `hop-mcp` for MCP server functionality.

### Crate: hop-core

The core library providing networking, authentication, protocol, file transfer, sandboxing, and configuration. All heavy lifting lives here.

**Modules:**

| Module | Purpose |
|---|---|
| `admin/` | Host-side admin command handlers (create user, fleet management) |
| `auth/` | Authentication flow (invite verification, peer authorization) |
| `config/mod.rs` | Identity management, peer/known-host stores, host config |
| `datastore/` | Embedded redb database: KV, time-series, cron, secrets |
| `fleet/` | Fleet membership, heartbeat, tagging |
| `invite/mod.rs` | Invite token generation/verification (SHA-256 verifiers; post-auth grants) |
| `net/mod.rs` | iroh endpoint creation, QUIC connection management |
| `net/netmon.rs` | Network interface polling, reconnection triggers |
| `netdoc/mod.rs` | **Warren network document**: iroh-docs/gossip/blobs CRDT (on an isolated endpoint) holding membership, roles, revocations, virtual IPs, VPN endpoints, host tags, names; virtual-IP allocation, role→tag→ACL reach resolver, federation (DocTickets), MagicDNS |
| `vpn/` | **Warren VPN data plane** (unix): TUN device (`100.64.0.0/10`, MTU 1280), ALPN `hop/vpn/1` over QUIC datagrams, `VpnInbound` handler, `role_reaches` ACL (`acl.rs`), DNS A-record codec (`dns.rs`), CGNAT-conflict guard |
| `proto/mod.rs` | Wire protocol: message enums, frame encoding, ALPN versions |
| `sandbox/` | OS-native sandboxing (macOS Seatbelt, Linux Landlock) |
| `shell/` | PTY session management, session registry |
| `transfer/` | File copy/sync: delta algorithm, negotiation, sender/receiver |
| `unix_user.rs` | Unix user lookup and validation |
| `lib.rs` | Public re-exports |

**Key dependencies:**

```toml
iroh          # QUIC-based P2P networking (custom fork: thedracle/iroh@hop-relay-fix-0.97, iroh 0.97)
iroh-docs     # CRDT document replication for the warren network document (0.97)
iroh-gossip   # Gossip overlay backing iroh-docs (0.97)
iroh-blobs    # Content-addressed blob store backing iroh-docs (0.99)
tun           # TUN/utun device for the VPN data plane (unix)
tokio         # Async runtime
bincode       # Binary serialization for wire protocol
redb          # Embedded key-value database
argon2        # Verifies pending invites written by hop <= 0.9.37 (until they expire)
chacha20poly1305  # AEAD encryption for secrets
portable-pty  # Cross-platform PTY spawning
landlock      # Linux filesystem sandbox (cfg(target_os = "linux"))
```

> The custom iroh fork is wired in via `[patch.crates-io]` in the root
> `Cargo.toml` (iroh + iroh-base + iroh-relay → `thedracle/iroh@hop-relay-fix-0.97`,
> which is iroh 0.97.0 plus a macOS relay-cascade fix).

### Crate: hop-cli

Thin CLI wrapper that provides the `hop` binary. Handles argument parsing, TUI, connection multiplexing, and delegates to `hop-core` and `hop-mcp`.

**Modules:**

| Module | Purpose |
|---|---|
| `main.rs` | Entry point, clap command dispatch |
| `cli.rs` | CLI argument definitions |
| `agent.rs` | Connection multiplexer agent (singleton process with QUIC pool) |
| `mux.rs` | IPC protocol for agent communication (MuxConnect/MuxResult) |
| `reconnect.rs` | Reconnection TUI (inline banner + full alternate-screen) |
| `progress_ui.rs` | Transfer progress display |
| `itemize.rs` | Sync dry-run itemization display |

**Key dependencies:**

```toml
hop-core      # Core library
hop-mcp       # MCP server functionality
clap          # CLI argument parsing
ratatui       # TUI framework for reconnection UI
crossterm     # Terminal manipulation
```

### Crate: hop-mcp

MCP (Model Context Protocol) server with an embedded QuickJS JavaScript runtime for orchestration scripts.

**Modules:**

| Module | Purpose |
|---|---|
| `lib.rs` | Public re-exports |
| `server.rs` | MCP server (JSON-RPC over stdio) |
| `protocol.rs` | MCP message types |
| `policy.rs` | MCP capability policies |
| `audit.rs` | MCP audit logging (mcp_audit.jsonl) |
| `cron.rs` | Cron job scheduler |
| `js/mod.rs` | QuickJS runtime factory and sandbox configuration |
| `js/bindings.rs` | Rust-to-JS bindings (`hop.*` global API) |
| `js/types.rs` | JS binding result types |
| `backend/` | OrchestratorBackend trait and implementations |
| `capabilities/` | MCP capability definitions |
| `skills/` | MCP skill handlers |
| `tools/` | MCP tool handlers |

**Key dependencies:**

```toml
hop-core      # Core library
rquickjs      # QuickJS JavaScript engine bindings
reqwest       # HTTP client (blocking mode for JS thread)
async-trait   # Async trait definitions
chrono        # Date/time for cron scheduling
cron          # Cron expression parsing
```

### Key Workspace Dependencies

All versions are pinned in the workspace root and referenced via `.workspace = true` in each crate.

| Dependency | Version | Purpose |
|---|---|---|
| `iroh` | git (custom fork) | QUIC-based P2P networking |
| `tokio` | 1 | Async runtime (multi-thread, signal, net, sync) |
| `bincode` | 2 | Binary serialization with serde |
| `serde` / `serde_json` | 1 | Serialization framework |
| `redb` | 2 | Embedded database (ACID, zero-copy reads) |
| `argon2` | 0.5 | Verifies legacy (<= 0.9.37) pending-invite hashes until they expire |
| `chacha20poly1305` | 0.10 | AEAD encryption for secrets |
| `sha2` | 0.10 | SHA-256 for key derivation |
| `zstd` | 0.13 | Compression for wire frames and file transfer |
| `xxhash-rust` | 0.8 | Fast hashing for file sync and delta transfer |
| `nix` | 0.29 | Unix system calls |
| `landlock` | 0.4 | Linux filesystem sandbox |

### Release Profile

```toml
[profile.release]
lto = true           # Full link-time optimization
codegen-units = 1    # Single codegen unit for max optimization
strip = true         # Strip debug symbols
panic = "abort"      # No unwinding overhead

[profile.release-cross]
inherits = "release"
lto = "thin"         # Faster cross-compilation (QEMU)
codegen-units = 4    # Parallel codegen
```

*Last updated: v0.6.33*


---

## Wire Protocol

### ALPN Versions

hop uses ALPN (Application-Layer Protocol Negotiation) to version the wire protocol. The host advertises all supported versions; the client selects the highest it supports.

```rust
pub const ALPN_V0: &[u8] = b"hop/0";  // Legacy: basic shell + auth + transfer
pub const ALPN_V1: &[u8] = b"hop/1";  // + compression, content hashing, parallel streams, delta transfer
pub const ALPN_V2: &[u8] = b"hop/2";  // + admin protocol, fleet, roles
pub const ALPN_V3: &[u8] = b"hop/3";  // + zstd compression on large frames (Output messages)
pub const ALPN_V4: &[u8] = b"hop/4";  // + AuthResultV2: invite grants delivered after auth

pub const VPN_ALPN: &[u8] = b"hop/vpn/1";  // Warren VPN data plane (separate endpoint)
```

The host endpoint binds with ALPNs in preference order: `[V4, V3, V2, V1, V0]`. The `negotiated_protocol_version()` function maps the negotiated ALPN to a `u8` (0-4). The client agent dials `hop/4` first and steps down to `hop/3`, then `hop/2`, when a host refuses the ALPN (a dial *timeout* is not a version mismatch and is not retried on an older ALPN).

`hop/vpn/1` is **not** part of this stack: it runs on the warren's separate,
isolated netdoc endpoint (see [Warren protocols](#warren-protocols-vpn--netdoc))
and carries raw L3 IP packets as QUIC datagrams, not length-prefixed frames.

### Frame Format

All messages use length-prefixed bincode encoding:

```
+--4 bytes--+--N bytes--+
|  length   |  payload  |
+-----------+-----------+
```

- **Length**: 4-byte big-endian `u32`. The high bit (0x8000_0000) is a compression flag.
- **Payload**: bincode-encoded (using `bincode::config::standard()`) Rust struct.

#### Compression (hop/3+)

When the high bit of the length prefix is set, the payload is zstd-compressed:

```
Bit layout of the 4-byte length:
  [C][--- 31-bit payload length ---]
   ^
   compression flag (0x8000_0000)
```

- **Compression threshold**: 64 bytes. Payloads smaller than this are never compressed.
- **Compression level**: 1 (speed-optimized).
- **Only compressed if smaller**: if zstd output >= original size, sends uncompressed.
- **Max decompressed size**: 64 MiB (prevents decompression bombs).
- **Max frame size**: 16 MiB (enforced on read).

#### Write Variants

```rust
// Standard: encode + flush (control messages)
async fn write_message<T: Serialize>(stream, msg) -> Result<()>

// Buffered: encode without flush (high-throughput FileData chunks)
async fn write_message_buffered<T: Serialize>(stream, msg) -> Result<()>

// Compressed: zstd when beneficial, always flushes (hop/3 Output messages)
async fn write_message_compressed<T: Serialize>(stream, msg) -> Result<()>
```

#### Read

```rust
// Transparently handles both compressed and uncompressed frames.
// NOT cancellation-safe — only use in a plain read loop.
async fn read_message<T: Deserialize>(stream) -> Result<T>

// Cancellation-safe: partial-frame state lives in the struct, so `next()` can be
// a `tokio::select!` branch — a cancelled read resumes where it left off.
struct FramedReader<R> { /* ... */ }
impl FramedReader { async fn next<T: Deserialize>(&mut self) -> Result<T> }
```

**Cancellation safety (why interactive sessions use `FramedReader`).** The bare
`read_message` future holds partial-frame state (the length prefix, the payload
accumulator) on its own stack across two `read_exact` awaits. If that future is
dropped mid-frame — which happens **every time it loses a `tokio::select!` race** —
the bytes it already pulled off the QUIC stream are lost, and the next read starts
mid-frame and desyncs (surfacing as `frame too large` / `decode failed`). The
interactive PTY loops (both client and host) multiplex the message read against
other branches in a `select!` — an always-ready `output_rx` (host) and a 10 s
heartbeat tick (client) — so under a sustained **output flood** (e.g. scrolling a
tmux buffer) one of those branches reliably cancels the read mid-frame, dropping
the session. (Plain `exec` and the VPN data plane were immune: exec uses a bare
read loop with no `select!`; the VPN is raw datagram forwarding.) `FramedReader`
fixes this by keeping the partial frame in the struct and advancing it with single,
individually cancel-safe `read()` calls, so its `next()` is safe as a `select!`
branch. All four live interactive/flood read loops use it.

### HostMessage (Host -> Client)

```rust
pub enum HostMessage {
    Output(Vec<u8>),                      // Shell output data
    Exit(i32),                            // Shell exited with status code
    WindowSizeAck,                        // Terminal resize acknowledged
    AuthResult { authorized: bool },      // Invite auth result
    SessionInfo {                         // Response to RequestShellV2/V3
        session_id: String,
        resumed: bool,
    },
    AdminResponse(AdminResponse),         // Admin command result (hop/2+)
    SessionError(String),                 // Session setup failure
    PeerResponse(PeerResponse),           // Peer-op result (secrets/kv/cap/cron/ext/tap)
    NetdocAuthorAck { recorded: bool },   // Ack for AnnounceNetdocAuthor; recorded=true on the trust anchor
    Attention {                           // hop/4+: another session on this host rang the bell unattended
        session_id: String, title: Option<String>, username: Option<String>, host_name: Option<String>,
    },
    AuthResultV2 {                        // hop/4+: invite auth result WITH the invite's grant
        authorized: bool,
        reason: Option<String>,           //   why not (never reveals whether an invite existed)
        tier: InviteTier,                 //   tier recorded when the invite was minted
        warren_ticket: Option<String>,    //   read ticket (node/warren-only), write ticket (admin), None (client)
        founder_author: Option<String>,   //   founder's netdoc author id (C1 trust anchor), warren tiers
        host_name: Option<String>,        //   host's name, for the client's known-hosts alias
    },
}
```

`PeerRequest::ListSessions` / `PeerResponse::Sessions(Vec<SessionSummary>)`
(both appended last, hop/4) back `hop sessions <host>`; the daemon socket
serves the same list locally as `AdminRequest::ListSessions` /
`AdminResponse::Sessions`. A `SessionSummary` carries session id, owner,
user, attached flag, start time, idle seconds, exit status, the app's OSC
title, bells since the last attach, and the grid size; the host's `VtScreen`
records titles and bells through alacritty's event listener.

`AuthResultV2` is the reason `hop/4` exists. Before it, an invite token
embedded the warren ticket (a plain `hop invite` on a warren host even embedded
the **write** ticket), so a token stayed a live capability after its secret was
burned. On `hop/4` the host answers a verified `AuthResponse` with
`AuthResultV2`, and the token carries nothing but node id, secret, relay hint
and tier. A `hop/3` client still gets the one-bit `AuthResult` (and a legacy
token that carries its own ticket still works as before).

### ClientMessage (Client -> Host)

```rust
pub enum ClientMessage {
    Input(Vec<u8>),                       // Shell input data
    WindowSize {                          // Terminal resize
        cols: u16, rows: u16,
        pixel_width: u16, pixel_height: u16,
    },
    AuthResponse { secret: Vec<u8> },     // Invite secret (hex, plaintext over E2E-encrypted QUIC); metered per node on the host
    RequestView { session_id: String },   // hop/4+ (appended last): read-only view of a session; host drops all Input
    RequestShell,                         // Basic shell session (V0)
    RequestShellV2 {                      // Persistent session (V1+)
        session_id: Option<String>,       //   None = new, Some = resume
    },
    RequestTransfer(TransferRequest),     // File transfer session
    RequestExec { command: String },      // Remote command execution
    RequestShellV3 {                      // Shell with sandbox (V2+)
        session_id: Option<String>,
        sandbox: SandboxPolicy,
    },
    RequestExecV2 {                       // Exec with sandbox (V2+)
        command: String,
        sandbox: SandboxPolicy,
    },
    SetEnv { vars: HashMap<String, String> },  // Client env (TERM, LANG, etc.)
    RequestAdmin(AdminRequest),           // Admin request (hop/2+)
    RequestPeerOp(PeerRequest),           // Peer op: secrets/kv/cap/cron/ext/tap (any authed peer)
    AnnounceNetdocAuthor {                // Warren member -> founder: announce doc author (+ self-doc
        author: String,                   //   read ticket) for peer/<node>.netdoc_author (C1 enforce)
        self_doc: Option<String>,         //   and peer/<node>.self_doc (per-member self-document model).
    },                                    //   Authorized by NodeId (existing peer); best-effort.
}
```

### AdminRequest (hop/2+)

Requires `Creator` role. Sent wrapped in `ClientMessage::RequestAdmin`.

```rust
pub enum AdminRequest {
    // Peer management
    CreateInvite { username: Option<String>, role: PeerRole },
    ListPeers,
    RemovePeer { node_id_prefix: String },
    CreateUser {
        username: String, sudo: bool, admin: bool,
        groups: Vec<String>, shell: Option<String>, invite: bool,
    },
    Status,

    // Fleet (Phase 2)
    CreateFleetInvite { tags: Vec<String>, max_uses: u32, expiry_secs: u64 },
    ListFleet { tag_filter: Option<String> },
    RemoveFleetMember { node_id_prefix: String },
    UpdateFleetTags { node_id_prefix: String, tags: Vec<String> },

    // Role management (Phase 2)
    CreateRole { definition: RoleDefinition },
    ListRoles,
    UpdateRole { name: String, updates: RoleUpdates },
    DeleteRole { name: String },

    // Aggregate invites (Phase 3)
    CreateAggregateInvite { role: String, peer_name: String },
    RedeemAggregateInvite { secret: String },

    // Metrics
    PushMetrics { points: Vec<PushMetricPoint> },
}
```

### AdminResponse (hop/2+)

```rust
pub enum AdminResponse {
    InviteCreated { token: String },
    PeerList { peers: Vec<PeerInfo> },
    PeerRemoved { success: bool },
    UserCreated { username: String, invite_token: Option<String> },
    HostStatus { version: String, peer_count: usize, active_sessions: usize },
    FleetInviteCreated { token: String },
    FleetList { members: Vec<FleetMemberInfo> },
    FleetMemberRemoved { success: bool },
    FleetTagsUpdated { success: bool },
    RoleCreated { name: String },
    RoleList { roles: Vec<RoleDefinition> },
    RoleUpdated { name: String },
    RoleDeleted { name: String },
    AggregateInviteCreated { token: String },
    AggregateInviteRedeemed { hosts: Vec<RedeemHostEntry> },
    MetricsReceived { count: usize },
    Error { message: String },
}
```

### Transfer Protocol

#### TransferRequest

Sent inside `ClientMessage::RequestTransfer`:

```rust
pub struct TransferRequest {
    pub mode: TransferMode,          // Copy { recursive } | Sync
    pub direction: TransferDirection, // Push (client->host) | Pull (host->client)
    pub remote_path: String,
    pub delete_extraneous: bool,
    pub dry_run: bool,
}
```

#### TransferMsg Enum

Messages exchanged during a file transfer session:

```rust
pub enum TransferMsg {
    // Listing (sync mode)
    FileList(Vec<FileEntry>),
    TransferPlan { files_to_send: Vec<FileEntry>, files_to_delete: Vec<String>, dry_run: bool },
    PlanAck { proceed: bool },

    // Data transfer
    FileHeader(FileHeader),           // { path, size, mode, mtime }
    FileData(Vec<u8>),                // Chunk of file data
    FileEnd,                          // End of single file
    CreateDirectory(DirEntry),        // { path, mode, mtime }
    DeletePath(String),
    CreateSymlink { path, target },

    // Control
    FileAck { path, success, error }, // Per-file acknowledgment
    Done,                             // Transfer complete
    Error(String),                    // Fatal error

    // Negotiation (hop/1+)
    Capabilities { compression: Vec<String>, max_chunk_size: u32, features_version: u32 },
    Negotiated { compression: Option<String>, chunk_size: u32, zstd_level: Option<i32> },

    // Parallel streams (hop/1+)
    FileManifest { session_id: u64, total_files/dirs/symlinks/deletes },
    StreamHeader { session_id: u64 },

    // Delta transfers (hop/1+)
    BlockSignatures { path, block_size: u32, signatures: Vec<BlockSignature> },
    DeltaHeader { path, new_size: u64, mode: u32, mtime: u64 },
    DeltaOp(DeltaOperation),         // CopyBlock { index } | Literal(Vec<u8>)
    DeltaEnd,
}
```

#### Transfer Constants

```rust
pub const TRANSFER_CHUNK_SIZE: usize = 64 * 1024;      // 64 KiB
pub const MIN_CHUNK_SIZE: usize     = 64 * 1024;       // 64 KiB
pub const MAX_CHUNK_SIZE: usize     = 1024 * 1024;     // 1 MiB
pub const DEFAULT_ZSTD_LEVEL: i32   = 3;
pub const DEFAULT_PARALLEL_STREAMS: usize = 4;
pub const DELTA_BLOCK_SIZE: usize   = 64 * 1024;       // Same as chunk size
pub const DELTA_MIN_FILE_SIZE: u64  = 64 * 1024;       // Min file size for delta
```

#### Supporting Structs

```rust
pub struct FileEntry {
    pub path: String, pub size: u64, pub mtime: u64, pub mode: u32,
    pub is_dir: bool, pub is_symlink: bool, pub symlink_target: Option<String>,
    pub content_hash: Option<u64>,  // xxh3-64, None for dirs/symlinks
}

pub struct BlockSignature {
    pub index: u32,     // Block index in the file
    pub rolling: u32,   // Adler32-variant rolling checksum
    pub strong: u64,    // xxh3-64 strong hash
}

pub enum DeltaOperation {
    CopyBlock { index: u32 },   // Reuse block from old file
    Literal(Vec<u8>),           // New data not in old file
}
```

---

### Warren protocols (VPN + netdoc)

The warren private network runs on a **separate iroh endpoint** (derived key →
stable NodeId, `net::create_netdoc_endpoint`), independent of the main hop stack
above. It has two protocols.

#### VPN data plane — `hop/vpn/1`

- **Transport:** QUIC **datagrams** (`send_datagram`/`read_datagram`), not
  length-prefixed bincode frames. Each datagram is one raw L3 IP packet.
- **MTU:** 1280 (`VPN_MTU`); the TUN interface is configured to match.
- **Handler:** `VpnInbound` (an iroh `ProtocolHandler`) writes received datagrams
  to the local TUN device; an outbound loop reads the TUN, looks up the
  destination virtual IP's owner, applies the reach ACL, and sends a datagram.
- **Addressing:** virtual IPs in `100.64.0.0/10` (CGNAT range), allocated
  deterministically (hash of NodeId) and claimed in the netdoc.
- **Reach ACL:** `vpn_reach_allowed(src, dst)` resolves src IP → member → role →
  tags and dst IP → host → tags, then `role_reaches` (wildcard `*` or tag
  intersection). **Default-deny.**

#### Network document (netdoc) — iroh-docs CRDT

Membership and network state replicate as an iroh-docs document (backed by
iroh-gossip + iroh-blobs). Entries are `key → JSON value` for debuggability:

| Key prefix | Holds |
|---|---|
| `peer/<node_id>` | Authorized peer (role_name, username, sandbox, timestamps) |
| `role/<name>` | Role definition (host_tags, admin, sandbox, …) |
| `revocation/<node_id>` | Tombstone for a removed peer |
| `ip/<addr>` | Virtual-IP → owner NodeId claim |
| `vpn/<addr>` | VPN endpoint (NodeId + relay) for a virtual IP |
| `tag/<node_id>` | A host's tags |
| `name/<name>` | MagicDNS name → virtual IP |
| `network/<key>` | Network config (e.g. `network/domain` for MagicDNS) |
| `acl/policy` | Legacy hand-authored ACL (superseded by role→tag derivation) |

**Federation** is via iroh-docs `DocTicket`s (a write ticket lets a host join the
namespace; `HOP_VPN_JOIN_TICKET` / `<config>/netdoc-join.ticket` / installer
`--join`). On a shared namespace, `reconcile` is **additive-only** so hosts can't
cross-revoke each other's entries; the `ip`/`vpn`/`name` tables are
federation-safe by construction (each host writes only its own).

#### MagicDNS

A minimal DNS `A`-record codec (`vpn/dns.rs`) answers `<name>.<domain>` lookups
from the `name/*` table on the virtual interface. The domain comes from
`network/domain` (default `hop`).

*Last updated: v0.6.33*
