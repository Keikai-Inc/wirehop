# Wire Protocol

## ALPN Versions

hop uses ALPN (Application-Layer Protocol Negotiation) to version the wire protocol. The host advertises all supported versions; the client selects the highest it supports.

```rust
pub const ALPN_V0: &[u8] = b"hop/0";  // Legacy: basic shell + auth + transfer
pub const ALPN_V1: &[u8] = b"hop/1";  // + compression, content hashing, parallel streams, delta transfer
pub const ALPN_V2: &[u8] = b"hop/2";  // + admin protocol, fleet, roles
pub const ALPN_V3: &[u8] = b"hop/3";  // + zstd compression on large frames (Output messages)

pub const VPN_ALPN: &[u8] = b"hop/vpn/1";  // Warren VPN data plane (separate endpoint)
```

The host endpoint binds with ALPNs in preference order: `[V3, V2, V1, V0]`. The `negotiated_protocol_version()` function maps the negotiated ALPN to a `u8` (0-3).

`hop/vpn/1` is **not** part of this stack: it runs on the warren's separate,
isolated netdoc endpoint (see [Warren protocols](#warren-protocols-vpn--netdoc))
and carries raw L3 IP packets as QUIC datagrams, not length-prefixed frames.

## Frame Format

All messages use length-prefixed bincode encoding:

```
+--4 bytes--+--N bytes--+
|  length   |  payload  |
+-----------+-----------+
```

- **Length**: 4-byte big-endian `u32`. The high bit (0x8000_0000) is a compression flag.
- **Payload**: bincode-encoded (using `bincode::config::standard()`) Rust struct.

### Compression (hop/3+)

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

### Write Variants

```rust
// Standard: encode + flush (control messages)
async fn write_message<T: Serialize>(stream, msg) -> Result<()>

// Buffered: encode without flush (high-throughput FileData chunks)
async fn write_message_buffered<T: Serialize>(stream, msg) -> Result<()>

// Compressed: zstd when beneficial, always flushes (hop/3 Output messages)
async fn write_message_compressed<T: Serialize>(stream, msg) -> Result<()>
```

### Read

```rust
// Transparently handles both compressed and uncompressed frames
async fn read_message<T: Deserialize>(stream) -> Result<T>
```

## HostMessage (Host -> Client)

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
}
```

## ClientMessage (Client -> Host)

```rust
pub enum ClientMessage {
    Input(Vec<u8>),                       // Shell input data
    WindowSize {                          // Terminal resize
        cols: u16, rows: u16,
        pixel_width: u16, pixel_height: u16,
    },
    AuthResponse { secret: Vec<u8> },     // Invite secret (hex, plaintext over E2E-encrypted QUIC)
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

## AdminRequest (hop/2+)

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

## AdminResponse (hop/2+)

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

## Transfer Protocol

### TransferRequest

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

### TransferMsg Enum

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

### Transfer Constants

```rust
pub const TRANSFER_CHUNK_SIZE: usize = 64 * 1024;      // 64 KiB
pub const MIN_CHUNK_SIZE: usize     = 64 * 1024;       // 64 KiB
pub const MAX_CHUNK_SIZE: usize     = 1024 * 1024;     // 1 MiB
pub const DEFAULT_ZSTD_LEVEL: i32   = 3;
pub const DEFAULT_PARALLEL_STREAMS: usize = 4;
pub const DELTA_BLOCK_SIZE: usize   = 64 * 1024;       // Same as chunk size
pub const DELTA_MIN_FILE_SIZE: u64  = 64 * 1024;       // Min file size for delta
```

### Supporting Structs

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

## Warren protocols (VPN + netdoc)

The warren private network runs on a **separate iroh endpoint** (derived key →
stable NodeId, `net::create_netdoc_endpoint`), independent of the main hop stack
above. It has two protocols.

### VPN data plane — `hop/vpn/1`

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

### Network document (netdoc) — iroh-docs CRDT

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

### MagicDNS

A minimal DNS `A`-record codec (`vpn/dns.rs`) answers `<name>.<domain>` lookups
from the `name/*` table on the virtual interface. The domain comes from
`network/domain` (default `hop`).

*Last updated: v0.6.33*
