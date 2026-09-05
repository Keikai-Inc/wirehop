use std::collections::HashMap;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::config::PeerRole;
use crate::sandbox::policy::{sandbox_is_unrestricted, SandboxPolicy};

/// ALPN protocol identifier for hop connections (legacy).
pub const ALPN_V0: &[u8] = b"hop/0";

/// ALPN protocol identifier for hop v1 (compression, hashing, parallel streams, delta).
pub const ALPN_V1: &[u8] = b"hop/1";

/// ALPN protocol identifier for hop v2 (admin, fleet, roles).
pub const ALPN_V2: &[u8] = b"hop/2";

/// ALPN protocol identifier for hop v3 (zstd compression on large frames).
pub const ALPN_V3: &[u8] = b"hop/3";
/// ALPN protocol identifier for hop v4 (post-auth invite grants: `AuthResultV2`).
pub const ALPN_V4: &[u8] = b"hop/4";

/// Messages sent from the host to the client.
#[derive(Debug, Serialize, Deserialize)]
pub enum HostMessage {
    /// Shell output data.
    Output(Vec<u8>),
    /// Shell exited with status code.
    Exit(i32),
    /// Terminal window size acknowledgement.
    WindowSizeAck,
    /// Auth result.
    AuthResult { authorized: bool },
    /// Session info sent in response to `RequestShellV2`.
    SessionInfo {
        session_id: String,
        resumed: bool,
    },
    /// Response to an admin request (hop/2+).
    AdminResponse(AdminResponse),
    /// Session setup error — sent instead of SessionInfo when the host
    /// cannot start a session (e.g. missing root privileges, invalid user).
    SessionError(String),
    /// Response to a peer operation.
    PeerResponse(PeerResponse),
    /// Acknowledge an `AnnounceNetdocAuthor`. `recorded` is true when the
    /// receiver is the founder/admin and wrote the binding; false when it
    /// accepted the announce but is not the trust anchor (member retries later).
    NetdocAuthorAck { recorded: bool },
    /// Auth result on hop/4+. What the redeemed invite grants is delivered
    /// here, over the authenticated stream, and never inside the token: a
    /// hop/4 invite token carries only node id, secret, relay hint and tier,
    /// so a used or expired token is inert. Appended at the END of the enum
    /// (bincode encodes the variant index); only sent when hop/4 negotiated.
    AuthResultV2 {
        authorized: bool,
        /// Why not, when `authorized` is false. Never says whether an invite
        /// with that secret existed.
        reason: Option<String>,
        /// Capability tier recorded when the invite was minted.
        tier: crate::invite::InviteTier,
        /// Warren ticket for warren tiers: the read ticket for node and
        /// warren-only, the write ticket for admin. `None` for client tier.
        warren_ticket: Option<String>,
        /// The founder's netdoc author id (the C1 trust anchor), warren tiers only.
        founder_author: Option<String>,
        /// The host's human-readable name, for the client's known-hosts alias.
        host_name: Option<String>,
    },
    /// Another session on this host rang the bell while nobody was attached
    /// to it (hop/4+; appended last). Sent to every attached client on the
    /// host so the notification reaches wherever the operator is sitting; the
    /// client raises it as a terminal notification (OSC 9 / OSC 777).
    Attention {
        session_id: String,
        title: Option<String>,
        username: Option<String>,
        host_name: Option<String>,
    },
}

/// Messages sent from the client to the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ClientMessage {
    /// Shell input data.
    Input(Vec<u8>),
    /// Terminal window size changed.
    WindowSize {
        cols: u16,
        rows: u16,
        pixel_width: u16,
        pixel_height: u16,
    },
    /// Auth response during invite flow (client proves knowledge of invite secret).
    AuthResponse {
        /// The raw invite secret (hex-encoded). Verified by the host against
        /// the stored Argon2 hash. Safe to send in plaintext because the
        /// transport is end-to-end encrypted (QUIC/TLS 1.3).
        secret: Vec<u8>,
    },
    /// Request a shell session (after auth).
    RequestShell,
    /// Request a shell session with optional session persistence (after auth).
    /// `session_id: None` = new session, `session_id: Some(id)` = resume existing.
    RequestShellV2 { session_id: Option<String> },
    /// Request a file transfer session (after auth).
    RequestTransfer(TransferRequest),
    /// Request a remote command execution session (after auth).
    RequestExec { command: String },
    /// Request a shell session with optional persistence and client-requested sandbox.
    RequestShellV3 {
        session_id: Option<String>,
        sandbox: SandboxPolicy,
    },
    /// Request a remote command execution with client-requested sandbox.
    RequestExecV2 {
        command: String,
        sandbox: SandboxPolicy,
    },
    /// Request a TCP local port-forward (`hop tunnel`, like `ssh -L`): after this
    /// message the stream becomes a transparent byte pipe, and the host dials
    /// `127.0.0.1:<port>` and bridges it. One stream per forwarded TCP connection.
    /// Gated like exec: an authenticated peer, denied if the session sandbox
    /// blocks network (`no_network`).
    RequestTunnel { port: u16 },
    /// Client environment variables (TERM, LANG, LC_*, COLORTERM).
    SetEnv { vars: HashMap<String, String> },
    /// Admin request (hop/2+). Requires creator role.
    RequestAdmin(AdminRequest),
    /// Peer operation (any authenticated peer). Secrets, KV, cap, cron.
    RequestPeerOp(PeerRequest),
    /// Announce this node's network-document author (and, optionally, its
    /// per-member self-doc read ticket) so the founder/admin can record the
    /// `peer/<node>.netdoc_author` binding (C1 self-key enforce) and
    /// `peer/<node>.self_doc` (per-member self-document model). Sent
    /// daemon-outbound on startup by a warren member to its founder; the founder
    /// authenticates the sender by NodeId (existing peer) and writes the
    /// admin-owned entries. Best-effort — never gates membership or reach.
    /// `self_doc` is `#[serde(default)]` so pre-self-doc senders still decode.
    AnnounceNetdocAuthor {
        author: String,
        #[serde(default)]
        self_doc: Option<String>,
        /// The member's VPN endpoint `"<endpoint_id> <relay>"` (static), so the
        /// founder records `peer/N.vpn_endpoint` and routing resolves from the
        /// admin doc instead of the member's self-doc namespace. `#[serde(default)]`
        /// so pre-roster-endpoint senders still decode.
        #[serde(default)]
        vpn_endpoint: Option<String>,
    },
    /// Watch an existing session without being able to type into it (hop/4+;
    /// appended last). `session_id` may be an unambiguous prefix. Allowed for
    /// the session's owner and for admins; the host drops every `Input`.
    RequestView { session_id: String },
}

// --- Admin protocol (hop/2+) ---

/// Admin requests sent by creator peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminRequest {
    /// Create an invite on this host.
    CreateInvite {
        username: Option<String>,
        role: PeerRole,
        /// Named role for the invited peer (`None` → host default role).
        #[serde(default)]
        role_name: Option<String>,
    },
    /// Mint an invite from the full `hop invite` parameter set (tier, max-uses,
    /// expiry, sandbox, …) — used by the local operator CLI over `daemon.sock`
    /// so it never reads `_hop`-owned config or needs root.
    CreateInviteFull(Box<crate::invite::InviteParams>),
    /// Return this host's node id (public key) — lets `hop id` work without
    /// reading `_hop`-owned `identity.json` or needing root.
    HostIdentity,
    /// Change an existing peer's named role (elevation/demotion).
    SetPeerRole {
        node_id_prefix: String,
        role_name: String,
    },
    /// List authorized peers.
    ListPeers,
    /// Remove a peer by node_id prefix.
    RemovePeer { node_id_prefix: String },
    /// Rename a peer (G26) — propagated to the warren doc so the new name shows in
    /// every node's `hop fleet list`, not just the local one.
    RenamePeer { node_id_prefix: String, name: String },
    /// Prune (revoke) every warren member not seen for `older_than_secs` (G25
    /// roster hygiene). Handled out-of-band by the daemon socket (needs async
    /// netdoc + VPN-liveness access); writes a replicated revocation per member.
    /// `dry_run` returns the would-prune list without revoking anything.
    PruneMembers { older_than_secs: u64, dry_run: bool },
    /// Create a Unix user on this host.
    CreateUser {
        username: String,
        sudo: bool,
        admin: bool,
        groups: Vec<String>,
        shell: Option<String>,
        /// Also generate an invite for this user.
        invite: bool,
    },
    /// Get host status.
    Status,
    // --- Fleet admin (Phase 2) ---
    /// Create a fleet invite token.
    CreateFleetInvite {
        tags: Vec<String>,
        max_uses: u32,
        expiry_secs: u64,
        /// Capability tier for redeemers (client/warren-only/node/admin). `None`
        /// (serde default → back-compatible) keeps the legacy admin/Creator
        /// behaviour. A warren tier needs a warren on the orchestrating host.
        #[serde(default)]
        tier: Option<String>,
    },
    /// List fleet members.
    ListFleet { tag_filter: Option<String> },
    /// Remove a fleet member.
    RemoveFleetMember { node_id_prefix: String },
    /// Update tags on a fleet member.
    UpdateFleetTags {
        node_id_prefix: String,
        tags: Vec<String>,
    },
    // --- Role management (Phase 2) ---
    /// Create a role definition.
    CreateRole { definition: RoleDefinition },
    /// List all role definitions.
    ListRoles,
    /// Update a role definition.
    UpdateRole { name: String, updates: RoleUpdates },
    /// Delete a role definition.
    DeleteRole { name: String },
    // --- Aggregate invite (Phase 3) ---
    /// Create an aggregate invite for a role.
    CreateAggregateInvite {
        role: String,
        peer_name: String,
    },
    /// Redeem an aggregate invite.
    RedeemAggregateInvite { secret: String },
    /// Push metric points from a remote host to the orchestrator's datastore.
    PushMetrics { points: Vec<PushMetricPoint> },
    /// List this host's pending (unredeemed) invites.
    ListInvites,
    /// Revoke a pending invite by id (or unambiguous id prefix).
    RevokeInvite { id: String },
    /// List this host's persistent PTY sessions (served by the daemon socket).
    ListSessions,
}

/// A single metric point pushed from a remote host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushMetricPoint {
    pub metric: String,
    pub value: f64,
    pub tags: std::collections::BTreeMap<String, String>,
    /// Optional timestamp in epoch milliseconds. If None, uses server time.
    pub timestamp: Option<u64>,
}

/// Admin responses sent by the host.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminResponse {
    /// An invite was created.
    InviteCreated { token: String },
    /// This host's node id (public key), for `hop id`.
    HostIdentity { node_id: String },
    /// List of authorized peers.
    PeerList { peers: Vec<PeerInfo> },
    /// A peer was removed.
    PeerRemoved { success: bool },
    PeerRenamed { success: bool },
    /// Result of a `PruneMembers`: the `(node_id, name)` of every member revoked.
    Pruned { members: Vec<(String, String)> },
    /// A peer's role was changed.
    PeerRoleUpdated { success: bool },
    /// A Unix user was created.
    UserCreated {
        username: String,
        invite_token: Option<String>,
    },
    /// Host status info.
    HostStatus {
        version: String,
        peer_count: usize,
        active_sessions: usize,
    },
    /// Fleet invite created.
    FleetInviteCreated { token: String },
    /// Fleet member list.
    FleetList { members: Vec<FleetMemberInfo> },
    /// Fleet member removed.
    FleetMemberRemoved { success: bool },
    /// Fleet member tags updated.
    FleetTagsUpdated { success: bool },
    /// Role created.
    RoleCreated { name: String },
    /// Role list.
    RoleList { roles: Vec<RoleDefinition> },
    /// Role updated.
    RoleUpdated { name: String },
    /// Role deleted.
    RoleDeleted { name: String },
    /// Aggregate invite created.
    AggregateInviteCreated { token: String },
    /// Aggregate invite redeemed — list of per-host connections.
    AggregateInviteRedeemed { hosts: Vec<RedeemHostEntry> },
    /// Metrics were received and stored.
    MetricsReceived { count: usize },
    /// Error response.
    Error { message: String },
    /// Pending invites (`ListInvites`).
    InviteList { invites: Vec<crate::invite::PendingInviteInfo> },
    /// A pending invite was revoked (`RevokeInvite`).
    InviteRevoked { id: String },
    /// This host's sessions (`ListSessions`).
    Sessions(Vec<SessionSummary>),
}

/// One persistent PTY session as `hop sessions` shows it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionSummary {
    pub session_id: String,
    /// Owning peer's node id.
    pub peer_id: String,
    pub username: Option<String>,
    pub attached: bool,
    /// Unix ms when the session was created.
    pub started_ms: u64,
    /// Seconds since a client was last attached (0 while attached).
    pub idle_secs: u64,
    /// The shell's exit status once it has exited.
    pub exited: Option<i32>,
    /// The captured app's window title (OSC 0/2), if any.
    pub title: Option<String>,
    /// Bells rung since the last attach: the session asked for attention.
    pub bells: u64,
    pub rows: u16,
    pub cols: u16,
    /// Read-only viewers currently attached (`hop <host> --view`).
    pub viewers: u32,
}

/// Summary info about an authorized peer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub node_id: String,
    pub name: String,
    pub role: PeerRole,
    pub username: Option<String>,
    pub last_seen: Option<String>,
}

/// Summary info about a fleet member.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FleetMemberInfo {
    pub node_id: String,
    pub hostname: String,
    pub tags: Vec<String>,
    pub online: bool,
    pub last_heartbeat: Option<String>,
}

/// A role definition stored on the orchestrator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoleDefinition {
    pub name: String,
    pub host_tags: Vec<String>,
    #[serde(default)]
    pub user_mode: UserMode,
    #[serde(default)]
    pub sudo: bool,
    #[serde(default)]
    pub admin: bool,
    #[serde(default)]
    pub groups: Vec<String>,
    #[serde(default)]
    pub shell: Option<String>,
    /// Warren-only tier (install-and-invite-tiers.md): the peer may have L3 reach
    /// to services on the mesh (per `host_tags`) but **cannot open host sessions**
    /// (shell/exec/transfer). Enforced at session dispatch. Default false.
    #[serde(default)]
    pub network_only: bool,
    /// Sandbox policy enforced for peers with this role.
    #[serde(default, skip_serializing_if = "sandbox_is_unrestricted")]
    pub sandbox: SandboxPolicy,
    /// Application-layer capability grants (ACL Phase 5): a map of
    /// `{domain}/{path}` capability names to arrays of arbitrary JSON config
    /// objects, mirroring Tailscale's app-capability shape. Surfaced to services
    /// a member reaches so they can self-authorize. Empty for most roles.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub capabilities: std::collections::BTreeMap<String, Vec<serde_json::Value>>,
    /// Host-tags this role may open shell/exec/transfer/tunnel sessions on (G23
    /// capability scoping). **Empty = open** — any host the role is admitted to
    /// (today's behavior; no regression). Set to scope (`["dev"]`); `*` = all.
    /// `network_only` overrides to none. Enforced host-side at session dispatch.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exec_tags: Vec<String>,
    /// Host-tags this role may run READ-ONLY searches on (`hop fleet grep` /
    /// audit-read / metrics). Empty = same scope as `exec`; set to grant search
    /// beyond exec, or read-only search to an otherwise `network_only` role. `*` =
    /// all. The middle tier between `network_only` (none) and full `exec`.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub search_tags: Vec<String>,
}

/// Whether users for a role get individual or shared Unix accounts.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum UserMode {
    #[default]
    Individual,
    Shared,
}

/// Partial updates for a role definition.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RoleUpdates {
    pub add_tags: Vec<String>,
    pub remove_tags: Vec<String>,
    pub sudo: Option<bool>,
    pub admin: Option<bool>,
    pub groups: Option<Vec<String>>,
    pub shell: Option<Option<String>>,
    pub user_mode: Option<UserMode>,
    pub network_only: Option<bool>,
    pub sandbox: Option<SandboxPolicy>,
    /// Replace the role's session (exec) tag scope (G23). `Some(vec![])` clears it
    /// back to open; `None` leaves it unchanged.
    #[serde(default)]
    pub exec_tags: Option<Vec<String>>,
    /// Replace the role's read-only search tag scope (G23).
    #[serde(default)]
    pub search_tags: Option<Vec<String>>,
}

/// Entry returned when redeeming an aggregate invite.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedeemHostEntry {
    pub hostname: String,
    pub node_id: String,
    pub relay_url: Option<String>,
    pub invite_token: String,
}

// --- Peer operations (any authenticated peer) ---

/// Requests any authenticated peer can perform (no Creator role required).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeerRequest {
    SecretsGet { name: String },
    SecretsSet { name: String, value: Vec<u8> },
    SecretsDelete { name: String },
    SecretsList,
    CapList,
    CapEnable {
        id: String,
        schedule: Option<String>,
        targets: Option<String>,
    },
    CapDisable { id: String },
    CapStatus,
    CapRun {
        id: String,
        targets: Option<String>,
        params: Vec<(String, String)>,
    },
    KvGet { ns: String, key: String },
    KvSet { ns: String, key: String, value: Vec<u8> },
    KvList { ns: String, prefix: String },
    CronList,
    CronGet { id: String },

    // --- Extension routing ---
    //
    // Generic mechanism for hop extensions (companion daemons that register
    // via ~/.config/hop/extensions/*.toml manifests). Hop core forwards the
    // payload bytes opaquely; each extension defines its own sub-protocol.
    /// List installed extensions on this host.
    ExtensionList,

    /// Send a single request to a registered extension, expect a single response.
    ExtensionCall { ext_id: String, payload: Vec<u8> },

    /// Open a long-running stream against a registered extension. The
    /// extension may emit `ExtensionStreamFrame` responses; either side
    /// may close.
    ExtensionStreamOpen { ext_id: String, payload: Vec<u8> },

    /// Send input bytes from the peer into an open extension stream
    /// (e.g., keystrokes for a terminal session subscriber).
    ExtensionStreamInput { stream_id: u64, payload: Vec<u8> },

    /// Close an open extension stream from the peer side.
    ExtensionStreamClose { stream_id: u64 },
    /// List this host's persistent PTY sessions (hop/4+; appended last).
    ListSessions,
}

/// Response to a PeerRequest.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PeerResponse {
    Ok,
    Error(String),
    SecretValue(Option<Vec<u8>>),
    SecretNames(Vec<String>),
    KvEntry(Option<super::datastore::types::KvEntry>),
    KvEntries(Vec<(String, super::datastore::types::KvEntry)>),
    CapEntries(Vec<CapInfo>),
    CapStatusEntries(Vec<CapJobInfo>),
    CapEnabled { job_id: String },
    CapTriggered { job_id: String },
    CronJobs(Vec<CronJobSummary>),
    CronJob(Option<CronJobSummary>),

    // --- Extension routing ---
    /// List of registered extensions (response to `ExtensionList`).
    ExtensionEntries(Vec<ExtensionInfo>),

    /// Single response from an extension to `ExtensionCall`.
    ExtensionResult { ok: bool, payload: Vec<u8> },

    /// Acknowledges that an extension stream is open. The `stream_id` is
    /// used for subsequent `ExtensionStreamFrame` / `ExtensionStreamInput`
    /// / `ExtensionStreamClose` messages.
    ExtensionStreamOpened { stream_id: u64 },

    /// One frame in an open extension stream (extension → peer).
    ExtensionStreamFrame { stream_id: u64, payload: Vec<u8> },

    /// The extension closed an open stream (e.g., session ended).
    ExtensionStreamClosed { stream_id: u64, reason: Option<String> },
    /// Reply to `ListSessions` (appended last).
    Sessions(Vec<SessionSummary>),
}

/// Summary info for a registered extension.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExtensionInfo {
    pub ext_id: String,
    pub description: String,
    pub required_role: String,
    pub available: bool,
}

/// Summary info for a capability in `hop cap list`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapInfo {
    pub id: String,
    pub name: String,
    pub description: String,
    pub tier: String,
    pub trigger: String,
    pub category: String,
}

/// Status of an enabled capability.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapJobInfo {
    pub catalog_id: String,
    pub enabled: bool,
    pub schedule: String,
    pub targets: Option<String>,
    pub last_run: Option<u64>,
}

/// Summary of a cron job (safe to send over the wire).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJobSummary {
    pub id: String,
    pub name: String,
    pub schedule: String,
    pub enabled: bool,
    pub last_run: Option<u64>,
    pub next_run: u64,
    pub targets: Option<String>,
}

/// Chunk size for file data transfer (64 KiB).
pub const TRANSFER_CHUNK_SIZE: usize = 64 * 1024;

/// Minimum chunk size for adaptive sizing (64 KiB).
pub const MIN_CHUNK_SIZE: usize = 64 * 1024;

/// Maximum chunk size for adaptive sizing (1 MiB).
pub const MAX_CHUNK_SIZE: usize = 1024 * 1024;

/// Default zstd compression level.
pub const DEFAULT_ZSTD_LEVEL: i32 = 3;

/// Default number of parallel data streams.
pub const DEFAULT_PARALLEL_STREAMS: usize = 4;

/// Block size for delta transfers (same as chunk size).
pub const DELTA_BLOCK_SIZE: usize = TRANSFER_CHUNK_SIZE;

/// Minimum file size to consider for delta transfer.
pub const DELTA_MIN_FILE_SIZE: u64 = 64 * 1024;

/// Transfer features version advertised in [`TransferMsg::Capabilities`]. Each
/// side sends its own and reads the peer's, so both independently compute
/// `min(ours, theirs)` — no extra wire field is needed (bincode ignores
/// `#[serde(default)]`, so existing messages must never grow fields).
///
/// - `1`: listings sent as a single uncompressed `FileList` / `TransferPlan`
///   frame. A tree whose listing exceeds `MAX_FRAME_LEN` (16 MiB — roughly
///   140k entries) simply fails, and the sender only sees a broken pipe.
/// - `2`: listings sent as zstd-compressed `FileListChunk` /
///   `TransferPlanChunk` batches, so listing size is bounded for any tree.
pub const TRANSFER_FEATURES_VERSION: u32 = 2;

/// Entries per listing chunk when both peers are at features version ≥ 2.
/// A `FileEntry` serializes to roughly 120 B (path-dominated), so 5k entries
/// lands near 600 KB before compression — an order of magnitude under
/// `MAX_FRAME_LEN` with room for pathological path lengths.
pub const LIST_CHUNK_ENTRIES: usize = 5_000;

/// Request to initiate a file transfer session.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransferRequest {
    pub mode: TransferMode,
    pub direction: TransferDirection,
    pub remote_path: String,
    pub delete_extraneous: bool,
    pub dry_run: bool,
}

/// Whether this is a copy or sync operation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferMode {
    Copy { recursive: bool },
    Sync,
}

/// Direction of file transfer relative to the client.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransferDirection {
    /// Client -> Host
    Push,
    /// Host -> Client
    Pull,
}

/// Messages exchanged during a file transfer session (after session negotiation).
#[derive(Debug, Serialize, Deserialize)]
pub enum TransferMsg {
    // -- Listing (sync mode) --
    /// List of files at one side for comparison.
    FileList(Vec<FileEntry>),
    /// Plan of what to transfer/delete after comparison.
    TransferPlan {
        files_to_send: Vec<FileEntry>,
        files_to_delete: Vec<String>,
        dry_run: bool,
    },
    /// Acknowledgment of the transfer plan.
    PlanAck { proceed: bool },

    // -- Data transfer --
    /// Header before file data chunks.
    FileHeader(FileHeader),
    /// A chunk of file data.
    FileData(Vec<u8>),
    /// Marks the end of a single file's data.
    FileEnd,
    /// Create a directory on the receiving side.
    CreateDirectory(DirEntry),
    /// Delete a path on the receiving side.
    DeletePath(String),
    /// Create a symlink on the receiving side.
    CreateSymlink { path: String, target: String },

    // -- Control --
    /// Per-file acknowledgment from the receiver.
    FileAck {
        path: String,
        success: bool,
        error: Option<String>,
    },
    /// Transfer session complete.
    Done,
    /// Fatal error.
    Error(String),

    // -- Negotiation (hop/1) --
    /// Capabilities advertisement during session setup.
    Capabilities {
        compression: Vec<String>,
        max_chunk_size: u32,
        features_version: u32,
    },
    /// Negotiated parameters after capabilities exchange.
    Negotiated {
        compression: Option<String>,
        chunk_size: u32,
        zstd_level: Option<i32>,
    },

    // -- Parallel streams (hop/1) --
    /// Manifest sent before parallel file transfer.
    FileManifest {
        session_id: u64,
        total_files: u32,
        total_dirs: u32,
        total_symlinks: u32,
        total_deletes: u32,
    },
    /// Header on a data stream identifying the session.
    StreamHeader {
        session_id: u64,
    },

    // -- Delta transfers (hop/1) --
    /// Block signatures for delta sync.
    BlockSignatures {
        path: String,
        block_size: u32,
        signatures: Vec<BlockSignature>,
    },
    /// Header before delta operations.
    DeltaHeader {
        path: String,
        new_size: u64,
        mode: u32,
        mtime: u64,
    },
    /// A single delta operation.
    DeltaOp(DeltaOperation),
    /// End of delta operations for a file.
    DeltaEnd,

    // -- Chunked listings (features version >= 2) --
    //
    // Appended at the END of the enum on purpose: bincode encodes the variant
    // index, so adding variants here leaves every existing discriminant intact.
    // A features-version-1 peer cannot decode these, which is why they are only
    // sent once the negotiated version is >= 2.
    /// One batch of a file listing. `last` marks the final batch (an empty
    /// listing is a single batch with no entries and `last: true`).
    FileListChunk {
        entries: Vec<FileEntry>,
        last: bool,
    },
    /// One batch of a transfer plan. `last` marks the final batch. `dry_run` is
    /// repeated in every batch and is identical across them; the receiver takes
    /// it from whichever batch it sees.
    TransferPlanChunk {
        files_to_send: Vec<FileEntry>,
        files_to_delete: Vec<String>,
        dry_run: bool,
        last: bool,
    },
}

/// Metadata for a file/directory entry used in listings and sync comparison.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FileEntry {
    pub path: String,
    pub size: u64,
    pub mtime: u64,
    pub mode: u32,
    pub is_dir: bool,
    pub is_symlink: bool,
    pub symlink_target: Option<String>,
    /// xxh3-64 content hash (None for dirs/symlinks or when not computed).
    #[serde(default)]
    pub content_hash: Option<u64>,
}

/// Header sent before streaming a file's data.
#[derive(Debug, Serialize, Deserialize)]
pub struct FileHeader {
    pub path: String,
    pub size: u64,
    pub mode: u32,
    pub mtime: u64,
}

/// Metadata for creating a directory.
#[derive(Debug, Serialize, Deserialize)]
pub struct DirEntry {
    pub path: String,
    pub mode: u32,
    pub mtime: u64,
}

/// A block signature for delta transfer.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockSignature {
    pub index: u32,
    pub rolling: u32,
    pub strong: u64,
}

/// A delta operation: either copy a block from the old file or insert literal bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DeltaOperation {
    CopyBlock { index: u32 },
    Literal(Vec<u8>),
}

/// Compression flag: high bit of the 4-byte length prefix signals zstd-compressed payload.
const COMPRESS_FLAG: u32 = 0x8000_0000;
/// Only compress payloads above this threshold (small messages aren't worth it).
const COMPRESS_THRESHOLD: usize = 64;
/// Maximum decompressed size to prevent decompression bombs.
const MAX_DECOMPRESSED: usize = 64 * 1024 * 1024;

/// Write a length-prefixed bincode frame to a stream.
pub async fn write_message<T: Serialize>(
    stream: &mut (impl AsyncWriteExt + Unpin),
    msg: &T,
) -> Result<()> {
    let payload =
        bincode::serde::encode_to_vec(msg, bincode::config::standard()).context("encode failed")?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    stream.write_all(&frame).await.context("write frame")?;
    stream.flush().await.context("flush frame")?;
    Ok(())
}

/// Write a length-prefixed bincode frame **without flushing**.
///
/// Use this for high-throughput data streaming (e.g. FileData chunks) where
/// flushing after every message would force a stop-and-wait pattern. The
/// caller must flush explicitly at appropriate boundaries (e.g. after FileEnd).
pub async fn write_message_buffered<T: Serialize>(
    stream: &mut (impl AsyncWriteExt + Unpin),
    msg: &T,
) -> Result<()> {
    let payload =
        bincode::serde::encode_to_vec(msg, bincode::config::standard()).context("encode failed")?;
    let mut frame = Vec::with_capacity(4 + payload.len());
    frame.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    frame.extend_from_slice(&payload);
    stream.write_all(&frame).await.context("write frame")?;
    Ok(())
}

/// Write a length-prefixed bincode frame, zstd-compressing the payload when beneficial.
///
/// Used on hop/3 connections for Output messages. The high bit of the length
/// prefix signals compression so the receiver can distinguish compressed from
/// uncompressed frames.
pub async fn write_message_compressed<T: Serialize>(
    stream: &mut (impl AsyncWriteExt + Unpin),
    msg: &T,
) -> Result<()> {
    let payload =
        bincode::serde::encode_to_vec(msg, bincode::config::standard()).context("encode failed")?;
    let frame = if payload.len() > COMPRESS_THRESHOLD {
        if let Ok(compressed) = zstd::bulk::compress(&payload, 1) {
            if compressed.len() < payload.len() {
                let len = (compressed.len() as u32) | COMPRESS_FLAG;
                let mut f = Vec::with_capacity(4 + compressed.len());
                f.extend_from_slice(&len.to_be_bytes());
                f.extend_from_slice(&compressed);
                f
            } else {
                let mut f = Vec::with_capacity(4 + payload.len());
                f.extend_from_slice(&(payload.len() as u32).to_be_bytes());
                f.extend_from_slice(&payload);
                f
            }
        } else {
            let mut f = Vec::with_capacity(4 + payload.len());
            f.extend_from_slice(&(payload.len() as u32).to_be_bytes());
            f.extend_from_slice(&payload);
            f
        }
    } else {
        let mut f = Vec::with_capacity(4 + payload.len());
        f.extend_from_slice(&(payload.len() as u32).to_be_bytes());
        f.extend_from_slice(&payload);
        f
    };
    stream.write_all(&frame).await.context("write frame")?;
    stream.flush().await.context("flush frame")?;
    Ok(())
}

const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Decode a raw frame payload (`raw_len` = the on-wire length word, high bit =
/// zstd) into `T`. Shared by [`read_message`] and [`FramedReader`].
fn decode_frame<T: for<'de> Deserialize<'de>>(raw_len: u32, payload: Vec<u8>) -> Result<T> {
    let compressed = raw_len & COMPRESS_FLAG != 0;
    let decode_buf = if compressed {
        zstd::bulk::decompress(&payload, MAX_DECOMPRESSED).context("zstd decompress failed")?
    } else {
        payload
    };
    let (msg, _) = bincode::serde::decode_from_slice(&decode_buf, bincode::config::standard())
        .context("decode failed")?;
    Ok(msg)
}

/// Read a length-prefixed bincode frame from a stream.
///
/// Transparently decompresses zstd frames (high bit set in length prefix).
///
/// NOTE: this future holds partial-frame state on its own stack, so it is **not
/// cancellation-safe** — dropping it mid-frame (e.g. losing a `tokio::select!`
/// race) discards already-consumed bytes and desyncs the stream. Use it only in
/// a plain read loop. For a `select!` branch, use [`FramedReader`].
pub async fn read_message<T: for<'de> Deserialize<'de>>(
    stream: &mut (impl AsyncReadExt + Unpin),
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("read frame length")?;
    let raw_len = u32::from_be_bytes(len_buf);
    let len = (raw_len & !COMPRESS_FLAG) as usize;

    if len > MAX_FRAME_LEN {
        anyhow::bail!("frame too large: {len} bytes");
    }

    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .context("read frame payload")?;

    decode_frame(raw_len, payload)
}

/// A **cancellation-safe** framed message reader.
///
/// The bare [`read_message`] future keeps partial-frame state (length prefix,
/// payload accumulator) on its own stack, so if it's dropped mid-frame — which
/// happens every time it loses a `tokio::select!` race — the bytes it already
/// pulled from the stream are lost and the next read starts mid-frame, desyncing
/// the connection (surfacing as `frame too large` / `decode failed` → a spurious
/// disconnect). That is the root cause of interactive `hop <host>` sessions
/// dropping under heavy output: the always-ready output/heartbeat `select!`
/// branches cancel the read mid-frame during a flood.
///
/// `FramedReader` moves that partial state into the struct and advances it with
/// single, individually cancel-safe `read()` calls (a cancelled `read()` reads
/// nothing). So [`next`](Self::next) can be raced in a `select!` freely: if the
/// future is dropped, it resumes exactly where it left off on the next call.
pub struct FramedReader<R> {
    inner: R,
    len_buf: [u8; 4],
    len_got: usize,
    raw_len: u32,
    payload: Vec<u8>,
    payload_len: Option<usize>,
    payload_got: usize,
}

impl<R: AsyncReadExt + Unpin> FramedReader<R> {
    pub fn new(inner: R) -> Self {
        Self {
            inner,
            len_buf: [0u8; 4],
            len_got: 0,
            raw_len: 0,
            payload: Vec::new(),
            payload_len: None,
            payload_got: 0,
        }
    }

    fn reset(&mut self) {
        self.len_got = 0;
        self.payload_len = None;
        self.payload_got = 0;
        self.payload = Vec::new();
    }

    /// Read the next complete message. **Cancellation-safe** — safe as a
    /// `tokio::select!` branch.
    pub async fn next<T: for<'de> Deserialize<'de>>(&mut self) -> Result<T> {
        loop {
            match self.payload_len {
                None => {
                    // Reading the 4-byte length prefix (resumable).
                    let n = self
                        .inner
                        .read(&mut self.len_buf[self.len_got..])
                        .await
                        .context("read frame length")?;
                    if n == 0 {
                        anyhow::bail!("connection closed");
                    }
                    self.len_got += n;
                    if self.len_got == 4 {
                        self.raw_len = u32::from_be_bytes(self.len_buf);
                        let len = (self.raw_len & !COMPRESS_FLAG) as usize;
                        if len > MAX_FRAME_LEN {
                            anyhow::bail!("frame too large: {len} bytes");
                        }
                        self.payload = vec![0u8; len];
                        self.payload_len = Some(len);
                        self.payload_got = 0;
                    }
                }
                Some(len) => {
                    if self.payload_got < len {
                        let n = self
                            .inner
                            .read(&mut self.payload[self.payload_got..])
                            .await
                            .context("read frame payload")?;
                        if n == 0 {
                            anyhow::bail!("connection closed");
                        }
                        self.payload_got += n;
                    }
                    if self.payload_got >= len {
                        let raw_len = self.raw_len;
                        let payload = std::mem::take(&mut self.payload);
                        self.reset();
                        return decode_frame(raw_len, payload);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxPolicy;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Serialize a message to its exact on-wire frame bytes.
    async fn frame_of(msg: &ClientMessage) -> Vec<u8> {
        let (mut w, mut r) = tokio::io::duplex(1 << 20);
        write_message(&mut w, msg).await.unwrap();
        drop(w);
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).await.unwrap();
        buf
    }

    /// The core guarantee: `FramedReader::next` survives repeated mid-frame
    /// cancellation (losing a `select!` race) without desyncing the stream. A
    /// partial length prefix AND a partial payload are each interrupted, then
    /// resumed — the message must still decode intact. This is the exact
    /// situation that dropped interactive sessions under output floods.
    #[tokio::test]
    async fn framed_reader_survives_midframe_cancellation() {
        let msg = ClientMessage::Input(b"scroll the tmux buffer fast".to_vec());
        let frame = frame_of(&msg).await;
        assert!(frame.len() > 6, "need a multi-byte frame to split");

        let (mut w, r) = tokio::io::duplex(1 << 20);
        let mut framed = FramedReader::new(r);

        // 1) Feed 2 of the 4 length-prefix bytes, then cancel a read mid-prefix.
        w.write_all(&frame[..2]).await.unwrap();
        tokio::select! {
            biased;
            _ = std::future::ready(()) => {}                 // always-ready → cancels next()
            _ = framed.next::<ClientMessage>() => panic!("should not complete yet"),
        }

        // 2) Feed the rest of the prefix + part of the payload, cancel again.
        w.write_all(&frame[2..5]).await.unwrap();
        tokio::select! {
            biased;
            _ = std::future::ready(()) => {}
            _ = framed.next::<ClientMessage>() => panic!("should not complete yet"),
        }

        // 3) Feed the remainder — the message must decode intact despite two
        //    mid-frame cancellations.
        w.write_all(&frame[5..]).await.unwrap();
        let got: ClientMessage = framed.next().await.unwrap();
        assert!(matches!(got, ClientMessage::Input(ref d) if d == b"scroll the tmux buffer fast"));
    }

    fn input_bytes(m: &ClientMessage) -> Vec<u8> {
        match m {
            ClientMessage::Input(d) => d.clone(),
            _ => panic!("expected Input"),
        }
    }

    /// Back-to-back frames read through repeated cancellation stay in order.
    #[tokio::test]
    async fn framed_reader_multiple_frames_with_cancellation() {
        let msgs: Vec<ClientMessage> = (0..5)
            .map(|i| ClientMessage::Input(vec![i as u8; 3 + i as usize]))
            .collect();
        let mut wire = Vec::new();
        for m in &msgs {
            wire.extend(frame_of(m).await);
        }

        let (mut w, r) = tokio::io::duplex(1 << 20);
        let mut framed = FramedReader::new(r);
        // Dribble the concatenated frames one byte at a time; between each byte,
        // race next() against an always-ready branch so it's cancelled constantly.
        let feeder = tokio::spawn(async move {
            for b in wire {
                w.write_all(&[b]).await.unwrap();
                tokio::task::yield_now().await;
            }
            drop(w);
        });

        let mut got: Vec<ClientMessage> = Vec::new();
        while got.len() < msgs.len() {
            tokio::select! {
                r = framed.next::<ClientMessage>() => got.push(r.unwrap()),
                _ = tokio::task::yield_now() => {}   // frequently cancels the read
            }
        }
        feeder.await.unwrap();
        let got_bytes: Vec<Vec<u8>> = got.iter().map(input_bytes).collect();
        let want_bytes: Vec<Vec<u8>> = msgs.iter().map(input_bytes).collect();
        assert_eq!(got_bytes, want_bytes);
    }

    #[test]
    fn sandbox_policy_bincode_roundtrip() {
        let policy = SandboxPolicy {
            read_only: true,
            ..Default::default()
        };
        let msg = ClientMessage::RequestShellV3 {
            session_id: None,
            sandbox: policy,
        };
        let encoded =
            bincode::serde::encode_to_vec(&msg, bincode::config::standard()).unwrap();
        let (decoded, _): (ClientMessage, _) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard())
                .unwrap();
        match decoded {
            ClientMessage::RequestShellV3 { sandbox, .. } => {
                assert!(sandbox.read_only, "read_only must survive roundtrip");
                assert!(!sandbox.no_network);
                assert!(sandbox.allowed_paths.is_empty());
                assert!(sandbox.allowed_commands.is_empty());
                assert!(sandbox.denied_commands.is_empty());
            }
            _ => panic!("wrong variant after roundtrip"),
        }
    }

    #[test]
    fn exec_v2_sandbox_bincode_roundtrip() {
        let policy = SandboxPolicy {
            read_only: true,
            no_network: true,
            ..Default::default()
        };
        let msg = ClientMessage::RequestExecV2 {
            command: "ls -la".into(),
            sandbox: policy,
        };
        let encoded =
            bincode::serde::encode_to_vec(&msg, bincode::config::standard()).unwrap();
        let (decoded, _): (ClientMessage, _) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard())
                .unwrap();
        match decoded {
            ClientMessage::RequestExecV2 { command, sandbox } => {
                assert_eq!(command, "ls -la");
                assert!(sandbox.read_only);
                assert!(sandbox.no_network);
            }
            _ => panic!("wrong variant after roundtrip"),
        }
    }

    #[test]
    fn all_client_message_variants_roundtrip() {
        use std::collections::HashMap;

        let variants: Vec<ClientMessage> = vec![
            ClientMessage::Input(b"hello".to_vec()),
            ClientMessage::WindowSize {
                cols: 80,
                rows: 24,
                pixel_width: 640,
                pixel_height: 480,
            },
            ClientMessage::AuthResponse {
                secret: b"deadbeef".to_vec(),
            },
            ClientMessage::RequestShell,
            ClientMessage::RequestShellV2 {
                session_id: Some("abc123".into()),
            },
            ClientMessage::RequestShellV2 { session_id: None },
            ClientMessage::RequestExec {
                command: "ls -la".into(),
            },
            ClientMessage::RequestShellV3 {
                session_id: Some("xyz".into()),
                sandbox: SandboxPolicy::preset_monitor(),
            },
            ClientMessage::RequestExecV2 {
                command: "ps aux".into(),
                sandbox: SandboxPolicy::preset_audit(),
            },
            ClientMessage::SetEnv {
                vars: HashMap::from([
                    ("TERM".into(), "xterm-256color".into()),
                    ("LANG".into(), "en_US.UTF-8".into()),
                ]),
            },
        ];

        for msg in &variants {
            let encoded =
                bincode::serde::encode_to_vec(msg, bincode::config::standard())
                    .expect("encode should succeed");
            let (decoded, _): (ClientMessage, _) =
                bincode::serde::decode_from_slice(&encoded, bincode::config::standard())
                    .expect("decode should succeed");
            // Verify variant discriminant matches via Debug format prefix
            let orig_debug = format!("{:?}", msg);
            let decoded_debug = format!("{:?}", decoded);
            let orig_variant = orig_debug.split('(').next().unwrap_or(&orig_debug)
                .split('{').next().unwrap_or(&orig_debug)
                .split(' ').next().unwrap_or(&orig_debug);
            let decoded_variant = decoded_debug.split('(').next().unwrap_or(&decoded_debug)
                .split('{').next().unwrap_or(&decoded_debug)
                .split(' ').next().unwrap_or(&decoded_debug);
            assert_eq!(orig_variant, decoded_variant, "variant mismatch for: {orig_debug}");
        }
    }

    #[test]
    fn fully_populated_sandbox_policy_roundtrip() {
        use std::path::PathBuf;

        let policy = SandboxPolicy {
            read_only: true,
            no_network: true,
            allowed_paths: vec![
                PathBuf::from("/etc"),
                PathBuf::from("/var/log"),
                PathBuf::from("/proc"),
            ],
            allowed_commands: vec!["ps".into(), "ls".into(), "cat".into()],
            denied_commands: vec!["rm".into(), "dd".into(), "shutdown".into()],
        };
        let msg = ClientMessage::RequestShellV3 {
            session_id: Some("full-test".into()),
            sandbox: policy.clone(),
        };
        let encoded =
            bincode::serde::encode_to_vec(&msg, bincode::config::standard()).unwrap();
        let (decoded, _): (ClientMessage, _) =
            bincode::serde::decode_from_slice(&encoded, bincode::config::standard()).unwrap();
        match decoded {
            ClientMessage::RequestShellV3 { session_id, sandbox } => {
                assert_eq!(session_id, Some("full-test".into()));
                assert_eq!(sandbox, policy);
            }
            _ => panic!("wrong variant"),
        }
    }

    #[test]
    fn host_message_variants_roundtrip() {
        let variants: Vec<HostMessage> = vec![
            HostMessage::Output(b"hello world".to_vec()),
            HostMessage::Exit(0),
            HostMessage::Exit(127),
            HostMessage::WindowSizeAck,
            HostMessage::AuthResult { authorized: true },
            HostMessage::AuthResult { authorized: false },
            HostMessage::SessionInfo {
                session_id: "sess-abc".into(),
                resumed: false,
            },
            HostMessage::SessionInfo {
                session_id: "sess-xyz".into(),
                resumed: true,
            },
        ];

        for msg in &variants {
            let encoded =
                bincode::serde::encode_to_vec(msg, bincode::config::standard())
                    .expect("encode should succeed");
            let (decoded, _): (HostMessage, _) =
                bincode::serde::decode_from_slice(&encoded, bincode::config::standard())
                    .expect("decode should succeed");
            let orig_debug = format!("{:?}", msg);
            let decoded_debug = format!("{:?}", decoded);
            let orig_variant = orig_debug.split('(').next().unwrap_or(&orig_debug)
                .split('{').next().unwrap_or(&orig_debug)
                .split(' ').next().unwrap_or(&orig_debug);
            let decoded_variant = decoded_debug.split('(').next().unwrap_or(&decoded_debug)
                .split('{').next().unwrap_or(&decoded_debug)
                .split(' ').next().unwrap_or(&decoded_debug);
            assert_eq!(orig_variant, decoded_variant, "variant mismatch for: {orig_debug}");
        }
    }

    #[tokio::test]
    async fn compressed_write_read_roundtrip() {
        // Large output that benefits from compression
        let data = "AAAA ".repeat(200); // 1000 bytes, highly compressible
        let msg = HostMessage::Output(data.as_bytes().to_vec());

        // Write compressed
        let mut buf = Vec::new();
        write_message_compressed(&mut buf, &msg).await.unwrap();

        // Verify compression flag is set (high bit of length)
        let raw_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert!(raw_len & COMPRESS_FLAG != 0, "compression flag should be set for large payload");
        let wire_len = (raw_len & !COMPRESS_FLAG) as usize;
        assert!(wire_len < 1000, "compressed size ({wire_len}) should be much smaller than 1000");

        // Read back — read_message handles decompression transparently
        let mut cursor = std::io::Cursor::new(buf);
        let decoded: HostMessage = read_message(&mut cursor).await.unwrap();
        match decoded {
            HostMessage::Output(d) => assert_eq!(d, data.as_bytes()),
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn small_message_not_compressed() {
        let msg = HostMessage::Output(b"hello".to_vec());

        let mut buf = Vec::new();
        write_message_compressed(&mut buf, &msg).await.unwrap();

        // Small payload should NOT be compressed
        let raw_len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        assert!(raw_len & COMPRESS_FLAG == 0, "small payload should not be compressed");

        let mut cursor = std::io::Cursor::new(buf);
        let decoded: HostMessage = read_message(&mut cursor).await.unwrap();
        match decoded {
            HostMessage::Output(d) => assert_eq!(d, b"hello"),
            _ => panic!("wrong variant"),
        }
    }

    #[tokio::test]
    async fn uncompressed_write_read_roundtrip() {
        // Verify old-style write_message still works with new read_message
        let msg = HostMessage::Output(b"test data".to_vec());

        let mut buf = Vec::new();
        write_message(&mut buf, &msg).await.unwrap();

        let mut cursor = std::io::Cursor::new(buf);
        let decoded: HostMessage = read_message(&mut cursor).await.unwrap();
        match decoded {
            HostMessage::Output(d) => assert_eq!(d, b"test data"),
            _ => panic!("wrong variant"),
        }
    }
}
