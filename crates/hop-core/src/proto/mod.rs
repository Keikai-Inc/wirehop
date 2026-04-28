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

/// Legacy alias — kept so existing callers that reference `ALPN` still compile.
pub const ALPN: &[u8] = ALPN_V0;

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
    /// Client environment variables (TERM, LANG, LC_*, COLORTERM).
    SetEnv { vars: HashMap<String, String> },
    /// Admin request (hop/2+). Requires creator role.
    RequestAdmin(AdminRequest),
    /// Peer operation (any authenticated peer). Secrets, KV, cap, cron.
    RequestPeerOp(PeerRequest),
}

// --- Admin protocol (hop/2+) ---

/// Admin requests sent by creator peers.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AdminRequest {
    /// Create an invite on this host.
    CreateInvite {
        username: Option<String>,
        role: PeerRole,
    },
    /// List authorized peers.
    ListPeers,
    /// Remove a peer by node_id prefix.
    RemovePeer { node_id_prefix: String },
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
    /// List of authorized peers.
    PeerList { peers: Vec<PeerInfo> },
    /// A peer was removed.
    PeerRemoved { success: bool },
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
    /// Sandbox policy enforced for peers with this role.
    #[serde(default, skip_serializing_if = "sandbox_is_unrestricted")]
    pub sandbox: SandboxPolicy,
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
    pub sandbox: Option<SandboxPolicy>,
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

/// Read a length-prefixed bincode frame from a stream.
///
/// Transparently decompresses zstd frames (high bit set in length prefix).
pub async fn read_message<T: for<'de> Deserialize<'de>>(
    stream: &mut (impl AsyncReadExt + Unpin),
) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("read frame length")?;
    let raw_len = u32::from_be_bytes(len_buf);
    let compressed = raw_len & COMPRESS_FLAG != 0;
    let len = (raw_len & !COMPRESS_FLAG) as usize;

    if len > 16 * 1024 * 1024 {
        anyhow::bail!("frame too large: {len} bytes");
    }

    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .context("read frame payload")?;

    let decode_buf = if compressed {
        zstd::bulk::decompress(&payload, MAX_DECOMPRESSED)
            .context("zstd decompress failed")?
    } else {
        payload
    };

    let (msg, _) =
        bincode::serde::decode_from_slice(&decode_buf, bincode::config::standard())
            .context("decode failed")?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::SandboxPolicy;

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
