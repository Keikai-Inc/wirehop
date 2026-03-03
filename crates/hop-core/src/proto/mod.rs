use std::collections::HashMap;

use anyhow::{Context, Result};
use iroh::endpoint::{RecvStream, SendStream};
use serde::{Deserialize, Serialize};

/// ALPN protocol identifier for hop connections (legacy).
pub const ALPN_V0: &[u8] = b"hop/0";

/// ALPN protocol identifier for hop v1 (compression, hashing, parallel streams, delta).
pub const ALPN_V1: &[u8] = b"hop/1";

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
}

/// Messages sent from the client to the host.
#[derive(Debug, Serialize, Deserialize)]
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
    /// Client environment variables (TERM, LANG, LC_*, COLORTERM).
    SetEnv { vars: HashMap<String, String> },
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
pub const DELTA_MIN_FILE_SIZE: usize = 64 * 1024;

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

/// Write a length-prefixed bincode frame to a QUIC send stream.
pub async fn write_message<T: Serialize>(stream: &mut SendStream, msg: &T) -> Result<()> {
    let payload =
        bincode::serde::encode_to_vec(msg, bincode::config::standard()).context("encode failed")?;
    let len = (payload.len() as u32).to_be_bytes();
    stream
        .write_all(&len)
        .await
        .context("write frame length")?;
    stream
        .write_all(&payload)
        .await
        .context("write frame payload")?;
    Ok(())
}

/// Read a length-prefixed bincode frame from a QUIC recv stream.
pub async fn read_message<T: for<'de> Deserialize<'de>>(stream: &mut RecvStream) -> Result<T> {
    let mut len_buf = [0u8; 4];
    stream
        .read_exact(&mut len_buf)
        .await
        .context("read frame length")?;
    let len = u32::from_be_bytes(len_buf) as usize;

    if len > 16 * 1024 * 1024 {
        anyhow::bail!("frame too large: {len} bytes");
    }

    let mut payload = vec![0u8; len];
    stream
        .read_exact(&mut payload)
        .await
        .context("read frame payload")?;

    let (msg, _) =
        bincode::serde::decode_from_slice(&payload, bincode::config::standard())
            .context("decode failed")?;
    Ok(msg)
}
