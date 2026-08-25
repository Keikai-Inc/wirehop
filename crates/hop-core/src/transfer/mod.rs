//! File transfer sessions (copy and sync).

pub mod delta;
pub mod hashing;
pub mod helper;
pub mod listing;
pub mod negotiation;
pub mod progress;
pub mod receiver;
pub mod sender;

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Result, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream};

use crate::proto::{
    self, FileEntry, TransferDirection, TransferMode, TransferMsg, TransferRequest,
    LIST_CHUNK_ENTRIES, MAX_CHUNK_SIZE, DEFAULT_ZSTD_LEVEL, TRANSFER_FEATURES_VERSION,
};
use negotiation::NegotiatedParams;
use progress::{ProgressReporter, SilentProgress, TransferSummary};

// ---------------------------------------------------------------------------
// Listing wire format
// ---------------------------------------------------------------------------
//
// A listing is the one message whose size scales with the tree, so it is the
// one that outgrows `MAX_FRAME_LEN` (16 MiB ≈ 140k entries — a Rust repo with
// its `target/` dir gets there easily). Everything else on the wire is bounded.
//
// When both peers are at features version >= 2 the listing goes out as
// zstd-compressed batches of `LIST_CHUNK_ENTRIES`, which bounds frame size for
// any tree. Against an older peer it falls back to the original single
// uncompressed frame, preserving the exact bytes that peer expects.
//
// The readers accept BOTH encodings regardless of what was negotiated: being
// liberal here costs nothing and means a version mismatch degrades to "works"
// rather than "expected FileList, got FileListChunk".

/// Send a file listing, batching + compressing when `chunked`.
pub async fn write_file_list(
    send: &mut (impl tokio::io::AsyncWriteExt + Unpin),
    entries: Vec<FileEntry>,
    chunked: bool,
) -> Result<()> {
    if !chunked {
        proto::write_message(send, &TransferMsg::FileList(entries)).await?;
        return Ok(());
    }
    // `chunks` yields nothing for an empty slice, so an empty listing still
    // needs one terminating batch or the reader would block forever.
    if entries.is_empty() {
        proto::write_message_compressed(
            send,
            &TransferMsg::FileListChunk { entries: Vec::new(), last: true },
        )
        .await?;
        return Ok(());
    }
    let total = entries.len();
    let mut sent = 0usize;
    for batch in entries.chunks(LIST_CHUNK_ENTRIES) {
        sent += batch.len();
        proto::write_message_compressed(
            send,
            &TransferMsg::FileListChunk { entries: batch.to_vec(), last: sent == total },
        )
        .await?;
    }
    Ok(())
}

/// Read a file listing written by [`write_file_list`], in either encoding.
pub async fn read_file_list(
    recv: &mut (impl tokio::io::AsyncReadExt + Unpin),
) -> Result<Vec<FileEntry>> {
    let mut acc: Vec<FileEntry> = Vec::new();
    loop {
        let msg: TransferMsg = proto::read_message(recv).await?;
        match msg {
            TransferMsg::FileList(entries) => return Ok(entries),
            TransferMsg::FileListChunk { entries, last } => {
                acc.extend(entries);
                if last {
                    return Ok(acc);
                }
            }
            TransferMsg::Error(e) => bail!("peer error: {e}"),
            other => bail!("expected FileList, got: {other:?}"),
        }
    }
}

/// Send a transfer plan, batching + compressing when `chunked`.
pub async fn write_transfer_plan(
    send: &mut (impl tokio::io::AsyncWriteExt + Unpin),
    files_to_send: Vec<FileEntry>,
    files_to_delete: Vec<String>,
    dry_run: bool,
    chunked: bool,
) -> Result<()> {
    if !chunked {
        proto::write_message(
            send,
            &TransferMsg::TransferPlan { files_to_send, files_to_delete, dry_run },
        )
        .await?;
        return Ok(());
    }
    // Both vectors scale with the tree. Batch them independently and let the
    // deletes ride along with the first batches; `last` is driven by whichever
    // list still has entries left.
    let send_batches = files_to_send.len().div_ceil(LIST_CHUNK_ENTRIES).max(1);
    let del_batches = files_to_delete.len().div_ceil(LIST_CHUNK_ENTRIES).max(1);
    let total_batches = send_batches.max(del_batches);

    for i in 0..total_batches {
        let s = i * LIST_CHUNK_ENTRIES;
        let batch_send: Vec<FileEntry> = files_to_send
            .get(s..(s + LIST_CHUNK_ENTRIES).min(files_to_send.len()))
            .unwrap_or(&[])
            .to_vec();
        let batch_del: Vec<String> = files_to_delete
            .get(s..(s + LIST_CHUNK_ENTRIES).min(files_to_delete.len()))
            .unwrap_or(&[])
            .to_vec();
        proto::write_message_compressed(
            send,
            &TransferMsg::TransferPlanChunk {
                files_to_send: batch_send,
                files_to_delete: batch_del,
                dry_run,
                last: i + 1 == total_batches,
            },
        )
        .await?;
    }
    Ok(())
}

/// Read a transfer plan written by [`write_transfer_plan`], in either encoding.
/// Returns `(files_to_send, files_to_delete, dry_run)`.
pub async fn read_transfer_plan(
    recv: &mut (impl tokio::io::AsyncReadExt + Unpin),
) -> Result<(Vec<FileEntry>, Vec<String>, bool)> {
    let mut acc_send: Vec<FileEntry> = Vec::new();
    let mut acc_del: Vec<String> = Vec::new();
    loop {
        let msg: TransferMsg = proto::read_message(recv).await?;
        match msg {
            TransferMsg::TransferPlan { files_to_send, files_to_delete, dry_run } => {
                return Ok((files_to_send, files_to_delete, dry_run));
            }
            TransferMsg::TransferPlanChunk { files_to_send, files_to_delete, dry_run, last } => {
                acc_send.extend(files_to_send);
                acc_del.extend(files_to_delete);
                if last {
                    return Ok((acc_send, acc_del, dry_run));
                }
            }
            TransferMsg::Error(e) => bail!("peer error: {e}"),
            other => bail!("expected TransferPlan, got: {other:?}"),
        }
    }
}

/// Parsed path specification: local path or remote `host:path`.
#[derive(Debug, Clone)]
pub enum PathSpec {
    Local(PathBuf),
    Remote { host: String, path: String },
}

/// Parse a CLI path argument into a `PathSpec`.
///
/// Uses `host:path` notation. A leading `/` or `./` is treated as local.
/// Windows drive letters like `C:\` are treated as local.
pub fn parse_path_spec(input: &str) -> PathSpec {
    // Absolute paths and explicit relative paths are local
    if input.starts_with('/')
        || input.starts_with("./")
        || input.starts_with("../")
        || input == "."
        || input == ".."
    {
        return PathSpec::Local(PathBuf::from(input));
    }

    // Windows drive letters (e.g., C:\)
    if input.len() >= 3 && input.as_bytes()[1] == b':' && (input.as_bytes()[2] == b'\\' || input.as_bytes()[2] == b'/') {
        return PathSpec::Local(PathBuf::from(input));
    }

    // Look for host:path pattern
    if let Some(colon_pos) = input.find(':') {
        let host = &input[..colon_pos];
        let path = &input[colon_pos + 1..];
        // Only treat as remote if host part looks like a hostname (no slashes)
        if !host.is_empty() && !host.contains('/') && !host.contains('\\') {
            return PathSpec::Remote {
                host: host.to_string(),
                path: if path.is_empty() {
                    "~".to_string()
                } else {
                    path.to_string()
                },
            };
        }
    }

    // Default to local path
    PathSpec::Local(PathBuf::from(input))
}

// ---------------------------------------------------------------------------
// Host-side session handler
// ---------------------------------------------------------------------------

/// Host-side: handle a file transfer session after authentication.
///
/// Dispatches to the appropriate flow based on the transfer request's
/// mode and direction.
pub async fn host_transfer_session(
    conn: Connection,
    mut send: SendStream,
    mut recv: RecvStream,
    request: TransferRequest,
    username: Option<&str>,
    protocol_version: u8,
    sandbox: &crate::sandbox::SandboxPolicy,
) -> Result<()> {
    // Resolve the remote path to an absolute path on the host filesystem.
    let base_path = resolve_host_path(&request.remote_path, username)?;

    crate::audit::record(
        crate::audit::AuditEvent::new(
            crate::audit::AuditCategory::Transfer,
            "transfer",
            crate::audit::AuditOutcome::Info,
        )
        .user_opt(username)
        .target(request.remote_path.clone())
        .detail(match request.direction {
            TransferDirection::Push => "push",
            TransferDirection::Pull => "pull",
        }),
    );

    // Enforce the peer's sandbox policy on the data plane (security-audit C3).
    // Transfer previously ran with full host privileges regardless of the
    // policy attached to the invite, nullifying read-only and path scope for
    // every restricted peer.
    let is_write = matches!(request.direction, TransferDirection::Push);
    if let Err(e) = enforce_transfer_policy(sandbox, &base_path, is_write) {
        let _ = proto::write_message(&mut send, &TransferMsg::Error(format!("{e:#}"))).await;
        let _ = send.finish();
        return Err(e);
    }

    let progress = SilentProgress;

    // Negotiate session parameters
    let params = if protocol_version >= 1 {
        negotiate_host(&mut send, &mut recv).await?
    } else {
        NegotiatedParams::legacy()
    };

    // On unix with a bound username, file I/O for the transfer is delegated to a
    // privilege-separated helper process so it runs under the target user's
    // kernel-enforced permissions — spawned directly when we're root, or via the
    // privsep monitor (`SpawnHelper`) when we're the unprivileged worker, which
    // can't switch to the bound user itself. The
    // arm bodies below intentionally do NOT early-return on the helper
    // path: we want helper errors to flow through the shared
    // TransferMsg::Error write below so the client sees a real message
    // instead of just a closed stream.
    let result = match (&request.mode, &request.direction) {
        (TransferMode::Copy { .. }, TransferDirection::Push) => {
            // Client pushes files to us — we receive.
            #[cfg(unix)]
            let arm_result = if (crate::unix_user::is_running_as_root()
                || crate::privsep::is_privsep_worker())
                && let Some(user) = username
            {
                helper::proxy_via_helper(
                    &mut send, &mut recv, &base_path, user, &params, "receive",
                ).await
            } else {
                host_receive_files(&conn, &mut send, &mut recv, &base_path, &progress, &params).await
            };
            #[cfg(not(unix))]
            let arm_result = host_receive_files(&conn, &mut send, &mut recv, &base_path, &progress, &params).await;
            arm_result
        }
        (TransferMode::Copy { .. }, TransferDirection::Pull) => {
            // Client pulls files from us — we send.
            let recursive = matches!(request.mode, TransferMode::Copy { recursive: true });
            #[cfg(unix)]
            let arm_result = if (crate::unix_user::is_running_as_root()
                || crate::privsep::is_privsep_worker())
                && let Some(user) = username
            {
                let send_mode = if recursive { "send-recursive" } else { "send" };
                helper::proxy_via_helper(
                    &mut send, &mut recv, &base_path, user, &params, send_mode,
                ).await
            } else {
                host_send_files(&mut send, &mut recv, &base_path, &request, &progress, &params).await
            };
            #[cfg(not(unix))]
            let arm_result = host_send_files(&mut send, &mut recv, &base_path, &request, &progress, &params).await;
            arm_result
        }
        (TransferMode::Sync, TransferDirection::Push) => {
            // Client sync-pushes to us.
            #[cfg(unix)]
            let arm_result = if (crate::unix_user::is_running_as_root()
                || crate::privsep::is_privsep_worker())
                && let Some(user) = username
            {
                helper::proxy_via_helper(
                    &mut send, &mut recv, &base_path, user, &params, "sync-receive",
                ).await
            } else {
                host_sync_receive(&conn, &mut send, &mut recv, &base_path, &request, &progress, &params).await
            };
            #[cfg(not(unix))]
            let arm_result = host_sync_receive(&conn, &mut send, &mut recv, &base_path, &request, &progress, &params).await;
            arm_result
        }
        (TransferMode::Sync, TransferDirection::Pull) => {
            // Client sync-pulls from us.
            #[cfg(unix)]
            let arm_result = if (crate::unix_user::is_running_as_root()
                || crate::privsep::is_privsep_worker())
                && let Some(user) = username
            {
                let mode = if request.delete_extraneous { "sync-send-delete" } else { "sync-send" };
                helper::proxy_via_helper(
                    &mut send, &mut recv, &base_path, user, &params, mode,
                ).await
            } else {
                host_sync_send(&mut send, &mut recv, &base_path, &request, &progress, &params).await
            };
            #[cfg(not(unix))]
            let arm_result = host_sync_send(&mut send, &mut recv, &base_path, &request, &progress, &params).await;
            arm_result
        }
    };

    if let Err(ref e) = result {
        let _ = proto::write_message(&mut send, &TransferMsg::Error(format!("{e:#}"))).await;
    }

    // Gracefully close the send stream so the client receives all buffered
    // data (especially the final Done message). Without this, dropping the
    // SendStream sends a QUIC RESET which discards undelivered data.
    let _ = send.finish();

    // Keep the connection alive briefly so the QUIC transport can deliver
    // the buffered FIN + data before the Connection is dropped (which
    // sends CONNECTION_CLOSE). We wait for the client to close their side,
    // but cap it so we don't hang if the client disappears.
    let _ = tokio::time::timeout(
        std::time::Duration::from_millis(200),
        recv.read_to_end(1),
    )
    .await;

    result
}

/// Host receives files pushed by the client (copy push).
async fn host_receive_files(
    _conn: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    dest: &Path,
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,
) -> Result<()> {
    receiver::receive_files(send, recv, dest, progress, params).await?;
    proto::write_message(send, &TransferMsg::Done).await?;
    Ok(())
}

/// Host sends files pulled by the client (copy pull).
async fn host_send_files(
    send: &mut SendStream,
    recv: &mut RecvStream,
    source: &Path,
    request: &TransferRequest,
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,
) -> Result<()> {
    let recursive = matches!(request.mode, TransferMode::Copy { recursive: true });

    let entries = if source.is_file() {
        // Single file
        let metadata = std::fs::metadata(source)?;
        let file_name = source
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        vec![FileEntry {
            path: file_name,
            size: metadata.len(),
            mtime: metadata
                .modified()
                .unwrap_or(std::time::UNIX_EPOCH)
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            mode: listing::file_mode_from_metadata(&metadata),
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            content_hash: None,
        }]
    } else if source.is_dir() {
        if !recursive {
            bail!("source is a directory; use -r for recursive copy");
        }
        listing::walk_directory(source)?
    } else {
        bail!("source path does not exist: {}", source.display());
    };

    let base_dir = if source.is_file() {
        source.parent().unwrap_or(source)
    } else {
        source
    };

    sender::send_files(send, base_dir, &entries, progress, params).await?;
    // Read acks for non-directory entries
    let ack_count = entries.iter().filter(|e| !e.is_dir || e.is_symlink).count()
        + entries.iter().filter(|e| e.is_dir && !e.is_symlink).count();
    let _errors = receiver::read_acks(recv, ack_count, None).await?;
    proto::write_message(send, &TransferMsg::Done).await?;
    Ok(())
}

/// Host receives sync-pushed files from the client.
async fn host_sync_receive(
    _conn: &Connection,
    send: &mut SendStream,
    recv: &mut RecvStream,
    dest: &Path,
    _request: &TransferRequest,
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,
) -> Result<()> {
    // 1. Walk our (destination) directory and send the listing to the client
    let dest_entries = if dest.is_dir() {
        listing::walk_directory(dest)?
    } else {
        Vec::new()
    };
    write_file_list(send, dest_entries, params.chunked_listing()).await?;

    // 2. Client computes the plan and sends TransferPlan
    let (files_to_send, files_to_delete, dry_run) = read_transfer_plan(recv).await?;

    if dry_run {
        // Dry run — nothing to transfer
        proto::write_message(send, &TransferMsg::PlanAck { proceed: true }).await?;
        proto::write_message(send, &TransferMsg::Done).await?;
        return Ok(());
    }

    proto::write_message(send, &TransferMsg::PlanAck { proceed: true }).await?;

    // 3. Compute delta candidates on host side
    // Delta candidates: files that exist locally, are in files_to_send, and both
    // the local and source version are above DELTA_MIN_FILE_SIZE
    let delta_candidates: std::collections::HashSet<String> = files_to_send
        .iter()
        .filter(|f| {
            !f.is_dir
                && !f.is_symlink
                && f.size >= proto::DELTA_MIN_FILE_SIZE
                && dest.join(&f.path).exists()
                && dest
                    .join(&f.path)
                    .metadata()
                    .map(|m| m.len() >= proto::DELTA_MIN_FILE_SIZE)
                    .unwrap_or(false)
        })
        .map(|f| f.path.clone())
        .collect();

    let _ = files_to_delete; // deletes come via DeletePath messages

    if !delta_candidates.is_empty() {
        // Delta-aware receiving
        receiver::receive_files_with_delta(
            send,
            recv,
            dest,
            &delta_candidates,
            &files_to_send,
            progress,
            params,
        )
        .await?;
    } else {
        receiver::receive_files(send, recv, dest, progress, params).await?;
    }
    proto::write_message(send, &TransferMsg::Done).await?;
    Ok(())
}

/// Host sends files for a sync-pull by the client.
async fn host_sync_send(
    send: &mut SendStream,
    recv: &mut RecvStream,
    source: &Path,
    request: &TransferRequest,
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,
) -> Result<()> {
    // 1. Read the client's local file list
    tracing::debug!("host_sync_send: waiting for FileList from client...");
    let client_entries = read_file_list(recv).await?;
    tracing::debug!(
        "host_sync_send: got FileList with {} entries",
        client_entries.len()
    );

    // 2. Walk our source and compute the plan
    let (source_entries, base_dir) = if source.is_dir() {
        (listing::walk_directory(source)?, source.to_path_buf())
    } else if source.is_file() {
        let metadata = std::fs::metadata(source)?;
        let file_name = source
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let entry = FileEntry {
            path: file_name,
            size: metadata.len(),
            mtime: metadata
                .modified()
                .unwrap_or(std::time::UNIX_EPOCH)
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            mode: listing::file_mode_from_metadata(&metadata),
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            content_hash: None,
        };
        (vec![entry], source.parent().unwrap_or(source).to_path_buf())
    } else {
        bail!("source path does not exist: {}", source.display());
    };

    let plan =
        listing::compute_sync_plan(&source_entries, &client_entries, request.delete_extraneous);

    // 3. Send the plan
    write_transfer_plan(
        send,
        plan.files_to_send.clone(),
        plan.files_to_delete.clone(),
        request.dry_run,
        params.chunked_listing(),
    )
    .await?;

    // 4. Wait for PlanAck
    let ack_msg: TransferMsg = proto::read_message(recv).await?;
    match ack_msg {
        TransferMsg::PlanAck { proceed: true } => {}
        TransferMsg::PlanAck { proceed: false } => {
            proto::write_message(send, &TransferMsg::Done).await?;
            return Ok(());
        }
        other => bail!("expected PlanAck, got: {other:?}"),
    }

    if request.dry_run {
        proto::write_message(send, &TransferMsg::Done).await?;
        return Ok(());
    }

    // 5. Send the files (with delta support if candidates exist)
    let files_to_send: Vec<_> = plan.files_to_send;
    let delta_set: std::collections::HashSet<String> =
        plan.delta_candidates.into_iter().collect();

    if !delta_set.is_empty() {
        sender::send_files_with_delta(
            send, recv, &base_dir, &files_to_send, &delta_set, progress, params,
        )
        .await?;
    } else {
        sender::send_files(send, &base_dir, &files_to_send, progress, params).await?;
    }

    // 6. Send deletes
    sender::send_deletes(send, &plan.files_to_delete, progress).await?;

    proto::write_message(send, &TransferMsg::Done).await?;

    // 7. Read acks from client
    let total_acks = files_to_send.len() + plan.files_to_delete.len();
    let _errors = receiver::read_acks(recv, total_acks, None).await?;

    // 8. Read client's Done
    let done_msg: TransferMsg = proto::read_message(recv).await?;
    match done_msg {
        TransferMsg::Done => {}
        other => tracing::warn!("expected Done from client, got: {other:?}"),
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Client-side session functions
// ---------------------------------------------------------------------------

/// Client-side: push files to the remote host (copy push).
///
/// Ack reading is pipelined: a background task reads acks from the recv stream
/// while we continue sending files, so confirmations arrive during sending
/// rather than in a post-send stall.
/// Push local files to the remote host.
///
/// `contents_only` is parallel to `local_paths`. When `true` (source had a
/// trailing slash, rsync convention), directory contents are sent without
/// the directory name prefix. When `false`, the directory name is included
/// in all entry paths so the receiver creates it under the destination.
pub async fn client_push_copy(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    local_paths: &[PathBuf],
    contents_only: &[bool],
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,
) -> Result<TransferSummary> {
    let start = Instant::now();
    let mut summary = TransferSummary::default();

    // Collect all entries to send (walk directories upfront).
    let mut all_sends: Vec<(PathBuf, Vec<FileEntry>)> = Vec::new();

    for (i, local_path) in local_paths.iter().enumerate() {
        let (base_dir, entries) = if local_path.is_file() {
            let metadata = std::fs::metadata(local_path)?;
            let file_name = local_path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let entry = FileEntry {
                path: file_name,
                size: metadata.len(),
                mtime: metadata
                    .modified()
                    .unwrap_or(std::time::UNIX_EPOCH)
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
                mode: listing::file_mode_from_metadata(&metadata),
                is_dir: false,
                is_symlink: false,
                symlink_target: None,
                content_hash: None,
            };
            (
                local_path.parent().unwrap_or(Path::new(".")).to_path_buf(),
                vec![entry],
            )
        } else if local_path.is_dir() {
            let is_contents_only = contents_only.get(i).copied().unwrap_or(false);
            if is_contents_only {
                (local_path.clone(), listing::walk_directory(local_path)?)
            } else {
                let dir_name = local_path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_string();
                let parent = local_path.parent().unwrap_or(Path::new(".")).to_path_buf();
                let mut entries = listing::walk_directory(local_path)?;
                for entry in &mut entries {
                    entry.path = format!("{dir_name}/{}", entry.path);
                }
                (parent, entries)
            }
        } else {
            bail!("path does not exist: {}", local_path.display());
        };

        summary.files_transferred += entries.iter().filter(|e| !e.is_dir).count() as u64;
        summary.dirs_created += entries.iter().filter(|e| e.is_dir).count() as u64;
        all_sends.push((base_dir, entries));
    }

    // Send files in batches and drain acks between batches. Without draining
    // acks during send, large transfers deadlock: the host writes acks to its
    // stdout pipe, the pipe fills (64KB), the helper blocks, can't read more
    // data from stdin, QUIC flow control back-pressures the client → deadlock.
    const BATCH_SIZE: usize = 100;

    for (base_dir, entries) in &all_sends {
        for batch in entries.chunks(BATCH_SIZE) {
            let bytes = sender::send_files(send, base_dir, batch, progress, params).await?;
            summary.bytes_transferred += bytes;

            // Drain any pending acks (non-blocking) to prevent back-pressure
            drain_pending_acks(recv, progress, &mut summary.errors).await;
        }
    }

    // Send Done
    proto::write_message(send, &TransferMsg::Done).await?;

    // Read remaining acks + host's Done
    let errors = receiver::read_acks_until_done(recv, Some(progress)).await?;
    summary.errors.extend(errors);

    summary.elapsed = start.elapsed();
    Ok(summary)
}

/// Drain any pending ack messages without blocking.
///
/// Reads acks that are immediately available. Returns when no more data
/// is ready (the read would block). This prevents the recv buffer from
/// filling up during large sends, which would cause QUIC back-pressure deadlock.
async fn drain_pending_acks(
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    progress: &dyn ProgressReporter,
    errors: &mut Vec<String>,
) {
    use std::time::Duration;
    // Try to read acks with a very short timeout — just drain what's buffered
    loop {
        match tokio::time::timeout(Duration::from_millis(1), proto::read_message::<TransferMsg>(recv)).await {
            Ok(Ok(TransferMsg::FileAck { path, success, error })) => {
                if success {
                    progress.file_confirmed(&path);
                } else {
                    errors.push(format!("{}: {}", path, error.unwrap_or_else(|| "unknown error".into())));
                }
            }
            Ok(Ok(TransferMsg::Done)) => break, // host sent Done early
            Ok(Ok(_)) => {} // ignore other messages
            Ok(Err(_)) => break, // read error
            Err(_) => break, // timeout — no more pending acks
        }
    }
}

/// Client-side: pull files from the remote host (copy pull).
pub async fn client_pull_copy(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    local_dest: &Path,
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,
) -> Result<TransferSummary> {
    let start = Instant::now();
    let mut summary = TransferSummary::default();

    // receive_files reads messages until Done (inclusive), sends acks for each file.
    let bytes = receiver::receive_files(send, recv, local_dest, progress, params).await?;
    summary.bytes_transferred = bytes;

    // Signal to the host that we're done. This may fail if the host has
    // already closed the connection — the acks were already delivered, so
    // the Done is best-effort.
    let _ = proto::write_message(send, &TransferMsg::Done).await;

    summary.elapsed = start.elapsed();
    Ok(summary)
}

/// Result of push-sync plan negotiation (phase 1).
pub struct PushSyncNegotiation {
    pub local_entries: Vec<proto::FileEntry>,
    pub remote_entries: Vec<proto::FileEntry>,
    pub plan: listing::SyncPlan,
}

/// Client-side push-sync phase 1: exchange file lists and negotiate plan.
///
/// Call this BEFORE starting the progress UI so the user can compute
/// itemize maps from the local/remote entries.
pub async fn client_push_sync_negotiate(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    local_dir: &Path,
    request: &TransferRequest,
    chunked: bool,
) -> Result<PushSyncNegotiation> {
    // 1. Read the host's destination file listing
    let remote_entries = read_file_list(recv).await?;

    // 2. Walk local directory and compute plan
    let local_entries = listing::walk_directory(local_dir)?;
    let plan =
        listing::compute_sync_plan(&local_entries, &remote_entries, request.delete_extraneous);

    // 3. Send plan
    write_transfer_plan(
        send,
        plan.files_to_send.clone(),
        plan.files_to_delete.clone(),
        request.dry_run,
        chunked,
    )
    .await?;

    // 4. Wait for PlanAck
    let ack_msg: TransferMsg = proto::read_message(recv).await?;
    match ack_msg {
        TransferMsg::PlanAck { proceed: true } => {}
        TransferMsg::PlanAck { proceed: false } => {
            bail!("host declined the sync plan");
        }
        TransferMsg::Error(e) => bail!("host error: {e}"),
        other => bail!("expected PlanAck, got: {other:?}"),
    }

    Ok(PushSyncNegotiation {
        local_entries,
        remote_entries,
        plan,
    })
}

/// Client-side push-sync phase 2: transfer files according to the plan.
///
/// Call this AFTER starting the progress UI.
pub async fn client_push_sync_transfer(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    local_dir: &Path,
    request: &TransferRequest,
    negotiation: PushSyncNegotiation,
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,
) -> Result<TransferSummary> {
    let start = Instant::now();
    let mut summary = TransferSummary::default();
    let plan = negotiation.plan;

    if request.dry_run {
        // In dry run, report what would happen
        for entry in &plan.files_to_send {
            if entry.is_dir {
                summary.dirs_created += 1;
            } else {
                summary.files_transferred += 1;
                summary.bytes_transferred += entry.size;
            }
        }
        summary.files_deleted = plan.files_to_delete.len() as u64;
        // Read host's Done (host sends Done after dry run too)
        let msg: TransferMsg = proto::read_message(recv).await?;
        match msg {
            TransferMsg::Done => {}
            other => tracing::warn!("expected Done from host, got: {other:?}"),
        }
        summary.elapsed = start.elapsed();
        return Ok(summary);
    }

    // 5. Send files that need transferring (with delta support)
    let files_only: Vec<_> = plan.files_to_send;
    let delta_set: std::collections::HashSet<String> =
        plan.delta_candidates.into_iter().collect();

    if !delta_set.is_empty() {
        // Delta-aware sync: sender reads BlockSignatures for delta candidates
        let (bytes, saved) = sender::send_files_with_delta(
            send, recv, local_dir, &files_only, &delta_set, progress, params,
        )
        .await?;
        summary.bytes_transferred = bytes;
        summary.bytes_saved = saved;
    } else {
        let bytes = sender::send_files(send, local_dir, &files_only, progress, params).await?;
        summary.bytes_transferred = bytes;
    }
    summary.files_transferred = files_only.iter().filter(|e| !e.is_dir).count() as u64;
    summary.dirs_created = files_only.iter().filter(|e| e.is_dir).count() as u64;

    // 6. Send deletes
    sender::send_deletes(send, &plan.files_to_delete, progress).await?;
    summary.files_deleted = plan.files_to_delete.len() as u64;

    proto::write_message(send, &TransferMsg::Done).await?;

    // 7. Read all acks + host's Done in one pass (pipelined)
    let errors = receiver::read_acks_until_done(recv, Some(progress)).await?;
    summary.errors = errors;

    summary.elapsed = start.elapsed();
    Ok(summary)
}

/// Client-side: sync-push local directory to remote host.
///
/// Convenience wrapper that calls negotiate + transfer in one shot.
pub async fn client_push_sync(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    local_dir: &Path,
    request: &TransferRequest,
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,
) -> Result<TransferSummary> {
    let negotiation =
        client_push_sync_negotiate(send, recv, local_dir, request, params.chunked_listing()).await?;
    client_push_sync_transfer(send, recv, local_dir, request, negotiation, progress, params).await
}

/// Result of sync plan negotiation (phase 1).
pub struct SyncPlanResult {
    pub files_to_send: Vec<proto::FileEntry>,
    pub files_to_delete: Vec<String>,
    pub dry_run: bool,
}

/// Client-side sync-pull phase 1: exchange file list and negotiate plan.
///
/// Call this BEFORE starting the progress UI so the user doesn't see an
/// empty "0/0 files" display during the multi-second plan exchange.
pub async fn client_pull_sync_negotiate(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    local_dir: &Path,
    chunked: bool,
) -> Result<SyncPlanResult> {
    // 1. Walk local directory and send listing to host
    let local_entries = if local_dir.is_dir() {
        listing::walk_directory(local_dir)?
    } else {
        Vec::new()
    };
    tracing::debug!("sync: sending FileList ({} entries)", local_entries.len());
    write_file_list(send, local_entries, chunked).await?;

    // 2. Read the host's TransferPlan
    tracing::debug!("sync: waiting for TransferPlan from host...");
    let (files_to_send, files_to_delete, dry_run) = read_transfer_plan(recv).await?;
    tracing::debug!(
        "sync: got TransferPlan: {} to send, {} to delete, dry_run={}",
        files_to_send.len(),
        files_to_delete.len(),
        dry_run
    );
    Ok(SyncPlanResult {
        files_to_send,
        files_to_delete,
        dry_run,
    })
}

/// Client-side sync-pull phase 2: transfer files according to the plan.
///
/// Call this AFTER starting the progress UI.
pub async fn client_pull_sync_transfer(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    local_dir: &Path,
    plan: SyncPlanResult,
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,
) -> Result<TransferSummary> {
    let start = Instant::now();
    let mut summary = TransferSummary::default();

    if plan.dry_run {
        proto::write_message(send, &TransferMsg::PlanAck { proceed: true }).await?;
        for entry in &plan.files_to_send {
            if entry.is_dir {
                summary.dirs_created += 1;
            } else {
                summary.files_transferred += 1;
                summary.bytes_transferred += entry.size;
            }
        }
        summary.files_deleted = plan.files_to_delete.len() as u64;
        // Read host's Done
        let msg: TransferMsg = proto::read_message(recv).await?;
        match msg {
            TransferMsg::Done => {}
            other => tracing::warn!("expected Done from host, got: {other:?}"),
        }
        proto::write_message(send, &TransferMsg::Done).await?;
        summary.elapsed = start.elapsed();
        return Ok(summary);
    }

    // Acknowledge the plan
    tracing::debug!("sync: sending PlanAck");
    proto::write_message(send, &TransferMsg::PlanAck { proceed: true }).await?;

    // Compute delta candidates on client side and receive files
    let delta_candidates: std::collections::HashSet<String> = plan
        .files_to_send
        .iter()
        .filter(|f| {
            !f.is_dir
                && !f.is_symlink
                && f.size >= proto::DELTA_MIN_FILE_SIZE
                && local_dir.join(&f.path).exists()
                && local_dir
                    .join(&f.path)
                    .metadata()
                    .map(|m| m.len() >= proto::DELTA_MIN_FILE_SIZE)
                    .unwrap_or(false)
        })
        .map(|f| f.path.clone())
        .collect();

    // Count files/dirs from the plan before receiving
    for entry in &plan.files_to_send {
        if entry.is_dir {
            summary.dirs_created += 1;
        } else {
            summary.files_transferred += 1;
        }
    }
    summary.files_deleted = plan.files_to_delete.len() as u64;

    tracing::debug!("sync: {} delta candidates, receiving files...", delta_candidates.len());
    if !delta_candidates.is_empty() {
        let (bytes, saved) = receiver::receive_files_with_delta(
            send,
            recv,
            local_dir,
            &delta_candidates,
            &plan.files_to_send,
            progress,
            params,
        )
        .await?;
        summary.bytes_transferred = bytes;
        summary.bytes_saved = saved;
    } else {
        let bytes = receiver::receive_files(send, recv, local_dir, progress, params).await?;
        summary.bytes_transferred = bytes;
    }
    tracing::debug!("sync: receive complete, sending client Done");

    // receive_files/receive_files_with_delta already consumed the host's Done.
    // Best-effort Done — host may have already closed the connection.
    let _ = proto::write_message(send, &TransferMsg::Done).await;

    summary.elapsed = start.elapsed();
    Ok(summary)
}

// ---------------------------------------------------------------------------
// Negotiation helpers
// ---------------------------------------------------------------------------

/// Host-side: exchange Capabilities → receive client's Capabilities → send Negotiated.
async fn negotiate_host(
    send: &mut SendStream,
    recv: &mut RecvStream,
) -> Result<NegotiatedParams> {
    // Send our capabilities
    proto::write_message(
        send,
        &TransferMsg::Capabilities {
            compression: vec!["zstd".to_string()],
            max_chunk_size: MAX_CHUNK_SIZE as u32,
            features_version: TRANSFER_FEATURES_VERSION,
        },
    )
    .await?;

    // Read client capabilities
    let client_caps: TransferMsg = proto::read_message(recv).await?;
    let (_client_compression, client_max_chunk, client_version) = match client_caps {
        TransferMsg::Capabilities {
            compression,
            max_chunk_size,
            features_version,
        } => (compression, max_chunk_size, features_version),
        other => bail!("expected Capabilities, got: {other:?}"),
    };

    // Resolve: pick zstd if both support it
    let use_compression = Some("zstd".to_string());
    let chunk_size = client_max_chunk.min(MAX_CHUNK_SIZE as u32);
    let zstd_level = Some(DEFAULT_ZSTD_LEVEL);

    proto::write_message(
        send,
        &TransferMsg::Negotiated {
            compression: use_compression.clone(),
            chunk_size,
            zstd_level,
        },
    )
    .await?;

    Ok(NegotiatedParams::from_negotiated(
        use_compression.as_deref(),
        chunk_size,
        zstd_level,
        client_version,
    ))
}

/// Client-side: exchange Capabilities → read host's Capabilities → read Negotiated.
pub async fn negotiate_client(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<NegotiatedParams> {
    // Read host capabilities
    let host_caps: TransferMsg = proto::read_message(recv).await?;
    let (_host_compression, _host_max_chunk, host_version) = match host_caps {
        TransferMsg::Capabilities {
            compression,
            max_chunk_size,
            features_version,
        } => (compression, max_chunk_size, features_version),
        other => bail!("expected Capabilities from host, got: {other:?}"),
    };

    // Send our capabilities
    proto::write_message(
        send,
        &TransferMsg::Capabilities {
            compression: vec!["zstd".to_string()],
            max_chunk_size: MAX_CHUNK_SIZE as u32,
            features_version: TRANSFER_FEATURES_VERSION,
        },
    )
    .await?;

    // Read host's negotiated decision
    let negotiated: TransferMsg = proto::read_message(recv).await?;
    match negotiated {
        TransferMsg::Negotiated {
            compression,
            chunk_size,
            zstd_level,
        } => Ok(NegotiatedParams::from_negotiated(
            compression.as_deref(),
            chunk_size,
            zstd_level,
            host_version,
        )),
        other => bail!("expected Negotiated from host, got: {other:?}"),
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Enforce the peer's sandbox policy on a transfer (security-audit C3).
/// A push (peer → host) is a write, rejected when the policy is read-only.
/// Both directions are confined to the policy's `allowed_paths` scope.
fn enforce_transfer_policy(
    sandbox: &crate::sandbox::SandboxPolicy,
    base_path: &Path,
    is_write: bool,
) -> Result<()> {
    if is_write && sandbox.read_only {
        anyhow::bail!(
            "transfer denied: read-only sandbox does not permit writing to {}",
            base_path.display()
        );
    }
    if !sandbox.path_in_scope(base_path) {
        anyhow::bail!(
            "transfer denied: {} is outside the sandbox's allowed paths",
            base_path.display()
        );
    }
    Ok(())
}

/// Resolve `~/...` and relative paths to absolute paths on the host.
fn resolve_host_path(remote_path: &str, username: Option<&str>) -> Result<PathBuf> {
    let path = if remote_path.starts_with("~/") || remote_path == "~" {
        let home = if let Some(user) = username {
            home_dir_for_user(user)?
        } else {
            dirs_home()?
        };
        if remote_path == "~" {
            home
        } else {
            home.join(&remote_path[2..])
        }
    } else if remote_path.starts_with('/') {
        PathBuf::from(remote_path)
    } else {
        // Relative path — resolve relative to user's home
        let home = if let Some(user) = username {
            home_dir_for_user(user)?
        } else {
            dirs_home()?
        };
        home.join(remote_path)
    };

    Ok(path)
}

fn dirs_home() -> Result<PathBuf> {
    directories::BaseDirs::new()
        .map(|d| d.home_dir().to_path_buf())
        .ok_or_else(|| anyhow::anyhow!("cannot determine home directory"))
}

#[cfg(unix)]
fn home_dir_for_user(username: &str) -> Result<PathBuf> {
    use uzers::os::unix::UserExt;
    let user = uzers::get_user_by_name(username)
        .ok_or_else(|| anyhow::anyhow!("user not found: {username}"))?;
    Ok(user.home_dir().to_path_buf())
}

#[cfg(not(unix))]
fn home_dir_for_user(_username: &str) -> Result<PathBuf> {
    dirs_home()
}

#[cfg(test)]
mod listing_wire_tests {
    use super::*;

    fn entry(path: &str) -> FileEntry {
        FileEntry {
            path: path.to_string(),
            size: 1234,
            mtime: 99,
            mode: 0o644,
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            content_hash: None,
        }
    }

    fn entries(n: usize) -> Vec<FileEntry> {
        // Deep, highly-repetitive paths — the shape that made a real listing
        // 16.8 MB (a Rust `target/` tree).
        (0..n)
            .map(|i| entry(&format!("target/debug/build/some-crate-abcdef0123456789/out/file{i}.rs")))
            .collect()
    }

    async fn roundtrip(list: Vec<FileEntry>, chunked: bool) -> Vec<FileEntry> {
        let mut buf: Vec<u8> = Vec::new();
        write_file_list(&mut buf, list, chunked).await.unwrap();
        read_file_list(&mut buf.as_slice()).await.unwrap()
    }

    #[tokio::test]
    async fn file_list_roundtrips_single_frame() {
        let out = roundtrip(entries(10), false).await;
        assert_eq!(out.len(), 10);
        assert_eq!(out[9].path, entries(10)[9].path);
    }

    #[tokio::test]
    async fn file_list_roundtrips_chunked() {
        let out = roundtrip(entries(10), true).await;
        assert_eq!(out.len(), 10);
        assert_eq!(out[9].path, entries(10)[9].path);
    }

    #[tokio::test]
    async fn empty_list_terminates_in_both_encodings() {
        // An empty listing must still produce exactly one terminating message,
        // or the reader blocks forever waiting for `last`.
        assert!(roundtrip(Vec::new(), true).await.is_empty());
        assert!(roundtrip(Vec::new(), false).await.is_empty());
    }

    #[tokio::test]
    async fn exact_multiple_of_chunk_size_sets_last() {
        // Boundary: len % LIST_CHUNK_ENTRIES == 0 must still mark a final batch.
        let out = roundtrip(entries(LIST_CHUNK_ENTRIES * 2), true).await;
        assert_eq!(out.len(), LIST_CHUNK_ENTRIES * 2);
    }

    #[tokio::test]
    async fn chunked_list_preserves_order_across_batches() {
        let src = entries(LIST_CHUNK_ENTRIES + 7);
        let out = roundtrip(src.clone(), true).await;
        assert_eq!(out.len(), src.len());
        for (a, b) in src.iter().zip(out.iter()) {
            assert_eq!(a.path, b.path);
        }
    }

    /// The regression this work exists for: a listing that overflows
    /// MAX_FRAME_LEN (16 MiB) as one frame must succeed when chunked.
    #[tokio::test]
    async fn oversized_listing_fails_unchunked_but_succeeds_chunked() {
        let big = entries(250_000);

        let mut buf: Vec<u8> = Vec::new();
        write_file_list(&mut buf, big.clone(), false).await.unwrap();
        // Assert the fixture really is over the cap, so this test can't quietly
        // stop testing anything if FileEntry's encoding gets smaller.
        assert!(
            buf.len() > 16 * 1024 * 1024,
            "fixture must exceed MAX_FRAME_LEN to be meaningful, got {} bytes",
            buf.len()
        );

        // The write succeeds; the READER enforces the cap — which is exactly why
        // the sending side only ever saw "Broken pipe".
        match read_file_list(&mut buf.as_slice()).await {
            // Don't unwrap_err(): Debug-printing 250k entries floods the output.
            Ok(v) => panic!("expected frame-too-large, but read {} entries", v.len()),
            Err(e) => assert!(
                format!("{e:#}").contains("frame too large"),
                "expected frame-too-large, got: {e:#}"
            ),
        }

        let out = roundtrip(big.clone(), true).await;
        assert_eq!(out.len(), big.len());
    }

    #[tokio::test]
    async fn transfer_plan_roundtrips_both_encodings() {
        let send = entries(LIST_CHUNK_ENTRIES + 3);
        let del: Vec<String> = (0..10).map(|i| format!("stale/{i}.txt")).collect();

        for chunked in [false, true] {
            let mut buf: Vec<u8> = Vec::new();
            write_transfer_plan(&mut buf, send.clone(), del.clone(), true, chunked)
                .await
                .unwrap();
            let (got_send, got_del, dry) = read_transfer_plan(&mut buf.as_slice()).await.unwrap();
            assert_eq!(got_send.len(), send.len(), "chunked={chunked}");
            assert_eq!(got_del, del, "chunked={chunked}");
            assert!(dry, "dry_run must survive, chunked={chunked}");
        }
    }

    #[tokio::test]
    async fn transfer_plan_handles_lopsided_lists() {
        // deletes far outnumber sends: batching is driven by whichever list is
        // longer, and neither may be truncated.
        let send = entries(2);
        let del: Vec<String> = (0..LIST_CHUNK_ENTRIES * 2 + 5)
            .map(|i| format!("gone/{i}"))
            .collect();
        let mut buf: Vec<u8> = Vec::new();
        write_transfer_plan(&mut buf, send.clone(), del.clone(), false, true)
            .await
            .unwrap();
        let (got_send, got_del, _) = read_transfer_plan(&mut buf.as_slice()).await.unwrap();
        assert_eq!(got_send.len(), send.len());
        assert_eq!(got_del.len(), del.len());
    }

    #[tokio::test]
    async fn reader_surfaces_peer_error() {
        let mut buf: Vec<u8> = Vec::new();
        proto::write_message(&mut buf, &TransferMsg::Error("boom".into()))
            .await
            .unwrap();
        let err = read_file_list(&mut buf.as_slice()).await.unwrap_err();
        assert!(format!("{err:#}").contains("boom"));
    }

    #[tokio::test]
    async fn negotiation_gates_chunking_on_older_peer() {
        // Peer at features version 1 → single-frame encoding.
        let old = negotiation::NegotiatedParams::from_negotiated(Some("zstd"), 65536, Some(3), 1);
        assert!(!old.chunked_listing());
        // Peer at our version → chunked.
        let new = negotiation::NegotiatedParams::from_negotiated(
            Some("zstd"),
            65536,
            Some(3),
            TRANSFER_FEATURES_VERSION,
        );
        assert!(new.chunked_listing());
        // A peer claiming a FUTURE version must clamp to what we implement.
        let future =
            negotiation::NegotiatedParams::from_negotiated(Some("zstd"), 65536, Some(3), 99);
        assert_eq!(future.features_version, TRANSFER_FEATURES_VERSION);
    }

    /// Drive the REAL `negotiate_client` against a peer advertising
    /// `peer_version`, and report whether it decides to chunk. e2e can't cover
    /// this: it runs both ends on the same binary, so the older-peer fallback
    /// would never be exercised.
    async fn negotiated_against_peer(peer_version: u32) -> NegotiatedParams {
        let mut host_side: Vec<u8> = Vec::new();
        proto::write_message(
            &mut host_side,
            &TransferMsg::Capabilities {
                compression: vec!["zstd".to_string()],
                max_chunk_size: MAX_CHUNK_SIZE as u32,
                features_version: peer_version,
            },
        )
        .await
        .unwrap();
        proto::write_message(
            &mut host_side,
            &TransferMsg::Negotiated {
                compression: Some("zstd".to_string()),
                chunk_size: MAX_CHUNK_SIZE as u32,
                zstd_level: Some(3),
            },
        )
        .await
        .unwrap();

        let mut sink: Vec<u8> = Vec::new();
        negotiate_client(&mut sink, &mut host_side.as_slice())
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn negotiate_client_falls_back_against_v1_host() {
        let p = negotiated_against_peer(1).await;
        assert!(
            !p.chunked_listing(),
            "must not send FileListChunk to a host that cannot decode it"
        );
    }

    #[tokio::test]
    async fn negotiate_client_enables_chunking_against_current_host() {
        let p = negotiated_against_peer(TRANSFER_FEATURES_VERSION).await;
        assert!(p.chunked_listing());
    }

    /// A listing written for a v1 peer must be byte-identical to what the old
    /// code produced — a single uncompressed `FileList` frame — or upgrading one
    /// end silently breaks the other.
    #[tokio::test]
    async fn v1_encoding_is_unchanged_on_the_wire() {
        let list = entries(50);
        let mut new_writer: Vec<u8> = Vec::new();
        write_file_list(&mut new_writer, list.clone(), false).await.unwrap();

        let mut legacy: Vec<u8> = Vec::new();
        proto::write_message(&mut legacy, &TransferMsg::FileList(list)).await.unwrap();

        assert_eq!(new_writer, legacy, "v1 framing must not drift");
    }

    /// Compression must actually pay off on listing data, otherwise chunking is
    /// carrying the whole fix alone.
    #[tokio::test]
    async fn chunked_listing_is_substantially_smaller_on_the_wire() {
        let list = entries(20_000);
        let mut plain: Vec<u8> = Vec::new();
        write_file_list(&mut plain, list.clone(), false).await.unwrap();
        let mut packed: Vec<u8> = Vec::new();
        write_file_list(&mut packed, list, true).await.unwrap();
        assert!(
            packed.len() * 5 < plain.len(),
            "expected >5x shrink, got {} -> {}",
            plain.len(),
            packed.len()
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Helper: run a push-copy roundtrip and return the relative paths written to dest.
    async fn push_roundtrip(
        local_paths: &[PathBuf],
        contents_only: &[bool],
        dest_dir: &Path,
    ) -> Vec<String> {
        let params = negotiation::NegotiatedParams::legacy();

        let (client, server) = tokio::io::duplex(256 * 1024);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (mut server_read, mut server_write) = tokio::io::split(server);

        let paths = local_paths.to_vec();
        let co = contents_only.to_vec();
        let params_c = params.clone();

        // Push side (client)
        let push = tokio::spawn(async move {
            let progress = progress::SilentProgress;
            client_push_copy(&mut client_write, &mut client_read, &paths, &co, &progress, &params_c)
                .await
                .unwrap();
        });

        // Receive side (host)
        let dest = dest_dir.to_path_buf();
        let recv = tokio::spawn(async move {
            let progress = progress::SilentProgress;
            receiver::receive_files(&mut server_write, &mut server_read, &dest, &progress, &params)
                .await
                .unwrap();
            // Send Done so client_push_copy can finish reading acks
            crate::proto::write_message(&mut server_write, &crate::proto::TransferMsg::Done)
                .await
                .unwrap();
        });

        push.await.unwrap();
        recv.await.unwrap();

        // Collect relative paths in dest_dir
        let mut result = Vec::new();
        collect_paths_recursive(dest_dir, dest_dir, &mut result);
        result.sort();
        result
    }

    fn collect_paths_recursive(base: &Path, current: &Path, out: &mut Vec<String>) {
        if let Ok(entries) = std::fs::read_dir(current) {
            for entry in entries.flatten() {
                let path = entry.path();
                let rel = path.strip_prefix(base).unwrap().to_string_lossy().to_string();
                out.push(rel.clone());
                if path.is_dir() {
                    collect_paths_recursive(base, &path, out);
                }
            }
        }
    }

    #[tokio::test]
    async fn push_single_file() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("src");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&dst).unwrap();

        std::fs::write(src.join("hello.txt"), b"hello").unwrap();

        let paths = push_roundtrip(
            &[src.join("hello.txt")],
            &[false],
            &dst,
        ).await;

        assert_eq!(paths, vec!["hello.txt"]);
        assert_eq!(std::fs::read_to_string(dst.join("hello.txt")).unwrap(), "hello");
    }

    #[tokio::test]
    async fn push_dir_no_trailing_slash() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("mydir");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();

        std::fs::write(src.join("a.txt"), b"aaa").unwrap();
        std::fs::write(src.join("sub").join("b.txt"), b"bbb").unwrap();

        let paths = push_roundtrip(
            std::slice::from_ref(&src),
            &[false], // no trailing slash — include dir name
            &dst,
        ).await;

        assert!(paths.contains(&"mydir".to_string()), "should contain dir entry");
        assert!(paths.contains(&"mydir/a.txt".to_string()), "should contain mydir/a.txt");
        assert!(paths.contains(&"mydir/sub/b.txt".to_string()), "should contain mydir/sub/b.txt");
        assert_eq!(std::fs::read_to_string(dst.join("mydir/a.txt")).unwrap(), "aaa");
    }

    #[tokio::test]
    async fn push_dir_trailing_slash() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("mydir");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(src.join("sub")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();

        std::fs::write(src.join("a.txt"), b"aaa").unwrap();
        std::fs::write(src.join("sub").join("b.txt"), b"bbb").unwrap();

        let paths = push_roundtrip(
            std::slice::from_ref(&src),
            &[true], // trailing slash — contents only, no dir name prefix
            &dst,
        ).await;

        assert!(!paths.iter().any(|p| p.starts_with("mydir")), "should NOT contain mydir/ prefix");
        assert!(paths.contains(&"a.txt".to_string()), "should contain a.txt");
        assert!(paths.contains(&"sub/b.txt".to_string()), "should contain sub/b.txt");
        assert_eq!(std::fs::read_to_string(dst.join("a.txt")).unwrap(), "aaa");
    }

    #[tokio::test]
    async fn push_dir_with_nested_subdirs() {
        let tmp = tempfile::tempdir().unwrap();
        let src = tmp.path().join("project");
        let dst = tmp.path().join("dst");
        std::fs::create_dir_all(src.join("src/components")).unwrap();
        std::fs::create_dir_all(&dst).unwrap();

        std::fs::write(src.join("README.md"), b"# readme").unwrap();
        std::fs::write(src.join("src/main.rs"), b"fn main() {}").unwrap();
        std::fs::write(src.join("src/components/app.rs"), b"struct App;").unwrap();

        // Without trailing slash
        let paths = push_roundtrip(std::slice::from_ref(&src), &[false], &dst).await;
        assert!(paths.contains(&"project/README.md".to_string()));
        assert!(paths.contains(&"project/src/main.rs".to_string()));
        assert!(paths.contains(&"project/src/components/app.rs".to_string()));
    }

    #[test]
    fn parse_path_spec_preserves_trailing_slash() {
        match parse_path_spec("host:~/dir/") {
            PathSpec::Remote { path, .. } => assert!(path.ends_with('/'), "trailing slash should be preserved in remote path"),
            _ => panic!("expected Remote"),
        }
        match parse_path_spec("host:~/dir") {
            PathSpec::Remote { path, .. } => assert!(!path.ends_with('/'), "no trailing slash"),
            _ => panic!("expected Remote"),
        }
    }
}
