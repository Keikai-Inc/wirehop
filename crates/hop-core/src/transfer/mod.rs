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
    MAX_CHUNK_SIZE, DEFAULT_ZSTD_LEVEL,
};
use negotiation::NegotiatedParams;
use progress::{ProgressReporter, SilentProgress, TransferSummary};

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
    proto::write_message(send, &TransferMsg::FileList(dest_entries)).await?;

    // 2. Client computes the plan and sends TransferPlan
    let plan_msg: TransferMsg = proto::read_message(recv).await?;
    let (files_to_send, files_to_delete, dry_run) = match plan_msg {
        TransferMsg::TransferPlan {
            files_to_send,
            files_to_delete,
            dry_run,
        } => (files_to_send, files_to_delete, dry_run),
        TransferMsg::Error(e) => bail!("client error: {e}"),
        other => bail!("expected TransferPlan, got: {other:?}"),
    };

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
    let client_list_msg: TransferMsg = proto::read_message(recv).await?;
    let client_entries = match client_list_msg {
        TransferMsg::FileList(entries) => {
            tracing::debug!("host_sync_send: got FileList with {} entries", entries.len());
            entries
        }
        TransferMsg::Error(e) => bail!("client error: {e}"),
        other => bail!("expected FileList, got: {other:?}"),
    };

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
    proto::write_message(
        send,
        &TransferMsg::TransferPlan {
            files_to_send: plan.files_to_send.clone(),
            files_to_delete: plan.files_to_delete.clone(),
            dry_run: request.dry_run,
        },
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
) -> Result<PushSyncNegotiation> {
    // 1. Read the host's destination file listing
    let remote_list_msg: TransferMsg = proto::read_message(recv).await?;
    let remote_entries = match remote_list_msg {
        TransferMsg::FileList(entries) => entries,
        TransferMsg::Error(e) => bail!("host error: {e}"),
        other => bail!("expected FileList from host, got: {other:?}"),
    };

    // 2. Walk local directory and compute plan
    let local_entries = listing::walk_directory(local_dir)?;
    let plan =
        listing::compute_sync_plan(&local_entries, &remote_entries, request.delete_extraneous);

    // 3. Send plan
    proto::write_message(
        send,
        &TransferMsg::TransferPlan {
            files_to_send: plan.files_to_send.clone(),
            files_to_delete: plan.files_to_delete.clone(),
            dry_run: request.dry_run,
        },
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
    let negotiation = client_push_sync_negotiate(send, recv, local_dir, request).await?;
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
) -> Result<SyncPlanResult> {
    // 1. Walk local directory and send listing to host
    let local_entries = if local_dir.is_dir() {
        listing::walk_directory(local_dir)?
    } else {
        Vec::new()
    };
    tracing::debug!("sync: sending FileList ({} entries)", local_entries.len());
    proto::write_message(send, &TransferMsg::FileList(local_entries)).await?;

    // 2. Read the host's TransferPlan
    tracing::debug!("sync: waiting for TransferPlan from host...");
    let plan_msg: TransferMsg = proto::read_message(recv).await?;
    match plan_msg {
        TransferMsg::TransferPlan {
            files_to_send,
            files_to_delete,
            dry_run,
        } => {
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
        TransferMsg::Error(e) => bail!("host error: {e}"),
        other => bail!("expected TransferPlan from host, got: {other:?}"),
    }
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
            features_version: 1,
        },
    )
    .await?;

    // Read client capabilities
    let client_caps: TransferMsg = proto::read_message(recv).await?;
    let (_client_compression, client_max_chunk, _client_version) = match client_caps {
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
    ))
}

/// Client-side: exchange Capabilities → read host's Capabilities → read Negotiated.
pub async fn negotiate_client(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
) -> Result<NegotiatedParams> {
    // Read host capabilities
    let host_caps: TransferMsg = proto::read_message(recv).await?;
    let (_host_compression, _host_max_chunk, _host_version) = match host_caps {
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
            features_version: 1,
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
    use users::os::unix::UserExt;
    let user = users::get_user_by_name(username)
        .ok_or_else(|| anyhow::anyhow!("user not found: {username}"))?;
    Ok(user.home_dir().to_path_buf())
}

#[cfg(not(unix))]
fn home_dir_for_user(_username: &str) -> Result<PathBuf> {
    dirs_home()
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
