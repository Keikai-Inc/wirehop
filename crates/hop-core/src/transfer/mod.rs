//! File transfer sessions (copy and sync).

pub mod listing;
pub mod progress;
pub mod receiver;
pub mod sender;

use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Result, bail};
use iroh::endpoint::{RecvStream, SendStream};

use crate::proto::{
    self, FileEntry, TransferDirection, TransferMode, TransferMsg, TransferRequest,
};
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
    mut send: SendStream,
    mut recv: RecvStream,
    request: TransferRequest,
    username: Option<&str>,
) -> Result<()> {
    // Resolve the remote path to an absolute path on the host filesystem.
    let base_path = resolve_host_path(&request.remote_path, username)?;

    let progress = SilentProgress;

    let result = match (&request.mode, &request.direction) {
        (TransferMode::Copy { .. }, TransferDirection::Push) => {
            // Client pushes files to us — we receive
            host_receive_files(&mut send, &mut recv, &base_path, &progress).await
        }
        (TransferMode::Copy { .. }, TransferDirection::Pull) => {
            // Client pulls files from us — we send
            host_send_files(&mut send, &mut recv, &base_path, &request, &progress).await
        }
        (TransferMode::Sync, TransferDirection::Push) => {
            // Client sync-pushes to us
            host_sync_receive(&mut send, &mut recv, &base_path, &request, &progress).await
        }
        (TransferMode::Sync, TransferDirection::Pull) => {
            // Client sync-pulls from us
            host_sync_send(&mut send, &mut recv, &base_path, &request, &progress).await
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
    send: &mut SendStream,
    recv: &mut RecvStream,
    dest: &Path,
    progress: &dyn ProgressReporter,
) -> Result<()> {
    receiver::receive_files(send, recv, dest, progress).await?;
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

    sender::send_files(send, base_dir, &entries, progress).await?;
    // Read acks for non-directory entries
    let ack_count = entries.iter().filter(|e| !e.is_dir || e.is_symlink).count()
        + entries.iter().filter(|e| e.is_dir && !e.is_symlink).count();
    let _errors = receiver::read_acks(recv, ack_count, None).await?;
    proto::write_message(send, &TransferMsg::Done).await?;
    Ok(())
}

/// Host receives sync-pushed files from the client.
async fn host_sync_receive(
    send: &mut SendStream,
    recv: &mut RecvStream,
    dest: &Path,
    _request: &TransferRequest,
    progress: &dyn ProgressReporter,
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

    // 3. Receive transferred files and process deletes
    let _ = files_to_send; // plan info — actual data comes via FileHeader/FileData
    let _ = files_to_delete; // deletes come via DeletePath messages
    receiver::receive_files(send, recv, dest, progress).await?;
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
) -> Result<()> {
    // 1. Read the client's local file list
    let client_list_msg: TransferMsg = proto::read_message(recv).await?;
    let client_entries = match client_list_msg {
        TransferMsg::FileList(entries) => entries,
        TransferMsg::Error(e) => bail!("client error: {e}"),
        other => bail!("expected FileList, got: {other:?}"),
    };

    // 2. Walk our (source) directory and compute the plan
    let source_entries = if source.is_dir() {
        listing::walk_directory(source)?
    } else {
        bail!("sync source must be a directory: {}", source.display());
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

    // 5. Send the files
    let files_to_send: Vec<_> = plan.files_to_send;
    sender::send_files(send, source, &files_to_send, progress).await?;

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
pub async fn client_push_copy(
    send: &mut SendStream,
    recv: &mut RecvStream,
    local_paths: &[PathBuf],
    progress: &dyn ProgressReporter,
) -> Result<TransferSummary> {
    let start = Instant::now();
    let mut summary = TransferSummary::default();

    let mut total_ack_count = 0usize;
    for local_path in local_paths {
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
            };
            (
                local_path.parent().unwrap_or(Path::new(".")).to_path_buf(),
                vec![entry],
            )
        } else if local_path.is_dir() {
            (local_path.clone(), listing::walk_directory(local_path)?)
        } else {
            bail!("path does not exist: {}", local_path.display());
        };

        let bytes = sender::send_files(send, &base_dir, &entries, progress).await?;
        summary.bytes_transferred += bytes;
        summary.files_transferred += entries.iter().filter(|e| !e.is_dir).count() as u64;
        summary.dirs_created += entries.iter().filter(|e| e.is_dir).count() as u64;
        total_ack_count += entries.len();
    }

    // Send Done immediately after all files — don't block on acks first.
    // This lets the host process files + Done without waiting for us to
    // read acks in between, collapsing 2 round-trips into 1.
    proto::write_message(send, &TransferMsg::Done).await?;

    // Now read all acks and host's Done in one batch
    let errors = receiver::read_acks(recv, total_ack_count, Some(progress)).await?;
    summary.errors = errors;

    let msg: TransferMsg = proto::read_message(recv).await?;
    match msg {
        TransferMsg::Done => {}
        TransferMsg::Error(e) => bail!("host error: {e}"),
        other => tracing::warn!("expected Done from host, got: {other:?}"),
    }

    summary.elapsed = start.elapsed();
    Ok(summary)
}

/// Client-side: pull files from the remote host (copy pull).
pub async fn client_pull_copy(
    send: &mut SendStream,
    recv: &mut RecvStream,
    local_dest: &Path,
    progress: &dyn ProgressReporter,
) -> Result<TransferSummary> {
    let start = Instant::now();
    let mut summary = TransferSummary::default();

    let bytes = receiver::receive_files(send, recv, local_dest, progress).await?;
    summary.bytes_transferred = bytes;
    // Count is approximate — the receive_files function handles acks internally

    // Read host's Done
    let msg: TransferMsg = proto::read_message(recv).await?;
    match msg {
        TransferMsg::Done => {}
        TransferMsg::Error(e) => bail!("host error: {e}"),
        other => tracing::warn!("expected Done from host, got: {other:?}"),
    }

    proto::write_message(send, &TransferMsg::Done).await?;

    summary.elapsed = start.elapsed();
    Ok(summary)
}

/// Client-side: sync-push local directory to remote host.
pub async fn client_push_sync(
    send: &mut SendStream,
    recv: &mut RecvStream,
    local_dir: &Path,
    request: &TransferRequest,
    progress: &dyn ProgressReporter,
) -> Result<TransferSummary> {
    let start = Instant::now();
    let mut summary = TransferSummary::default();

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
            summary.elapsed = start.elapsed();
            return Ok(summary);
        }
        TransferMsg::Error(e) => bail!("host error: {e}"),
        other => bail!("expected PlanAck, got: {other:?}"),
    }

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

    // 5. Send files that need transferring
    let files_only: Vec<_> = plan.files_to_send;
    let bytes = sender::send_files(send, local_dir, &files_only, progress).await?;
    summary.bytes_transferred = bytes;
    summary.files_transferred = files_only.iter().filter(|e| !e.is_dir).count() as u64;
    summary.dirs_created = files_only.iter().filter(|e| e.is_dir).count() as u64;

    // 6. Send deletes
    sender::send_deletes(send, &plan.files_to_delete, progress).await?;
    summary.files_deleted = plan.files_to_delete.len() as u64;

    proto::write_message(send, &TransferMsg::Done).await?;

    // 7. Read acks
    let total_acks = files_only.len() + plan.files_to_delete.len();
    let errors = receiver::read_acks(recv, total_acks, Some(progress)).await?;
    summary.errors = errors;

    // 8. Read host's Done
    let msg: TransferMsg = proto::read_message(recv).await?;
    match msg {
        TransferMsg::Done => {}
        TransferMsg::Error(e) => bail!("host error: {e}"),
        other => tracing::warn!("expected Done from host, got: {other:?}"),
    }

    summary.elapsed = start.elapsed();
    Ok(summary)
}

/// Client-side: sync-pull from remote host to local directory.
pub async fn client_pull_sync(
    send: &mut SendStream,
    recv: &mut RecvStream,
    local_dir: &Path,
    _request: &TransferRequest,
    progress: &dyn ProgressReporter,
) -> Result<TransferSummary> {
    let start = Instant::now();
    let mut summary = TransferSummary::default();

    // 1. Walk local directory and send listing to host
    let local_entries = if local_dir.is_dir() {
        listing::walk_directory(local_dir)?
    } else {
        Vec::new()
    };
    proto::write_message(send, &TransferMsg::FileList(local_entries)).await?;

    // 2. Read the host's TransferPlan
    let plan_msg: TransferMsg = proto::read_message(recv).await?;
    let (files_to_send, files_to_delete, dry_run) = match plan_msg {
        TransferMsg::TransferPlan {
            files_to_send,
            files_to_delete,
            dry_run,
        } => (files_to_send, files_to_delete, dry_run),
        TransferMsg::Error(e) => bail!("host error: {e}"),
        other => bail!("expected TransferPlan from host, got: {other:?}"),
    };

    if dry_run {
        proto::write_message(send, &TransferMsg::PlanAck { proceed: true }).await?;
        for entry in &files_to_send {
            if entry.is_dir {
                summary.dirs_created += 1;
            } else {
                summary.files_transferred += 1;
                summary.bytes_transferred += entry.size;
            }
        }
        summary.files_deleted = files_to_delete.len() as u64;
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

    // 3. Acknowledge the plan
    proto::write_message(send, &TransferMsg::PlanAck { proceed: true }).await?;

    // 4. Receive files and deletes from host
    let _ = (files_to_send, files_to_delete); // data arrives as messages
    let bytes = receiver::receive_files(send, recv, local_dir, progress).await?;
    summary.bytes_transferred = bytes;

    // 5. Read host's Done
    let msg: TransferMsg = proto::read_message(recv).await?;
    match msg {
        TransferMsg::Done => {}
        TransferMsg::Error(e) => bail!("host error: {e}"),
        other => tracing::warn!("expected Done from host, got: {other:?}"),
    }

    proto::write_message(send, &TransferMsg::Done).await?;

    summary.elapsed = start.elapsed();
    Ok(summary)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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
    use std::ffi::CString;
    let c_name = CString::new(username)?;
    let pwd = unsafe { libc::getpwnam(c_name.as_ptr()) };
    if pwd.is_null() {
        bail!("user not found: {username}");
    }
    let home = unsafe { std::ffi::CStr::from_ptr((*pwd).pw_dir) };
    Ok(PathBuf::from(home.to_string_lossy().to_string()))
}

#[cfg(not(unix))]
fn home_dir_for_user(_username: &str) -> Result<PathBuf> {
    dirs_home()
}
