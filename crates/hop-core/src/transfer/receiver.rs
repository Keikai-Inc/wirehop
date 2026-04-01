//! Receive files from a QUIC stream and write them to disk.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};


use anyhow::{Context, Result, bail};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use tokio::sync::mpsc;

use crate::proto::{self, TransferMsg};
use super::negotiation::NegotiatedParams;
use super::progress::ProgressReporter;

/// Receive files from the stream and write them under `dest_dir`.
///
/// Reads messages until `TransferMsg::Done` is received.
/// Sends `FileAck` for each completed file/directory/delete.
///
/// Returns the total bytes written.
pub async fn receive_files(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    dest_dir: &Path,
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,

) -> Result<u64> {
    let dest_dir = if dest_dir.exists() {
        dest_dir.canonicalize()?
    } else {
        fs::create_dir_all(dest_dir)?;
        dest_dir.canonicalize()?
    };

    let mut total_bytes = 0u64;

    loop {
        let msg: TransferMsg = proto::read_message(recv).await?;

        match msg {
            TransferMsg::FileHeader(header) => {
                let target = safe_join(&dest_dir, &header.path)?;
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }

                progress.file_started(&header.path, header.size);

                // Write to a temp file then rename for atomicity
                let tmp_path = tmp_name(&target);
                let result =
                    receive_file_data(recv, &tmp_path, &header.path, header.size, progress, params).await;

                match result {
                    Ok(_wire_bytes) => {
                        fs::rename(&tmp_path, &target).with_context(|| {
                            format!("rename {} -> {}", tmp_path.display(), target.display())
                        })?;
                        set_metadata(&target, header.mode, header.mtime);
                        total_bytes += header.size; // actual file size, not wire bytes
                        progress.file_done(&header.path);
                        send_ack(send, &header.path, true, None).await?;
                    }
                    Err(e) => {
                        let _ = fs::remove_file(&tmp_path);
                        let err_msg = format!("{e:#}");
                        progress.file_error(&header.path, &err_msg);
                        send_ack(send, &header.path, false, Some(err_msg)).await?;
                    }
                }
            }
            TransferMsg::CreateDirectory(dir) => {
                let target = safe_join(&dest_dir, &dir.path)?;
                fs::create_dir_all(&target)
                    .with_context(|| format!("mkdir: {}", target.display()))?;
                set_metadata(&target, dir.mode, dir.mtime);
                progress.dir_created(&dir.path);
                send_ack(send, &dir.path, true, None).await?;
            }
            TransferMsg::CreateSymlink { path, target } => {
                validate_symlink_target(&target)?;
                let link_path = safe_join(&dest_dir, &path)?;
                if let Some(parent) = link_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                // Remove existing symlink/file if present
                let _ = fs::remove_file(&link_path);
                #[cfg(unix)]
                std::os::unix::fs::symlink(&target, &link_path)
                    .with_context(|| format!("symlink: {}", link_path.display()))?;
                #[cfg(not(unix))]
                {
                    // On non-Unix, just skip symlinks
                    tracing::warn!("Symlinks not supported on this platform, skipping: {path}");
                }
                send_ack(send, &path, true, None).await?;
            }
            TransferMsg::DeletePath(path) => {
                let target = safe_join(&dest_dir, &path)?;
                if target.is_dir() {
                    let _ = fs::remove_dir_all(&target);
                } else {
                    let _ = fs::remove_file(&target);
                }
                progress.file_deleted(&path);
                send_ack(send, &path, true, None).await?;
            }
            TransferMsg::Done => break,
            TransferMsg::Error(e) => bail!("remote error: {e}"),
            other => {
                tracing::warn!("Unexpected message during receive: {other:?}");
            }
        }
    }

    Ok(total_bytes)
}

/// Read FileData chunks until FileEnd, writing to `path`.
async fn receive_file_data(
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    path: &Path,
    rel_path: &str,
    total_size: u64,
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,
) -> Result<u64> {
    let file = fs::File::create(path)
        .with_context(|| format!("create file: {}", path.display()))?;
    let mut bytes_written = 0u64;

    if params.is_compressed() {
        // Compressed path: accumulate compressed data, then decompress at FileEnd
        let mut decoder = zstd::stream::write::Decoder::new(file)
            .with_context(|| format!("zstd decoder init: {}", path.display()))?;

        loop {
            let msg: TransferMsg = proto::read_message(recv).await?;
            match msg {
                TransferMsg::FileData(data) => {
                    decoder.write_all(&data)?;
                    bytes_written += data.len() as u64;
                    progress.file_progress(rel_path, bytes_written, total_size);
                }
                TransferMsg::FileEnd => break,
                TransferMsg::Error(e) => bail!("remote error during file transfer: {e}"),
                other => bail!("unexpected message during file data: {other:?}"),
            }
        }

        decoder.flush()?;
        // Drop the decoder to finalize the zstd stream and release the inner file
        drop(decoder);
    } else {
        // Uncompressed path
        let mut file = file;
        loop {
            let msg: TransferMsg = proto::read_message(recv).await?;
            match msg {
                TransferMsg::FileData(data) => {
                    file.write_all(&data)?;
                    bytes_written += data.len() as u64;
                    progress.file_progress(rel_path, bytes_written, total_size);
                }
                TransferMsg::FileEnd => break,
                TransferMsg::Error(e) => bail!("remote error during file transfer: {e}"),
                other => bail!("unexpected message during file data: {other:?}"),
            }
        }
        file.flush()?;
    }

    Ok(bytes_written)
}

/// Read acks until a Done message is received, without knowing the count up front.
/// Returns collected error strings. Used for pipelined ack reading.
/// Timeout for reading individual ack messages. If the host doesn't respond
/// within this time, the transfer is considered failed (connection likely dead).
const ACK_READ_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(60);

pub async fn read_acks_until_done(
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    progress: Option<&dyn ProgressReporter>,
) -> Result<Vec<String>> {
    let mut errors = Vec::new();
    loop {
        let msg: TransferMsg = tokio::time::timeout(
            ACK_READ_TIMEOUT,
            proto::read_message(recv),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Transfer timed out waiting for host (no response in {}s). Connection may have dropped.", ACK_READ_TIMEOUT.as_secs()))??;
        match msg {
            TransferMsg::FileAck {
                path,
                success,
                error,
            } => {
                if success {
                    if let Some(p) = progress {
                        p.file_confirmed(&path);
                    }
                } else {
                    errors.push(format!(
                        "{}: {}",
                        path,
                        error.unwrap_or_else(|| "unknown error".into())
                    ));
                }
            }
            TransferMsg::Done => break,
            TransferMsg::Error(e) => bail!("remote error: {e}"),
            other => bail!("expected FileAck or Done, got: {other:?}"),
        }
    }
    Ok(errors)
}

/// Read FileAck messages, one per expected path. Collect errors.
///
/// When `progress` is provided, calls `file_confirmed` for each successful ack
/// so the UI can distinguish "buffered into QUIC" from "host confirmed receipt".
pub async fn read_acks(
    recv: &mut RecvStream,
    expected_count: usize,
    progress: Option<&dyn ProgressReporter>,
) -> Result<Vec<String>> {
    let mut errors = Vec::new();
    for _ in 0..expected_count {
        let msg: TransferMsg = tokio::time::timeout(
            ACK_READ_TIMEOUT,
            proto::read_message(recv),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Transfer timed out waiting for host acknowledgment"))??;
        match msg {
            TransferMsg::FileAck {
                path,
                success,
                error,
            } => {
                if success {
                    if let Some(p) = progress {
                        p.file_confirmed(&path);
                    }
                } else {
                    errors.push(format!(
                        "{}: {}",
                        path,
                        error.unwrap_or_else(|| "unknown error".into())
                    ));
                }
            }
            TransferMsg::Error(e) => bail!("remote error: {e}"),
            other => bail!("expected FileAck, got: {other:?}"),
        }
    }
    Ok(errors)
}

/// Receive files from a single data stream (used in parallel mode).
/// Reads StreamHeader → repeated FileHeader/FileData/FileEnd → stream finish.
/// Sends acks via an mpsc channel back to the control stream handler.
pub async fn receive_files_from_data_stream(
    mut recv: RecvStream,
    dest_dir: &Path,
    ack_tx: mpsc::Sender<TransferMsg>,
    params: &NegotiatedParams,

) -> Result<u64> {
    let progress = super::progress::SilentProgress;
    let mut total_bytes = 0u64;

    // Read StreamHeader
    let header_msg: TransferMsg = proto::read_message(&mut recv).await?;
    match header_msg {
        TransferMsg::StreamHeader { session_id: _ } => {}
        other => bail!("expected StreamHeader on data stream, got: {other:?}"),
    }

    // Read files until stream ends
    loop {
        let msg: TransferMsg = match proto::read_message(&mut recv).await {
            Ok(msg) => msg,
            Err(_) => break, // Stream finished
        };

        match msg {
            TransferMsg::FileHeader(header) => {
                let target = safe_join(dest_dir, &header.path)?;
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }

                let tmp_path = tmp_name(&target);
                let result =
                    receive_file_data(&mut recv, &tmp_path, &header.path, header.size, &progress, params).await;

                match result {
                    Ok(bytes_written) => {
                        fs::rename(&tmp_path, &target).with_context(|| {
                            format!("rename {} -> {}", tmp_path.display(), target.display())
                        })?;
                        set_metadata(&target, header.mode, header.mtime);
                        total_bytes += bytes_written;
                        let _ = ack_tx
                            .send(TransferMsg::FileAck {
                                path: header.path,
                                success: true,
                                error: None,
                            })
                            .await;
                    }
                    Err(e) => {
                        let _ = fs::remove_file(&tmp_path);
                        let _ = ack_tx
                            .send(TransferMsg::FileAck {
                                path: header.path,
                                success: false,
                                error: Some(format!("{e:#}")),
                            })
                            .await;
                    }
                }
            }
            other => {
                tracing::warn!("Unexpected message on data stream: {other:?}");
            }
        }
    }

    Ok(total_bytes)
}

/// Receive files in parallel mode: read FileManifest from control stream,
/// accept data streams, process files, forward acks.
pub async fn receive_parallel(
    conn: Connection,
    control_send: &mut SendStream,
    control_recv: &mut RecvStream,
    dest_dir: &Path,
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,

) -> Result<u64> {
    let dest_dir_canon = if dest_dir.exists() {
        dest_dir.canonicalize()?
    } else {
        fs::create_dir_all(dest_dir)?;
        dest_dir.canonicalize()?
    };

    // Read FileManifest from control stream
    let manifest_msg: TransferMsg = proto::read_message(control_recv).await?;
    let (_session_id, total_files, _total_dirs, _total_symlinks) = match manifest_msg {
        TransferMsg::FileManifest {
            session_id,
            total_files,
            total_dirs,
            total_symlinks,
            total_deletes: _,
        } => (session_id, total_files, total_dirs, total_symlinks),
        other => bail!("expected FileManifest, got: {other:?}"),
    };

    let mut total_bytes = 0u64;

    // Process control stream messages (dirs, symlinks) until we've read them all
    loop {
        let msg: TransferMsg = proto::read_message(control_recv).await?;
        match msg {
            TransferMsg::CreateDirectory(dir) => {
                let target = safe_join(&dest_dir_canon, &dir.path)?;
                fs::create_dir_all(&target)
                    .with_context(|| format!("mkdir: {}", target.display()))?;
                set_metadata(&target, dir.mode, dir.mtime);
                progress.dir_created(&dir.path);
                send_ack(control_send, &dir.path, true, None).await?;
            }
            TransferMsg::CreateSymlink { path, target } => {
                validate_symlink_target(&target)?;
                let link_path = safe_join(&dest_dir_canon, &path)?;
                if let Some(parent) = link_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let _ = fs::remove_file(&link_path);
                #[cfg(unix)]
                std::os::unix::fs::symlink(&target, &link_path)
                    .with_context(|| format!("symlink: {}", link_path.display()))?;
                #[cfg(not(unix))]
                {
                    tracing::warn!("Symlinks not supported on this platform, skipping: {path}");
                }
                send_ack(control_send, &path, true, None).await?;
            }
            TransferMsg::Done => break,
            TransferMsg::Error(e) => bail!("remote error: {e}"),
            _ => {
                // Once we see Done or any other message, stop reading control
                break;
            }
        }
    }

    if total_files == 0 {
        return Ok(total_bytes);
    }

    // Accept data streams and process files in parallel
    let (ack_tx, mut ack_rx) = mpsc::channel::<TransferMsg>(256);

    let dest_dir_for_tasks = dest_dir_canon.clone();
    let params_clone = params.clone();
    let conn_clone = conn.clone();

    let acceptor = tokio::spawn(async move {
        let mut handles = Vec::new();
        while let Ok((_send, recv)) = conn_clone.accept_bi().await {
            let dest = dest_dir_for_tasks.clone();
            let tx = ack_tx.clone();
            let p = params_clone.clone();
            handles.push(tokio::spawn(async move {
                receive_files_from_data_stream(recv, &dest, tx, &p).await
            }));
        }
        // Wait for all data stream tasks
        let mut bytes = 0u64;
        for h in handles {
            if let Ok(Ok(b)) = h.await {
                bytes += b;
            }
        }
        bytes
    });

    // Forward acks from data stream tasks to control send stream
    while let Some(ack_msg) = ack_rx.recv().await {
        proto::write_message(control_send, &ack_msg).await?;
    }

    // Wait for acceptor
    if let Ok(bytes) = acceptor.await {
        total_bytes += bytes;
    }

    Ok(total_bytes)
}

/// Receive files with delta support for sync mode.
///
/// For files in `delta_candidates`, sends `BlockSignatures` before expecting
/// delta operations instead of full file data.
pub async fn receive_files_with_delta(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    dest_dir: &Path,
    delta_candidates: &std::collections::HashSet<String>,
    files_to_send: &[crate::proto::FileEntry],
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,

) -> Result<(u64, u64)> {
    let dest_dir = if dest_dir.exists() {
        dest_dir.canonicalize()?
    } else {
        fs::create_dir_all(dest_dir)?;
        dest_dir.canonicalize()?
    };

    let mut total_bytes = 0u64;
    let mut bytes_saved = 0u64;

    // We iterate files_to_send in the same order as the sender.
    // For delta candidates, we proactively send BlockSignatures.
    for entry in files_to_send {
        if entry.is_symlink || entry.is_dir {
            // These come as regular messages; handle them in the message loop below
            continue;
        }

        if delta_candidates.contains(&entry.path) {
            // Send block signatures for this file
            let target = safe_join(&dest_dir, &entry.path)?;
            if target.exists() {
                let signatures = super::delta::compute_block_signatures(
                    &target,
                    crate::proto::DELTA_BLOCK_SIZE,
                )?;
                proto::write_message(
                    send,
                    &TransferMsg::BlockSignatures {
                        path: entry.path.clone(),
                        block_size: crate::proto::DELTA_BLOCK_SIZE as u32,
                        signatures,
                    },
                )
                .await?;
            }
        }
    }

    // Now read messages (dirs, symlinks, files, deltas, Done) from sender
    loop {
        let msg: TransferMsg = proto::read_message(recv).await?;

        match msg {
            TransferMsg::FileHeader(header) => {
                let target = safe_join(&dest_dir, &header.path)?;
                if let Some(parent) = target.parent() {
                    fs::create_dir_all(parent)?;
                }

                progress.file_started(&header.path, header.size);

                let tmp_path = tmp_name(&target);
                let result =
                    receive_file_data(recv, &tmp_path, &header.path, header.size, progress, params)
                        .await;

                match result {
                    Ok(_wire_bytes) => {
                        fs::rename(&tmp_path, &target).with_context(|| {
                            format!("rename {} -> {}", tmp_path.display(), target.display())
                        })?;
                        set_metadata(&target, header.mode, header.mtime);
                        total_bytes += header.size; // actual file size, not wire bytes
                        progress.file_done(&header.path);
                        send_ack(send, &header.path, true, None).await?;
                    }
                    Err(e) => {
                        let _ = fs::remove_file(&tmp_path);
                        let err_msg = format!("{e:#}");
                        progress.file_error(&header.path, &err_msg);
                        send_ack(send, &header.path, false, Some(err_msg)).await?;
                    }
                }
            }
            TransferMsg::DeltaHeader {
                path,
                new_size,
                mode,
                mtime,
            } => {
                // Delta transfer for an existing file
                let target = safe_join(&dest_dir, &path)?;
                let old_path = target.clone(); // The existing file
                let tmp_path = tmp_name(&target);

                progress.file_started(&path, new_size);

                // Collect delta ops
                let mut ops = Vec::new();
                loop {
                    let op_msg: TransferMsg = proto::read_message(recv).await?;
                    match op_msg {
                        TransferMsg::DeltaOp(op) => ops.push(op),
                        TransferMsg::DeltaEnd => break,
                        TransferMsg::Error(e) => bail!("remote error during delta: {e}"),
                        other => bail!("unexpected message during delta: {other:?}"),
                    }
                }

                // Reconstruct the file
                match super::delta::reconstruct_file(
                    &old_path,
                    &tmp_path,
                    &ops,
                    crate::proto::DELTA_BLOCK_SIZE,
                ) {
                    Ok(_written) => {
                        fs::rename(&tmp_path, &target).with_context(|| {
                            format!("rename {} -> {}", tmp_path.display(), target.display())
                        })?;
                        set_metadata(&target, mode, mtime);
                        total_bytes += new_size; // actual file size
                        // bytes_saved tracks how much we avoided sending over the wire
                        bytes_saved += new_size; // delta avoided full retransmit
                        progress.file_done(&path);
                        send_ack(send, &path, true, None).await?;
                    }
                    Err(e) => {
                        let _ = fs::remove_file(&tmp_path);
                        let err_msg = format!("{e:#}");
                        progress.file_error(&path, &err_msg);
                        send_ack(send, &path, false, Some(err_msg)).await?;
                    }
                }
            }
            TransferMsg::CreateDirectory(dir) => {
                let target = safe_join(&dest_dir, &dir.path)?;
                fs::create_dir_all(&target)
                    .with_context(|| format!("mkdir: {}", target.display()))?;
                set_metadata(&target, dir.mode, dir.mtime);
                progress.dir_created(&dir.path);
                send_ack(send, &dir.path, true, None).await?;
            }
            TransferMsg::CreateSymlink { path, target } => {
                validate_symlink_target(&target)?;
                let link_path = safe_join(&dest_dir, &path)?;
                if let Some(parent) = link_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                let _ = fs::remove_file(&link_path);
                #[cfg(unix)]
                std::os::unix::fs::symlink(&target, &link_path)
                    .with_context(|| format!("symlink: {}", link_path.display()))?;
                #[cfg(not(unix))]
                {
                    tracing::warn!("Symlinks not supported on this platform, skipping: {path}");
                }
                send_ack(send, &path, true, None).await?;
            }
            TransferMsg::DeletePath(path) => {
                let target = safe_join(&dest_dir, &path)?;
                if target.is_dir() {
                    let _ = fs::remove_dir_all(&target);
                } else {
                    let _ = fs::remove_file(&target);
                }
                progress.file_deleted(&path);
                send_ack(send, &path, true, None).await?;
            }
            TransferMsg::Done => break,
            TransferMsg::Error(e) => bail!("remote error: {e}"),
            other => {
                tracing::warn!("Unexpected message during delta receive: {other:?}");
            }
        }
    }

    Ok((total_bytes, bytes_saved))
}

async fn send_ack(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    path: &str,
    success: bool,
    error: Option<String>,
) -> Result<()> {
    proto::write_message(
        send,
        &TransferMsg::FileAck {
            path: path.to_string(),
            success,
            error,
        },
    )
    .await
}

/// Validate a symlink target is safe: no absolute paths, no `..` traversal.
/// Only relative targets that stay within the destination are allowed.
fn validate_symlink_target(target: &str) -> Result<()> {
    if target.starts_with('/') {
        bail!("symlink with absolute target rejected: {target}");
    }
    if target.contains("..") {
        bail!("symlink with traversal target rejected: {target}");
    }
    Ok(())
}

/// Join `base / relative` and validate the result stays within `base`
/// to prevent path traversal attacks.
fn safe_join(base: &Path, relative: &str) -> Result<PathBuf> {
    // Reject obvious traversal attempts
    if relative.contains("..") {
        bail!("path traversal rejected: {relative}");
    }

    let joined = base.join(relative);

    // Canonicalize if the path exists, otherwise check the parent
    let resolved = if joined.exists() {
        joined.canonicalize()?
    } else {
        // Ensure the parent exists and is within base
        if let Some(parent) = joined.parent()
            && parent.exists()
        {
            let canonical_parent = parent.canonicalize()?;
            if !canonical_parent.starts_with(base) {
                bail!("path traversal rejected: {relative}");
            }
        }
        joined
    };

    if resolved.exists() && !resolved.starts_with(base) {
        bail!("path traversal rejected: {relative}");
    }

    Ok(resolved)
}

fn tmp_name(path: &Path) -> PathBuf {
    let file_name = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    path.with_file_name(format!(".hop-tmp-{file_name}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proto::TransferMsg;

    /// Reproduce the sender/receiver zstd roundtrip to verify data integrity.
    #[tokio::test]
    async fn zstd_compressed_file_roundtrip() {
        use crate::transfer::negotiation::NegotiatedParams;

        let original = b"# .bash_profile\nexport PATH=$HOME/bin:$PATH\necho hello world\nsome more content here to make it bigger\n";
        let tmp_dir = tempfile::tempdir().unwrap();
        let src_dir = tmp_dir.path().join("src");
        let dst_dir = tmp_dir.path().join("dst");
        std::fs::create_dir_all(&src_dir).unwrap();
        std::fs::create_dir_all(&dst_dir).unwrap();

        // Write source file
        let src_file = src_dir.join("test.txt");
        std::fs::write(&src_file, original).unwrap();

        let params = NegotiatedParams::v1_default(); // zstd compression enabled

        // Use duplex streams to simulate sender/receiver
        let (client, server) = tokio::io::duplex(64 * 1024);
        let (mut client_read, mut client_write) = tokio::io::split(client);
        let (_server_read, mut server_write) = tokio::io::split(server);

        let entry = crate::proto::FileEntry {
            path: "test.txt".to_string(),
            size: original.len() as u64,
            mtime: 0,
            mode: 0o644,
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            content_hash: None,
        };

        let params_clone = params.clone();
        let src_dir_clone = src_dir.clone();
        let entry_clone = entry.clone();
        let dst_dir_clone = dst_dir.clone();

        // Sender task
        let sender = tokio::spawn(async move {
            let progress = crate::transfer::progress::SilentProgress;
            crate::transfer::sender::send_files(
                &mut server_write,
                &src_dir_clone,
                &[entry_clone],
                &progress,
                &params_clone,
            )
            .await
            .unwrap();
            crate::proto::write_message(&mut server_write, &TransferMsg::Done)
                .await
                .unwrap();
        });

        // Receiver task
        let receiver = tokio::spawn(async move {
            let progress = crate::transfer::progress::SilentProgress;
            receive_files(
                &mut client_write,
                &mut client_read,
                &dst_dir_clone,
                &progress,
                &params,
            )
            .await
            .unwrap();
        });

        sender.await.unwrap();
        receiver.await.unwrap();

        // Verify
        let output = std::fs::read(dst_dir.join("test.txt")).unwrap();
        assert_eq!(output.len(), original.len(), "Size mismatch");
        assert_eq!(output, original, "Content mismatch - got all zeros: {}", output.iter().all(|&b| b == 0));
    }
}

fn set_metadata(path: &Path, mode: u32, mtime: u64) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        // Strip setuid (04000), setgid (02000), and sticky (01000) bits.
        let safe_mode = mode & 0o0777;
        let _ = fs::set_permissions(path, fs::Permissions::from_mode(safe_mode));

        if mtime > 0 {
            let ft = filetime::FileTime::from_unix_time(mtime as i64, 0);
            let _ = filetime::set_file_mtime(path, ft);
        }
    }
    #[cfg(not(unix))]
    {
        let _ = (path, mode, mtime);
    }
}
