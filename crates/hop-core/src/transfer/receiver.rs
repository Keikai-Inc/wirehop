//! Receive files from a QUIC stream and write them to disk.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use iroh::endpoint::{RecvStream, SendStream};

use crate::proto::{self, TransferMsg};
use super::progress::ProgressReporter;

/// Receive files from the stream and write them under `dest_dir`.
///
/// Reads messages until `TransferMsg::Done` is received.
/// Sends `FileAck` for each completed file/directory/delete.
///
/// Returns the total bytes written.
pub async fn receive_files(
    send: &mut SendStream,
    recv: &mut RecvStream,
    dest_dir: &Path,
    progress: &dyn ProgressReporter,
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
                    receive_file_data(recv, &tmp_path, &header.path, header.size, progress).await;

                match result {
                    Ok(bytes_written) => {
                        fs::rename(&tmp_path, &target).with_context(|| {
                            format!("rename {} -> {}", tmp_path.display(), target.display())
                        })?;
                        set_metadata(&target, header.mode, header.mtime);
                        total_bytes += bytes_written;
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
    recv: &mut RecvStream,
    path: &Path,
    rel_path: &str,
    total_size: u64,
    progress: &dyn ProgressReporter,
) -> Result<u64> {
    let mut file = fs::File::create(path)
        .with_context(|| format!("create file: {}", path.display()))?;
    let mut bytes_written = 0u64;

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
    Ok(bytes_written)
}

/// Read FileAck messages, one per expected path. Collect errors.
pub async fn read_acks(recv: &mut RecvStream, expected_count: usize) -> Result<Vec<String>> {
    let mut errors = Vec::new();
    for _ in 0..expected_count {
        let msg: TransferMsg = proto::read_message(recv).await?;
        match msg {
            TransferMsg::FileAck {
                path,
                success,
                error,
            } => {
                if !success {
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

async fn send_ack(
    send: &mut SendStream,
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
        if let Some(parent) = joined.parent() {
            if parent.exists() {
                let canonical_parent = parent.canonicalize()?;
                if !canonical_parent.starts_with(base) {
                    bail!("path traversal rejected: {relative}");
                }
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

fn set_metadata(path: &Path, mode: u32, mtime: u64) {
    // Set mtime
    if mtime > 0 {
        let _mtime_system = UNIX_EPOCH + Duration::from_secs(mtime);
        // Use filetime if available, otherwise best-effort
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = fs::set_permissions(path, fs::Permissions::from_mode(mode));

            let ts = libc::timespec {
                tv_sec: mtime as i64,
                tv_nsec: 0,
            };
            let times = [ts, ts]; // [atime, mtime]
            let c_path = std::ffi::CString::new(path.to_string_lossy().as_bytes()).ok();
            if let Some(c_path) = c_path {
                unsafe {
                    libc::utimensat(libc::AT_FDCWD, c_path.as_ptr(), times.as_ptr(), 0);
                }
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (path, mode, mtime_system);
        }
    }
}
