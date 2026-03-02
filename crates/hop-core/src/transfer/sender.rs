//! Send files over a QUIC stream using the transfer protocol.

use std::path::Path;

use anyhow::{Context, Result};
use iroh::endpoint::SendStream;

use crate::proto::{
    self, DirEntry, FileEntry, FileHeader, TransferMsg, TRANSFER_CHUNK_SIZE,
};
use super::progress::ProgressReporter;

/// Send a list of files from `base_dir` over the stream.
///
/// For each entry in `files`:
/// - Directories: send `CreateDirectory`
/// - Symlinks: send `CreateSymlink`
/// - Regular files: send `FileHeader`, then `FileData` chunks, then `FileEnd`
///
/// The caller is responsible for reading `FileAck` responses (see receiver).
pub async fn send_files(
    send: &mut SendStream,
    base_dir: &Path,
    files: &[FileEntry],
    progress: &dyn ProgressReporter,
) -> Result<u64> {
    let mut total_bytes = 0u64;

    for entry in files {
        let full_path = base_dir.join(&entry.path);

        if entry.is_symlink {
            if let Some(ref target) = entry.symlink_target {
                proto::write_message(
                    send,
                    &TransferMsg::CreateSymlink {
                        path: entry.path.clone(),
                        target: target.clone(),
                    },
                )
                .await?;
            }
            continue;
        }

        if entry.is_dir {
            proto::write_message(
                send,
                &TransferMsg::CreateDirectory(DirEntry {
                    path: entry.path.clone(),
                    mode: entry.mode,
                    mtime: entry.mtime,
                }),
            )
            .await?;
            progress.dir_created(&entry.path);
            continue;
        }

        // Regular file
        progress.file_started(&entry.path, entry.size);

        proto::write_message(
            send,
            &TransferMsg::FileHeader(FileHeader {
                path: entry.path.clone(),
                size: entry.size,
                mode: entry.mode,
                mtime: entry.mtime,
            }),
        )
        .await?;

        // Stream file data in chunks
        let file = std::fs::File::open(&full_path)
            .with_context(|| format!("cannot open file: {}", full_path.display()))?;
        let mut reader = std::io::BufReader::new(file);
        let mut bytes_sent = 0u64;

        loop {
            let mut buf = vec![0u8; TRANSFER_CHUNK_SIZE];
            let n = std::io::Read::read(&mut reader, &mut buf)
                .with_context(|| format!("read error: {}", full_path.display()))?;
            if n == 0 {
                break;
            }
            buf.truncate(n);
            bytes_sent += n as u64;
            total_bytes += n as u64;
            proto::write_message(send, &TransferMsg::FileData(buf)).await?;
            progress.file_progress(&entry.path, bytes_sent, entry.size);
        }

        proto::write_message(send, &TransferMsg::FileEnd).await?;
        progress.file_done(&entry.path);
    }

    Ok(total_bytes)
}

/// Send delete commands for the given paths.
pub async fn send_deletes(
    send: &mut SendStream,
    paths: &[String],
    progress: &dyn ProgressReporter,
) -> Result<()> {
    for path in paths {
        proto::write_message(send, &TransferMsg::DeletePath(path.clone())).await?;
        progress.file_deleted(path);
    }
    Ok(())
}
