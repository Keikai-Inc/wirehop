//! Send files over a QUIC stream using the transfer protocol.

use std::collections::VecDeque;
use std::io::Read as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use iroh::endpoint::{Connection, SendStream};
use tokio::sync::{Mutex, Semaphore};

use crate::proto::{self, DirEntry, FileEntry, FileHeader, TransferMsg, DEFAULT_PARALLEL_STREAMS};
use super::negotiation::{ChunkSizer, NegotiatedParams};
use super::progress::ProgressReporter;

/// Send a list of files from `base_dir` over the stream.
///
/// For each entry in `files`:
/// - Directories: send `CreateDirectory`
/// - Symlinks: send `CreateSymlink`
/// - Regular files: send `FileHeader`, then `FileData` chunks, then `FileEnd`
///
/// The caller is responsible for reading `FileAck` responses (see receiver).
/// Timeout for write operations. If the connection is dead, writes
/// will eventually fail when buffers fill, but this caps the wait.
const WRITE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub async fn send_files(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    base_dir: &Path,
    files: &[FileEntry],
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,
) -> Result<u64> {
    let mut total_bytes = 0u64;
    let mut sizer = ChunkSizer::new(params.max_chunk_size);
    // Reusable read buffer — allocated once at max chunk size
    let mut read_buf = vec![0u8; params.max_chunk_size];

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

        if params.is_compressed() {
            // Compressed path: wrap reader in zstd encoder, read compressed chunks
            let level = params.zstd_level();
            let mut encoder = zstd::stream::read::Encoder::new(&mut reader, level)
                .with_context(|| format!("zstd encoder init: {}", full_path.display()))?;

            loop {
                let chunk_size = sizer.chunk_size();
                let buf = &mut read_buf[..chunk_size];
                let n = encoder
                    .read(buf)
                    .with_context(|| format!("zstd read error: {}", full_path.display()))?;
                if n == 0 {
                    break;
                }
                let chunk = buf[..n].to_vec();
                bytes_sent += n as u64;
                total_bytes += n as u64;
                sizer.record(n as u64);
                proto::write_message_buffered(send, &TransferMsg::FileData(chunk)).await?;
                progress.file_progress(&entry.path, bytes_sent, entry.size);
            }
        } else {
            // Uncompressed path
            loop {
                let chunk_size = sizer.chunk_size();
                let buf = &mut read_buf[..chunk_size];
                let n = reader
                    .read(buf)
                    .with_context(|| format!("read error: {}", full_path.display()))?;
                if n == 0 {
                    break;
                }
                let chunk = buf[..n].to_vec();
                bytes_sent += n as u64;
                total_bytes += n as u64;
                sizer.record(n as u64);
                proto::write_message_buffered(send, &TransferMsg::FileData(chunk)).await?;
                progress.file_progress(&entry.path, bytes_sent, entry.size);
            }
        }

        tokio::time::timeout(
            WRITE_TIMEOUT,
            proto::write_message(send, &TransferMsg::FileEnd),
        )
        .await
        .map_err(|_| anyhow::anyhow!("Write timed out sending {} — connection may have dropped", entry.path))??;
        progress.file_done(&entry.path);
    }

    Ok(total_bytes)
}

/// Send a single regular file's data on a stream (FileHeader + FileData chunks + FileEnd).
async fn send_single_file(
    send: &mut SendStream,
    base_dir: &Path,
    entry: &FileEntry,
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,
) -> Result<u64> {
    let full_path = base_dir.join(&entry.path);
    let mut total_bytes = 0u64;
    let mut sizer = ChunkSizer::new(params.max_chunk_size);
    let mut read_buf = vec![0u8; params.max_chunk_size];

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

    let file = std::fs::File::open(&full_path)
        .with_context(|| format!("cannot open file: {}", full_path.display()))?;
    let mut reader = std::io::BufReader::new(file);

    if params.is_compressed() {
        let level = params.zstd_level();
        let mut encoder = zstd::stream::read::Encoder::new(&mut reader, level)
            .with_context(|| format!("zstd encoder init: {}", full_path.display()))?;
        loop {
            let chunk_size = sizer.chunk_size();
            let buf = &mut read_buf[..chunk_size];
            let n = encoder
                .read(buf)
                .with_context(|| format!("zstd read error: {}", full_path.display()))?;
            if n == 0 {
                break;
            }
            let chunk = buf[..n].to_vec();
            total_bytes += n as u64;
            sizer.record(n as u64);
            proto::write_message_buffered(send, &TransferMsg::FileData(chunk)).await?;
            progress.file_progress(&entry.path, total_bytes, entry.size);
        }
    } else {
        loop {
            let chunk_size = sizer.chunk_size();
            let buf = &mut read_buf[..chunk_size];
            let n = reader
                .read(buf)
                .with_context(|| format!("read error: {}", full_path.display()))?;
            if n == 0 {
                break;
            }
            let chunk = buf[..n].to_vec();
            total_bytes += n as u64;
            sizer.record(n as u64);
            proto::write_message_buffered(send, &TransferMsg::FileData(chunk)).await?;
            progress.file_progress(&entry.path, total_bytes, entry.size);
        }
    }

    proto::write_message(send, &TransferMsg::FileEnd).await?;
    progress.file_done(&entry.path);

    Ok(total_bytes)
}

/// Send files in parallel using multiple QUIC streams.
///
/// - Directories, symlinks, and deletes go on the control stream (preserves ordering).
/// - Regular files are distributed across N data streams opened on the connection.
/// - Each data stream sends a `StreamHeader` followed by one or more files.
#[allow(clippy::too_many_arguments)]
pub async fn send_files_parallel(
    conn: &Connection,
    control_send: &mut SendStream,
    session_id: u64,
    base_dir: &Path,
    files: &[FileEntry],
    progress: &dyn ProgressReporter,
    max_streams: usize,
    params: &NegotiatedParams,
) -> Result<u64> {
    // Separate dirs/symlinks (control stream) from regular files (data streams)
    let mut regular_files = Vec::new();
    let mut total_dirs = 0u32;
    let mut total_symlinks = 0u32;

    for entry in files {
        if entry.is_symlink {
            total_symlinks += 1;
        } else if entry.is_dir {
            total_dirs += 1;
        } else {
            regular_files.push(entry.clone());
        }
    }

    // Send manifest on control stream
    proto::write_message(
        control_send,
        &TransferMsg::FileManifest {
            session_id,
            total_files: regular_files.len() as u32,
            total_dirs,
            total_symlinks,
            total_deletes: 0,
        },
    )
    .await?;

    // Send dirs and symlinks on control stream first (ordering guarantee)
    for entry in files {
        if entry.is_symlink {
            if let Some(ref target) = entry.symlink_target {
                proto::write_message(
                    control_send,
                    &TransferMsg::CreateSymlink {
                        path: entry.path.clone(),
                        target: target.clone(),
                    },
                )
                .await?;
            }
        } else if entry.is_dir {
            proto::write_message(
                control_send,
                &TransferMsg::CreateDirectory(DirEntry {
                    path: entry.path.clone(),
                    mode: entry.mode,
                    mtime: entry.mtime,
                }),
            )
            .await?;
            progress.dir_created(&entry.path);
        }
    }

    if regular_files.is_empty() {
        return Ok(0);
    }

    // Create work queue for data stream workers
    let work_queue = Arc::new(Mutex::new(VecDeque::from(regular_files)));
    let total_bytes = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let semaphore = Arc::new(Semaphore::new(max_streams.min(DEFAULT_PARALLEL_STREAMS)));
    let base_dir: PathBuf = base_dir.to_path_buf();
    let params = params.clone();

    let mut handles = Vec::new();

    // Spawn workers — each opens a new bi-directional stream
    // Workers pull files from the shared queue until empty
    loop {
        let file = {
            let mut queue = work_queue.lock().await;
            queue.pop_front()
        };

        let Some(file) = file else { break };

        let permit = semaphore.clone().acquire_owned().await?;
        let conn = conn.clone();
        let base_dir = base_dir.clone();
        let params = params.clone();
        let total_bytes = total_bytes.clone();
        let work_queue = work_queue.clone();

        let handle = tokio::spawn(async move {
            let result: Result<()> = async {
                let (mut data_send, _data_recv) = conn.open_bi().await?;

                // Send stream header
                proto::write_message(
                    &mut data_send,
                    &TransferMsg::StreamHeader { session_id },
                )
                .await?;

                // Send the first file we already popped
                let silent = super::progress::SilentProgress;
                let bytes =
                    send_single_file(&mut data_send, &base_dir, &file, &silent, &params).await?;
                total_bytes.fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);

                // Pull more files from the queue
                loop {
                    let next = {
                        let mut queue = work_queue.lock().await;
                        queue.pop_front()
                    };
                    let Some(next_file) = next else { break };
                    let bytes =
                        send_single_file(&mut data_send, &base_dir, &next_file, &silent, &params)
                            .await?;
                    total_bytes.fetch_add(bytes, std::sync::atomic::Ordering::Relaxed);
                }

                let _ = data_send.finish();
                Ok(())
            }
            .await;

            drop(permit);
            result
        });

        handles.push(handle);
    }

    // Wait for all workers
    for handle in handles {
        handle.await??;
    }

    Ok(total_bytes.load(std::sync::atomic::Ordering::Relaxed))
}

/// Send files with delta support for sync mode.
///
/// For files in `delta_candidates`, reads `BlockSignatures` from the receiver,
/// computes delta, and sends `DeltaHeader`/`DeltaOp`/`DeltaEnd` instead of
/// full file data.
pub async fn send_files_with_delta(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    recv: &mut (impl tokio::io::AsyncRead + Unpin),
    base_dir: &Path,
    files: &[FileEntry],
    delta_candidates: &std::collections::HashSet<String>,
    progress: &dyn ProgressReporter,
    params: &NegotiatedParams,
) -> Result<(u64, u64)> {
    let mut total_bytes = 0u64;
    let mut bytes_saved = 0u64;
    let mut sizer = ChunkSizer::new(params.max_chunk_size);
    let mut read_buf = vec![0u8; params.max_chunk_size];

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

        // Check if this file is a delta candidate
        if delta_candidates.contains(&entry.path) {
            // Read block signatures from receiver
            let sig_msg: TransferMsg = proto::read_message(recv).await?;
            match sig_msg {
                TransferMsg::BlockSignatures {
                    path: _,
                    block_size,
                    signatures,
                } => {
                    progress.file_started(&entry.path, entry.size);

                    // Compute delta
                    let ops = super::delta::compute_delta(
                        &full_path,
                        &signatures,
                        block_size as usize,
                    )?;

                    // Send DeltaHeader
                    proto::write_message(
                        send,
                        &TransferMsg::DeltaHeader {
                            path: entry.path.clone(),
                            new_size: entry.size,
                            mode: entry.mode,
                            mtime: entry.mtime,
                        },
                    )
                    .await?;

                    // Send delta ops (buffered, flush at DeltaEnd)
                    let mut delta_bytes = 0u64;
                    for op in &ops {
                        match op {
                            crate::proto::DeltaOperation::CopyBlock { .. } => {
                                // CopyBlock is just an index — minimal wire cost
                                delta_bytes += 4; // approximate
                            }
                            crate::proto::DeltaOperation::Literal(data) => {
                                delta_bytes += data.len() as u64;
                            }
                        }
                        proto::write_message_buffered(send, &TransferMsg::DeltaOp(op.clone())).await?;
                    }

                    proto::write_message(send, &TransferMsg::DeltaEnd).await?;

                    // Track savings
                    total_bytes += delta_bytes;
                    if entry.size > delta_bytes {
                        bytes_saved += entry.size - delta_bytes;
                    }

                    progress.file_done(&entry.path);
                }
                other => {
                    // Unexpected — fall back to full transfer
                    tracing::warn!("expected BlockSignatures for {}, got: {other:?}", entry.path);
                    progress.file_started(&entry.path, entry.size);
                    let bytes = send_file_data(send, &full_path, entry, progress, &mut sizer, &mut read_buf, params).await?;
                    total_bytes += bytes;
                }
            }
        } else {
            // Regular full file transfer
            progress.file_started(&entry.path, entry.size);
            let bytes = send_file_data(send, &full_path, entry, progress, &mut sizer, &mut read_buf, params).await?;
            total_bytes += bytes;
        }
    }

    Ok((total_bytes, bytes_saved))
}

/// Send a file's data (FileHeader + FileData chunks + FileEnd).
async fn send_file_data(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    full_path: &Path,
    entry: &FileEntry,
    progress: &dyn ProgressReporter,
    sizer: &mut ChunkSizer,
    read_buf: &mut [u8],
    params: &NegotiatedParams,
) -> Result<u64> {
    let mut total_bytes = 0u64;

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

    let file = std::fs::File::open(full_path)
        .with_context(|| format!("cannot open file: {}", full_path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut bytes_sent = 0u64;

    if params.is_compressed() {
        let level = params.zstd_level();
        let mut encoder = zstd::stream::read::Encoder::new(&mut reader, level)
            .with_context(|| format!("zstd encoder init: {}", full_path.display()))?;
        loop {
            let chunk_size = sizer.chunk_size();
            let buf = &mut read_buf[..chunk_size];
            let n = encoder
                .read(buf)
                .with_context(|| format!("zstd read error: {}", full_path.display()))?;
            if n == 0 {
                break;
            }
            let chunk = buf[..n].to_vec();
            bytes_sent += n as u64;
            total_bytes += n as u64;
            sizer.record(n as u64);
            proto::write_message_buffered(send, &TransferMsg::FileData(chunk)).await?;
            progress.file_progress(&entry.path, bytes_sent, entry.size);
        }
    } else {
        loop {
            let chunk_size = sizer.chunk_size();
            let buf = &mut read_buf[..chunk_size];
            let n = reader
                .read(buf)
                .with_context(|| format!("read error: {}", full_path.display()))?;
            if n == 0 {
                break;
            }
            let chunk = buf[..n].to_vec();
            bytes_sent += n as u64;
            total_bytes += n as u64;
            sizer.record(n as u64);
            proto::write_message_buffered(send, &TransferMsg::FileData(chunk)).await?;
            progress.file_progress(&entry.path, bytes_sent, entry.size);
        }
    }

    proto::write_message(send, &TransferMsg::FileEnd).await?;
    progress.file_done(&entry.path);

    Ok(total_bytes)
}

/// Send delete commands for the given paths.
pub async fn send_deletes(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
    paths: &[String],
    progress: &dyn ProgressReporter,
) -> Result<()> {
    for path in paths {
        proto::write_message(send, &TransferMsg::DeletePath(path.clone())).await?;
        progress.file_deleted(path);
    }
    Ok(())
}
