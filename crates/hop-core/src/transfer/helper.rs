//! Privilege-separated transfer helper.
//!
//! When the daemon runs as root, file I/O during transfers is delegated to a
//! child process running as the target user. This provides kernel-enforced
//! file permissions (like sshd's scp/sftp model) instead of application-level
//! chown after creation.
//!
//! The parent (root) proxies QUIC data to/from the child's stdin/stdout pipes.
//! The child runs the same transfer functions, just as a different user.

use std::path::Path;

use anyhow::{Context, Result, bail};

use super::negotiation::NegotiatedParams;
use super::progress::SilentProgress;

/// Spawn a privilege-separated helper and proxy the QUIC stream through it.
///
/// The helper runs as the target user. Bidirectional proxy:
///   QUIC recv → child stdin (data from client)
///   child stdout → QUIC send (data/acks from helper)
#[cfg(unix)]
pub async fn proxy_via_helper(
    quic_send: &mut (impl tokio::io::AsyncWrite + Unpin + Send),
    quic_recv: &mut (impl tokio::io::AsyncRead + Unpin + Send),
    dest: &Path,
    username: &str,
    params: &NegotiatedParams,
    mode: &str,
) -> Result<()> {
    use tokio::io;

    let (uid, gid) = lookup_uid_gid(username)?;

    let exe = std::env::current_exe().context("cannot determine hop executable path")?;

    let mut args = vec![
        "__transfer-helper".to_string(),
        "--mode".to_string(),
        mode.to_string(),
        "--dest".to_string(),
        dest.to_string_lossy().to_string(),
    ];
    if let Some(ref comp) = params.compression {
        match comp {
            super::negotiation::Compression::Zstd { level } => {
                args.push("--compression".to_string());
                args.push(format!("zstd:{level}"));
            }
        }
    }
    args.push("--chunk-size".to_string());
    args.push(params.max_chunk_size.to_string());

    let username_for_pre_exec = username.to_string();
    let mut cmd = tokio::process::Command::new(&exe);
    cmd.args(&args)
        .stdin(std::process::Stdio::piped())
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::inherit())
        .uid(uid)
        .gid(gid);
    unsafe {
        cmd.pre_exec(move || {
            // initgroups sets supplementary groups (staff, admin, etc.)
            let c_name = std::ffi::CString::new(username_for_pre_exec.as_str())
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
            // nix::unistd::initgroups is not available on macOS, use libc directly
            libc::initgroups(c_name.as_ptr(), gid as _);
            Ok(())
        });
    }
    let mut child = cmd.spawn().context("failed to spawn transfer helper")?;

    let mut child_stdin = child.stdin.take().context("no child stdin")?;
    let mut child_stdout = child.stdout.take().context("no child stdout")?;

    let proxy_in = async {
        io::copy(quic_recv, &mut child_stdin).await?;
        drop(child_stdin);
        Ok::<_, anyhow::Error>(())
    };
    let proxy_out = async {
        io::copy(&mut child_stdout, quic_send).await?;
        Ok::<_, anyhow::Error>(())
    };

    let (in_result, out_result) = tokio::join!(proxy_in, proxy_out);

    if let Err(e) = in_result {
        tracing::debug!("proxy_in ended: {e:#}");
    }
    if let Err(e) = out_result {
        tracing::debug!("proxy_out ended: {e:#}");
    }

    let status = child.wait().await.context("failed to wait for transfer helper")?;
    if !status.success() {
        bail!("transfer helper exited with {status}");
    }

    Ok(())
}

/// Entry point for the `__transfer-helper` child process.
///
/// Dispatches to the appropriate transfer function based on `mode`.
/// stdin/stdout are the IPC pipes to the parent daemon.
pub async fn run_transfer_helper(
    mode: &str,
    dest: &Path,
    params: NegotiatedParams,
) -> Result<()> {
    let mut stdin = tokio::io::BufReader::new(tokio::io::stdin());
    let mut stdout = tokio::io::BufWriter::new(tokio::io::stdout());
    let progress = SilentProgress;

    match mode {
        "receive" => {
            super::receiver::receive_files(&mut stdout, &mut stdin, dest, &progress, &params).await?;
            crate::proto::write_message(&mut stdout, &crate::proto::TransferMsg::Done).await?;
        }
        "send" | "send-recursive" => {
            let recursive = mode == "send-recursive";

            let entries = if dest.is_file() {
                let metadata = std::fs::metadata(dest)?;
                let file_name = dest.file_name().unwrap_or_default().to_string_lossy().to_string();
                vec![crate::proto::FileEntry {
                    path: file_name,
                    size: metadata.len(),
                    mtime: metadata.modified()
                        .unwrap_or(std::time::UNIX_EPOCH)
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_secs(),
                    mode: super::listing::file_mode_from_metadata(&metadata),
                    is_dir: false,
                    is_symlink: false,
                    symlink_target: None,
                    content_hash: None,
                }]
            } else if dest.is_dir() {
                if !recursive {
                    bail!("source is a directory; use -r for recursive copy");
                }
                super::listing::walk_directory(dest)?
            } else {
                bail!("source path does not exist: {}", dest.display());
            };

            let base_dir = if dest.is_file() { dest.parent().unwrap_or(dest) } else { dest };

            super::sender::send_files(&mut stdout, base_dir, &entries, &progress, &params).await?;
            let _errors = super::receiver::read_acks_until_done(&mut stdin, None).await?;
        }
        "sync-receive" => {
            // Sync receive: read file list request, send our listing, receive plan, receive files
            // The full sync protocol runs through stdin/stdout
            super::receiver::receive_files(&mut stdout, &mut stdin, dest, &progress, &params).await?;
            crate::proto::write_message(&mut stdout, &crate::proto::TransferMsg::Done).await?;
        }
        other => bail!("unknown transfer helper mode: {other}"),
    }

    tokio::io::AsyncWriteExt::flush(&mut stdout).await?;
    Ok(())
}

/// Look up uid and gid for a username.
#[cfg(unix)]
pub fn lookup_uid_gid(username: &str) -> Result<(u32, u32)> {
    let user = users::get_user_by_name(username)
        .ok_or_else(|| anyhow::anyhow!("user not found: {username}"))?;
    Ok((user.uid(), user.primary_group_id()))
}
