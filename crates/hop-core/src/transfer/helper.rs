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
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

use super::negotiation::NegotiatedParams;
use super::progress::SilentProgress;

/// Maximum time the proxy will tolerate zero progress in BOTH directions
/// before killing the child. Prevents orphaned helpers when iroh-quinn
/// fails to surface a dead connection as an error.
const PROXY_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Maximum time the child helper will wait for parent IPC activity before
/// self-exiting. Insurance against parent-side bugs that leave us orphaned.
const HELPER_IDLE_TIMEOUT: Duration = Duration::from_secs(900);

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
    let exe = std::env::current_exe().context("cannot determine hop executable path")?;

    let mut helper_args = vec![
        "__transfer-helper".to_string(),
        "--mode".to_string(),
        mode.to_string(),
        "--dest".to_string(),
        dest.to_string_lossy().to_string(),
    ];
    if let Some(ref comp) = params.compression {
        match comp {
            super::negotiation::Compression::Zstd { level } => {
                helper_args.push("--compression".to_string());
                helper_args.push(format!("zstd:{level}"));
            }
        }
    }
    helper_args.push("--chunk-size".to_string());
    helper_args.push(params.max_chunk_size.to_string());
    // The helper talks to the client directly over its stdio, so it needs the
    // negotiated features version to pick the listing encoding the client
    // expects. Defaults to 1 if absent, keeping an older helper binary safe.
    helper_args.push("--features-version".to_string());
    helper_args.push(params.features_version.to_string());

    // Acquire the helper's I/O. When this worker is unprivileged (privsep), it
    // can't switch users, so the root monitor spawns the helper (`SpawnHelper`)
    // and hands back the pipe fds + a status fd; otherwise spawn it locally.
    let via_monitor =
        !crate::unix_user::is_running_as_root() && crate::privsep::is_privsep_worker();

    let child_stdin: Box<dyn tokio::io::AsyncWrite + Unpin + Send>;
    let child_stdout: Box<dyn tokio::io::AsyncRead + Unpin + Send>;
    let mut exit: HelperExit;
    let child_pid;

    if via_monitor {
        use tokio::net::unix::pipe;
        let mut argv = vec![exe.to_string_lossy().to_string()];
        argv.extend(helper_args);
        let fds = crate::privsep::worker_spawn_helper(&argv, username)
            .context("privsep monitor SpawnHelper")?;
        let mut it = fds.into_iter();
        let stdin = it.next().context("SpawnHelper missing stdin fd")?;
        let stdout = it.next().context("SpawnHelper missing stdout fd")?;
        let status = it.next().context("SpawnHelper missing status fd")?;
        child_stdin = Box::new(pipe::Sender::from_owned_fd(stdin)?);
        child_stdout = Box::new(pipe::Receiver::from_owned_fd(stdout)?);
        exit = HelperExit::Status(pipe::Receiver::from_owned_fd(status)?);
        child_pid = None;
    } else {
        // On macOS, route through `login -fpq` so the child gets a real user
        // session (fresh audit session id, setlogin, PAM setup). A bare setuid
        // from launchd's root audit session leaves filesystem access blocked
        // on user-owned files — the same reason `hop on <host>` uses `login -fp`
        // to spawn shells. `-q` suppresses the "Last login" banner so it doesn't
        // corrupt our stdout IPC framing.
        #[cfg(target_os = "macos")]
        let mut cmd = {
            let mut c = tokio::process::Command::new("/usr/bin/login");
            c.arg("-fpq").arg(username).arg(&exe).args(&helper_args);
            c
        };

        // Linux has no audit-session axis, so uid/gid drop + initgroups is
        // sufficient.
        #[cfg(not(target_os = "macos"))]
        let mut cmd = {
            let (uid, gid) = lookup_uid_gid(username)?;
            let username_for_pre_exec = username.to_string();
            let mut c = tokio::process::Command::new(&exe);
            c.args(&helper_args).uid(uid).gid(gid);
            unsafe {
                c.pre_exec(move || {
                    let c_name = std::ffi::CString::new(username_for_pre_exec.as_str())
                        .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
                    libc::initgroups(c_name.as_ptr(), gid as _);
                    Ok(())
                });
            }
            c
        };

        cmd.stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::inherit())
            // If the parent future is dropped (cancellation, panic, connection
            // torn down), ensure the child is SIGKILLed instead of orphaned.
            .kill_on_drop(true);

        let mut child = cmd.spawn().context("failed to spawn transfer helper")?;
        child_pid = child.id();
        child_stdin = Box::new(child.stdin.take().context("no child stdin")?);
        child_stdout = Box::new(child.stdout.take().context("no child stdout")?);
        exit = HelperExit::Child(child);
    }

    // Monotonic counter bumped on every successful read or write in either
    // direction. The watchdog reads it to detect a stuck proxy.
    let activity = Arc::new(AtomicU64::new(0));

    let proxy_in = copy_with_activity("recv→child", quic_recv, child_stdin, Arc::clone(&activity));
    let proxy_out = copy_with_activity("child→send", child_stdout, quic_send, Arc::clone(&activity));
    let watchdog = idle_watchdog(Arc::clone(&activity), PROXY_IDLE_TIMEOUT);

    tokio::pin!(proxy_in);
    tokio::pin!(proxy_out);
    tokio::pin!(watchdog);

    // proxy_out finishing is the definitive "session is over" signal:
    // the helper has closed its stdout, so whatever it was going to say
    // has already been forwarded and there is nothing left to proxy. Do
    // not wait on proxy_in in that case — if the helper bailed early the
    // client is usually parked waiting to *receive* data and will never
    // send anything to unblock proxy_in, so a `join!` here would stall
    // for the full 10-minute watchdog timeout before tearing down.
    tokio::select! {
        r = &mut proxy_out => {
            if let Err(e) = r {
                tracing::debug!("proxy_out ended: {e:#}");
            }
        }
        r = &mut proxy_in => {
            if let Err(e) = r {
                tracing::debug!("proxy_in ended: {e:#}");
            }
            // Client side hung up. Give the helper a short grace period
            // to deliver any final output before we tear down.
            let _ = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                &mut proxy_out,
            ).await;
        }
        _ = &mut watchdog => {
            tracing::warn!(
                "transfer helper (pid={child_pid:?}) idle > {}s; killing",
                PROXY_IDLE_TIMEOUT.as_secs()
            );
            exit.kill().await;
            bail!("transfer helper idle timeout");
        }
    }

    let code = exit.code().await;
    if code != 0 {
        bail!("transfer helper exited with code {code}");
    }

    Ok(())
}

/// Where a transfer helper's exit comes from: the local child, or — under
/// privsep — the monitor's status pipe (4-byte LE exit code written on reap).
#[cfg(unix)]
enum HelperExit {
    Child(tokio::process::Child),
    Status(tokio::net::unix::pipe::Receiver),
}

#[cfg(unix)]
impl HelperExit {
    /// Best-effort kill on idle timeout. The monitor-owned child can't be killed
    /// directly; dropping our fds (on return) closes its stdin → the helper sees
    /// EOF and exits.
    async fn kill(&mut self) {
        if let HelperExit::Child(c) = self {
            let _ = c.kill().await;
        }
    }
    async fn code(&mut self) -> i32 {
        match self {
            HelperExit::Child(c) => c.wait().await.ok().and_then(|s| s.code()).unwrap_or(1),
            HelperExit::Status(r) => {
                use tokio::io::AsyncReadExt;
                let mut buf = [0u8; 4];
                match r.read_exact(&mut buf).await {
                    Ok(_) => i32::from_le_bytes(buf),
                    Err(_) => 1,
                }
            }
        }
    }
}

/// `tokio::io::copy` equivalent that bumps `activity` on every successful
/// read/write. Used to feed the idle watchdog.
#[cfg(unix)]
async fn copy_with_activity<R, W>(
    label: &'static str,
    mut reader: R,
    mut writer: W,
    activity: Arc<AtomicU64>,
) -> Result<u64>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let mut buf = vec![0u8; 64 * 1024];
    let mut total: u64 = 0;
    loop {
        let n = reader.read(&mut buf).await?;
        if n == 0 {
            writer.flush().await.ok();
            tracing::trace!("{label}: EOF after {total} bytes");
            return Ok(total);
        }
        writer.write_all(&buf[..n]).await?;
        total += n as u64;
        activity.fetch_add(1, Ordering::Relaxed);
    }
}

/// Watchdog future. Resolves (returns) once `activity` has been idle
/// for `timeout`. Polls at `timeout / 4` granularity, clamped to [50ms, 60s]
/// so it stays responsive for short test timeouts without burning CPU
/// on the 10-minute production timeout.
#[cfg(unix)]
async fn idle_watchdog(activity: Arc<AtomicU64>, timeout: Duration) {
    let mut last_seen = activity.load(Ordering::Relaxed);
    let mut last_change = Instant::now();
    let tick = (timeout / 4).clamp(Duration::from_millis(50), Duration::from_secs(60));
    loop {
        tokio::time::sleep(tick).await;
        let current = activity.load(Ordering::Relaxed);
        if current != last_seen {
            last_seen = current;
            last_change = Instant::now();
            continue;
        }
        if last_change.elapsed() >= timeout {
            return;
        }
    }
}

/// AsyncRead wrapper that bumps a shared counter on every non-empty read.
/// Used by the child helper's idle watchdog to detect a dead parent.
struct ActivityStdin {
    inner: tokio::io::Stdin,
    activity: Arc<AtomicU64>,
}

impl tokio::io::AsyncRead for ActivityStdin {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let res = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        if let std::task::Poll::Ready(Ok(())) = &res
            && buf.filled().len() > before
        {
            self.activity.fetch_add(1, Ordering::Relaxed);
        }
        res
    }
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
    let activity = Arc::new(AtomicU64::new(0));
    let stdin_inner = ActivityStdin {
        inner: tokio::io::stdin(),
        activity: Arc::clone(&activity),
    };
    let mut stdin = tokio::io::BufReader::new(stdin_inner);
    let mut stdout = tokio::io::BufWriter::new(tokio::io::stdout());
    let progress = SilentProgress;

    // Background task: if stdin has been idle for > HELPER_IDLE_TIMEOUT,
    // self-terminate. Guards against orphaning when the parent daemon has
    // a bug that leaves us with nothing to read.
    let watchdog_activity = Arc::clone(&activity);
    tokio::spawn(async move {
        idle_watchdog(watchdog_activity, HELPER_IDLE_TIMEOUT).await;
        eprintln!(
            "hop transfer helper: stdin idle > {}s, self-exiting to avoid orphan",
            HELPER_IDLE_TIMEOUT.as_secs()
        );
        // Hard exit; the parent will observe EOF on our stdout and clean up.
        std::process::exit(2);
    });

    match mode {
        "receive" => {
            super::receiver::receive_files(&mut stdout, &mut stdin, dest, &progress, &params).await?;
            crate::proto::write_message(&mut stdout, &crate::proto::TransferMsg::Done).await?;
        }
        "send" | "send-recursive" => {
            let recursive = mode == "send-recursive";

            // Explicit metadata() so the caller sees the real errno
            // (ENOENT vs EACCES vs EPERM) instead of the misleading
            // "source path does not exist" that `is_file()`/`is_dir()`
            // would produce by swallowing every error into `false`.
            let metadata = std::fs::metadata(dest)
                .with_context(|| format!("cannot access source path: {}", dest.display()))?;

            let entries = if metadata.is_file() {
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
            } else if metadata.is_dir() {
                if !recursive {
                    bail!("source is a directory; use -r for recursive copy");
                }
                super::listing::walk_directory(dest)?
            } else {
                bail!("source is not a regular file or directory: {}", dest.display());
            };

            let base_dir = if metadata.is_file() { dest.parent().unwrap_or(dest) } else { dest };

            super::sender::send_files(&mut stdout, base_dir, &entries, &progress, &params).await?;
            // Read one ack per entry sent (files + dirs + symlinks)
            let ack_count = entries.len();
            for _ in 0..ack_count {
                let _ack: crate::proto::TransferMsg = crate::proto::read_message(&mut stdin).await?;
            }
            // Signal end of transfer — client reads until Done
            crate::proto::write_message(&mut stdout, &crate::proto::TransferMsg::Done).await?;
        }
        "sync-receive" => {
            // Full sync protocol: send our listing, read plan, receive files
            use crate::proto::{TransferMsg, DELTA_MIN_FILE_SIZE};

            // 1. Walk destination and send listing to client
            let dest_entries = if dest.is_dir() {
                super::listing::walk_directory(dest)?
            } else {
                Vec::new()
            };
            super::write_file_list(&mut stdout, dest_entries, params.chunked_listing()).await?;
            tokio::io::AsyncWriteExt::flush(&mut stdout).await?;

            // 2. Read client's transfer plan
            let (files_to_send, _files_to_delete, dry_run) =
                super::read_transfer_plan(&mut stdin).await?;

            if dry_run {
                crate::proto::write_message(&mut stdout, &TransferMsg::PlanAck { proceed: true }).await?;
                crate::proto::write_message(&mut stdout, &TransferMsg::Done).await?;
                tokio::io::AsyncWriteExt::flush(&mut stdout).await?;
                return Ok(());
            }

            crate::proto::write_message(&mut stdout, &TransferMsg::PlanAck { proceed: true }).await?;
            tokio::io::AsyncWriteExt::flush(&mut stdout).await?;

            // 3. Compute delta candidates
            let delta_candidates: std::collections::HashSet<String> = files_to_send
                .iter()
                .filter(|f| {
                    !f.is_dir && !f.is_symlink
                        && f.size >= DELTA_MIN_FILE_SIZE
                        && dest.join(&f.path).exists()
                        && dest.join(&f.path).metadata()
                            .map(|m| m.len() >= DELTA_MIN_FILE_SIZE)
                            .unwrap_or(false)
                })
                .map(|f| f.path.clone())
                .collect();

            // 4. Receive files
            if !delta_candidates.is_empty() {
                super::receiver::receive_files_with_delta(
                    &mut stdout, &mut stdin, dest, &delta_candidates, &files_to_send, &progress, &params,
                ).await?;
            } else {
                super::receiver::receive_files(&mut stdout, &mut stdin, dest, &progress, &params).await?;
            }
            crate::proto::write_message(&mut stdout, &TransferMsg::Done).await?;
        }
        "sync-send" | "sync-send-delete" => {
            use crate::proto::{TransferMsg, FileEntry};

            let delete_extraneous = mode == "sync-send-delete";

            // 1. Read client's file list
            let client_entries = super::read_file_list(&mut stdin).await?;

            // 2. Walk source and compute plan. Explicit metadata() so the
            // caller sees the real errno rather than the misleading
            // "source path does not exist" that comes from
            // is_file()/is_dir() swallowing every error into false.
            let metadata = std::fs::metadata(dest)
                .with_context(|| format!("cannot access source path: {}", dest.display()))?;
            let (source_entries, base_dir) = if metadata.is_dir() {
                (super::listing::walk_directory(dest)?, dest.to_path_buf())
            } else if metadata.is_file() {
                let file_name = dest.file_name().unwrap_or_default().to_string_lossy().to_string();
                let entry = FileEntry {
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
                };
                (vec![entry], dest.parent().unwrap_or(dest).to_path_buf())
            } else {
                bail!("source is not a regular file or directory: {}", dest.display());
            };

            let plan = super::listing::compute_sync_plan(&source_entries, &client_entries, delete_extraneous);

            // 3. Send plan
            super::write_transfer_plan(
                &mut stdout,
                plan.files_to_send.clone(),
                plan.files_to_delete.clone(),
                false,
                params.chunked_listing(),
            )
            .await?;
            tokio::io::AsyncWriteExt::flush(&mut stdout).await?;

            // 4. Read PlanAck
            let ack_msg: TransferMsg = crate::proto::read_message(&mut stdin).await?;
            match ack_msg {
                TransferMsg::PlanAck { proceed: true } => {}
                TransferMsg::PlanAck { proceed: false } => {
                    crate::proto::write_message(&mut stdout, &TransferMsg::Done).await?;
                    tokio::io::AsyncWriteExt::flush(&mut stdout).await?;
                    return Ok(());
                }
                other => bail!("expected PlanAck, got: {other:?}"),
            }

            // 5. Send files
            let files_to_send = plan.files_to_send;
            let delta_set: std::collections::HashSet<String> = plan.delta_candidates.into_iter().collect();

            if !delta_set.is_empty() {
                super::sender::send_files_with_delta(
                    &mut stdout, &mut stdin, &base_dir, &files_to_send, &delta_set, &progress, &params,
                ).await?;
            } else {
                super::sender::send_files(&mut stdout, &base_dir, &files_to_send, &progress, &params).await?;
            }

            // 6. Send deletes
            super::sender::send_deletes(&mut stdout, &plan.files_to_delete, &progress).await?;

            // 7. Send Done
            crate::proto::write_message(&mut stdout, &TransferMsg::Done).await?;
            tokio::io::AsyncWriteExt::flush(&mut stdout).await?;

            // 8. Read acks
            let total_acks = files_to_send.len() + plan.files_to_delete.len();
            for _ in 0..total_acks {
                let _ack: TransferMsg = crate::proto::read_message(&mut stdin).await?;
            }

            // 9. Read client's Done
            let done_msg: TransferMsg = crate::proto::read_message(&mut stdin).await?;
            match done_msg {
                TransferMsg::Done => {}
                other => tracing::warn!("expected Done from client, got: {other:?}"),
            }
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

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn watchdog_fires_when_idle() {
        let activity = Arc::new(AtomicU64::new(0));
        let start = Instant::now();
        // Use a 200ms timeout and a 60ms tick floor. We must wait at least
        // one full `timeout` of silence after the first tick.
        let watchdog = idle_watchdog(Arc::clone(&activity), Duration::from_millis(200));
        tokio::time::timeout(Duration::from_secs(5), watchdog)
            .await
            .expect("watchdog should have fired");
        assert!(start.elapsed() >= Duration::from_millis(200));
    }

    #[tokio::test]
    async fn watchdog_does_not_fire_while_active() {
        let activity = Arc::new(AtomicU64::new(0));
        let bump = Arc::clone(&activity);
        let bumper = tokio::spawn(async move {
            for _ in 0..20 {
                tokio::time::sleep(Duration::from_millis(30)).await;
                bump.fetch_add(1, Ordering::Relaxed);
            }
        });
        let watchdog = idle_watchdog(Arc::clone(&activity), Duration::from_millis(500));
        // Should timeout (watchdog doesn't fire) while bumper is active.
        let res = tokio::time::timeout(Duration::from_millis(400), watchdog).await;
        assert!(res.is_err(), "watchdog must not fire while activity present");
        bumper.abort();
    }
}
