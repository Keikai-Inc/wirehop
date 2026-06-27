//! Hop extension: echo.
//!
//! Smallest possible Hop extension. Echoes every payload back unchanged.
//! Useful as:
//!
//! 1. An end-to-end smoke test of the extension plumbing on a host.
//! 2. A reference implementation showing what a Hop extension daemon
//!    looks like in practice.
//!
//! ## Running locally
//!
//! ```bash
//! # In one shell:
//! mkdir -p /tmp/hop-echo
//! hop-ext-echo --bootstrap /tmp/hop-echo/bootstrap
//!
//! # In another, install the manifest:
//! cat > ~/.config/hop/extensions/echo.toml <<'EOF'
//! ext_id         = "echo"
//! description    = "Echo extension (smoke test)"
//! bootstrap_path = "/tmp/hop-echo/bootstrap"
//! expected_uid   = ${YOUR_UID}
//! version        = "0.1.0"
//! EOF
//!
//! # Restart hop daemon, then:
//! hop <host> ext list
//! hop <host> ext call echo --text "hello world"
//! ```

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use clap::Parser;
use hop_core::extensions::{Bootstrap, ExtMessage};
use ipc_channel::ipc::{IpcOneShotServer, IpcSender};
use tracing::{debug, info, warn};
use tracing_subscriber::filter::{LevelFilter, Targets};
use tracing_subscriber::prelude::*;

#[derive(Parser, Debug)]
#[command(version, about = "Hop echo extension daemon")]
struct Args {
    /// Path where this daemon will write its bootstrap-rendezvous file.
    /// Hop reads this file (specified in the manifest as `bootstrap_path`)
    /// to discover the ipc-channel server name to connect to.
    #[arg(long)]
    bootstrap: PathBuf,

    /// Protocol version advertised in the bootstrap file. Must match the
    /// `version` field in the corresponding hop-side manifest.
    #[arg(long = "protocol-version", default_value = "0.1.0")]
    protocol_version: String,
}

fn main() -> Result<()> {
    // Targets filter (no regex/env-filter feature): honors RUST_LOG's
    // target=level syntax, defaults to info.
    let filter = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| s.parse::<Targets>().ok())
        .unwrap_or_else(|| Targets::new().with_default(LevelFilter::INFO));
    tracing_subscriber::registry()
        .with(filter)
        .with(tracing_subscriber::fmt::layer())
        .init();

    let args = Args::parse();

    info!(
        bootstrap = %args.bootstrap.display(),
        version = %args.protocol_version,
        "starting echo extension"
    );

    // 1. Create our IpcOneShotServer. The server_name is what hop will
    //    use to connect; we publish it via the bootstrap file.
    let (server, server_name): (IpcOneShotServer<ExtMessage>, String) =
        IpcOneShotServer::new().context("creating ipc-channel server")?;
    debug!(%server_name, "ipc-channel server bound");

    // 2. Write the bootstrap file. Atomically create with 0600 mode and
    //    O_NOFOLLOW so we can't be tricked into writing through a symlink.
    write_bootstrap_atomically(&args.bootstrap, &server_name, &args.protocol_version)?;
    info!(path = %args.bootstrap.display(), "bootstrap file written");

    // 3. Wait for hop to send Hello. This blocks until hop reads our
    //    bootstrap and connects.
    let (rx_from_hop, hello) = server.accept().context("waiting for hop Hello")?;
    let reverse_name = match hello {
        ExtMessage::Hello { reverse_name, hop_version } => {
            info!(%hop_version, "hop connected");
            reverse_name
        }
        other => bail!("expected Hello from hop, got {:?}", other),
    };

    // 4. Connect back to hop's reverse server, send HelloAck.
    let tx_to_hop: IpcSender<ExtMessage> = IpcSender::connect(reverse_name)
        .context("connecting to hop reverse server")?;
    tx_to_hop
        .send(ExtMessage::HelloAck {
            ext_version: args.protocol_version.clone(),
        })
        .context("sending HelloAck")?;
    info!("handshake complete");

    // 5. Echo loop. For each Request we receive, send a Response back
    //    with the same payload. Other variants are ignored with a log.
    loop {
        let msg = match rx_from_hop.recv() {
            Ok(m) => m,
            Err(e) => {
                warn!(error = ?e, "ipc-channel recv failed; shutting down");
                break;
            }
        };

        match msg {
            ExtMessage::Request {
                request_id,
                peer_username,
                payload,
                ..
            } => {
                debug!(
                    request_id,
                    peer = peer_username.as_deref().unwrap_or("?"),
                    bytes = payload.len(),
                    "echoing request"
                );
                if tx_to_hop
                    .send(ExtMessage::Response {
                        request_id,
                        ok: true,
                        payload,
                    })
                    .is_err()
                {
                    warn!("send to hop failed; shutting down");
                    break;
                }
            }
            ExtMessage::StreamOpen { request_id, .. } => {
                // Echo extension doesn't do streaming; politely close.
                let _ = tx_to_hop.send(ExtMessage::StreamClosed {
                    stream_id: 0,
                    reason: Some("echo extension does not support streams".into()),
                });
                debug!(request_id, "rejected stream open");
            }
            other => {
                debug!(?other, "ignored non-Request message");
            }
        }
    }

    // Best-effort cleanup.
    let _ = std::fs::remove_file(&args.bootstrap);
    info!("echo extension stopped");
    Ok(())
}

/// Write the bootstrap file atomically with 0600 mode and O_NOFOLLOW.
///
/// Strategy: write to a sibling temp file first, fsync, rename into
/// place. This way hop never sees a partial file and a concurrent
/// reader either sees the old file or the new one, never something
/// in between.
fn write_bootstrap_atomically(path: &std::path::Path, server_name: &str, version: &str) -> Result<()> {
    let parent = path
        .parent()
        .context("bootstrap path has no parent directory")?;
    std::fs::create_dir_all(parent)
        .with_context(|| format!("creating parent directory {}", parent.display()))?;

    let bs = Bootstrap {
        server_name: server_name.to_string(),
        pid: std::process::id(),
        version: version.to_string(),
    };
    let serialized = toml::to_string(&bs).context("serializing bootstrap")?;

    // Write to a temp sibling with 0600 mode, then rename.
    let tmp_path = path.with_extension("tmp");

    // O_CREAT | O_EXCL | O_NOFOLLOW with mode 0600 in a single syscall.
    use std::os::unix::fs::OpenOptionsExt;
    use std::io::Write as _;
    let mut f = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(0o600)
        .open(&tmp_path)
        .or_else(|_| {
            // Old tmp left behind from a previous crash; remove and retry.
            let _ = std::fs::remove_file(&tmp_path);
            std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .custom_flags(libc::O_NOFOLLOW)
                .mode(0o600)
                .open(&tmp_path)
        })
        .with_context(|| format!("creating temp bootstrap {}", tmp_path.display()))?;

    f.write_all(serialized.as_bytes())
        .with_context(|| format!("writing bootstrap to {}", tmp_path.display()))?;
    f.sync_all().context("fsync bootstrap")?;
    drop(f);

    std::fs::rename(&tmp_path, path)
        .with_context(|| format!("renaming {} to {}", tmp_path.display(), path.display()))?;

    // Defense in depth: ensure final file is 0600 even if the rename
    // somehow lost it (it shouldn't, but cheap to verify).
    let perms = std::fs::Permissions::from_mode(0o600);
    std::fs::set_permissions(path, perms).context("chmod bootstrap")?;

    Ok(())
}
