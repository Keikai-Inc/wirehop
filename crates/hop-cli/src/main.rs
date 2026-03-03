mod cli;
mod progress_ui;
mod reconnect;

use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Command, PeersAction};
use iroh::endpoint::{RecvStream, SendStream};
use iroh::{Endpoint, PublicKey, RelayUrl, TransportAddr, Watcher};
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

use hop_core::auth::{self, AuthOutcome};
use hop_core::config::{self, KnownHostsStore, PeersStore};
use hop_core::invite;
use hop_core::net;
use hop_core::proto::{self, ClientMessage, TransferDirection, TransferMode, TransferRequest};
use hop_core::shell::{self, SessionOutcome};
use hop_core::shell::session_registry::SessionRegistry;
use hop_core::transfer::{self, PathSpec};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing
    let filter = match cli.verbose {
        0 => "hop=info",
        1 => "hop=debug",
        _ => "hop=trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::new(filter))
        .init();

    match cli.command {
        Command::Host { quiet } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_host(secret_key, &config_dir, quiet).await
        }
        Command::Invite { user, name } => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_identity(&config_dir)?;
            cmd_invite(secret_key, &config_dir, user.as_deref(), name.as_deref())
        }
        Command::Connect { target, name } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_connect(secret_key, &target, &config_dir, name.as_deref()).await
        }
        Command::Exec { target, command } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_exec(secret_key, &target, &config_dir, &command).await
        }
        Command::Cp { recursive, paths } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_cp(secret_key, &config_dir, recursive, &paths).await
        }
        Command::Sync {
            delete,
            dry_run,
            verbose,
            source,
            dest,
        } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_sync(secret_key, &config_dir, delete, dry_run, verbose, &source, &dest).await
        }
        Command::Peers { action } => {
            let host_config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            let user_config_dir = config::default_config_dir()?;
            cmd_peers(action, &host_config_dir, &user_config_dir)
        }
        Command::On { target, name } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_connect(secret_key, &target, &config_dir, name.as_deref()).await
        }
        Command::Id => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            let public_key = secret_key.public();
            println!("{public_key}");
            Ok(())
        }
        Command::External(args) => {
            // Treat the first arg as a connect target: "hop myhost"
            let target = args.first().context("no target specified")?;
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_connect(secret_key, target, &config_dir, None).await
        }
    }
}

async fn cmd_host(secret_key: iroh::SecretKey, config_dir: &std::path::Path, quiet: bool) -> Result<()> {
    let public_key = secret_key.public();
    let endpoint = net::create_host_endpoint(secret_key).await?;

    let relay_url = net::host_relay_url(&endpoint);
    tracing::info!("Hosting as: {public_key}");
    if let Some(ref url) = relay_url {
        tracing::info!("Relay: {url}");
        // Persist relay URL so `hop invite` can embed it in tokens
        let relay_path = config_dir.join("relay_url");
        if let Err(e) = std::fs::write(&relay_path, url.to_string()) {
            tracing::warn!("Failed to write relay_url: {e}");
        }
    }

    // Watch for relay URL changes and keep the file up to date
    {
        let relay_path = config_dir.join("relay_url");
        let mut watcher = endpoint.watch_addr();
        tokio::spawn(async move {
            loop {
                match watcher.updated().await {
                    Ok(addr) => {
                        if let Some(new_relay) = addr.relay_urls().next() {
                            let _ = std::fs::write(&relay_path, new_relay.to_string());
                            tracing::debug!("Updated relay_url file: {new_relay}");
                        }
                    }
                    Err(_) => break,
                }
            }
        });
    }

    // Warn about legacy peers with no bound username when running as root
    #[cfg(unix)]
    if hop_core::unix_user::is_running_as_root() {
        let peers = PeersStore::load(config_dir)?;
        let unbound: Vec<_> = peers
            .peers
            .iter()
            .filter(|p| p.username.is_none())
            .collect();
        if !unbound.is_empty() {
            eprintln!("WARNING: running as root but {} peer(s) have no bound username:", unbound.len());
            for p in &unbound {
                eprintln!("  {} ({})", &p.node_id[..10], p.name);
            }
            eprintln!(
                "These peers will be REJECTED until re-invited with `hop invite --user <username>`."
            );
            eprintln!();
        }
    }

    if !quiet {
        println!("Hosting as: {public_key}");
        if let Some(ref url) = relay_url {
            println!("Relay: {url}");
        }
        println!("Waiting for connections...");
        println!();
        println!("Clients can connect with:");
        println!("  hop connect {public_key}");
        println!();
    }

    // Session registry for persistent PTY sessions (5-minute detach timeout)
    let registry = Arc::new(tokio::sync::Mutex::new(
        SessionRegistry::new(Duration::from_secs(5 * 60)),
    ));

    // Spawn reaper task: every 30s, remove expired/exited sessions
    {
        let registry = registry.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                registry.lock().await.reap_expired();
            }
        });
    }

    while let Some(incoming) = endpoint.accept().await {
        let config_dir = config_dir.to_path_buf();
        let registry = registry.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_incoming(incoming, &config_dir, registry).await {
                tracing::error!("Connection error: {e:#}");
            }
        });
    }

    endpoint.close().await;
    Ok(())
}

async fn handle_incoming(
    incoming: iroh::endpoint::Incoming,
    config_dir: &std::path::Path,
    registry: Arc<tokio::sync::Mutex<SessionRegistry>>,
) -> Result<()> {
    let conn: iroh::endpoint::Connection = incoming.await?;
    let remote_id = conn.remote_id();
    let protocol_version = net::negotiated_protocol_version(&conn);
    tracing::info!("Connection from: {} (protocol v{})", remote_id.fmt_short(), protocol_version);

    let (mut send, mut recv) = conn.accept_bi().await?;

    // Authenticate the client
    let (outcome, _first_msg) = auth::authenticate_client(
        &mut send,
        &mut recv,
        &remote_id,
        config_dir,
    )
    .await?;

    let peer_id = remote_id.to_string();

    match outcome {
        AuthOutcome::Authorized { username } => {
            tracing::info!("Authorized peer {}", remote_id.fmt_short());
            dispatch_session(_first_msg, conn, send, recv, username.as_deref(), protocol_version, &peer_id, registry).await?;
        }
        AuthOutcome::InviteAccepted { username } => {
            tracing::info!("Invite accepted for {}, waiting for session request", remote_id.fmt_short());
            let msg: ClientMessage = proto::read_message(&mut recv).await?;
            dispatch_session(Some(msg), conn, send, recv, username.as_deref(), protocol_version, &peer_id, registry).await?;
        }
        AuthOutcome::Rejected => {
            tracing::info!("Rejected connection from {}", remote_id.fmt_short());
        }
    }

    Ok(())
}

async fn dispatch_session(
    msg: Option<ClientMessage>,
    conn: iroh::endpoint::Connection,
    send: SendStream,
    recv: RecvStream,
    username: Option<&str>,
    protocol_version: u8,
    peer_id: &str,
    registry: Arc<tokio::sync::Mutex<SessionRegistry>>,
) -> Result<()> {
    match msg {
        Some(ClientMessage::RequestShell) => {
            tracing::info!("Starting shell session");
            shell::host_shell_session(send, recv, username).await?;
        }
        Some(ClientMessage::RequestShellV2 { session_id }) => {
            tracing::info!("Starting persistent shell session (resume: {})", session_id.is_some());
            shell::host_shell_session_persistent(send, recv, username, peer_id, session_id, registry).await?;
        }
        Some(ClientMessage::RequestTransfer(req)) => {
            tracing::info!("Starting transfer session: {:?} (v{})", req.mode, protocol_version);
            transfer::host_transfer_session(conn, send, recv, req, username, protocol_version).await?;
        }
        Some(ClientMessage::RequestExec { command }) => {
            tracing::info!("Starting exec session: {command}");
            shell::host_exec_session(send, recv, &command, username).await?;
        }
        Some(other) => {
            tracing::warn!("Expected RequestShell, RequestTransfer, or RequestExec, got: {:?}", other);
        }
        None => {
            tracing::warn!("No session request message received");
        }
    }
    Ok(())
}

fn cmd_invite(secret_key: iroh::SecretKey, config_dir: &std::path::Path, username: Option<&str>, host_name: Option<&str>) -> Result<()> {
    let public_key = secret_key.public();

    // Default to current user when --user is not specified.
    // This ensures peers always have a bound username when the daemon runs as root.
    #[cfg(unix)]
    let default_user;
    #[cfg(unix)]
    let username = match username {
        Some(u) => Some(u),
        None => {
            default_user = hop_core::unix_user::current_username();
            default_user.as_deref()
        }
    };

    // Read relay URL persisted by the daemon (if available) so the client
    // can connect via relay immediately instead of waiting for discovery.
    let relay_url = std::fs::read_to_string(config_dir.join("relay_url")).ok();
    let token = invite::generate_invite(&public_key, config_dir, relay_url.as_deref(), username, host_name)?;

    println!("Invite token (share with the client):");
    println!();
    println!("  {token}");
    println!();
    println!("The client connects with:");
    println!("  hop connect {token}");
    println!();
    println!("This invite expires in 15 minutes and is single-use.");

    Ok(())
}

/// Resolved target info retained for reconnection.
struct ResolvedHost {
    host_id: PublicKey,
    relay_url: Option<RelayUrl>,
}

/// Perform target resolution, initial connection, auth (if invite), and send
/// the session request. Returns the resolved host info, the connection, and the
/// (send, recv) pair ready for the session.
async fn resolve_and_initial_connect(
    endpoint: &Endpoint,
    target: &str,
    config_dir: &std::path::Path,
    cli_name: Option<&str>,
    session_request: &ClientMessage,
) -> Result<(ResolvedHost, iroh::endpoint::Connection, iroh::endpoint::SendStream, iroh::endpoint::RecvStream)> {
    // 1. Check known_hosts for alias match
    let hosts = KnownHostsStore::load(config_dir)?;
    if let Some(node_id_str) = hosts.resolve_alias(target) {
        let host_id: PublicKey = node_id_str
            .parse()
            .context("Invalid NodeId in known_hosts")?;

        let relay_url: Option<RelayUrl> = hosts
            .hosts
            .iter()
            .find(|h| h.node_id == node_id_str)
            .and_then(|h| h.relay_url.as_deref())
            .map(|u| u.parse())
            .transpose()
            .ok()
            .flatten();

        println!("Resolved '{}' -> {}...", target, host_id.fmt_short());

        let (conn, relay_failed) = net::connect_to_host(endpoint, host_id, relay_url.as_ref()).await?;
        let relay_url = if relay_failed { None } else { relay_url };
        let (mut send, recv) = conn.open_bi().await?;
        proto::write_message(&mut send, session_request).await?;

        return Ok((ResolvedHost { host_id, relay_url }, conn, send, recv));
    }

    // 2. Check if invite token
    if invite::is_invite_token(target) {
        let token = invite::decode_invite(target)?;
        let host_id: PublicKey = token
            .node_id
            .parse()
            .context("Invalid NodeId in invite token")?;

        let relay_url: Option<RelayUrl> = token
            .relay_url
            .as_deref()
            .map(|u| u.parse())
            .transpose()
            .context("Invalid relay URL in invite token")?;

        println!("Connecting to host {}...", host_id.fmt_short());

        let (conn, _relay_failed) = net::connect_to_host(endpoint, host_id, relay_url.as_ref()).await?;
        let (mut send, mut recv) = conn.open_bi().await?;

        proto::write_message(
            &mut send,
            &ClientMessage::AuthResponse {
                secret: token.secret.as_bytes().to_vec(),
            },
        )
        .await?;

        let result: proto::HostMessage = proto::read_message(&mut recv).await?;
        match result {
            proto::HostMessage::AuthResult { authorized: true } => {
                println!("Authorized!");

                let desired_name = cli_name
                    .map(String::from)
                    .or(token.host_name)
                    .unwrap_or_else(|| format!("host-{}", host_id.fmt_short()));

                let mut hosts = KnownHostsStore::load(config_dir)?;
                let actual_name = hosts.add_host_dedup(
                    &host_id,
                    desired_name,
                    relay_url.as_ref().map(|u| u.to_string()),
                );
                hosts.save(config_dir)?;
                println!("Saved as known host: {actual_name}");

                // Send session request on the same stream — the host is waiting for it
                proto::write_message(&mut send, session_request).await?;

                return Ok((ResolvedHost { host_id, relay_url }, conn, send, recv));
            }
            proto::HostMessage::AuthResult { authorized: false } => {
                anyhow::bail!("Invite rejected by host (expired or already used)");
            }
            other => {
                anyhow::bail!("Unexpected response from host: {other:?}");
            }
        }
    }

    // 3. Parse as NodeId (64-char hex)
    let host_id: PublicKey = target
        .parse()
        .context("Unknown host alias, invalid invite token, or invalid NodeId")?;

    println!("Connecting to {}...", host_id.fmt_short());

    let (conn, _) = net::connect_to_host(endpoint, host_id, None).await?;
    let (mut send, recv) = conn.open_bi().await?;
    proto::write_message(&mut send, session_request).await?;

    Ok((ResolvedHost { host_id, relay_url: None }, conn, send, recv))
}

/// After a successful connection, query the remote's current relay URL and
/// update known_hosts so future connections use the freshest relay.
/// Returns the fresh relay URL (if any) so callers can update in-memory state.
async fn refresh_known_host_relay(
    endpoint: &Endpoint,
    host_id: &PublicKey,
    config_dir: &std::path::Path,
) -> Option<RelayUrl> {
    let remote_info = endpoint.remote_info(*host_id).await?;
    let fresh_relay_str = remote_info
        .addrs()
        .filter_map(|a| match a.addr() {
            TransportAddr::Relay(url) => Some(url.to_string()),
            _ => None,
        })
        .next();
    if let Ok(mut hosts) = KnownHostsStore::load(config_dir) {
        hosts.update_relay_url(&host_id.to_string(), fresh_relay_str.clone());
        let _ = hosts.save(config_dir);
    }
    let fresh_relay: Option<RelayUrl> = fresh_relay_str
        .as_deref()
        .map(|u| u.parse())
        .transpose()
        .ok()
        .flatten();
    if fresh_relay.is_some() {
        tracing::debug!("Refreshed relay URL for {}", host_id.fmt_short());
    }
    fresh_relay
}

/// Spawn a blocking stdin reader and return the receiver half.
fn spawn_stdin_reader() -> mpsc::Receiver<Vec<u8>> {
    let (input_tx, input_rx) = mpsc::channel::<Vec<u8>>(64);
    tokio::task::spawn_blocking(move || {
        let mut buf = [0u8; 1024];
        let stdin = std::io::stdin();
        loop {
            match stdin.lock().read(&mut buf) {
                Ok(0) => break,
                Ok(n) => {
                    if input_tx.blocking_send(buf[..n].to_vec()).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    input_rx
}

async fn cmd_connect(
    secret_key: iroh::SecretKey,
    target: &str,
    config_dir: &std::path::Path,
    cli_name: Option<&str>,
) -> Result<()> {
    let endpoint = net::create_client_endpoint(secret_key).await?;

    // Always use RequestShellV2 — supports session persistence.
    let (mut resolved, _conn, first_send, first_recv) =
        resolve_and_initial_connect(
            &endpoint, target, config_dir, cli_name,
            &ClientMessage::RequestShellV2 { session_id: None },
        ).await?;

    // Refresh relay URL
    if resolved.relay_url.is_some() {
        if let Some(fresh) = refresh_known_host_relay(&endpoint, &resolved.host_id, config_dir).await {
            resolved.relay_url = Some(fresh);
        }
    } else {
        if let Ok(mut hosts) = KnownHostsStore::load(config_dir) {
            hosts.update_relay_url(&resolved.host_id.to_string(), None);
            let _ = hosts.save(config_dir);
        }
    }

    // Spawn stdin reader once — shared across reconnections
    let mut stdin_rx = spawn_stdin_reader();

    // Run the first shell session
    let (mut session_id, mut outcome) =
        shell::client_shell_session_v2(first_send, first_recv, &mut stdin_rx).await?;

    // Reconnection loop
    loop {
        match outcome {
            SessionOutcome::Exited(code) => {
                std::process::exit(code);
            }
            SessionOutcome::Disconnected => {
                match reconnect::show_reconnect_tui(
                    &endpoint,
                    resolved.host_id,
                    resolved.relay_url.as_ref(),
                    &mut stdin_rx,
                )
                .await
                {
                    reconnect::ReconnectAction::Reconnected(conn) => {
                        let (mut send, recv) = conn.open_bi().await?;
                        proto::write_message(
                            &mut send,
                            &ClientMessage::RequestShellV2 {
                                session_id: session_id.clone(),
                            },
                        )
                        .await?;
                        let (new_sid, out) =
                            shell::client_shell_session_v2(send, recv, &mut stdin_rx).await?;
                        session_id = new_sid;
                        outcome = out;
                    }
                    reconnect::ReconnectAction::Quit => {
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}

async fn cmd_exec(
    secret_key: iroh::SecretKey,
    target: &str,
    config_dir: &std::path::Path,
    command: &[String],
) -> Result<()> {
    let command_str = command.join(" ");
    let endpoint = net::create_client_endpoint(secret_key).await?;

    let (resolved, _conn, send, recv) = resolve_and_initial_connect(
        &endpoint,
        target,
        config_dir,
        None,
        &ClientMessage::RequestExec { command: command_str },
    )
    .await?;

    refresh_known_host_relay(&endpoint, &resolved.host_id, config_dir).await;

    let mut stdin_rx = spawn_stdin_reader();
    let outcome = shell::client_exec_session(send, recv, &mut stdin_rx).await?;

    match outcome {
        SessionOutcome::Exited(code) => std::process::exit(code),
        SessionOutcome::Disconnected => {
            eprintln!("Connection lost");
            std::process::exit(1);
        }
    }
}

async fn cmd_cp(
    secret_key: iroh::SecretKey,
    config_dir: &std::path::Path,
    recursive: bool,
    paths: &[String],
) -> Result<()> {
    if paths.len() < 2 {
        anyhow::bail!("cp requires at least a source and destination");
    }

    let dest_spec = transfer::parse_path_spec(paths.last().unwrap());
    let source_specs: Vec<PathSpec> = paths[..paths.len() - 1]
        .iter()
        .map(|p| transfer::parse_path_spec(p))
        .collect();

    // Determine direction: exactly one side must be remote
    let sources_have_remote = source_specs.iter().any(|s| matches!(s, PathSpec::Remote { .. }));
    let dest_is_remote = matches!(dest_spec, PathSpec::Remote { .. });

    if sources_have_remote && dest_is_remote {
        anyhow::bail!("remote-to-remote copy is not supported");
    }
    if !sources_have_remote && !dest_is_remote {
        anyhow::bail!("one side must be remote (use host:path notation)");
    }

    let endpoint = net::create_client_endpoint(secret_key).await?;

    if dest_is_remote {
        // Push: local sources -> remote dest
        let (host, remote_path) = match &dest_spec {
            PathSpec::Remote { host, path } => (host.as_str(), path.as_str()),
            _ => unreachable!(),
        };

        let local_paths: Vec<std::path::PathBuf> = source_specs
            .iter()
            .map(|s| match s {
                PathSpec::Local(p) => Ok(p.clone()),
                PathSpec::Remote { .. } => anyhow::bail!("mixed local/remote sources not supported"),
            })
            .collect::<Result<Vec<_>>>()?;

        // Validate local paths exist and check recursive requirement
        for p in &local_paths {
            if !p.exists() {
                anyhow::bail!("source path does not exist: {}", p.display());
            }
            if p.is_dir() && !recursive {
                anyhow::bail!("{} is a directory (use -r for recursive copy)", p.display());
            }
        }

        let request = TransferRequest {
            mode: TransferMode::Copy { recursive },
            direction: TransferDirection::Push,
            remote_path: remote_path.to_string(),
            delete_extraneous: false,
            dry_run: false,
        };

        let (resolved, conn, mut send, mut recv) = resolve_and_initial_connect(
            &endpoint,
            host,
            config_dir,
            None,
            &ClientMessage::RequestTransfer(request),
        )
        .await?;

        refresh_known_host_relay(&endpoint, &resolved.host_id, config_dir).await;

        let protocol_version = net::negotiated_protocol_version(&conn);
        let params = if protocol_version >= 1 {
            transfer::negotiate_client(&mut send, &mut recv).await?
        } else {
            transfer::negotiation::NegotiatedParams::legacy()
        };

        let state = progress_ui::TransferState::new(true);
        let render_handle = progress_ui::spawn_render_loop(state.clone());

        let summary =
            transfer::client_push_copy(&conn, &mut send, &mut recv, &local_paths, &state, &params).await?;
        state.mark_finished();
        let _ = render_handle.await;
        let _ = send.finish();
        eprintln!("{summary}");
    } else {
        // Pull: remote source -> local dest
        if source_specs.len() != 1 {
            anyhow::bail!("pull mode supports only one remote source");
        }

        let (host, remote_path) = match &source_specs[0] {
            PathSpec::Remote { host, path } => (host.as_str(), path.as_str()),
            _ => unreachable!(),
        };

        let local_dest = match &dest_spec {
            PathSpec::Local(p) => p.clone(),
            _ => unreachable!(),
        };

        let request = TransferRequest {
            mode: TransferMode::Copy { recursive },
            direction: TransferDirection::Pull,
            remote_path: remote_path.to_string(),
            delete_extraneous: false,
            dry_run: false,
        };

        let (resolved, conn, mut send, mut recv) = resolve_and_initial_connect(
            &endpoint,
            host,
            config_dir,
            None,
            &ClientMessage::RequestTransfer(request),
        )
        .await?;

        refresh_known_host_relay(&endpoint, &resolved.host_id, config_dir).await;

        let protocol_version = net::negotiated_protocol_version(&conn);
        let params = if protocol_version >= 1 {
            transfer::negotiate_client(&mut send, &mut recv).await?
        } else {
            transfer::negotiation::NegotiatedParams::legacy()
        };

        let state = progress_ui::TransferState::new(false);
        let render_handle = progress_ui::spawn_render_loop(state.clone());

        let summary =
            transfer::client_pull_copy(&conn, &mut send, &mut recv, &local_dest, &state, &params).await?;
        state.mark_finished();
        let _ = render_handle.await;
        let _ = send.finish();
        eprintln!("{summary}");
    }

    Ok(())
}

async fn cmd_sync(
    secret_key: iroh::SecretKey,
    config_dir: &std::path::Path,
    delete: bool,
    dry_run: bool,
    _verbose: bool,
    source: &str,
    dest: &str,
) -> Result<()> {
    let source_spec = transfer::parse_path_spec(source);
    let dest_spec = transfer::parse_path_spec(dest);

    let source_is_remote = matches!(source_spec, PathSpec::Remote { .. });
    let dest_is_remote = matches!(dest_spec, PathSpec::Remote { .. });

    if source_is_remote && dest_is_remote {
        anyhow::bail!("remote-to-remote sync is not supported");
    }
    if !source_is_remote && !dest_is_remote {
        anyhow::bail!("one side must be remote (use host:path notation)");
    }

    let endpoint = net::create_client_endpoint(secret_key).await?;

    if dry_run {
        eprintln!("DRY RUN \u{2014} no files will be transferred");
    }

    if dest_is_remote {
        // Push sync: local -> remote
        let local_dir = match &source_spec {
            PathSpec::Local(p) => p.clone(),
            _ => unreachable!(),
        };
        let (host, remote_path) = match &dest_spec {
            PathSpec::Remote { host, path } => (host.as_str(), path.as_str()),
            _ => unreachable!(),
        };

        if !local_dir.is_dir() {
            anyhow::bail!("sync source must be a directory: {}", local_dir.display());
        }

        let request = TransferRequest {
            mode: TransferMode::Sync,
            direction: TransferDirection::Push,
            remote_path: remote_path.to_string(),
            delete_extraneous: delete,
            dry_run,
        };

        let (resolved, conn, mut send, mut recv) = resolve_and_initial_connect(
            &endpoint,
            host,
            config_dir,
            None,
            &ClientMessage::RequestTransfer(request.clone()),
        )
        .await?;

        refresh_known_host_relay(&endpoint, &resolved.host_id, config_dir).await;

        let protocol_version = net::negotiated_protocol_version(&conn);
        let params = if protocol_version >= 1 {
            transfer::negotiate_client(&mut send, &mut recv).await?
        } else {
            transfer::negotiation::NegotiatedParams::legacy()
        };

        let state = progress_ui::TransferState::new(true);
        let render_handle = progress_ui::spawn_render_loop(state.clone());

        let summary =
            transfer::client_push_sync(&conn, &mut send, &mut recv, &local_dir, &request, &state, &params)
                .await?;
        state.mark_finished();
        let _ = render_handle.await;
        let _ = send.finish();
        eprintln!("{summary}");
    } else {
        // Pull sync: remote -> local
        let (host, remote_path) = match &source_spec {
            PathSpec::Remote { host, path } => (host.as_str(), path.as_str()),
            _ => unreachable!(),
        };
        let local_dir = match &dest_spec {
            PathSpec::Local(p) => p.clone(),
            _ => unreachable!(),
        };

        let request = TransferRequest {
            mode: TransferMode::Sync,
            direction: TransferDirection::Pull,
            remote_path: remote_path.to_string(),
            delete_extraneous: delete,
            dry_run,
        };

        let (resolved, conn, mut send, mut recv) = resolve_and_initial_connect(
            &endpoint,
            host,
            config_dir,
            None,
            &ClientMessage::RequestTransfer(request.clone()),
        )
        .await?;

        refresh_known_host_relay(&endpoint, &resolved.host_id, config_dir).await;

        let protocol_version = net::negotiated_protocol_version(&conn);
        let params = if protocol_version >= 1 {
            transfer::negotiate_client(&mut send, &mut recv).await?
        } else {
            transfer::negotiation::NegotiatedParams::legacy()
        };

        let state = progress_ui::TransferState::new(false);
        let render_handle = progress_ui::spawn_render_loop(state.clone());

        let summary =
            transfer::client_pull_sync(&conn, &mut send, &mut recv, &local_dir, &request, &state, &params)
                .await?;
        state.mark_finished();
        let _ = render_handle.await;
        let _ = send.finish();
        eprintln!("{summary}");
    }

    Ok(())
}

fn cmd_peers(action: Option<PeersAction>, host_config_dir: &std::path::Path, user_config_dir: &std::path::Path) -> Result<()> {
    let mut peers = PeersStore::load(host_config_dir)?;
    let hosts = KnownHostsStore::load(user_config_dir)?;

    match action {
        None => {
            if !peers.peers.is_empty() {
                println!("Authorized peers:");
                for peer in &peers.peers {
                    let last_seen = peer
                        .last_seen
                        .as_deref()
                        .unwrap_or("never");
                    let user_info = peer
                        .username
                        .as_deref()
                        .map(|u| format!(", user: {u}"))
                        .unwrap_or_default();
                    println!(
                        "  {} ({}) - authorized: {}, last seen: {}{user_info}",
                        &peer.node_id[..10],
                        peer.name,
                        peer.authorized_at,
                        last_seen
                    );
                }
            } else {
                println!("No authorized peers.");
            }

            if !hosts.hosts.is_empty() {
                println!();
                println!("Known hosts:");
                for host in &hosts.hosts {
                    println!(
                        "  {} ({}) - added: {}",
                        &host.node_id[..10],
                        host.name,
                        host.added_at
                    );
                }
            }

            Ok(())
        }
        Some(PeersAction::Remove { id }) => {
            if peers.remove_peer(&id) {
                peers.save(host_config_dir)?;
                println!("Peer removed.");
            } else {
                println!("No peer found matching '{id}'.");
            }
            Ok(())
        }
        Some(PeersAction::Rename { id, name }) => {
            if peers.rename_peer(&id, name.clone()) {
                peers.save(host_config_dir)?;
                println!("Peer renamed to '{name}'.");
            } else {
                let mut hosts = KnownHostsStore::load(user_config_dir)?;
                if hosts.rename_host(&id, name.clone()) {
                    hosts.save(user_config_dir)?;
                    println!("Known host renamed to '{name}'.");
                } else {
                    println!("No peer or known host found matching '{id}'.");
                }
            }
            Ok(())
        }
    }
}
