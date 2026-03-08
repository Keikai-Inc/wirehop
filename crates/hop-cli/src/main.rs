mod agent;
mod cli;
mod itemize;
mod mux;
mod progress_ui;
mod reconnect;

use std::collections::HashSet;
use std::io::Read;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{AdminAction, AgentAction, Cli, Command, ConfigAction, FleetAction, PeersAction, RoleAction};
use iroh::endpoint::{RecvStream, SendStream};
use iroh::Watcher;
use tokio::sync::mpsc;
use tracing_subscriber::EnvFilter;

use hop_core::auth::{self, AuthOutcome};
use hop_core::config::{self, HostConfig, KnownHostsStore, PeerRole, PeersStore};
use hop_core::invite;
use hop_core::net;
use hop_core::proto::{
    self, AdminRequest, AdminResponse, ClientMessage, RoleDefinition, RoleUpdates, UserMode,
    TransferDirection, TransferMode, TransferMsg, TransferRequest,
};
use hop_core::shell::{self, SessionOutcome};
use hop_core::shell::session_registry::SessionRegistry;
use hop_core::transfer::{self, PathSpec};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Initialize tracing — respect RUST_LOG if set, otherwise use verbosity flag
    let filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new(match cli.verbose {
            0 => "hop=info",
            1 => "hop=debug",
            _ => "hop=trace",
        })
    };
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .init();

    match cli.command {
        Command::Host { quiet } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_host(secret_key, &config_dir, quiet).await
        }
        Command::Invite { user, name, read_only, no_network, scopes, allow_commands, preset } => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_identity(&config_dir)?;
            let sandbox = build_sandbox_policy(preset.as_deref(), read_only, no_network, &scopes, &allow_commands)?;
            cmd_invite(secret_key, &config_dir, user.as_deref(), name.as_deref(), sandbox)
        }
        Command::Connect { target, name, read_only, no_network, scopes, allow_commands, preset } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            let sandbox = build_sandbox_policy(preset.as_deref(), read_only, no_network, &scopes, &allow_commands)?;
            cmd_connect(secret_key, &target, &config_dir, name.as_deref(), sandbox).await
        }
        Command::Exec { target, read_only, no_network, scopes, allow_commands, preset, command } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            let sandbox = build_sandbox_policy(preset.as_deref(), read_only, no_network, &scopes, &allow_commands)?;
            cmd_exec(secret_key, &target, &config_dir, &command, sandbox).await
        }
        Command::Cp { recursive, paths } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_cp(secret_key, &config_dir, recursive, &paths).await
        }
        Command::Sync {
            delete,
            dry_run,
            itemize,
            stats,
            no_progress,
            source,
            dest,
            // no-op compat flags
            archive: _,
            compress: _,
            partial_progress: _,
            progress: _,
            human_readable: _,
        } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_sync(secret_key, &config_dir, delete, dry_run, itemize, stats, no_progress, &source, &dest).await
        }
        Command::Config { action } => {
            let host_config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            cmd_config(action, &host_config_dir)
        }
        Command::Peers { action } => {
            let host_config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            let user_config_dir = config::default_config_dir()?;
            cmd_peers(action, &host_config_dir, &user_config_dir)
        }
        Command::On { target, name, read_only, no_network, scopes, allow_commands, preset } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            let sandbox = build_sandbox_policy(preset.as_deref(), read_only, no_network, &scopes, &allow_commands)?;
            cmd_connect(secret_key, &target, &config_dir, name.as_deref(), sandbox).await
        }
        Command::Admin { target, action } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_admin(secret_key, &target, &config_dir, action).await
        }
        Command::CreatorInvite => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            cmd_creator_invite(&config_dir)
        }
        Command::Fleet { action } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_fleet(secret_key, &config_dir, action).await
        }
        Command::Mcp => {
            // MCP server: all output goes to stdout (JSON-RPC), logs to stderr only
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            hop_mcp::run_stdio_server(&config_dir).await
        }
        Command::Id => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            let public_key = secret_key.public();
            println!("{public_key}");
            Ok(())
        }
        Command::Agent { action, daemon, config: agent_config } => {
            let config_dir = config::ensure_config_dir(
                agent_config.as_deref().or(cli.config.as_deref()),
            )?;
            match action {
                Some(AgentAction::Stop) => agent::stop_agent(&config_dir),
                Some(AgentAction::Status) => agent::agent_status(&config_dir),
                None if daemon => agent::run_daemon(&config_dir).await,
                None => agent::run_foreground(&config_dir).await,
            }
        }
        Command::External(args) => {
            let target = args.first().context("no target specified")?;
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;

            // "hop myhost -- cmd args" → exec shorthand
            if let Some(sep) = args.iter().position(|a| a == "--") {
                let command = args[sep + 1..].to_vec();
                if command.is_empty() {
                    anyhow::bail!("no command specified after --");
                }
                cmd_exec(secret_key, target, &config_dir, &command, hop_core::sandbox::SandboxPolicy::default()).await
            } else {
                cmd_connect(secret_key, target, &config_dir, None, hop_core::sandbox::SandboxPolicy::default()).await
            }
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

    // Generate creator invite on first startup (empty peers.json + no creator_invite file)
    {
        let peers = PeersStore::load(config_dir)?;
        let creator_invite_path = config_dir.join("creator_invite");
        if peers.peers.is_empty() && !creator_invite_path.exists() {
            let relay_url_str = relay_url.as_ref().map(|u| u.to_string());
            match invite::generate_invite_with_role(
                &public_key,
                config_dir,
                relay_url_str.as_deref(),
                None,
                None,
                PeerRole::Creator,
                3600, // 1-hour expiry
                hop_core::sandbox::SandboxPolicy::default(),
            ) {
                Ok(token) => {
                    // Write to file with restricted permissions
                    if let Err(e) = config::write_shared_file(&creator_invite_path, &token) {
                        tracing::warn!("Failed to write creator_invite: {e}");
                    } else {
                        if !quiet {
                            println!();
                            println!("=== CREATOR INVITE (expires in 1 hour) ===");
                            println!();
                            println!("  hop connect {token}");
                            println!();
                            println!("This grants full admin access. Use it to set up the first administrator.");
                            println!("Re-read with: hop creator-invite");
                            println!();
                        }
                        tracing::info!("Creator invite generated and saved to {}", creator_invite_path.display());
                    }
                }
                Err(e) => {
                    tracing::warn!("Failed to generate creator invite: {e}");
                }
            }
        }
    }

    // Seed default roles on first startup
    {
        let roles_path = config_dir.join("roles.json");
        if !roles_path.exists() {
            match hop_core::fleet::RolesStore::seed_defaults(config_dir) {
                Ok(store) => {
                    if !quiet {
                        println!(
                            "Created default roles ({}):",
                            store.roles.iter().map(|r| r.name.as_str()).collect::<Vec<_>>().join(", ")
                        );
                        println!("  Edit with: hop admin <host> role list/update/delete");
                        println!("  Or edit roles.json directly.");
                        println!();
                    }
                }
                Err(e) => tracing::warn!("Failed to seed default roles: {e}"),
            }
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

    // Load host configuration
    let host_config = HostConfig::load(config_dir)?;
    tracing::info!(
        "Session config: timeout={}s, max_sessions={}",
        host_config.session_timeout_secs,
        host_config.max_sessions
    );

    // Session registry for persistent PTY sessions
    let registry = Arc::new(tokio::sync::Mutex::new(
        SessionRegistry::new(
            Duration::from_secs(host_config.session_timeout_secs),
            host_config.max_sessions,
        ),
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

    // First bi-stream: full authentication
    let (mut send, mut recv) = conn.accept_bi().await?;

    let (outcome, _first_msg) = auth::authenticate_client(
        &mut send,
        &mut recv,
        &remote_id,
        config_dir,
    )
    .await?;

    let peer_id = remote_id.to_string();

    let (username, role, sandbox) = match outcome {
        AuthOutcome::Authorized { username, role, sandbox } => {
            tracing::info!("Authorized peer {} (role: {:?})", remote_id.fmt_short(), role);
            // Spawn first session
            let conn_c = conn.clone();
            let reg = registry.clone();
            let u = username.clone();
            let r = role.clone();
            let s = sandbox.clone();
            let pid = peer_id.clone();
            let cd = config_dir.to_path_buf();
            tokio::spawn(async move {
                if let Err(e) = dispatch_session(_first_msg, conn_c, send, recv, u.as_deref(), protocol_version, &pid, &r, &s, &cd, reg).await {
                    tracing::error!("Session error: {e:#}");
                }
            });
            (username, role, sandbox)
        }
        AuthOutcome::InviteAccepted { username, role, sandbox } => {
            tracing::info!("Invite accepted for {} (role: {:?}), waiting for session request", remote_id.fmt_short(), role);
            let msg: ClientMessage = proto::read_message(&mut recv).await?;
            // Spawn first session
            let conn_c = conn.clone();
            let reg = registry.clone();
            let u = username.clone();
            let r = role.clone();
            let s = sandbox.clone();
            let pid = peer_id.clone();
            let cd = config_dir.to_path_buf();
            tokio::spawn(async move {
                if let Err(e) = dispatch_session(Some(msg), conn_c, send, recv, u.as_deref(), protocol_version, &pid, &r, &s, &cd, reg).await {
                    tracing::error!("Session error: {e:#}");
                }
            });
            (username, role, sandbox)
        }
        AuthOutcome::Rejected => {
            tracing::info!("Rejected connection from {}", remote_id.fmt_short());
            return Ok(());
        }
    };

    // Additional bi-streams: already authenticated (same QUIC connection = same peer).
    // This enables connection multiplexing — multiple sessions over one connection.
    loop {
        match conn.accept_bi().await {
            Ok((send, mut recv)) => {
                let msg: ClientMessage = match proto::read_message(&mut recv).await {
                    Ok(msg) => msg,
                    Err(e) => {
                        tracing::debug!("Failed to read message on multiplexed stream: {e:#}");
                        continue;
                    }
                };
                let conn_c = conn.clone();
                let reg = registry.clone();
                let u = username.clone();
                let r = role.clone();
                let s = sandbox.clone();
                let pid = peer_id.clone();
                let cd = config_dir.to_path_buf();
                tokio::spawn(async move {
                    if let Err(e) = dispatch_session(Some(msg), conn_c, send, recv, u.as_deref(), protocol_version, &pid, &r, &s, &cd, reg).await {
                        tracing::error!("Session error: {e:#}");
                    }
                });
            }
            Err(_) => break, // Connection closed
        }
    }

    Ok(())
}

async fn dispatch_session(
    msg: Option<ClientMessage>,
    conn: iroh::endpoint::Connection,
    mut send: SendStream,
    recv: RecvStream,
    username: Option<&str>,
    protocol_version: u8,
    peer_id: &str,
    role: &config::PeerRole,
    sandbox: &hop_core::sandbox::SandboxPolicy,
    config_dir: &std::path::Path,
    registry: Arc<tokio::sync::Mutex<SessionRegistry>>,
) -> Result<()> {
    match msg {
        Some(ClientMessage::RequestShell) => {
            tracing::info!("Starting shell session");
            shell::host_shell_session(send, recv, username, sandbox).await?;
        }
        Some(ClientMessage::RequestShellV2 { session_id }) => {
            tracing::info!("Starting persistent shell session (resume: {})", session_id.is_some());
            shell::host_shell_session_persistent(send, recv, username, peer_id, session_id, registry, sandbox).await?;
        }
        Some(ClientMessage::RequestShellV3 { session_id, sandbox: client_sandbox }) => {
            let merged = sandbox.merge_stricter(&client_sandbox);
            tracing::info!("Starting persistent shell session with client sandbox (resume: {})", session_id.is_some());
            shell::host_shell_session_persistent(send, recv, username, peer_id, session_id, registry, &merged).await?;
        }
        Some(ClientMessage::RequestTransfer(req)) => {
            tracing::info!("Starting transfer session: {:?} (v{})", req.mode, protocol_version);
            transfer::host_transfer_session(conn, send, recv, req, username, protocol_version).await?;
        }
        Some(ClientMessage::RequestExec { command }) => {
            tracing::info!("Starting exec session: {command}");
            shell::host_exec_session(send, recv, &command, username, sandbox).await?;
        }
        Some(ClientMessage::RequestExecV2 { command, sandbox: client_sandbox }) => {
            let merged = sandbox.merge_stricter(&client_sandbox);
            tracing::info!("Starting exec session with client sandbox: {command}");
            shell::host_exec_session(send, recv, &command, username, &merged).await?;
        }
        Some(ClientMessage::RequestAdmin(request)) => {
            if *role != config::PeerRole::Creator {
                tracing::warn!("Non-creator peer {} attempted admin request", peer_id);
                let resp = AdminResponse::Error {
                    message: "permission denied: creator role required".to_string(),
                };
                proto::write_message(&mut send, &proto::HostMessage::AdminResponse(resp)).await?;
                return Ok(());
            }
            tracing::info!("Admin request from creator {}: {:?}", peer_id, request);
            let relay_url = std::fs::read_to_string(config_dir.join("relay_url")).ok();
            let secret_key = config::load_identity(config_dir)?;
            let host_public_key = secret_key.public();
            let response = hop_core::admin::handle_admin_request(
                request,
                config_dir,
                relay_url.as_deref(),
                &host_public_key,
            );
            proto::write_message(&mut send, &proto::HostMessage::AdminResponse(response)).await?;
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

fn cmd_invite(
    secret_key: iroh::SecretKey,
    config_dir: &std::path::Path,
    username: Option<&str>,
    host_name: Option<&str>,
    sandbox: hop_core::sandbox::SandboxPolicy,
) -> Result<()> {
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
    let token = invite::generate_invite_with_role(
        &public_key,
        config_dir,
        relay_url.as_deref(),
        username,
        host_name,
        PeerRole::Peer,
        15 * 60,
        sandbox.clone(),
    )?;

    println!("Invite token (share with the client):");
    println!();
    println!("  {token}");
    println!();
    println!("The client connects with:");
    println!("  hop connect {token}");
    println!();
    println!("This invite expires in 15 minutes and is single-use.");
    if sandbox.is_restricted() {
        println!();
        println!("Sandbox restrictions:");
        if sandbox.read_only { println!("  - Read-only filesystem"); }
        if sandbox.no_network { println!("  - No network access"); }
        if !sandbox.allowed_paths.is_empty() {
            println!("  - Scoped to: {}", sandbox.allowed_paths.iter().map(|p| p.display().to_string()).collect::<Vec<_>>().join(", "));
        }
        if !sandbox.allowed_commands.is_empty() {
            println!("  - Allowed commands: {}", sandbox.allowed_commands.join(", "));
        }
    }

    Ok(())
}

/// Build a SandboxPolicy from CLI flags.
fn build_sandbox_policy(
    preset: Option<&str>,
    read_only: bool,
    no_network: bool,
    scopes: &[std::path::PathBuf],
    allow_commands: &[String],
) -> Result<hop_core::sandbox::SandboxPolicy> {
    use hop_core::sandbox::SandboxPolicy;

    let base = if let Some(name) = preset {
        SandboxPolicy::from_preset(name)
            .ok_or_else(|| anyhow::anyhow!("unknown sandbox preset: '{name}' (valid: monitor, audit, deploy)"))?
    } else {
        SandboxPolicy::default()
    };

    // Apply overrides — only set flags that were explicitly passed
    let ro = if read_only { Some(true) } else { None };
    let nn = if no_network { Some(true) } else { None };

    Ok(base.with_overrides(ro, nn, scopes, allow_commands))
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

/// Rebuild a session request with a different session_id, preserving sandbox policy.
fn rebuild_session_request(
    original: &ClientMessage,
    session_id: Option<String>,
) -> ClientMessage {
    match original {
        ClientMessage::RequestShellV3 { sandbox, .. } => ClientMessage::RequestShellV3 {
            session_id,
            sandbox: sandbox.clone(),
        },
        _ => ClientMessage::RequestShellV2 { session_id },
    }
}

async fn cmd_connect(
    _secret_key: iroh::SecretKey,
    target: &str,
    config_dir: &std::path::Path,
    cli_name: Option<&str>,
    sandbox: hop_core::sandbox::SandboxPolicy,
) -> Result<()> {
    // Choose the protocol variant based on whether sandbox is restricted
    let session_msg: ClientMessage = if sandbox.is_restricted() {
        ClientMessage::RequestShellV3 { session_id: None, sandbox }
    } else {
        ClientMessage::RequestShellV2 { session_id: None }
    };

    // Connect through the agent (avoids relay conflicts, enables multiplexing)
    let (resolved, first_send, first_recv) =
        mux::connect_to_host(
            config_dir, target, cli_name,
            &session_msg,
        ).await?;

    // Spawn stdin reader once — shared across reconnections
    let mut stdin_rx = spawn_stdin_reader();

    // Run the first shell session
    let (mut session_id, mut outcome) =
        shell::client_shell_session_v2(first_send, first_recv, &mut stdin_rx).await?;

    // Anti-flapping state: track recent reconnections to detect rapid cycling
    let mut last_reconnect_time: Option<std::time::Instant> = None;
    let mut flap_attempt_offset: u32 = 0;

    // Reconnection loop
    loop {
        match outcome {
            SessionOutcome::Exited(code) => {
                std::process::exit(code);
            }
            SessionOutcome::Disconnected => {
                // Detect flapping: disconnect within 10s of last reconnect
                if let Some(last) = last_reconnect_time {
                    if last.elapsed() < Duration::from_secs(10) {
                        flap_attempt_offset = (flap_attempt_offset + 2).min(5);
                        tracing::warn!(
                            "Flapping detected (disconnected {}s after reconnect), offset={}",
                            last.elapsed().as_secs(),
                            flap_attempt_offset,
                        );
                    } else {
                        flap_attempt_offset = 0;
                    }
                }

                // Tier 1: Quick inline reconnect (non-disruptive, 5s window)
                // Skip if flapping — go straight to full TUI with backoff
                let reconnect_msg = rebuild_session_request(
                    &session_msg,
                    session_id.clone(),
                );

                let quick_result = if flap_attempt_offset == 0 {
                    reconnect::try_quick_reconnect(
                        config_dir,
                        &resolved,
                        &reconnect_msg,
                        Duration::from_secs(5),
                    )
                    .await
                } else {
                    None
                };

                let reconnect_result = if let Some(action) = quick_result {
                    action
                } else {
                    // Tier 2: Full alternate-screen TUI with backoff
                    reconnect::show_reconnect_tui_via_agent(
                        config_dir,
                        &resolved,
                        &reconnect_msg,
                        &mut stdin_rx,
                        flap_attempt_offset,
                    )
                    .await
                };

                match reconnect_result {
                    reconnect::ReconnectAction::ReconnectedViaAgent {
                        send,
                        recv,
                        new_session_id,
                    } => {
                        // Brief stabilization delay to let the connection settle
                        tokio::time::sleep(Duration::from_millis(500)).await;

                        last_reconnect_time = Some(std::time::Instant::now());

                        let (new_sid, out) =
                            shell::client_shell_session_v2(send, recv, &mut stdin_rx).await?;
                        session_id = new_sid.or(new_session_id);
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
    _secret_key: iroh::SecretKey,
    target: &str,
    config_dir: &std::path::Path,
    command: &[String],
    sandbox: hop_core::sandbox::SandboxPolicy,
) -> Result<()> {
    let command_str = command.join(" ");

    let exec_msg: ClientMessage = if sandbox.is_restricted() {
        ClientMessage::RequestExecV2 { command: command_str, sandbox }
    } else {
        ClientMessage::RequestExec { command: command_str }
    };

    let (_resolved, send, recv) = mux::connect_to_host(
        config_dir,
        target,
        None,
        &exec_msg,
    )
    .await?;

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
    _secret_key: iroh::SecretKey,
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

        let (_resolved, mut send, mut recv) = mux::connect_to_host(
            config_dir, host, None,
            &ClientMessage::RequestTransfer(request),
        ).await?;

        // Negotiate params (always use v2 through agent)
        let params = transfer::negotiate_client(&mut send, &mut recv).await?;

        let state = progress_ui::TransferState::new(true);
        let render_handle = progress_ui::spawn_render_loop(state.clone());

        let summary =
            transfer::client_push_copy(&mut send, &mut recv, &local_paths, &state, &params).await?;
        state.mark_finished();
        let _ = render_handle.await;
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

        let (_resolved, mut send, mut recv) = mux::connect_to_host(
            config_dir, host, None,
            &ClientMessage::RequestTransfer(request),
        ).await?;

        let params = transfer::negotiate_client(&mut send, &mut recv).await?;

        // When pulling a remote directory into an existing local directory,
        // nest under the source directory name (like scp -r / cp -r).
        let effective_dest = if recursive && local_dest.is_dir() {
            let dir_name = std::path::Path::new(remote_path)
                .file_name()
                .unwrap_or_default();
            if !dir_name.is_empty() {
                let nested = local_dest.join(dir_name);
                std::fs::create_dir_all(&nested)?;
                nested
            } else {
                local_dest.clone()
            }
        } else {
            local_dest.clone()
        };

        let state = progress_ui::TransferState::new(false);
        let render_handle = progress_ui::spawn_render_loop(state.clone());

        let summary =
            transfer::client_pull_copy(&mut send, &mut recv, &effective_dest, &state, &params).await?;
        state.mark_finished();
        let _ = render_handle.await;
        eprintln!("{summary}");
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
async fn cmd_sync(
    _secret_key: iroh::SecretKey,
    config_dir: &std::path::Path,
    delete: bool,
    dry_run: bool,
    itemize: bool,
    stats: bool,
    no_progress: bool,
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

        let (_resolved, mut send, mut recv) = mux::connect_to_host(
            config_dir, host, None,
            &ClientMessage::RequestTransfer(request.clone()),
        ).await?;

        let params = transfer::negotiate_client(&mut send, &mut recv).await?;

        // Print rsync-style header
        eprintln!(
            "sending file list to {}:{}",
            host, remote_path,
        );

        // Phase 1: negotiate (get plan + local/remote entries for itemize)
        let negotiation =
            transfer::client_push_sync_negotiate(&mut send, &mut recv, &local_dir, &request).await?;

        // Check if nothing to do
        if negotiation.plan.files_to_send.is_empty()
            && negotiation.plan.files_to_delete.is_empty()
            && !dry_run
        {
            // Read host's Done
            let msg: TransferMsg = proto::read_message(&mut recv).await?;
            match msg {
                TransferMsg::Done => {}
                other => tracing::warn!("expected Done from host, got: {other:?}"),
            }
            eprintln!("Already up to date.");
            return Ok(());
        }

        // Compute itemize map if requested
        let itemize_map = if itemize {
            itemize::compute_itemize_map(
                &negotiation.plan.files_to_send,
                &negotiation.remote_entries,
                true, // is_push
            )
        } else {
            std::collections::HashMap::new()
        };

        // Dry run with -i: print itemize strings and exit
        if dry_run && itemize {
            for entry in &negotiation.plan.files_to_send {
                if let Some(change_str) = itemize_map.get(&entry.path) {
                    if entry.is_dir {
                        eprintln!("{} {}/", change_str, entry.path);
                    } else {
                        eprintln!("{} {}", change_str, entry.path);
                    }
                }
            }
            for path in &negotiation.plan.files_to_delete {
                eprintln!("*deleting   {}", path);
            }
        }

        let total_file_count = negotiation.plan.files_to_send
            .iter()
            .filter(|e| !e.is_dir && !e.is_symlink)
            .count();
        let existing_dirs: HashSet<String> = negotiation.remote_entries
            .iter()
            .filter(|e| e.is_dir)
            .map(|e| e.path.clone())
            .collect();

        let state = progress_ui::TransferState::with_mode(
            true,
            progress_ui::DisplayMode::Rsync,
            total_file_count,
            existing_dirs,
        );
        state.set_itemize_map(itemize_map);
        state.set_no_progress(no_progress);
        let render_handle = progress_ui::spawn_render_loop(state.clone());

        let summary = transfer::client_push_sync_transfer(
            &mut send, &mut recv, &local_dir, &request, negotiation, &state, &params,
        ).await?;
        state.mark_finished();
        let _ = render_handle.await;
        eprintln!("{}", summary.format_rsync());
        if stats {
            eprintln!("\n{}", summary.format_stats());
        }
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

        // rsync convention: no trailing slash → sync the directory itself,
        // trailing slash → sync the contents into dest.
        let effective_dir = if !remote_path.ends_with('/') && local_dir.is_dir() {
            let dir_name = std::path::Path::new(remote_path)
                .file_name()
                .unwrap_or_default();
            if !dir_name.is_empty() {
                let nested = local_dir.join(dir_name);
                std::fs::create_dir_all(&nested)?;
                nested
            } else {
                local_dir.clone()
            }
        } else {
            local_dir.clone()
        };

        let request = TransferRequest {
            mode: TransferMode::Sync,
            direction: TransferDirection::Pull,
            remote_path: remote_path.to_string(),
            delete_extraneous: delete,
            dry_run,
        };

        let (_resolved, mut send, mut recv) = mux::connect_to_host(
            config_dir, host, None,
            &ClientMessage::RequestTransfer(request.clone()),
        ).await?;

        let params = transfer::negotiate_client(&mut send, &mut recv).await?;

        // Phase 1: plan exchange (before progress UI so no "0/0 files" flash)
        let plan =
            transfer::client_pull_sync_negotiate(&mut send, &mut recv, &effective_dir).await?;

        if plan.files_to_send.is_empty() && plan.files_to_delete.is_empty() && !plan.dry_run {
            // Nothing to transfer — still need to complete the protocol:
            // send PlanAck, host sends Done (0 files), we read it, send Done back.
            proto::write_message(&mut send, &TransferMsg::PlanAck { proceed: true }).await?;
            // Host sends 0 files then Done — read it
            let msg: TransferMsg = proto::read_message(&mut recv).await?;
            match msg {
                TransferMsg::Done => {}
                other => tracing::warn!("expected Done, got: {other:?}"),
            }
            let _ = proto::write_message(&mut send, &TransferMsg::Done).await;
            eprintln!("Already up to date.");
        } else {
            // Compute itemize map if requested: walk local dir for comparison
            let itemize_map = if itemize {
                let local_entries = if effective_dir.is_dir() {
                    hop_core::transfer::listing::walk_directory(&effective_dir)
                        .unwrap_or_default()
                } else {
                    Vec::new()
                };
                itemize::compute_itemize_map(
                    &plan.files_to_send,
                    &local_entries,
                    false, // is_pull
                )
            } else {
                std::collections::HashMap::new()
            };

            // Dry run with -i: print itemize strings and exit early from display
            if dry_run && itemize {
                for entry in &plan.files_to_send {
                    if let Some(change_str) = itemize_map.get(&entry.path) {
                        if entry.is_dir {
                            eprintln!("{} {}/", change_str, entry.path);
                        } else {
                            eprintln!("{} {}", change_str, entry.path);
                        }
                    }
                }
                for path in &plan.files_to_delete {
                    eprintln!("*deleting   {}", path);
                }
            }

            // Compute existing dirs from plan (suppress from rsync output)
            let existing_dirs: HashSet<String> = plan
                .files_to_send
                .iter()
                .filter(|e| e.is_dir && effective_dir.join(&e.path).is_dir())
                .map(|e| e.path.clone())
                .collect();
            let total_file_count = plan
                .files_to_send
                .iter()
                .filter(|e| !e.is_dir && !e.is_symlink)
                .count();

            // Print rsync-style header
            eprintln!(
                "receiving file list from {}:{} \u{2192} {}",
                host,
                remote_path,
                effective_dir.display(),
            );

            // Phase 2: transfer files (with progress UI)
            let state = progress_ui::TransferState::with_mode(
                false,
                progress_ui::DisplayMode::Rsync,
                total_file_count,
                existing_dirs,
            );
            state.set_itemize_map(itemize_map);
            state.set_no_progress(no_progress);
            let render_handle = progress_ui::spawn_render_loop(state.clone());

            let summary = transfer::client_pull_sync_transfer(
                &mut send, &mut recv, &effective_dir, plan, &state, &params,
            )
            .await?;
            state.mark_finished();
            let _ = render_handle.await;
            eprintln!("{}", summary.format_rsync());
            if stats {
                eprintln!("\n{}", summary.format_stats());
            }
        }
    }

    Ok(())
}

fn cmd_creator_invite(config_dir: &std::path::Path) -> Result<()> {
    let path = config_dir.join("creator_invite");
    if path.exists() {
        let token = std::fs::read_to_string(&path)
            .context("Failed to read creator_invite file")?;
        let token = token.trim();
        println!("Creator invite:");
        println!();
        println!("  hop connect {token}");
        println!();
        println!("This invite grants full admin (creator) access.");
    } else {
        println!("No creator invite found.");
        println!("A creator invite is generated on first daemon startup when no peers exist.");
        println!("If you already have a creator peer, no new invite is needed.");
    }
    Ok(())
}

async fn cmd_admin(
    _secret_key: iroh::SecretKey,
    target: &str,
    config_dir: &std::path::Path,
    action: AdminAction,
) -> Result<()> {
    let request = match &action {
        AdminAction::Invite { user, creator, .. } => AdminRequest::CreateInvite {
            username: user.clone(),
            role: if *creator { PeerRole::Creator } else { PeerRole::Peer },
        },
        AdminAction::Peers => AdminRequest::ListPeers,
        AdminAction::RemovePeer { id } => AdminRequest::RemovePeer {
            node_id_prefix: id.clone(),
        },
        AdminAction::CreateUser {
            username,
            sudo,
            admin,
            groups,
            shell,
            invite,
        } => AdminRequest::CreateUser {
            username: username.clone(),
            sudo: *sudo,
            admin: *admin,
            groups: groups.clone(),
            shell: shell.clone(),
            invite: *invite,
        },
        AdminAction::Status => AdminRequest::Status,
        AdminAction::FleetInvite { tags, max_uses, expiry } => AdminRequest::CreateFleetInvite {
            tags: tags.clone(),
            max_uses: *max_uses,
            expiry_secs: *expiry,
        },
        AdminAction::FleetList { tag } => AdminRequest::ListFleet {
            tag_filter: tag.clone(),
        },
        AdminAction::FleetRemove { id } => AdminRequest::RemoveFleetMember {
            node_id_prefix: id.clone(),
        },
        AdminAction::FleetTag { id, add, remove: _ } => {
            AdminRequest::UpdateFleetTags {
                node_id_prefix: id.clone(),
                tags: add.clone(),
            }
        }
        AdminAction::Role(role_action) => match role_action {
            RoleAction::Create {
                name,
                tags,
                shared,
                sudo,
                admin,
                groups,
                shell,
            } => AdminRequest::CreateRole {
                definition: RoleDefinition {
                    name: name.clone(),
                    host_tags: tags.clone(),
                    user_mode: if *shared { UserMode::Shared } else { UserMode::Individual },
                    sudo: *sudo,
                    admin: *admin,
                    groups: groups.clone(),
                    shell: shell.clone(),
                    sandbox: hop_core::sandbox::SandboxPolicy::default(),
                },
            },
            RoleAction::List => AdminRequest::ListRoles,
            RoleAction::Update {
                name,
                add_tags,
                remove_tags,
                sudo,
                admin,
            } => AdminRequest::UpdateRole {
                name: name.clone(),
                updates: RoleUpdates {
                    add_tags: add_tags.clone(),
                    remove_tags: remove_tags.clone(),
                    sudo: *sudo,
                    admin: *admin,
                    ..Default::default()
                },
            },
            RoleAction::Delete { name } => AdminRequest::DeleteRole { name: name.clone() },
        },
    };

    // Connect and send admin request
    let (_resolved, _send, mut recv) = mux::connect_to_host(
        config_dir,
        target,
        None,
        &ClientMessage::RequestAdmin(request),
    )
    .await?;

    // Read admin response
    let response: proto::HostMessage = proto::read_message(&mut recv).await?;
    match response {
        proto::HostMessage::AdminResponse(resp) => {
            display_admin_response(&action, resp);
        }
        other => {
            eprintln!("Unexpected response: {other:?}");
        }
    }

    Ok(())
}

fn display_admin_response(_action: &AdminAction, resp: AdminResponse) {
    match resp {
        AdminResponse::InviteCreated { token } => {
            println!("Invite created:");
            println!();
            println!("  hop connect {token}");
            println!();
        }
        AdminResponse::PeerList { peers } => {
            if peers.is_empty() {
                println!("No authorized peers.");
            } else {
                println!("Authorized peers:");
                for p in &peers {
                    let role = match p.role {
                        PeerRole::Creator => " [creator]",
                        PeerRole::Peer => "",
                    };
                    let user = p
                        .username
                        .as_deref()
                        .map(|u| format!(", user: {u}"))
                        .unwrap_or_default();
                    let seen = p
                        .last_seen
                        .as_deref()
                        .unwrap_or("never");
                    println!(
                        "  {} ({}){} - last seen: {}{user}",
                        &p.node_id[..10],
                        p.name,
                        role,
                        seen,
                    );
                }
            }
        }
        AdminResponse::PeerRemoved { success } => {
            if success {
                println!("Peer removed.");
            } else {
                println!("No peer found with that ID prefix.");
            }
        }
        AdminResponse::UserCreated {
            username,
            invite_token,
        } => {
            println!("User '{username}' created.");
            if let Some(token) = invite_token {
                println!();
                println!("Invite for {username}:");
                println!("  hop connect {token}");
            }
        }
        AdminResponse::HostStatus {
            version,
            peer_count,
            active_sessions,
        } => {
            println!("Host status:");
            println!("  Version: {version}");
            println!("  Peers: {peer_count}");
            println!("  Active sessions: {active_sessions}");
        }
        AdminResponse::FleetInviteCreated { token } => {
            println!("Fleet invite created:");
            println!("  {token}");
        }
        AdminResponse::FleetList { members } => {
            if members.is_empty() {
                println!("No fleet members.");
            } else {
                println!("Fleet members:");
                for m in &members {
                    let status = if m.online { "online" } else { "offline" };
                    let tags = m.tags.join(", ");
                    println!(
                        "  {} ({}) [{}] - tags: {tags}",
                        &m.node_id[..10],
                        m.hostname,
                        status,
                    );
                }
            }
        }
        AdminResponse::FleetMemberRemoved { success } => {
            if success {
                println!("Fleet member removed.");
            } else {
                println!("No fleet member found with that ID prefix.");
            }
        }
        AdminResponse::FleetTagsUpdated { success } => {
            if success {
                println!("Fleet member tags updated.");
            } else {
                println!("No fleet member found with that ID prefix.");
            }
        }
        AdminResponse::RoleCreated { name } => {
            println!("Role '{name}' created.");
        }
        AdminResponse::RoleList { roles } => {
            if roles.is_empty() {
                println!("No roles defined.");
            } else {
                println!("Roles:");
                for r in &roles {
                    let mode = match r.user_mode {
                        UserMode::Individual => "individual",
                        UserMode::Shared => "shared",
                    };
                    let tags = r.host_tags.join(", ");
                    let mut flags = Vec::new();
                    if r.sudo {
                        flags.push("sudo");
                    }
                    if r.admin {
                        flags.push("admin");
                    }
                    let flags_str = if flags.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", flags.join(", "))
                    };
                    println!("  {} ({mode}) - tags: {tags}{flags_str}", r.name);
                }
            }
        }
        AdminResponse::RoleUpdated { name } => {
            println!("Role '{name}' updated.");
        }
        AdminResponse::RoleDeleted { name } => {
            println!("Role '{name}' deleted.");
        }
        AdminResponse::AggregateInviteCreated { token } => {
            println!("Aggregate invite created:");
            println!();
            println!("  hop connect {token}");
            println!();
        }
        AdminResponse::AggregateInviteRedeemed { hosts } => {
            println!("Redeemed aggregate invite. {} host(s) available:", hosts.len());
            for h in &hosts {
                println!("  {} ({})", h.hostname, &h.node_id[..10]);
            }
        }
        AdminResponse::Error { message } => {
            eprintln!("Error: {message}");
        }
    }
}

async fn cmd_fleet(
    _secret_key: iroh::SecretKey,
    config_dir: &std::path::Path,
    action: FleetAction,
) -> Result<()> {
    match action {
        FleetAction::Status { fleet } => {
            let host_config_dir = config::resolve_host_config_dir(Some(config_dir))?;
            let store = hop_core::fleet::FleetRegistrationsStore::load(&host_config_dir)?;
            if store.registrations.is_empty() {
                println!("Not registered with any fleet.");
                return Ok(());
            }
            let reg = if let Some(name) = fleet {
                store
                    .registrations
                    .iter()
                    .find(|r| r.name == name)
                    .context(format!("No fleet registration named '{name}'"))?
            } else {
                &store.registrations[0]
            };
            println!("Fleet: {}", reg.name);
            println!("  Orchestrator: {}", &reg.orchestrator_node_id[..10]);
            println!("  Tags: {}", reg.tags.join(", "));
            println!("  Registered: {}", reg.registered_at);
            if let Some(ref url) = reg.orchestrator_relay_url {
                println!("  Orchestrator relay: {url}");
            }
            Ok(())
        }
        FleetAction::List { group } => {
            let hosts = KnownHostsStore::load(config_dir)?;
            let filtered: Vec<_> = hosts
                .hosts
                .iter()
                .filter(|h| {
                    group
                        .as_ref()
                        .map(|g| h.groups.contains(g))
                        .unwrap_or(true)
                })
                .collect();
            if filtered.is_empty() {
                println!("No hosts found.");
            } else {
                for h in &filtered {
                    let groups = if h.groups.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", h.groups.join(", "))
                    };
                    println!("  {} ({}){groups}", &h.node_id[..10], h.name);
                }
            }
            Ok(())
        }
        FleetAction::Exec { group, command } => {
            let hosts = KnownHostsStore::load(config_dir)?;
            let targets: Vec<_> = hosts
                .hosts
                .iter()
                .filter(|h| h.groups.contains(&group))
                .collect();
            if targets.is_empty() {
                println!("No hosts in group '{group}'.");
                return Ok(());
            }
            let command_str = command.join(" ");
            for host in &targets {
                println!("--- {} ({}) ---", host.name, &host.node_id[..10]);
                match mux::connect_to_host(
                    config_dir,
                    &host.name,
                    None,
                    &ClientMessage::RequestExec {
                        command: command_str.clone(),
                    },
                )
                .await
                {
                    Ok((_resolved, send, recv)) => {
                        let mut stdin_rx = spawn_stdin_reader();
                        let outcome = shell::client_exec_session(send, recv, &mut stdin_rx).await?;
                        match outcome {
                            SessionOutcome::Exited(code) => {
                                if code != 0 {
                                    eprintln!("Exit code: {code}");
                                }
                            }
                            SessionOutcome::Disconnected => {
                                eprintln!("Connection lost");
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to connect: {e:#}");
                    }
                }
                println!();
            }
            Ok(())
        }
    }
}

fn cmd_config(action: Option<ConfigAction>, config_dir: &std::path::Path) -> Result<()> {
    let mut cfg = HostConfig::load(config_dir)?;

    match action {
        None => {
            // Display current config
            let timeout = cfg.session_timeout_secs;
            let human = if timeout >= 86400 {
                format!("{}d", timeout / 86400)
            } else if timeout >= 3600 {
                format!("{}h", timeout / 3600)
            } else if timeout >= 60 {
                format!("{}m", timeout / 60)
            } else {
                format!("{timeout}s")
            };
            println!("session_timeout  {timeout} ({human})");
            println!("max_sessions     {}", cfg.max_sessions);
        }
        Some(ConfigAction::Set { key, value }) => {
            match key.as_str() {
                "session_timeout" => {
                    let secs: u64 = parse_duration_value(&value)?;
                    cfg.session_timeout_secs = secs;
                    cfg.save(config_dir)?;
                    println!("session_timeout set to {secs}s");
                }
                "max_sessions" => {
                    let n: usize = value.parse().context("max_sessions must be a positive integer")?;
                    cfg.max_sessions = n;
                    cfg.save(config_dir)?;
                    println!("max_sessions set to {n}");
                }
                _ => {
                    anyhow::bail!("Unknown config key '{key}'. Valid keys: session_timeout, max_sessions");
                }
            }
            println!("Note: restart the host/daemon for changes to take effect.");
        }
    }

    Ok(())
}

/// Parse a duration value that can be plain seconds or suffixed (s, m, h, d).
fn parse_duration_value(s: &str) -> Result<u64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('d') {
        Ok(n.parse::<u64>().context("invalid number")? * 86400)
    } else if let Some(n) = s.strip_suffix('h') {
        Ok(n.parse::<u64>().context("invalid number")? * 3600)
    } else if let Some(n) = s.strip_suffix('m') {
        Ok(n.parse::<u64>().context("invalid number")? * 60)
    } else if let Some(n) = s.strip_suffix('s') {
        Ok(n.parse::<u64>().context("invalid number")?)
    } else {
        Ok(s.parse::<u64>().context("invalid number — use a suffix like 1h, 30m, 1d, or plain seconds")?)
    }
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
                    let role_info = match peer.role {
                        PeerRole::Creator => " [creator]",
                        PeerRole::Peer => "",
                    };
                    println!(
                        "  {} ({}){role_info} - authorized: {}, last seen: {}{user_info}",
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

#[cfg(test)]
mod tests {
    use super::*;
    use hop_core::proto::ClientMessage;
    use hop_core::sandbox::SandboxPolicy;

    #[test]
    fn rebuild_v3_preserves_sandbox() {
        let policy = SandboxPolicy {
            read_only: true,
            no_network: true,
            allowed_commands: vec!["ps".into()],
            denied_commands: vec!["rm".into()],
            ..Default::default()
        };
        let original = ClientMessage::RequestShellV3 {
            session_id: Some("old-id".into()),
            sandbox: policy.clone(),
        };
        let rebuilt = rebuild_session_request(&original, Some("new-id".into()));
        match rebuilt {
            ClientMessage::RequestShellV3 { session_id, sandbox } => {
                assert_eq!(session_id, Some("new-id".into()));
                assert_eq!(sandbox, policy, "sandbox policy must be preserved");
            }
            _ => panic!("V3 should rebuild as V3"),
        }
    }

    #[test]
    fn rebuild_v2_stays_v2() {
        let original = ClientMessage::RequestShellV2 {
            session_id: Some("old-id".into()),
        };
        let rebuilt = rebuild_session_request(&original, Some("new-id".into()));
        match rebuilt {
            ClientMessage::RequestShellV2 { session_id } => {
                assert_eq!(session_id, Some("new-id".into()));
            }
            _ => panic!("V2 should rebuild as V2"),
        }
    }

    #[test]
    fn rebuild_v3_with_none_session_id() {
        let original = ClientMessage::RequestShellV3 {
            session_id: Some("existing".into()),
            sandbox: SandboxPolicy::preset_monitor(),
        };
        let rebuilt = rebuild_session_request(&original, None);
        match rebuilt {
            ClientMessage::RequestShellV3 { session_id, sandbox } => {
                assert_eq!(session_id, None);
                assert!(sandbox.read_only);
                assert!(sandbox.no_network);
            }
            _ => panic!("V3 with None session_id should still be V3"),
        }
    }

    #[test]
    fn rebuild_other_variants_fall_through_to_v2() {
        let variants: Vec<ClientMessage> = vec![
            ClientMessage::RequestShell,
            ClientMessage::RequestExec {
                command: "ls".into(),
            },
            ClientMessage::Input(b"data".to_vec()),
        ];
        for original in &variants {
            let rebuilt = rebuild_session_request(original, Some("sess".into()));
            match rebuilt {
                ClientMessage::RequestShellV2 { session_id } => {
                    assert_eq!(session_id, Some("sess".into()));
                }
                _ => panic!(
                    "non-V3 variant {:?} should fall through to V2",
                    original
                ),
            }
        }
    }
}
