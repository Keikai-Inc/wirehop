mod cli;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{Cli, Command, PeersAction};
use tracing_subscriber::EnvFilter;

use hop_core::auth::{self, AuthOutcome};
use hop_core::config::{self, KnownHostsStore, PeersStore};
use hop_core::invite;
use hop_core::net;
use hop_core::proto::{self, ClientMessage};
use hop_core::shell;

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
        Command::Invite { user } => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_identity(&config_dir)?;
            cmd_invite(secret_key, &config_dir, user.as_deref())
        }
        Command::Connect { target } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_connect(secret_key, &target, &config_dir).await
        }
        Command::Peers { action } => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            cmd_peers(action, &config_dir)
        }
        Command::Id => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            let public_key = secret_key.public();
            println!("{public_key}");
            Ok(())
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

    while let Some(incoming) = endpoint.accept().await {
        let config_dir = config_dir.to_path_buf();
        tokio::spawn(async move {
            if let Err(e) = handle_incoming(incoming, &config_dir).await {
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
) -> Result<()> {
    // We only advertise one ALPN, so no need to inspect it
    let conn: iroh::endpoint::Connection = incoming.await?;
    let remote_id = conn.remote_id();
    tracing::info!("Connection from: {}", remote_id.fmt_short());

    let (mut send, mut recv) = conn.accept_bi().await?;

    // Authenticate the client
    let (outcome, _first_msg) = auth::authenticate_client(
        &mut send,
        &mut recv,
        &remote_id,
        config_dir,
    )
    .await?;

    match outcome {
        AuthOutcome::Authorized { username } => {
            tracing::info!("Authorized peer {}, starting shell", remote_id.fmt_short());
            // first_msg should be RequestShell, already consumed
            shell::host_shell_session(send, recv, username.as_deref()).await?;
        }
        AuthOutcome::InviteAccepted { username } => {
            tracing::info!("Invite accepted for {}, waiting for shell request", remote_id.fmt_short());
            // Client will send RequestShell next
            let msg: ClientMessage = proto::read_message(&mut recv).await?;
            match msg {
                ClientMessage::RequestShell => {
                    shell::host_shell_session(send, recv, username.as_deref()).await?;
                }
                _ => {
                    tracing::warn!("Expected RequestShell after invite, got: {:?}", msg);
                }
            }
        }
        AuthOutcome::Rejected => {
            tracing::info!("Rejected connection from {}", remote_id.fmt_short());
        }
    }

    Ok(())
}

fn cmd_invite(secret_key: iroh::SecretKey, config_dir: &std::path::Path, username: Option<&str>) -> Result<()> {
    let public_key = secret_key.public();

    // Derive public key directly from identity — no endpoint needed.
    // relay_url is None; iroh discovers the host by NodeId automatically.
    let token = invite::generate_invite(&public_key, config_dir, None, username)?;

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

async fn cmd_connect(
    secret_key: iroh::SecretKey,
    target: &str,
    config_dir: &std::path::Path,
) -> Result<()> {
    let endpoint = net::create_client_endpoint(secret_key).await?;

    if invite::is_invite_token(target) {
        // Invite flow
        let token = invite::decode_invite(target)?;
        let host_id: iroh::PublicKey = token
            .node_id
            .parse()
            .context("Invalid NodeId in invite token")?;

        // Parse relay URL from invite token if present
        let relay_url: Option<iroh::RelayUrl> = token
            .relay_url
            .as_deref()
            .map(|u| u.parse())
            .transpose()
            .context("Invalid relay URL in invite token")?;

        println!("Connecting to host {}...", host_id.fmt_short());

        let conn = net::connect_to_host(&endpoint, host_id, relay_url.as_ref()).await?;
        let (mut send, mut recv) = conn.open_bi().await?;

        // Send the invite secret as auth response
        proto::write_message(
            &mut send,
            &ClientMessage::AuthResponse {
                secret: token.secret.as_bytes().to_vec(),
            },
        )
        .await?;

        // Wait for auth result
        let result: proto::HostMessage = proto::read_message(&mut recv).await?;
        match result {
            proto::HostMessage::AuthResult { authorized: true } => {
                println!("Authorized! Starting shell...");

                // Save as known host
                let mut hosts = KnownHostsStore::load(config_dir)?;
                hosts.add_host(&host_id, format!("host-{}", host_id.fmt_short()));
                hosts.save(config_dir)?;

                // Request shell
                proto::write_message(&mut send, &ClientMessage::RequestShell).await?;

                let exit_code = shell::client_shell_session(send, recv).await?;
                std::process::exit(exit_code);
            }
            proto::HostMessage::AuthResult { authorized: false } => {
                anyhow::bail!("Invite rejected by host (expired or already used)");
            }
            other => {
                anyhow::bail!("Unexpected response from host: {other:?}");
            }
        }
    } else {
        // Direct connect (already authorized)
        let host_id: iroh::PublicKey = target
            .parse()
            .context("Invalid NodeId (expected 64-char hex string or invite token)")?;

        println!("Connecting to {}...", host_id.fmt_short());

        let conn = net::connect_to_host(&endpoint, host_id, None).await?;
        let (mut send, recv) = conn.open_bi().await?;

        // Request shell directly
        proto::write_message(&mut send, &ClientMessage::RequestShell).await?;

        let exit_code = shell::client_shell_session(send, recv).await?;
        std::process::exit(exit_code);
    }
}

fn cmd_peers(action: Option<PeersAction>, config_dir: &std::path::Path) -> Result<()> {
    let mut peers = PeersStore::load(config_dir)?;
    let hosts = KnownHostsStore::load(config_dir)?;

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
                peers.save(config_dir)?;
                println!("Peer removed.");
            } else {
                println!("No peer found matching '{id}'.");
            }
            Ok(())
        }
    }
}
