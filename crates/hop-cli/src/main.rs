mod agent;
mod cli;
mod itemize;
mod oauth;
mod mux;
mod progress_ui;
mod reconnect;

use std::collections::HashSet;
use std::io::Read;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{AdminAction, AgentAction, CapAction, Cli, Command, ConfigAction, CronAction, FleetAction, KvAction, PeersAction, RoleAction, SecretsAction, TsAction};
use iroh::endpoint::{RecvStream, SendStream};
use iroh::Watcher;
use tokio::sync::mpsc;
use tracing_subscriber::prelude::*;
use tracing_subscriber::EnvFilter;
use tracing_subscriber::reload;

use hop_core::auth::{self, AuthOutcome};
use hop_core::config::{self, HostConfig, KnownHostsStore, PeerRole, PeersStore};
use hop_core::invite;
use hop_core::net;
use hop_core::proto::{
    self, AdminRequest, AdminResponse, ClientMessage, RoleDefinition, RoleUpdates, UserMode,
    TransferDirection, TransferMode, TransferMsg, TransferRequest,
};
use hop_core::shell::{self, SessionOutcome};
use hop_core::shell::session_registry::{self as session_registry, RegistryHandle};
use hop_core::transfer::{self, PathSpec};

#[tokio::main]
async fn main() -> Result<()> {
    // Broker shim detection: when invoked via symlink (e.g., "ps"),
    // argv[0] won't be "hop". Enter broker client mode immediately.
    if let Some(argv0) = std::env::args().next() {
        let name = std::path::Path::new(&argv0)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("");
        if name != "hop"
            && !name.is_empty()
            && hop_core::sandbox::broker::is_broker_safe(name)
        {
            let args: Vec<String> = std::env::args().skip(1).collect();
            std::process::exit(hop_core::sandbox::broker::broker_client_main(name, &args));
        }
    }

    let cli = Cli::parse();

    // Initialize tracing — respect RUST_LOG if set, otherwise use verbosity flag.
    // Uses a reload layer so the host daemon can toggle debug logging at runtime via SIGUSR1.
    let initial_filter = if std::env::var("RUST_LOG").is_ok() {
        EnvFilter::from_default_env()
    } else {
        EnvFilter::new(match cli.verbose {
            0 => "hop=info,hop_core=info,hop_mcp=info",
            1 => "hop=debug,hop_core=debug,hop_mcp=debug",
            _ => "hop=trace,hop_core=trace,hop_mcp=trace",
        })
    };
    let (filter_layer, reload_handle) = reload::Layer::new(initial_filter);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();

    match cli.command {
        Command::Host { quiet } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_host(secret_key, &config_dir, quiet, reload_handle).await
        }
        Command::Invite { user, role, tier, name, read_only, no_network, scopes, allow_commands, preset } => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            // Ensure dir exists and auto-generate identity if needed (no need to run `hop id` first)
            std::fs::create_dir_all(&config_dir)
                .with_context(|| format!("Failed to create config dir: {}", config_dir.display()))?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            let sandbox = build_sandbox_policy(preset.as_deref(), read_only, no_network, &scopes, &allow_commands)?;
            let tier = parse_invite_tier(tier.as_deref())?;
            cmd_invite(secret_key, &config_dir, user.as_deref(), role.as_deref(), tier, name.as_deref(), sandbox)
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
        Command::Warren { action } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_warren(secret_key, &config_dir, action).await
        }
        Command::Acl { action } => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            cmd_acl(action, &config_dir)
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
        Command::Cap { action } => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            cmd_cap(&config_dir, action).await
        }
        Command::Cron { action } => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            cmd_cron(&config_dir, action)
        }
        Command::Kv { action } => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            cmd_kv(&config_dir, action)
        }
        Command::Secrets { action } => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            cmd_secrets(&config_dir, action)
        }
        Command::Ts { action } => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            cmd_ts(&config_dir, action)
        }
        Command::Auth { provider } => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            cmd_auth(&provider, None, &config_dir).await
        }
        Command::Mcp => {
            // MCP server: all output goes to stdout (JSON-RPC), logs to stderr only
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            let datastore = match hop_core::datastore::Datastore::connect(&config_dir) {
                Ok(ds) => Some(ds),
                Err(e) => {
                    eprintln!("Daemon not available ({e}), running without datastore tools");
                    None
                }
            };
            hop_mcp::run_stdio_server_with_datastore(&config_dir, datastore).await
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
                None if daemon => agent::run_daemon(&config_dir, reload_handle).await,
                None => agent::run_foreground(&config_dir, reload_handle).await,
            }
        }
        Command::SandboxShell { policy, shell_args } => {
            cmd_sandbox_shell(&policy, &shell_args)
        }
        Command::Ps => {
            cmd_ps()
        }
        Command::InstallDaemon => {
            cmd_install_daemon()
        }
        Command::TransferHelper { mode, dest, compression, chunk_size } => {
            cmd_transfer_helper(&mode, &dest, compression.as_deref(), chunk_size).await
        }
        Command::External(args) => {
            // Check for remote subcommand: hop <host> secrets/cap/kv/cron ...
            if args.len() >= 2 {
                match args[1].as_str() {
                    "secrets" | "kv" | "cron" => {
                        let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
                        let _secret_key = config::load_or_generate_identity(&config_dir)?;
                        return cmd_remote_peer_op(&args[0], &args[1..], &config_dir).await
                    }
                    "auth" => {
                        let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
                        let provider = args.get(2).context("usage: hop <host> auth <provider>")?;
                        return cmd_auth(provider, Some(&args[0]), &config_dir).await
                    }
                    "cap" => {
                        let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
                        let _secret_key = config::load_or_generate_identity(&config_dir)?;
                        // Check for "cap setup" which needs special handling (auth flows)
                        if args.get(2).map(|s| s.as_str()) == Some("setup") {
                            let cap_id = args.get(3).context("usage: hop <host> cap setup <id>")?;
                            return cmd_cap_setup(cap_id, None, Some(&args[0]), &config_dir).await
                        }
                        return cmd_remote_peer_op(&args[0], &args[1..], &config_dir).await
                    }
                    _ => {}
                }
            }

            let ext = parse_external_args(&args)?;
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;

            let sandbox = build_sandbox_policy(
                ext.preset.as_deref(), ext.read_only, ext.no_network,
                &ext.scopes, &ext.allow_commands,
            )?;

            if let Some(command) = ext.exec_command {
                cmd_exec(secret_key, &ext.target, &config_dir, &command, sandbox).await
            } else {
                cmd_connect(secret_key, &ext.target, &config_dir, ext.name.as_deref(), sandbox).await
            }
        }
    }
}

/// Type alias for the reload handle used by the SIGUSR1 debug toggle.
type ReloadHandle = reload::Handle<EnvFilter, tracing_subscriber::Registry>;

async fn cmd_host(secret_key: iroh::SecretKey, config_dir: &std::path::Path, quiet: bool, reload_handle: ReloadHandle) -> Result<()> {
    let public_key = secret_key.public();
    let secrets_key = hop_core::datastore::derive_secrets_key(&secret_key.to_bytes());
    // Derive the netdoc endpoint key before the host secret is moved into the
    // host endpoint. The netdoc stack runs on its own isolated endpoint.
    let netdoc_key = net::derive_netdoc_secret_key(&secret_key);
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

    // Log addresses for debugging connectivity issues
    let addr = endpoint.addr();
    let direct_addrs: Vec<_> = addr.ip_addrs().collect();
    if !direct_addrs.is_empty() {
        tracing::info!("Direct addresses: {:?}", direct_addrs);
    }
    let relay_urls: Vec<_> = addr.relay_urls().collect();
    tracing::info!("Relay URLs from endpoint: {:?}", relay_urls);

    // Watch for relay URL changes and keep the file up to date
    {
        let relay_path = config_dir.join("relay_url");
        let mut watcher = endpoint.watch_addr();
        tokio::spawn(async move {
            while let Ok(addr) = watcher.updated().await {
                if let Some(new_relay) = addr.relay_urls().next() {
                    if let Err(e) = std::fs::write(&relay_path, new_relay.to_string()) {
                        tracing::warn!("Failed to update relay_url file: {e}");
                    } else {
                        tracing::debug!("Updated relay_url file: {new_relay}");
                    }
                }
            }
        });
    }

    // Network interface change detector — belt-and-suspenders over iroh's netwatch.
    // Polls interface addresses every 5s and calls endpoint.network_change() on change.
    let _netmon = net::netmon::spawn_interface_watcher(endpoint.clone(), None);

    // Relay reachability watcher. Probes the home relay every 30s and forces
    // re-discovery after 3 consecutive failures. Catches cert expiry / relay
    // crashes the interface watcher misses (the daemon's TCP session can stay
    // ESTABLISHED for hours after the relay link is functionally broken).
    let _relay_health = net::netmon::spawn_relay_health_watcher(endpoint.clone());

    // Network document (Phase 1): spawn the iroh-docs replication stack on its
    // own isolated endpoint and migrate existing peers/roles on first run. This
    // is best-effort and NON-FATAL — if any of it fails the daemon keeps serving
    // on peers.json exactly as before. Done in the background so it never delays
    // the accept loop; auth falls back to peers.json until the cell is populated.
    let netdoc_cell: NetDocCell = std::sync::Arc::new(tokio::sync::OnceCell::new());
    {
        let cell = netdoc_cell.clone();
        let cfg = config_dir.to_path_buf();
        let host_node_id = public_key.to_string();
        // The C1 member-binding announce goes out over the *main* hop endpoint
        // (the founder authenticates the sender by its main NodeId), so hand the
        // netdoc task a clone of it alongside the isolated netdoc endpoint.
        let main_endpoint = endpoint.clone();
        tokio::spawn(async move {
            let endpoint = match net::create_netdoc_endpoint(netdoc_key).await {
                Ok(ep) => ep,
                Err(e) => {
                    tracing::warn!("netdoc: endpoint bind failed, continuing without it: {e:#}");
                    return;
                }
            };
            let store_dir = cfg.join("netdoc");
            let meta_path = cfg.join("netdoc.json");
            // Opt-in federation: HOP_VPN_JOIN_TICKET (or <config>/netdoc-join.ticket)
            // joins an existing network's namespace on first run.
            let join = std::env::var("HOP_VPN_JOIN_TICKET")
                .ok()
                .or_else(|| std::fs::read_to_string(cfg.join("netdoc-join.ticket")).ok())
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .and_then(|s| match s.parse() {
                    Ok(t) => Some(t),
                    Err(e) => {
                        tracing::warn!("netdoc: invalid join ticket ignored: {e}");
                        None
                    }
                });
            match hop_core::netdoc::NetDoc::open_or_create(endpoint, &store_dir, &meta_path, join).await {
                Ok((net, _created)) => {
                    // Record the C1 trust anchor (founder/admin author). The
                    // founder (namespace creator) is its own admin; a federated
                    // node reads the founder author persisted by `hop warren join`.
                    let founder_hex = std::fs::read_to_string(cfg.join("netdoc-founder.author"))
                        .ok()
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty());
                    net.record_founder_anchor(founder_hex.as_deref());

                    // Reconcile the document with the host's peers.json/roles.json
                    // on every start (initial migration on first run, drift
                    // correction afterwards). Best-effort.
                    let peers = hop_core::config::PeersStore::load(&cfg)
                        .map(|p| p.peers)
                        .unwrap_or_default();
                    let roles = hop_core::fleet::RolesStore::load(&cfg)
                        .map(|r| r.roles)
                        .unwrap_or_default();
                    match net.reconcile(&peers, &roles).await {
                        Ok(()) => tracing::info!(
                            "netdoc: reconciled {} peer(s), {} role(s)",
                            peers.len(),
                            roles.len()
                        ),
                        Err(e) => tracing::warn!("netdoc: startup reconcile failed: {e:#}"),
                    }
                    // Build the trusted-admin-author set (founder + vouched
                    // co-admins) so enforce honors federated admins' entries.
                    net.refresh_admin_authors().await;
                    // Phase 2: claim this host's stable virtual IP in the doc.
                    match net.claim_virtual_ip(&host_node_id).await {
                        Ok(ip) => tracing::info!("netdoc: virtual IP {ip} (100.64.0.0/10)"),
                        Err(e) => tracing::warn!("netdoc: virtual IP claim failed: {e:#}"),
                    }
                    tracing::info!("netdoc ready (namespace {})", net.namespace());

                    // Publish a write ticket so other hosts can join this network
                    // (federation). Written to <config>/netdoc.ticket.
                    if let Ok(ticket) = net.write_ticket().await {
                        let ticket_str = ticket.to_string();
                        // 0600 — this is a warren *write* ticket (security-audit H7).
                        let _ = config::write_secret_file(&cfg.join("netdoc.ticket"), &ticket_str);
                        // The creator invite is generated at startup, before the
                        // netdoc namespace exists, so it can't embed the ticket
                        // up front. Augment it now (same secret) so the founder's
                        // invite doubles as the warren join token.
                        let ci_path = cfg.join("creator_invite");
                        if let Ok(tok_str) = std::fs::read_to_string(&ci_path)
                            && let Ok(mut tok) = hop_core::invite::decode_invite(tok_str.trim())
                            && tok.warren_ticket.is_none()
                        {
                            tok.warren_ticket = Some(ticket_str);
                            // Pin the founder's doc author as the C1 trust anchor:
                            // a joining node records this as the trusted admin
                            // author for validating admin-owned doc entries.
                            tok.founder_author = Some(net.author_hex());
                            if let Ok(reencoded) = hop_core::invite::encode_invite(&tok) {
                                let _ = config::write_shared_file(&ci_path, &reencoded);
                                tracing::info!("creator invite augmented with warren ticket + founder author");
                            }
                        }
                    }

                    let net = std::sync::Arc::new(net);

                    // Robustness: iroh-docs only starts live sync on the first
                    // `import`; reopening the namespace (every restart, e.g. after
                    // a reboot) does not. Actively re-establish sync with the
                    // warren's known peers so a rebooted node reconverges instead
                    // of running on a stale snapshot, and keep it converged.
                    match net.resume_sync().await {
                        Ok(n) if n > 0 => tracing::info!("netdoc: resumed warren sync with {n} peer(s)"),
                        Ok(_) => {}
                        Err(e) => tracing::warn!("netdoc: resume sync failed: {e:#}"),
                    }
                    net.spawn_sync_keepalive(std::time::Duration::from_secs(300));
                    // Converge on co-admin authority fast (enforce default-on
                    // readiness) — far lighter than a full re-sync.
                    net.spawn_admin_author_refresh(std::time::Duration::from_secs(20));

                    // Phase 3: the warren VPN data plane is OFF BY DEFAULT
                    // (opt-in; see security-audit.md C1). HOP_VPN=1 forces on
                    // (past the CGNAT guard), HOP_VPN=0 forces off; otherwise the
                    // config flag (default false) decides — a `--host` install or
                    // `hop config set vpn on` opts a node in. Bringup is ALWAYS
                    // best-effort — a TUN-creation failure or a 100.64.0.0/10
                    // conflict only skips the VPN; exec/shell/transfer keep working.
                    #[cfg(unix)]
                    {
                        let host_cfg = hop_core::config::HostConfig::load(&cfg).unwrap_or_default();
                        let force = std::env::var("HOP_VPN").ok();
                        let mode = match force.as_deref() {
                            Some("1") | Some("true") | Some("on") => Some(true),
                            Some("0") | Some("false") | Some("off") => Some(false),
                            _ => None, // unset → fall back to config
                        };
                        let enabled = mode.unwrap_or(host_cfg.vpn_enabled);
                        let forced_on = mode == Some(true);
                        if !enabled {
                            tracing::info!("vpn: disabled (HOP_VPN=0 or config); core access unaffected");
                        } else if !forced_on
                            && let Some(existing) = hop_core::vpn::cgnat_range_in_use()
                        {
                            // Auto mode + another overlay (e.g. Tailscale) owns the
                            // CGNAT range → don't clobber its route. HOP_VPN=1 forces.
                            tracing::warn!(
                                "vpn: 100.64.0.0/10 already in use by another interface ({existing}); \
                                 skipping VPN bringup to avoid a route conflict (set HOP_VPN=1 to force)"
                            );
                        } else {
                            let host_tags = host_cfg.tags.clone();
                            match net.enable_vpn(&host_node_id, &host_tags).await {
                                Ok(ip) => tracing::info!(
                                    "vpn: enabled, virtual IP {ip}, tags {host_tags:?}"
                                ),
                                Err(e) => tracing::warn!(
                                    "vpn: bringup failed, continuing without it (core access unaffected): {e:#}"
                                ),
                            }
                        }
                    }

                    // C1 self-key binding: a warren member announces its doc
                    // author to the founder so the founder can vouch it in the
                    // member's (admin-owned) peer entry. Without this, the
                    // member's self-owned vpn/ip entries can't be validated under
                    // enforce. Best-effort with retry; the founder skips its own
                    // announce (it's the trust anchor). Never blocks serving.
                    if !net.is_trust_anchor()
                        && let Ok(fnode) = std::fs::read_to_string(cfg.join("netdoc-founder.node"))
                    {
                        let fnode = fnode.trim().to_string();
                        let author = net.author_hex();
                        // Also announce this node's self-doc read ticket so the
                        // founder records peer/N.self_doc (per-member self-docs).
                        let self_doc = net.self_doc_read_ticket().await.ok();
                        if !fnode.is_empty() && fnode != host_node_id {
                            let ep = main_endpoint.clone();
                            tokio::spawn(async move {
                                announce_netdoc_author_with_retry(ep, &fnode, &author, self_doc).await;
                            });
                        }
                    }

                    let _ = cell.set(net);
                }
                Err(e) => tracing::warn!("netdoc: init failed, continuing without it: {e:#}"),
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

            // Bind the creator invite to a username so the shell guard
            // doesn't reject it when hop is running as root.
            #[cfg(unix)]
            let creator_username = if hop_core::unix_user::is_running_as_root() {
                let u = hop_core::unix_user::default_creator_username();
                if u.is_none() {
                    eprintln!(
                        "WARNING: running as root but could not detect a regular user.\n\
                         The creator invite will have no bound username.\n\
                         Re-invite with: hop invite --user <username> --role creator"
                    );
                }
                u
            } else {
                hop_core::unix_user::current_username()
            };
            #[cfg(not(unix))]
            let creator_username: Option<String> = None;

            match invite::generate_invite_with_role(
                &public_key,
                config_dir,
                relay_url_str.as_deref(),
                creator_username.as_deref(),
                None,
                PeerRole::Creator,
                Some("admin".to_string()),
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

    // Session registry actor for persistent PTY sessions
    let registry = session_registry::spawn_registry_actor(
        Duration::from_secs(host_config.session_timeout_secs),
        host_config.max_sessions,
    );

    // Spawn reaper task: every 30s, remove expired/exited sessions
    {
        let registry = registry.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            loop {
                interval.tick().await;
                registry.reap_expired().await;
            }
        });
    }

    // Open datastore once; share with socket listener, cron scheduler, and admin handler
    let ds_path = config_dir.join("datastore.redb");
    let datastore = hop_core::datastore::Datastore::open_with_secrets(&ds_path, secrets_key)?;

    // Discover hop extensions installed on this host. The registry only
    // loads manifests at startup; connections to each extension's IPC
    // server are established lazily on first use. A missing extensions
    // directory is normal — it just means no extensions are installed.
    let ext_manifest_dir = config_dir.join("extensions");
    let ext_registry = hop_core::extensions::ExtensionRegistry::discover(ext_manifest_dir).await?;
    let ext_dispatcher = hop_core::extensions::ExtensionDispatcher::new(ext_registry);

    // Migrate legacy unscoped secrets to user-scoped table
    let migration_user = hop_core::unix_user::default_creator_username()
        .unwrap_or_else(|| "default".to_string());
    if let Err(e) = datastore.migrate_secrets_if_needed(&migration_user) {
        tracing::warn!("Secret migration failed: {e}");
    }

    // Spawn Unix socket listener for out-of-process datastore access (e.g. `hop mcp`)
    let _socket_listener = hop_core::datastore::socket::spawn_listener(config_dir, datastore.clone()).await?;

    // Spawn cron scheduler: every 15s, check for due jobs and execute them.
    // Uses DirectBackend so cron jobs connect via the daemon's own iroh endpoint
    // instead of spawning a separate mux agent process (which would conflict
    // with the daemon's identity).
    let cron_backend: hop_mcp::backend::BoxedBackend = std::sync::Arc::new(
        hop_mcp::backend::direct::DirectBackend::new(
            std::sync::Arc::new(endpoint.clone()),
            config_dir.to_path_buf(),
        ),
    );
    hop_mcp::cron::spawn_cron_scheduler(datastore.clone(), Duration::from_secs(15), Some(cron_backend));

    // Signal handling for graceful shutdown + SIGUSR1 debug toggle
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .context("failed to register SIGTERM handler")?;
    let mut sigint = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())
        .context("failed to register SIGINT handler")?;
    let mut sigusr1 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined1())
        .context("failed to register SIGUSR1 handler")?;
    let mut debug_enabled = false;

    loop {
        tokio::select! {
            incoming = endpoint.accept() => {
                match incoming {
                    Some(inc) => {
                        tracing::info!("Incoming connection attempt (QUIC handshake pending)");
                        let config_dir = config_dir.to_path_buf();
                        let registry = registry.clone();
                        let ds = datastore.clone();
                        let ext = ext_dispatcher.clone();
                        let nd = netdoc_cell.clone();
                        // Double-spawn: the inner task's JoinHandle lets us
                        // observe panics explicitly (via JoinError::is_panic)
                        // and log which connection died, instead of just
                        // letting tokio's default panic hook print to stderr
                        // and losing the context.
                        tokio::spawn(async move {
                            let inner = tokio::spawn(async move {
                                handle_incoming(inc, &config_dir, registry, ds, ext, nd).await
                            });
                            match inner.await {
                                Ok(Ok(())) => {}
                                Ok(Err(e)) => tracing::error!("Connection error: {e:#}"),
                                Err(je) if je.is_panic() => {
                                    tracing::error!(
                                        "Connection handler panicked (tokio caught the \
                                         unwind; worker thread is safe): {je}"
                                    );
                                }
                                Err(je) => {
                                    tracing::error!("Connection task cancelled: {je}");
                                }
                            }
                        });
                    }
                    None => break,
                }
            }
            _ = sigusr1.recv() => {
                debug_enabled = !debug_enabled;
                let new_filter = if debug_enabled {
                    tracing::info!("Debug logging ENABLED (send SIGUSR1 again to disable)");
                    EnvFilter::new("hop=debug,hop_core=debug,hop_mcp=debug,iroh=debug,iroh_relay=debug")
                } else {
                    tracing::info!("Debug logging DISABLED (back to info level)");
                    EnvFilter::new("hop=info,hop_core=info,hop_mcp=info")
                };
                if let Err(e) = reload_handle.reload(new_filter) {
                    tracing::error!("Failed to reload log filter: {e}");
                }
            }
            _ = sigterm.recv() => {
                tracing::info!("Received SIGTERM, shutting down gracefully");
                break;
            }
            _ = sigint.recv() => {
                tracing::info!("Received SIGINT, shutting down gracefully");
                break;
            }
        }
    }

    endpoint.close().await;
    Ok(())
}

/// RAII guard that calls `Connection::close` on drop. Ensures the explicit
/// close runs even if `handle_incoming_inner` panics — dropping an iroh
/// connection without a prior close can trigger the iroh-quinn
/// "drained connections always have an error" path.
struct ConnCloseGuard<'a> {
    conn: &'a iroh::endpoint::Connection,
}

impl Drop for ConnCloseGuard<'_> {
    fn drop(&mut self) {
        self.conn.close(0u32.into(), b"done");
    }
}

/// Shared, lazily-initialized handle to the network document. `None` until the
/// netdoc stack finishes spawning in the background (auth falls back to
/// peers.json until then), and stays empty if netdoc init fails.
type NetDocCell = std::sync::Arc<tokio::sync::OnceCell<std::sync::Arc<hop_core::netdoc::NetDoc>>>;

async fn handle_incoming(
    incoming: iroh::endpoint::Incoming,
    config_dir: &std::path::Path,
    registry: RegistryHandle,
    datastore: hop_core::datastore::Datastore,
    ext_dispatcher: hop_core::extensions::ExtensionDispatcher,
    netdoc: NetDocCell,
) -> Result<()> {
    tracing::debug!("Awaiting QUIC handshake...");
    let conn: iroh::endpoint::Connection = incoming.await?;
    tracing::debug!("QUIC handshake complete from {}", conn.remote_id().fmt_short());
    let _close_guard = ConnCloseGuard { conn: &conn };
    handle_incoming_inner(&conn, config_dir, registry, datastore, ext_dispatcher, netdoc).await
}

async fn handle_incoming_inner(
    conn: &iroh::endpoint::Connection,
    config_dir: &std::path::Path,
    registry: RegistryHandle,
    datastore: hop_core::datastore::Datastore,
    ext_dispatcher: hop_core::extensions::ExtensionDispatcher,
    netdoc: NetDocCell,
) -> Result<()> {
    let remote_id = conn.remote_id();
    let protocol_version = net::negotiated_protocol_version(conn);
    tracing::info!("Connection from: {} (protocol v{})", remote_id.fmt_short(), protocol_version);

    // First bi-stream: full authentication
    let (mut send, mut recv) = conn.accept_bi().await?;
    tracing::debug!("First bi-stream accepted from {}", remote_id.fmt_short());

    let netdoc_ref = netdoc.get().map(|arc| arc.as_ref());
    let (outcome, _first_msg) = auth::authenticate_client(
        &mut send,
        &mut recv,
        &remote_id,
        config_dir,
        netdoc_ref,
    )
    .await?;

    tracing::debug!("Auth outcome for {}: {}",
        remote_id.fmt_short(),
        match &outcome {
            AuthOutcome::Authorized { role, .. } => format!("authorized (role: {role:?})"),
            AuthOutcome::InviteAccepted { role, .. } => format!("invite accepted (role: {role:?})"),
            AuthOutcome::Rejected => "rejected".to_string(),
        });

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
            let ds = datastore.clone();
            let ext = ext_dispatcher.clone();
            let nd = netdoc.get().cloned();
            tokio::spawn(async move {
                if let Err(e) = dispatch_session(_first_msg, conn_c, send, recv, u.as_deref(), protocol_version, &pid, &r, &s, &cd, reg, ds, ext, nd).await {
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
            let ds = datastore.clone();
            let ext = ext_dispatcher.clone();
            let nd = netdoc.get().cloned();
            tokio::spawn(async move {
                if let Err(e) = dispatch_session(Some(msg), conn_c, send, recv, u.as_deref(), protocol_version, &pid, &r, &s, &cd, reg, ds, ext, nd).await {
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
    while let Ok((send, mut recv)) = conn.accept_bi().await {
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
        let ds = datastore.clone();
        let ext = ext_dispatcher.clone();
        let nd = netdoc.get().cloned();
        tokio::spawn(async move {
            if let Err(e) = dispatch_session(Some(msg), conn_c, send, recv, u.as_deref(), protocol_version, &pid, &r, &s, &cd, reg, ds, ext, nd).await {
                tracing::error!("Session error: {e:#}");
            }
        });
    }

    Ok(())
}

/// Whether a hop system daemon (LaunchDaemon on macOS, systemd unit on Linux)
/// is already installed — used by the self-upgrade flow to decide whether to
/// offer setup or just tell the user to restart the existing daemon.
fn system_daemon_installed() -> bool {
    #[cfg(target_os = "macos")]
    {
        std::path::Path::new("/Library/LaunchDaemons/com.hop.daemon.plist").exists()
    }
    #[cfg(not(target_os = "macos"))]
    {
        std::path::Path::new("/etc/systemd/system/hop.service").exists()
    }
}

/// Whether the peer's named role is `network_only` (warren-only tier): on the
/// mesh for L3 reach, but barred from host sessions. Resolves peers.json →
/// role_name → the role definition. Best-effort: a missing role/peer = not
/// network-only (fail open to normal authorization, which still applies).
fn peer_is_network_only(config_dir: &std::path::Path, peer_id: &str) -> bool {
    let Ok(peers) = hop_core::config::PeersStore::load(config_dir) else { return false };
    let Some(role_name) = peers
        .peers
        .iter()
        .find(|p| p.node_id == peer_id)
        .and_then(|p| p.role_name.clone())
    else {
        return false;
    };
    let Ok(roles) = hop_core::fleet::RolesStore::load(config_dir) else { return false };
    roles.roles.iter().any(|r| r.name == role_name && r.network_only)
}

#[allow(clippy::too_many_arguments)]
/// Announce this node's netdoc author to the founder so it can vouch the
/// member's self-key binding (C1 enforce). Best-effort with exponential
/// backoff — the founder may be briefly offline, or not yet have admitted us.
async fn announce_netdoc_author_with_retry(
    endpoint: iroh::Endpoint,
    founder_node_hex: &str,
    author_hex: &str,
    self_doc: Option<String>,
) {
    let founder_id: iroh::PublicKey = match founder_node_hex.parse() {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!("netdoc announce: invalid founder node id {founder_node_hex:?}: {e}");
            return;
        }
    };
    let mut delay = std::time::Duration::from_secs(5);
    for attempt in 1..=8u32 {
        match announce_netdoc_author_once(&endpoint, founder_id, author_hex, self_doc.as_deref()).await {
            Ok(true) => {
                tracing::info!("netdoc announce: founder recorded our author binding");
                return;
            }
            Ok(false) => tracing::debug!(
                "netdoc announce: acked but not yet recorded (attempt {attempt}); retrying"
            ),
            Err(e) => tracing::debug!("netdoc announce: attempt {attempt} failed: {e:#}"),
        }
        tokio::time::sleep(delay).await;
        delay = (delay * 2).min(std::time::Duration::from_secs(300));
    }
    tracing::warn!(
        "netdoc announce: gave up; this member's self-keys may be unvalidated under enforce"
    );
}

/// One announce round-trip over the main endpoint.
async fn announce_netdoc_author_once(
    endpoint: &iroh::Endpoint,
    founder_id: iroh::PublicKey,
    author_hex: &str,
    self_doc: Option<&str>,
) -> Result<bool> {
    let (conn, _) = hop_core::net::connect_to_host_with_alpn(
        endpoint,
        founder_id,
        None,
        hop_core::proto::ALPN_V3,
    )
    .await?;
    let (mut send, mut recv) = conn.open_bi().await.context("open_bi for announce")?;
    proto::write_message(
        &mut send,
        &ClientMessage::AnnounceNetdocAuthor {
            author: author_hex.to_string(),
            self_doc: self_doc.map(String::from),
        },
    )
    .await?;
    let resp: proto::HostMessage = proto::read_message(&mut recv).await?;
    let _ = send.finish();
    match resp {
        proto::HostMessage::NetdocAuthorAck { recorded } => Ok(recorded),
        other => anyhow::bail!("unexpected announce response: {other:?}"),
    }
}

#[allow(clippy::too_many_arguments)]
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
    registry: RegistryHandle,
    datastore: hop_core::datastore::Datastore,
    ext_dispatcher: hop_core::extensions::ExtensionDispatcher,
    netdoc: Option<std::sync::Arc<hop_core::netdoc::NetDoc>>,
) -> Result<()> {
    // Warren-only tier: a peer whose role is `network_only` is on the mesh for
    // L3 reach but must not open host sessions (shell/exec/transfer). Refuse
    // those up front; datastore/admin requests are governed separately.
    let is_session_req = matches!(
        msg,
        Some(
            ClientMessage::RequestShell
                | ClientMessage::RequestShellV2 { .. }
                | ClientMessage::RequestShellV3 { .. }
                | ClientMessage::RequestTransfer(_)
                | ClientMessage::RequestExec { .. }
                | ClientMessage::RequestExecV2 { .. }
        )
    );
    if is_session_req && peer_is_network_only(config_dir, peer_id) {
        tracing::info!("Refusing host session for warren-only peer {}", &peer_id[..10.min(peer_id.len())]);
        let _ = proto::write_message(
            &mut send,
            &proto::HostMessage::SessionError(
                "this peer's role is warren-only (VPN reach, no host sessions)".to_string(),
            ),
        )
        .await;
        return Ok(());
    }
    match msg {
        Some(ClientMessage::RequestShell) => {
            tracing::info!("Starting shell session");
            shell::host_shell_session(send, recv, username, sandbox, config_dir, protocol_version).await?;
        }
        Some(ClientMessage::RequestShellV2 { session_id }) => {
            tracing::info!("Starting persistent shell session (resume: {})", session_id.is_some());
            shell::host_shell_session_persistent(send, recv, username, peer_id, session_id, registry, sandbox, config_dir, protocol_version).await?;
        }
        Some(ClientMessage::RequestShellV3 { session_id, sandbox: client_sandbox }) => {
            let merged = sandbox.merge_stricter(&client_sandbox);
            tracing::info!("Starting persistent shell session with client sandbox (resume: {})", session_id.is_some());
            shell::host_shell_session_persistent(send, recv, username, peer_id, session_id, registry, &merged, config_dir, protocol_version).await?;
        }
        Some(ClientMessage::RequestTransfer(req)) => {
            // Same security check as shell/exec: when daemon runs as root,
            // require a bound username so files are owned by the user, not root.
            if let Err(e) = shell::check_shell_security(username) {
                let _ = proto::write_message(&mut send, &proto::TransferMsg::Error(format!("{e:#}"))).await;
                return Err(e);
            }
            tracing::info!("Starting transfer session: {:?} (v{})", req.mode, protocol_version);
            transfer::host_transfer_session(conn, send, recv, req, username, protocol_version, sandbox).await?;
        }
        Some(ClientMessage::RequestExec { command }) => {
            tracing::info!("Starting exec session: {command}");
            shell::host_exec_session(send, recv, &command, username, sandbox, protocol_version).await?;
        }
        Some(ClientMessage::RequestExecV2 { command, sandbox: client_sandbox }) => {
            let merged = sandbox.merge_stricter(&client_sandbox);
            tracing::info!("Starting exec session with client sandbox: {command}");
            shell::host_exec_session(send, recv, &command, username, &merged, protocol_version).await?;
        }
        Some(ClientMessage::RequestPeerOp(request)) => {
            tracing::info!("Peer op from {}: {:?}", peer_id, request);
            // Four-way routing:
            //  - CapEnable/CapRun need hop-mcp's capability definitions, handled inline.
            //  - Extension* (single-response) variants are async (they wait on an
            //    extension daemon's response over ipc-channel), routed through
            //    the dispatcher.
            //  - ExtensionStreamOpen forks: dispatcher returns a StreamHandle;
            //    we relay each frame as a fresh PeerResponse over the same QUIC
            //    stream until StreamClosed.
            //  - Everything else is a sync peer op via hop-core::peer_ops.
            //
            // Streaming break-out is handled first because it doesn't fit the
            // single-PeerResponse shape the other arms produce.
            if let hop_core::proto::PeerRequest::ExtensionStreamOpen { ext_id, payload } = request {
                let peer_ctx = hop_core::extensions::PeerContext {
                    peer_id: peer_id.to_string(),
                    peer_username: username.map(|s| s.to_string()),
                    peer_role: format!("{:?}", role).to_lowercase(),
                };
                match ext_dispatcher.dispatch_stream_open(peer_ctx, ext_id, payload).await {
                    Ok(mut handle) => {
                        // 1. Inform the peer the stream is open.
                        let stream_id = handle.stream_id;
                        proto::write_message(
                            &mut send,
                            &proto::HostMessage::PeerResponse(
                                hop_core::proto::PeerResponse::ExtensionStreamOpened { stream_id },
                            ),
                        )
                        .await?;
                        // 2. Pump frames until close.
                        while let Some(kind) = handle.frames.recv().await {
                            let resp = match kind {
                                hop_core::extensions::StreamFrameKind::Frame(payload) => {
                                    hop_core::proto::PeerResponse::ExtensionStreamFrame {
                                        stream_id,
                                        payload,
                                    }
                                }
                                hop_core::extensions::StreamFrameKind::Closed(reason) => {
                                    hop_core::proto::PeerResponse::ExtensionStreamClosed {
                                        stream_id,
                                        reason,
                                    }
                                }
                            };
                            let is_close = matches!(
                                &resp,
                                hop_core::proto::PeerResponse::ExtensionStreamClosed { .. }
                            );
                            proto::write_message(
                                &mut send,
                                &proto::HostMessage::PeerResponse(resp),
                            )
                            .await?;
                            if is_close {
                                break;
                            }
                        }
                    }
                    Err(err_resp) => {
                        proto::write_message(
                            &mut send,
                            &proto::HostMessage::PeerResponse(err_resp),
                        )
                        .await?;
                    }
                }
                return Ok(());
            }

            let response = match request {
                hop_core::proto::PeerRequest::CapEnable { ref id, ref schedule, ref targets } => {
                    handle_remote_cap_enable(&datastore, id, schedule.as_deref(), targets.as_deref(), username)
                }
                hop_core::proto::PeerRequest::CapRun { ref id, ref targets, ref params } => {
                    handle_remote_cap_run(&datastore, id, targets.as_deref(), params, username)
                }
                req @ (hop_core::proto::PeerRequest::ExtensionList
                | hop_core::proto::PeerRequest::ExtensionCall { .. }
                | hop_core::proto::PeerRequest::ExtensionStreamInput { .. }
                | hop_core::proto::PeerRequest::ExtensionStreamClose { .. }) => {
                    let peer_ctx = hop_core::extensions::PeerContext {
                        peer_id: peer_id.to_string(),
                        peer_username: username.map(|s| s.to_string()),
                        peer_role: format!("{:?}", role).to_lowercase(),
                    };
                    ext_dispatcher.dispatch(peer_ctx, req).await
                }
                _ => {
                    let peer_user = username.unwrap_or("default");
                    hop_core::peer_ops::handle_peer_request(request, config_dir, &datastore, peer_user)
                }
            };
            proto::write_message(&mut send, &proto::HostMessage::PeerResponse(response)).await?;
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
                Some(&datastore),
            );
            // Mirror peer/role state into the network document after any admin
            // mutation (best-effort). Reconcile is idempotent and self-healing —
            // it adds new peers/roles and revokes ones removed from peers.json,
            // so RemovePeer immediately writes a doc revocation.
            if let Some(nd) = &netdoc
                && !matches!(response, AdminResponse::Error { .. })
            {
                let peers = hop_core::config::PeersStore::load(config_dir)
                    .map(|p| p.peers)
                    .unwrap_or_default();
                let roles = hop_core::fleet::RolesStore::load(config_dir)
                    .map(|r| r.roles)
                    .unwrap_or_default();
                if let Err(e) = nd.reconcile(&peers, &roles).await {
                    tracing::warn!("netdoc: reconcile after admin request failed: {e:#}");
                }
                // A grant/revoke of admin role changes the trusted-admin set.
                nd.refresh_admin_authors().await;
            }
            proto::write_message(&mut send, &proto::HostMessage::AdminResponse(response)).await?;
        }
        Some(ClientMessage::AnnounceNetdocAuthor { author, self_doc }) => {
            // A warren member announced its doc author (+ self-doc read ticket).
            // Only the founder/admin (the C1 trust anchor) records the admin-owned
            // bindings; any other receiver acks without recording so the member
            // keeps retrying until it reaches the anchor. Best-effort.
            let recorded = if let Some(nd) = &netdoc {
                let r = match nd.record_peer_author(peer_id, &author).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("netdoc: record_peer_author for {peer_id} failed: {e:#}");
                        false
                    }
                };
                // Record the member's self-doc ticket too (per-member self-docs).
                if let Some(ticket) = self_doc.as_deref()
                    && let Err(e) = nd.record_peer_self_doc(peer_id, ticket).await
                {
                    tracing::warn!("netdoc: record_peer_self_doc for {peer_id} failed: {e:#}");
                }
                r
            } else {
                false
            };
            let _ = proto::write_message(
                &mut send,
                &proto::HostMessage::NetdocAuthorAck { recorded },
            )
            .await;
        }
        Some(other) => {
            tracing::warn!("Expected RequestShell/Transfer/Exec/Admin/PeerOp, got: {:?}", other);
        }
        None => {
            tracing::warn!("No session request message received");
        }
    }
    Ok(())
}

/// Parse the `--tier` flag into an `InviteTier`. `None` (flag absent) means
/// "infer" — the legacy behaviour where `effective_tier()` derives the tier
/// from `warren_ticket` + role.
fn parse_invite_tier(s: Option<&str>) -> Result<Option<hop_core::invite::InviteTier>> {
    use hop_core::invite::InviteTier;
    let Some(s) = s else { return Ok(None) };
    let t = match s.trim().to_ascii_lowercase().replace('_', "-").as_str() {
        "client" => InviteTier::Client,
        "warren-only" | "warren" | "vpn" => InviteTier::WarrenOnly,
        "node" => InviteTier::Node,
        "admin" => InviteTier::Admin,
        other => anyhow::bail!(
            "unknown --tier {other:?} (expected: client, warren-only, node, admin)"
        ),
    };
    Ok(Some(t))
}

/// One-line description of what redeeming a tier does, for the `hop invite` output.
fn tier_summary(t: hop_core::invite::InviteTier) -> &'static str {
    use hop_core::invite::InviteTier;
    match t {
        InviteTier::Client => "reach this host only; no warren, no daemon, no sudo",
        InviteTier::WarrenOnly => "join the warren VPN (vIP/MagicDNS reach); cannot open host sessions",
        InviteTier::Node => "join the warren as a reachable node (self-upgrades to a daemon)",
        InviteTier::Admin => "node + warren admin (mint/grant); redeems with creator access",
    }
}

/// Resolve this host's founder (trust-anchor) doc author. A federated node has
/// it persisted (`netdoc-founder.author`); the founder itself carries it in its
/// own augmented `creator_invite`. Used to pin C1 trust into issued invites.
fn resolve_founder_author(config_dir: &std::path::Path) -> Option<String> {
    if let Ok(s) = std::fs::read_to_string(config_dir.join("netdoc-founder.author")) {
        let s = s.trim().to_string();
        if !s.is_empty() {
            return Some(s);
        }
    }
    let ci = std::fs::read_to_string(config_dir.join("creator_invite")).ok()?;
    invite::decode_invite(ci.trim()).ok()?.founder_author
}

fn cmd_invite(
    secret_key: iroh::SecretKey,
    config_dir: &std::path::Path,
    username: Option<&str>,
    role_name: Option<&str>,
    tier: Option<hop_core::invite::InviteTier>,
    host_name: Option<&str>,
    sandbox: hop_core::sandbox::SandboxPolicy,
) -> Result<()> {
    use hop_core::invite::InviteTier;
    let public_key = secret_key.public();

    // A warren tier needs an actual warren on this host.
    let has_warren = config_dir.join("netdoc.ticket").exists();
    if matches!(tier, Some(InviteTier::WarrenOnly | InviteTier::Node | InviteTier::Admin))
        && !has_warren
    {
        anyhow::bail!(
            "--tier {} needs a warren, but this host has none. Enable the VPN first \
             (`hop config set vpn on` or install with `--host`), then re-issue the invite.",
            match tier { Some(t) => t.as_str(), None => "" }
        );
    }
    // Tier decides the peer role recorded for redemption (must be set BEFORE the
    // pending invite is stored): admin → Creator; everything else → Peer with a
    // role name (warren-only pins the seeded `warren-only` network_only role).
    let (peer_role, resolved_role_name): (PeerRole, Option<String>) = match tier {
        Some(InviteTier::Admin) => (PeerRole::Creator, Some("admin".to_string())),
        Some(InviteTier::WarrenOnly) => (PeerRole::Peer, Some("warren-only".to_string())),
        _ => (
            PeerRole::Peer,
            role_name
                .map(String::from)
                .or_else(|| config::HostConfig::load(config_dir).ok().map(|c| c.default_role)),
        ),
    };

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
    // Fall back to the default relay URL — musl builds lack full DNS resolver
    // support, so discovery via DNS/pkarr may fail without a relay hint.
    let relay_url = std::fs::read_to_string(config_dir.join("relay_url"))
        .ok()
        .or_else(|| Some(hop_core::net::HOP_RELAY_URL.to_string()));
    let token = invite::generate_invite_with_role(
        &public_key,
        config_dir,
        relay_url.as_deref(),
        username,
        host_name,
        peer_role,
        resolved_role_name,
        15 * 60,
        sandbox.clone(),
    )?;

    // Stamp the explicit tier (and, for warren tiers, the founder trust anchor)
    // onto the token. Safe post-generation: the pending-invite store records
    // only the secret/role/sandbox, never the tier or warren_ticket, so this
    // can't desync redemption. A client-tier invite strips any warren_ticket so
    // it can never self-upgrade into a node.
    let token = if let Some(t) = tier {
        let mut decoded = invite::decode_invite(&token)?;
        decoded.tier = t;
        if t == InviteTier::Client {
            decoded.warren_ticket = None;
            decoded.founder_author = None;
        } else {
            // Pin the founder author so a joining node anchors C1 trust.
            decoded.founder_author = resolve_founder_author(config_dir);
        }
        invite::encode_invite(&decoded)?
    } else {
        token
    };

    if let Some(t) = tier {
        println!("Tier: {} — {}", t.as_str(), tier_summary(t));
        println!();
    }
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
/// Parsed arguments from the `External` (catch-all) subcommand handler.
///
/// `hop <target> [--read-only] [--no-network] [--preset X] [--name X]
///  [--scope P]... [--allow-command C]... [-- cmd args...]`
#[derive(Debug, PartialEq)]
struct ExternalArgs {
    target: String,
    read_only: bool,
    no_network: bool,
    preset: Option<String>,
    name: Option<String>,
    scopes: Vec<std::path::PathBuf>,
    allow_commands: Vec<String>,
    exec_command: Option<Vec<String>>,
}

/// Parse sandbox/connection flags from the External (catch-all) subcommand args.
///
/// Extracted from the inline handler so we can unit-test it without needing
/// config/key loading. Fails if `args` is empty (no target).
fn parse_external_args(args: &[String]) -> Result<ExternalArgs> {
    let target = args.first().context("no target specified")?.clone();

    let read_only = args.iter().any(|a| a == "--read-only");
    let no_network = args.iter().any(|a| a == "--no-network");
    let preset = args.iter().position(|a| a == "--preset")
        .and_then(|i| args.get(i + 1)).cloned();
    let name = args.iter().position(|a| a == "--name")
        .and_then(|i| args.get(i + 1)).cloned();
    let scopes: Vec<std::path::PathBuf> = args.windows(2)
        .filter(|w| w[0] == "--scope")
        .map(|w| std::path::PathBuf::from(&w[1]))
        .collect();
    let allow_commands: Vec<String> = args.windows(2)
        .filter(|w| w[0] == "--allow-command")
        .map(|w| w[1].clone())
        .collect();

    let exec_command = if let Some(sep) = args.iter().position(|a| a == "--") {
        let command = args[sep + 1..].to_vec();
        if command.is_empty() {
            anyhow::bail!("no command specified after --");
        }
        Some(command)
    } else {
        None
    };

    Ok(ExternalArgs {
        target,
        read_only,
        no_network,
        preset,
        name,
        scopes,
        allow_commands,
        exec_command,
    })
}

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

/// Internal subcommand: apply sandbox and exec a shell.
///
/// Used by the Linux PTY sandbox wrapper. The hop binary re-execs itself with
/// `__sandbox-shell --policy <json> -- <shell> <args...>`, applies Landlock +
/// no_new_privs in-process, then execs the real shell.
fn cmd_sandbox_shell(policy_json: &str, shell_args: &[String]) -> Result<()> {
    let policy: hop_core::sandbox::SandboxPolicy = serde_json::from_str(policy_json)
        .context("invalid sandbox policy JSON")?;

    // Apply sandbox restrictions to this process. A restricted policy that the
    // kernel can't enforce is fatal — refuse rather than exec unsandboxed.
    #[cfg(target_os = "linux")]
    hop_core::sandbox::linux::apply_sandbox(&policy)
        .map_err(|e| anyhow::anyhow!("sandbox enforcement failed: {e}"))?;

    #[cfg(not(target_os = "linux"))]
    {
        let _ = &policy;
    }

    // Exec the real shell (replaces this process)
    let shell = shell_args.first().context("no shell specified")?;
    let mut cmd = std::process::Command::new(shell);
    cmd.args(&shell_args[1..]);

    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let err = cmd.exec();
        Err(anyhow::anyhow!("exec failed: {err}"))
    }

    #[cfg(not(unix))]
    {
        let status = cmd.status().context("failed to run shell")?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Privilege-separated transfer helper entry point.
///
/// Runs as the target user (spawned by the daemon with uid/gid set).
/// Reads TransferMsg from stdin, writes files, sends acks to stdout.
async fn cmd_transfer_helper(mode: &str, dest: &str, compression: Option<&str>, chunk_size: usize) -> Result<()> {
    use hop_core::transfer::negotiation::{Compression, NegotiatedParams};

    let params = NegotiatedParams {
        compression: compression.and_then(|c| {
            if let Some(level_str) = c.strip_prefix("zstd:") {
                level_str.parse().ok().map(|level| Compression::Zstd { level })
            } else {
                None
            }
        }),
        max_chunk_size: chunk_size,
    };

    let dest_path = std::path::Path::new(dest);
    hop_core::transfer::helper::run_transfer_helper(mode, dest_path, params).await
}

/// List processes using libproc + sysctl (works inside macOS sandbox without setuid).
///
/// macOS sandbox-exec strips the setuid bit from child processes, so
/// /bin/ps (which is setuid) cannot run. This uses libproc to enumerate
/// PIDs, then KERN_PROCARGS2 sysctl to get full command lines.
/// Install + start the hop system daemon from **embedded** templates (launchd on
/// macOS, systemd on Linux) — no network round-trip for the setup logic. Must run
/// as root; it writes a system service file and (re)starts the daemon.
///
/// RESERVED FOR THE SELF-UPGRADE PATH AND NOT YET WIRED IN: `hop warren join`
/// still self-upgrades via the proven shell installer (`install.sh --host`).
/// Wiring this in is gated on a macOS daemon-install e2e (install-and-invite-tiers.md
/// §10), so this privileged path stays inert until it can be end-to-end tested.
#[allow(unused_variables, unreachable_code)]
fn cmd_install_daemon() -> Result<()> {
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    anyhow::bail!("__install-daemon is only supported on macOS and Linux");

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        anyhow::ensure!(
            hop_core::unix_user::is_running_as_root(),
            "__install-daemon must run as root (it installs a system service)"
        );
        let run = |cmd: &str, args: &[&str]| -> Result<()> {
            let status = std::process::Command::new(cmd)
                .args(args)
                .status()
                .with_context(|| format!("running {cmd}"))?;
            anyhow::ensure!(status.success(), "{cmd} {} failed ({status})", args.join(" "));
            Ok(())
        };

        #[cfg(target_os = "macos")]
        {
            const PLIST: &str = include_str!("../../../pkg/com.hop.daemon.plist");
            const PLIST_PATH: &str = "/Library/LaunchDaemons/com.hop.daemon.plist";
            std::fs::write(PLIST_PATH, PLIST)
                .with_context(|| format!("writing {PLIST_PATH}"))?;
            // bootstrap/enable are idempotent-ish; only kickstart must succeed.
            let _ = run("launchctl", &["bootstrap", "system", PLIST_PATH]);
            let _ = run("launchctl", &["enable", "system/com.hop.daemon"]);
            run("launchctl", &["kickstart", "-k", "system/com.hop.daemon"])?;
            println!("hop daemon installed + started (launchd: com.hop.daemon).");
        }
        #[cfg(target_os = "linux")]
        {
            const SERVICE: &str = include_str!("../../../pkg/hop.service");
            const UNIT_PATH: &str = "/etc/systemd/system/hop.service";
            let _ = run("groupadd", &["--system", "hop"]); // ignore "already exists"
            std::fs::create_dir_all("/etc/hop").context("creating /etc/hop")?;
            std::fs::write(UNIT_PATH, SERVICE).with_context(|| format!("writing {UNIT_PATH}"))?;
            run("systemctl", &["daemon-reload"])?;
            run("systemctl", &["enable", "--now", "hop"])?;
            println!("hop daemon installed + started (systemd: hop.service).");
        }
    }
    Ok(())
}

fn cmd_ps() -> Result<()> {
    #[cfg(target_os = "macos")]
    {
        unsafe extern "C" {
            fn proc_listallpids(buffer: *mut libc::c_void, buffersize: libc::c_int) -> libc::c_int;
        }

        // Get all PIDs via libproc
        let buf_size = unsafe { proc_listallpids(std::ptr::null_mut(), 0) };
        if buf_size <= 0 {
            anyhow::bail!("proc_listallpids failed");
        }
        let capacity = (buf_size as usize) * 2;
        let mut pids: Vec<i32> = vec![0i32; capacity];
        let actual = unsafe {
            proc_listallpids(
                pids.as_mut_ptr() as *mut libc::c_void,
                (capacity * std::mem::size_of::<i32>()) as libc::c_int,
            )
        };
        if actual <= 0 {
            anyhow::bail!("proc_listallpids failed");
        }
        pids.truncate(actual as usize);
        pids.retain(|&p| p > 0);
        pids.sort_unstable();

        println!("{:<12} {:>7} COMMAND", "USER", "PID");
        for &pid in &pids {
            // Get UID via KERN_PROC/KERN_PROC_PID sysctl
            let user = get_proc_uid(pid)
                .and_then(resolve_username)
                .unwrap_or_else(|| "-".to_string());

            // Get command name via KERN_PROCARGS2
            let cmd = get_proc_args(pid)
                .unwrap_or_else(|| "-".to_string());

            println!("{:<12} {:>7} {}", user, pid, cmd);
        }
        Ok(())
    }

    #[cfg(not(target_os = "macos"))]
    {
        // On Linux, ps is not setuid — just exec it
        let status = std::process::Command::new("ps")
            .args(["aux"])
            .status()
            .context("failed to run ps")?;
        std::process::exit(status.code().unwrap_or(1));
    }
}

/// Get the UID of a process via sysctl KERN_PROC.
#[cfg(target_os = "macos")]
fn get_proc_uid(pid: i32) -> Option<u32> {
    // KERN_PROC returns an opaque kinfo_proc; the UID is at a known offset.
    // struct kinfo_proc { struct extern_proc kp_proc; struct eproc kp_eproc; }
    // UID is in kp_eproc.e_ucred.cr_uid.
    let mut mib = [libc::CTL_KERN, libc::KERN_PROC, libc::KERN_PROC_PID, pid];
    let mut size: libc::size_t = 0;
    unsafe {
        libc::sysctl(mib.as_mut_ptr(), 4, std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0);
    }
    if size == 0 { return None; }
    let mut buf: Vec<u8> = vec![0u8; size];
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(), 4,
            buf.as_mut_ptr() as *mut libc::c_void, &mut size,
            std::ptr::null_mut(), 0,
        )
    };
    if ret != 0 || size < 300 { return None; }

    // On macOS (arm64/x86_64), UID (cr_uid) is at offset 304 in kinfo_proc.
    // This is: kp_eproc (offset 296) → e_ucred (offset 0) → cr_uid (offset 8).
    // Total: 296 + 0 + 8 = 304.
    // We read it as a u32.
    let uid_offset = 304usize;
    if uid_offset + 4 > buf.len() { return None; }
    let uid = u32::from_ne_bytes(buf[uid_offset..uid_offset + 4].try_into().ok()?);
    Some(uid)
}

/// Resolve a UID to a username.
#[cfg(target_os = "macos")]
fn resolve_username(uid: u32) -> Option<String> {
    Some(
        users::get_user_by_uid(uid)
            .map(|u| u.name().to_string_lossy().to_string())
            .unwrap_or_else(|| format!("{uid}"))
    )
}

/// Get the command line of a process via KERN_PROCARGS2 sysctl.
#[cfg(target_os = "macos")]
fn get_proc_args(pid: i32) -> Option<String> {
    const KERN_PROCARGS2: libc::c_int = 49;
    let mut mib = [libc::CTL_KERN, KERN_PROCARGS2, pid];
    let mut size: libc::size_t = 0;
    unsafe {
        libc::sysctl(mib.as_mut_ptr(), 3, std::ptr::null_mut(), &mut size, std::ptr::null_mut(), 0);
    }
    if size == 0 { return None; }
    let mut buf: Vec<u8> = vec![0u8; size];
    let ret = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(), 3,
            buf.as_mut_ptr() as *mut libc::c_void, &mut size,
            std::ptr::null_mut(), 0,
        )
    };
    if ret != 0 { return None; }
    buf.truncate(size);

    // KERN_PROCARGS2 format: [argc: i32] [exec_path\0] [padding\0...] [argv[0]\0] [argv[1]\0] ...
    if buf.len() < 4 { return None; }
    let argc = i32::from_ne_bytes(buf[0..4].try_into().ok()?) as usize;

    // Find the exec_path (starts at offset 4)
    let rest = &buf[4..];
    let exec_end = rest.iter().position(|&b| b == 0)?;
    let exec_path = String::from_utf8_lossy(&rest[..exec_end]).to_string();

    // Skip padding nulls after exec_path
    let mut pos = exec_end;
    while pos < rest.len() && rest[pos] == 0 {
        pos += 1;
    }

    // Collect argv strings
    let mut args = Vec::with_capacity(argc);
    for _ in 0..argc {
        if pos >= rest.len() { break; }
        let arg_end = rest[pos..].iter().position(|&b| b == 0).unwrap_or(rest.len() - pos);
        let arg = String::from_utf8_lossy(&rest[pos..pos + arg_end]).to_string();
        args.push(arg);
        pos += arg_end + 1;
    }

    if args.is_empty() {
        // Fall back to exec_path basename
        let basename = exec_path.rsplit('/').next().unwrap_or(&exec_path);
        Some(basename.to_string())
    } else {
        Some(args.join(" "))
    }
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
                        last_reconnect_time = Some(std::time::Instant::now());

                        // The reconnect function already sent setup messages
                        // (WindowSize + SetEnv) and consumed SessionInfo, so
                        // use the loop-only variant that skips the handshake.
                        let out =
                            shell::client_shell_loop_resumed(send, recv, &mut stdin_rx).await?;
                        session_id = new_session_id.or(session_id);
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

    // Detect trailing slash on source paths (rsync convention: trailing slash = contents only).
    // Must check raw strings before PathBuf normalization strips the slash.
    let source_contents_only: Vec<bool> = paths[..paths.len() - 1]
        .iter()
        .map(|p| {
            if let Some(colon_pos) = p.find(':') {
                p[colon_pos + 1..].ends_with('/')
            } else {
                p.ends_with('/')
            }
        })
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
            transfer::client_push_copy(&mut send, &mut recv, &local_paths, &source_contents_only, &state, &params).await?;
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
        // Skip nesting when source has trailing slash (rsync convention: contents only).
        let source_has_trailing_slash = source_contents_only[0];
        let effective_dest = if recursive && local_dest.is_dir() && !source_has_trailing_slash {
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

        // rsync convention: no trailing slash on source → sync the directory
        // itself into dest (creating dest/source_name/). Trailing slash →
        // sync the *contents* into dest.
        let effective_remote = if !source.ends_with('/') {
            if let Some(dir_name) = local_dir.file_name() {
                let name = dir_name.to_string_lossy();
                if remote_path.ends_with('/') {
                    format!("{}{}", remote_path, name)
                } else {
                    format!("{}/{}", remote_path, name)
                }
            } else {
                remote_path.to_string()
            }
        } else {
            remote_path.to_string()
        };

        let request = TransferRequest {
            mode: TransferMode::Sync,
            direction: TransferDirection::Push,
            remote_path: effective_remote.clone(),
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
            host, effective_remote,
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
        AdminAction::Invite { user, role, creator, .. } => AdminRequest::CreateInvite {
            username: user.clone(),
            role: if *creator { PeerRole::Creator } else { PeerRole::Peer },
            role_name: role.clone(),
        },
        AdminAction::Peers => AdminRequest::ListPeers,
        AdminAction::RemovePeer { id } => AdminRequest::RemovePeer {
            node_id_prefix: id.clone(),
        },
        AdminAction::Grant { id, role } => AdminRequest::SetPeerRole {
            node_id_prefix: id.clone(),
            role_name: role.clone(),
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
        AdminAction::FleetInvite { tags, max_uses, expiry, tier } => AdminRequest::CreateFleetInvite {
            tags: tags.clone(),
            max_uses: *max_uses,
            expiry_secs: *expiry,
            tier: tier.clone(),
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
                    network_only: false,
                    groups: groups.clone(),
                    shell: shell.clone(),
                    sandbox: hop_core::sandbox::SandboxPolicy::default(),
                    capabilities: Default::default(),
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
        AdminResponse::PeerRoleUpdated { success } => {
            if success {
                println!("Peer role updated.");
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
        AdminResponse::MetricsReceived { count } => {
            println!("Received {count} metric point(s)");
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
        FleetAction::Add { name, tags } => {
            // Read from user's known_hosts
            let host = KnownHostsStore::load(config_dir)?
                .hosts
                .iter()
                .find(|h| h.name == name)
                .cloned()
                .with_context(|| format!("Host '{name}' not found in known_hosts"))?;

            // Write to daemon's fleet.json (resolve without override to find system config dir)
            let host_config_dir = config::resolve_host_config_dir(None)?;
            let mut fleet = hop_core::fleet::FleetStore::load(&host_config_dir)?;
            fleet.add_member(hop_core::fleet::FleetMember {
                node_id: host.node_id.clone(),
                hostname: name.clone(),
                tags: tags.clone(),
                registered_at: unix_now_secs().to_string(),
                last_heartbeat: None,
                relay_url: host.relay_url.clone(),
                online: false,
            });
            fleet.save(&host_config_dir)?;

            let tag_display = if tags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", tags.join(", "))
            };
            println!("Added {} ({}) to fleet{tag_display}", name, &host.node_id[..10]);
            Ok(())
        }
        FleetAction::List { group } => {
            let mut seen = HashSet::new();
            let mut any = false;

            // 1. FleetStore members (daemon's fleet.json) — shown with tags
            let host_config_dir = config::resolve_host_config_dir(None)?;
            if let Ok(fleet) = hop_core::fleet::FleetStore::load(&host_config_dir) {
                for m in &fleet.members {
                    let matches = group.as_ref().map(|g| m.tags.iter().any(|t| t == g)).unwrap_or(true);
                    if !matches { continue; }
                    seen.insert(m.node_id.clone());
                    let tags = if m.tags.is_empty() {
                        String::new()
                    } else {
                        format!(" [{}]", m.tags.join(", "))
                    };
                    println!("  {} ({}){tags}", &m.node_id[..10], m.hostname);
                    any = true;
                }
            }

            // 2. KnownHostsStore (user's known_hosts) — shown with groups, skip dupes
            let hosts = KnownHostsStore::load(config_dir)?;
            for h in &hosts.hosts {
                if seen.contains(&h.node_id) { continue; }
                let matches = group.as_ref().map(|g| h.groups.contains(g)).unwrap_or(true);
                if !matches { continue; }
                let groups = if h.groups.is_empty() {
                    String::new()
                } else {
                    format!(" [{}]", h.groups.join(", "))
                };
                println!("  {} ({}){groups}", &h.node_id[..10], h.name);
                any = true;
            }

            if !any {
                println!("No hosts found.");
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

/// Run `hop auth <provider>` — authenticate with a service and store credentials.
/// If `target` is Some, stores secrets on the remote host. If None, stores locally.
///
/// Re-auth wipes any of the provider's `managed_secrets` that this flow doesn't
/// write, so leftover fields from a prior flow version (e.g. an old OAuth
/// `refresh_token` / `token_expiry` lingering after the user moves to the
/// setup-token flow) don't trip later token lookups.
async fn cmd_auth(provider: &str, target: Option<&str>, config_dir: &std::path::Path) -> Result<()> {
    let (secrets, managed) = if let Some(oauth) = oauth::oauth_provider(provider) {
        (oauth::run_oauth_flow(oauth)?, oauth.managed_secrets)
    } else if let Some(apikey) = oauth::api_key_provider(provider) {
        (oauth::run_api_key_flow(apikey)?, apikey.managed_secrets)
    } else {
        anyhow::bail!("Unknown auth provider: {provider}. Available: gmail, anthropic");
    };

    let written: std::collections::HashSet<&str> = secrets.iter().map(|(n, _)| n.as_str()).collect();
    for stale in managed.iter().filter(|k| !written.contains(*k)) {
        clear_auth_secret(target, config_dir, stale).await.ok();
    }
    for (name, value) in &secrets {
        store_auth_secret(target, config_dir, name, value.as_bytes()).await?;
    }
    println!("  \u{2713} {} authenticated.", provider);
    Ok(())
}

/// Delete a secret locally or on a remote host. Missing-key is not an error.
async fn clear_auth_secret(target: Option<&str>, config_dir: &std::path::Path, name: &str) -> Result<()> {
    if let Some(host) = target {
        let request = hop_core::proto::PeerRequest::SecretsDelete {
            name: name.to_string(),
        };
        let (_resolved, _send, mut recv) = mux::connect_to_host(
            config_dir,
            host,
            None,
            &hop_core::proto::ClientMessage::RequestPeerOp(request),
        ).await?;
        let response: hop_core::proto::HostMessage = hop_core::proto::read_message(&mut recv).await?;
        match response {
            hop_core::proto::HostMessage::PeerResponse(hop_core::proto::PeerResponse::Ok) => Ok(()),
            hop_core::proto::HostMessage::PeerResponse(hop_core::proto::PeerResponse::Error(e))
                if e.contains("secret not found") => Ok(()),
            hop_core::proto::HostMessage::PeerResponse(hop_core::proto::PeerResponse::Error(e)) => {
                anyhow::bail!("Failed to delete secret on {host}: {e}")
            }
            _ => anyhow::bail!("Unexpected response from {host}"),
        }
    } else {
        let ds = hop_core::datastore::Datastore::connect(config_dir)
            .context("Failed to connect to daemon — is `hop host` running?")?;
        let user = hop_core::unix_user::current_username()
            .unwrap_or_else(|| "default".to_string());
        // secrets_delete returns Ok(false) for missing keys, which is fine.
        let _ = ds.secrets_delete(&user, name)?;
        Ok(())
    }
}

/// Store a secret locally or on a remote host.
async fn store_auth_secret(target: Option<&str>, config_dir: &std::path::Path, name: &str, value: &[u8]) -> Result<()> {
    if let Some(host) = target {
        // Remote: send via PeerRequest over QUIC
        let request = hop_core::proto::PeerRequest::SecretsSet {
            name: name.to_string(),
            value: value.to_vec(),
        };
        let (_resolved, _send, mut recv) = mux::connect_to_host(
            config_dir,
            host,
            None,
            &hop_core::proto::ClientMessage::RequestPeerOp(request),
        ).await?;
        let response: hop_core::proto::HostMessage = hop_core::proto::read_message(&mut recv).await?;
        match response {
            hop_core::proto::HostMessage::PeerResponse(hop_core::proto::PeerResponse::Ok) => Ok(()),
            hop_core::proto::HostMessage::PeerResponse(hop_core::proto::PeerResponse::Error(e)) => {
                anyhow::bail!("Failed to store secret on {host}: {e}")
            }
            _ => anyhow::bail!("Unexpected response from {host}"),
        }
    } else {
        // Local: store via daemon Unix socket
        let ds = hop_core::datastore::Datastore::connect(config_dir)
            .context("Failed to connect to daemon — is `hop host` running?")?;
        let user = hop_core::unix_user::current_username()
            .unwrap_or_else(|| "default".to_string());
        ds.secrets_set(&user, name, value)?;
        Ok(())
    }
}

/// Run `hop cap setup <id>` — guided auth + enable.
async fn cmd_cap_setup(id: &str, schedule: Option<&str>, target: Option<&str>, config_dir: &std::path::Path) -> Result<()> {
    use hop_mcp::capabilities::CapabilityDefinition;

    let cap = CapabilityDefinition::find(id)
        .ok_or_else(|| anyhow::anyhow!("Unknown capability: '{id}'. Run `hop cap list` to see available capabilities."))?;

    println!("{} Setup", cap.name);
    println!("{}", "\u{2500}".repeat(cap.name.len() + 6));

    let reqs = cap.auth_requirements;
    if reqs.is_empty() {
        println!("\nNo authentication required.");
    } else {
        for (i, req) in reqs.iter().enumerate() {
            println!("\n[{}/{}] {}", i + 1, reqs.len(), req.description);
            cmd_auth(req.provider, target, config_dir).await?;
        }
    }

    // Enable the capability
    if !cap.is_schedulable() {
        println!("\n\u{2713} {} is on-demand only — run with `hop cap run {id}`.", cap.name);
        return Ok(());
    }

    let schedule = schedule
        .map(String::from)
        .or_else(|| cap.default_schedule().map(String::from))
        .ok_or_else(|| anyhow::anyhow!("No schedule provided and capability has no default"))?;

    println!("\nEnabling {} (schedule: {})...", cap.id, schedule);

    if let Some(host) = target {
        // Remote enable — use PeerRequest
        // For now, enable via hop exec since CapEnable needs the script
        // which only exists in the binary (hop-mcp), not on the wire protocol.
        // The remote host has the same binary, so `hop cap enable` works locally there.
        let request = hop_core::proto::PeerRequest::CapEnable {
            id: id.to_string(),
            schedule: Some(schedule),
            targets: None,
        };
        let (_resolved, _send, mut recv) = mux::connect_to_host(
            config_dir,
            host,
            None,
            &hop_core::proto::ClientMessage::RequestPeerOp(request),
        ).await?;
        let response: hop_core::proto::HostMessage = hop_core::proto::read_message(&mut recv).await?;
        match response {
            hop_core::proto::HostMessage::PeerResponse(hop_core::proto::PeerResponse::CapEnabled { job_id }) => {
                println!("\u{2713} {} active (job {job_id}).", cap.name);
            }
            hop_core::proto::HostMessage::PeerResponse(hop_core::proto::PeerResponse::Error(e)) => {
                // Remote cap enable not yet supported — tell user to run locally
                eprintln!("Note: {e}");
                eprintln!("Run on the remote host: hop cap enable {id}");
            }
            _ => {
                anyhow::bail!("Unexpected response");
            }
        }
    } else {
        // Local enable — same as cmd_cap CapAction::Enable
        let sched: cron::Schedule = schedule.parse()
            .map_err(|e| anyhow::anyhow!("Invalid cron expression '{schedule}': {e}"))?;

        let ds = hop_core::datastore::Datastore::connect(config_dir)
            .context("Failed to connect to daemon — is `hop host` running?")?;

        let catalog_id = cap.catalog_id();
        if let Ok(Some(existing)) = ds.cron_find_by_catalog_id(&catalog_id) {
            println!("\u{2713} {} already enabled (job {}).", cap.id, existing.id);
            return Ok(());
        }

        let now = unix_now_ms();
        let next_run = hop_mcp::cron::next_occurrence_ms(&sched, now);
        let job_id = format!("{:08x}", rand::random::<u32>());

        let job = hop_core::datastore::types::CronJob {
            id: job_id.clone(),
            name: format!("cap:{}", id),
            schedule,
            script: cap.script.to_string(),
            enabled: true,
            last_run: None,
            next_run,
            created_at: now,
            tags: vec![format!("cap:{}", id)],
            targets: None,
            catalog_id: Some(catalog_id),
            sandbox: Some(cap.tier.to_sandbox()),
            run_as_user: hop_core::unix_user::current_username(),
        };
        ds.cron_add(&job)?;
        println!("\u{2713} {} active (job {}).", cap.name, job_id);
    }

    if let Some(host) = target {
        println!("\nRun `hop {host} cap run {id}` to test now.");
    } else {
        println!("\nRun `hop cap run {id}` to test now.");
    }
    Ok(())
}

async fn cmd_cap(config_dir: &std::path::Path, action: CapAction) -> Result<()> {
    use hop_mcp::capabilities::{CapabilityDefinition, registry::builtin_capabilities};

    match action {
        CapAction::List => {
            let caps = builtin_capabilities();
            println!("Available capabilities:\n");
            for cap in caps {
                let trigger = match &cap.trigger {
                    hop_mcp::capabilities::TriggerMode::Scheduled { default_schedule } => {
                        format!("scheduled ({})", default_schedule)
                    }
                    hop_mcp::capabilities::TriggerMode::OnDemand => "on-demand".to_string(),
                    hop_mcp::capabilities::TriggerMode::Both { default_schedule } => {
                        format!("scheduled ({}) + on-demand", default_schedule)
                    }
                };
                println!("  {:20} {} [{}] [{}]", cap.id, cap.description.split('.').next().unwrap_or(""), cap.tier.name(), trigger);
            }
        }
        CapAction::Enable { id, targets, schedule } => {
            let cap = CapabilityDefinition::find(&id)
                .ok_or_else(|| anyhow::anyhow!("Unknown capability: '{id}'. Run `hop cap list` to see available capabilities."))?;

            if !cap.is_schedulable() {
                anyhow::bail!("Capability '{id}' is on-demand only — use `hop cap run {id}` instead");
            }

            let schedule = schedule
                .or_else(|| cap.default_schedule().map(String::from))
                .ok_or_else(|| anyhow::anyhow!("No schedule provided and capability has no default"))?;

            // Validate the schedule
            let sched: cron::Schedule = schedule.parse()
                .map_err(|e| anyhow::anyhow!("Invalid cron expression '{schedule}': {e}"))?;

            let ds = hop_core::datastore::Datastore::connect(config_dir)
                .context("Failed to connect to daemon — is `hop host` running?")?;

            let catalog_id = cap.catalog_id();

            // Check if already enabled
            if let Ok(Some(existing)) = ds.cron_find_by_catalog_id(&catalog_id) {
                println!("Capability '{}' already enabled (job {})", id, existing.id);
                return Ok(());
            }

            let now = unix_now_ms();
            let next_run = hop_mcp::cron::next_occurrence_ms(&sched, now);
            let job_id = format!("{:08x}", rand::random::<u32>());

            let job = hop_core::datastore::types::CronJob {
                id: job_id.clone(),
                name: format!("cap:{}", id),
                schedule,
                script: cap.script.to_string(),
                enabled: true,
                last_run: None,
                next_run,
                created_at: now,
                tags: vec![format!("cap:{}", id)],
                targets,
                catalog_id: Some(catalog_id),
                sandbox: Some(cap.tier.to_sandbox()),
                run_as_user: hop_core::unix_user::current_username(),
            };
            ds.cron_add(&job)?;
            println!("Enabled capability '{}' (job {}, sandbox: {})", id, job_id, cap.tier.name());
        }
        CapAction::Disable { id } => {
            let cap = CapabilityDefinition::find(&id)
                .ok_or_else(|| anyhow::anyhow!("Unknown capability: '{id}'"))?;

            let ds = hop_core::datastore::Datastore::connect(config_dir)
                .context("Failed to connect to daemon — is `hop host` running?")?;

            let catalog_id = cap.catalog_id();
            match ds.cron_find_by_catalog_id(&catalog_id) {
                Ok(Some(job)) => {
                    ds.cron_remove(&job.id)?;
                    println!("Disabled capability '{}' (removed job {})", id, job.id);
                }
                Ok(None) => {
                    println!("Capability '{}' is not enabled", id);
                }
                Err(e) => anyhow::bail!("Failed to check capability status: {e}"),
            }
        }
        CapAction::Status => {
            let ds = hop_core::datastore::Datastore::connect(config_dir)
                .context("Failed to connect to daemon — is `hop host` running?")?;

            let jobs = ds.cron_list()?;
            let cap_jobs: Vec<_> = jobs.iter()
                .filter(|j| j.catalog_id.as_deref().is_some_and(|id| id.starts_with("cap:")))
                .collect();

            if cap_jobs.is_empty() {
                println!("No capabilities enabled.");
            } else {
                println!("Enabled capabilities:\n");
                for j in &cap_jobs {
                    let status = if j.enabled { "active" } else { "paused" };
                    let targets = j.targets.as_deref().unwrap_or("local");
                    let last = j.last_run
                        .map(|t| format!("{}ms ago", unix_now_ms().saturating_sub(t)))
                        .unwrap_or_else(|| "never".into());
                    println!("  {:20} [{}] targets={} schedule={} last_run={}",
                        j.catalog_id.as_deref().unwrap_or(&j.name),
                        status, targets, j.schedule, last);
                }
            }
        }
        CapAction::Run { id, targets, params } => {
            let cap = CapabilityDefinition::find(&id)
                .ok_or_else(|| anyhow::anyhow!("Unknown capability: '{id}'"))?;

            let ds = hop_core::datastore::Datastore::connect(config_dir)
                .context("Failed to connect to daemon — is `hop host` running?")?;

            // Parse params into a JSON object
            let params_map: std::collections::HashMap<String, String> = params.iter()
                .filter_map(|p| {
                    let (key, value) = p.split_once('=')?;
                    Some((key.to_string(), value.to_string()))
                })
                .collect();

            // Build the script with params and targets injection
            let mut script = String::new();
            if !params_map.is_empty() {
                let params_json = serde_json::to_string(&params_map).unwrap_or_else(|_| "{}".to_string());
                script.push_str(&format!("hop.params = {};\n", params_json));
            }

            // Inject targets if provided — we create a minimal targets array
            if let Some(ref tag) = targets {
                // We can't resolve fleet hosts here without a backend, so create a placeholder
                // that the script can use. The actual host resolution happens in the cron scheduler.
                // For one-shot execution, create a temporary cron job with next_run=0.
                let catalog_id = format!("cap:run:{}", id);
                let now = unix_now_ms();
                let job_id = format!("{:08x}", rand::random::<u32>());

                let full_script = format!("{}{}", script, cap.script);
                let job = hop_core::datastore::types::CronJob {
                    id: job_id.clone(),
                    name: format!("cap:run:{}", id),
                    schedule: "0 0 0 1 1 * 2099".to_string(), // far future, won't repeat
                    script: full_script,
                    enabled: true,
                    last_run: None,
                    next_run: 0, // trigger immediately
                    created_at: now,
                    tags: vec![],
                    targets: Some(tag.clone()),
                    catalog_id: Some(catalog_id),
                    sandbox: Some(cap.tier.to_sandbox()),
                    run_as_user: hop_core::unix_user::current_username(),
                };
                ds.cron_add(&job)?;
                println!("Triggered capability '{}' on targets '{}' (job {}, will run on next scheduler tick ~15s)", id, tag, job_id);
                return Ok(());
            }

            // No targets — run locally via a one-shot cron job
            script.push_str(cap.script);
            let now = unix_now_ms();
            let job_id = format!("{:08x}", rand::random::<u32>());
            let job = hop_core::datastore::types::CronJob {
                id: job_id.clone(),
                name: format!("cap:run:{}", id),
                schedule: "0 0 0 1 1 * 2099".to_string(),
                script,
                enabled: true,
                last_run: None,
                next_run: 0,
                created_at: now,
                tags: vec![],
                targets: None,
                catalog_id: Some(format!("cap:run:{}", id)),
                sandbox: Some(cap.tier.to_sandbox()),
                run_as_user: hop_core::unix_user::current_username(),
            };
            ds.cron_add(&job)?;
            println!("Triggered capability '{}' locally (job {}, will run on next scheduler tick ~15s)", id, job_id);
        }
        CapAction::Deploy { id, targets } => {
            use hop_mcp::backend::OrchestratorBackend;

            let _cap = CapabilityDefinition::find(&id)
                .ok_or_else(|| anyhow::anyhow!("Unknown capability: '{id}'"))?;

            // Deploy uses fleet exec to run `hop cap enable <id>` on each node
            let config_dir2 = config_dir.to_path_buf();
            let secret_key = config::load_or_generate_identity(&config_dir2)?;
            let endpoint = net::create_client_endpoint(secret_key).await?;

            let backend = hop_mcp::backend::direct::DirectBackend::new(
                std::sync::Arc::new(endpoint),
                config_dir2,
            );

            let cmd = format!("hop cap enable {}", id);
            println!("Deploying capability '{}' to targets '{}'...", id, targets);

            match backend.fleet_exec(&targets, &cmd).await {
                Ok(results) => {
                    for r in &results {
                        if r.exit_code == 0 {
                            println!("  {}: ok", r.host);
                        } else {
                            eprintln!("  {}: failed (exit {}): {}", r.host, r.exit_code, r.stderr.trim());
                        }
                    }
                    println!("Deployed to {} hosts", results.len());
                }
                Err(e) => anyhow::bail!("Fleet exec failed: {e}"),
            }
        }
        CapAction::Setup { id, schedule } => {
            return cmd_cap_setup(&id, schedule.as_deref(), None, config_dir).await;
        }
    }
    Ok(())
}

fn cmd_cron(config_dir: &std::path::Path, action: CronAction) -> Result<()> {
    let ds = hop_core::datastore::Datastore::connect(config_dir)
        .context("Failed to connect to daemon — is `hop host` running?")?;

    match action {
        CronAction::List => {
            let jobs = ds.cron_list()?;
            if jobs.is_empty() {
                println!("No cron jobs.");
            } else {
                for j in &jobs {
                    let status = if j.enabled { "enabled" } else { "disabled" };
                    let targets = j.targets.as_deref().unwrap_or("-");
                    println!("  {} {} [{}] schedule={} targets={}", j.id, j.name, status, j.schedule, targets);
                }
            }
        }
        CronAction::Get { id } => {
            match ds.cron_get(&id)? {
                Some(j) => {
                    println!("ID:        {}", j.id);
                    println!("Name:      {}", j.name);
                    println!("Schedule:  {}", j.schedule);
                    println!("Enabled:   {}", j.enabled);
                    println!("Targets:   {}", j.targets.as_deref().unwrap_or("-"));
                    println!("Tags:      {}", if j.tags.is_empty() { "-".to_string() } else { j.tags.join(", ") });
                    println!("Created:   {}", j.created_at);
                    println!("Last run:  {}", j.last_run.map(|t| t.to_string()).unwrap_or_else(|| "never".into()));
                    println!("Next run:  {}", j.next_run);
                    println!("--- script ---");
                    println!("{}", j.script);
                }
                None => anyhow::bail!("Cron job '{id}' not found"),
            }
        }
        CronAction::Create { name, schedule, script, file, targets, tags } => {
            let script_content = match (script, file) {
                (Some(s), _) => s,
                (_, Some(path)) => std::fs::read_to_string(&path)
                    .with_context(|| format!("Failed to read script file: {}", path.display()))?,
                _ => anyhow::bail!("Either --script or --file is required"),
            };

            // Validate schedule
            let sched: cron::Schedule = schedule.parse()
                .map_err(|e| anyhow::anyhow!("Invalid cron expression '{schedule}': {e}"))?;

            let now = unix_now_ms();
            let next_run = hop_mcp::cron::next_occurrence_ms(&sched, now);

            let id = format!("{:08x}", rand::random::<u32>());
            let job = hop_core::datastore::types::CronJob {
                id: id.clone(),
                name,
                schedule,
                script: script_content,
                enabled: true,
                last_run: None,
                next_run,
                created_at: now,
                tags,
                targets,
                catalog_id: None,
                sandbox: None,
                run_as_user: hop_core::unix_user::current_username(),
            };
            ds.cron_add(&job)?;
            println!("Created cron job: {id}");
        }
        CronAction::Delete { id } => {
            if ds.cron_remove(&id)? {
                println!("Deleted cron job: {id}");
            } else {
                anyhow::bail!("Cron job '{id}' not found");
            }
        }
        CronAction::Enable { id } => {
            let mut job = ds.cron_get(&id)?
                .with_context(|| format!("Cron job '{id}' not found"))?;
            job.enabled = true;
            ds.cron_add(&job)?;
            println!("Enabled cron job: {id}");
        }
        CronAction::Disable { id } => {
            let mut job = ds.cron_get(&id)?
                .with_context(|| format!("Cron job '{id}' not found"))?;
            job.enabled = false;
            ds.cron_add(&job)?;
            println!("Disabled cron job: {id}");
        }
        CronAction::Run { id } => {
            let mut job = ds.cron_get(&id)?
                .with_context(|| format!("Cron job '{id}' not found"))?;
            job.next_run = 0;
            job.enabled = true;
            ds.cron_add(&job)?;
            println!("Triggered cron job: {id} (will run on next scheduler tick, ~15s)");
        }
        CronAction::Errors { id } => {
            if let Some(id) = id {
                // Show all errors for a specific job (timestamped history)
                let entries = ds.kv_list("cron_errors", &format!("{id}:"))?;
                if entries.is_empty() {
                    // Fallback: try exact key (legacy format without timestamp)
                    match ds.kv_get("cron_errors", &id)? {
                        Some(entry) => {
                            let text = String::from_utf8_lossy(&entry.value);
                            println!("{text}");
                        }
                        None => println!("No errors recorded for job {id}."),
                    }
                } else {
                    for (key, entry) in &entries {
                        // Extract timestamp from key format "job_id:0000001234567890"
                        let ts = key.rsplit(':').next()
                            .and_then(|s| s.parse::<u64>().ok())
                            .unwrap_or(entry.updated_at);
                        let dt = format_epoch_ms(ts);
                        let text = String::from_utf8_lossy(&entry.value);
                        println!("[{dt}] {text}");
                        println!();
                    }
                }
            } else {
                // List mode: show latest error per job
                let all = ds.kv_list("cron_errors", "")?;
                if all.is_empty() {
                    println!("No cron errors recorded.");
                } else {
                    // Group by job_id prefix, show only latest
                    let mut latest: std::collections::BTreeMap<String, (&str, &hop_core::datastore::types::KvEntry)> =
                        std::collections::BTreeMap::new();
                    for (key, entry) in &all {
                        let job_id = key.rsplit_once(':')
                            .map(|(prefix, _)| prefix)
                            .unwrap_or(key);
                        latest.insert(job_id.to_string(), (key, entry));
                    }
                    for (job_id, (_, entry)) in &latest {
                        let text = String::from_utf8_lossy(&entry.value);
                        let truncated = if text.len() > 120 { format!("{}...", &text[..117]) } else { text.to_string() };
                        let dt = format_epoch_ms(entry.updated_at);
                        println!("  {job_id} [{dt}]: {truncated}");
                    }
                }
            }
        }
    }
    Ok(())
}

/// Format epoch milliseconds as a human-readable UTC timestamp.
fn format_epoch_ms(ms: u64) -> String {
    let secs = ms / 1000;
    let s = secs % 60;
    let m = (secs / 60) % 60;
    let h = (secs / 3600) % 24;
    let days = secs / 86400;
    // Days since 1970-01-01
    let (y, mo, d) = days_to_ymd(days);
    format!("{y:04}-{mo:02}-{d:02} {h:02}:{m:02}:{s:02} UTC")
}

/// Convert days since epoch to (year, month, day). Simple calendar arithmetic.
fn days_to_ymd(days: u64) -> (u64, u64, u64) {
    // Algorithm from https://howardhinnant.github.io/date_algorithms.html
    let z = days + 719468;
    let era = z / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    (y, m, d)
}

fn cmd_kv(config_dir: &std::path::Path, action: KvAction) -> Result<()> {
    let ds = hop_core::datastore::Datastore::connect(config_dir)
        .context("Failed to connect to daemon — is `hop host` running?")?;
    let ns = "default";

    match action {
        KvAction::Get { key, raw } => {
            match ds.kv_get(ns, &key)? {
                Some(entry) => {
                    let text = String::from_utf8_lossy(&entry.value);
                    if raw {
                        // --raw: unwrap JSON strings so binary/HTML content
                        // can be piped directly to a file.
                        if text.starts_with('"') {
                            if let Ok(serde_json::Value::String(s)) =
                                serde_json::from_str(&text)
                            {
                                print!("{s}");
                            } else {
                                print!("{text}");
                            }
                        } else {
                            print!("{text}");
                        }
                    } else {
                        println!("{text}");
                    }
                }
                None => {
                    println!("(not found)");
                }
            }
        }
        KvAction::List { prefix } => {
            let prefix = prefix.as_deref().unwrap_or("");
            let entries = ds.kv_list(ns, prefix)?;
            if entries.is_empty() {
                println!("No keys found.");
            } else {
                for (key, entry) in &entries {
                    let value = String::from_utf8_lossy(&entry.value);
                    let truncated = if value.len() > 80 {
                        format!("{}...", &value[..77])
                    } else {
                        value.to_string()
                    };
                    println!("  {key} = {truncated}");
                }
            }
        }
        KvAction::Set { key, value } => {
            let entry = hop_core::datastore::types::KvEntry {
                value: value.into_bytes(),
                content_type: "text/plain".to_string(),
                updated_at: unix_now_ms(),
            };
            ds.kv_set(ns, &key, &entry)?;
            println!("OK");
        }
    }
    Ok(())
}

fn cmd_secrets(config_dir: &std::path::Path, action: SecretsAction) -> Result<()> {
    let ds = hop_core::datastore::Datastore::connect(config_dir)
        .context("Failed to connect to daemon — is `hop host` running?")?;
    let user = hop_core::unix_user::current_username()
        .unwrap_or_else(|| "default".to_string());

    match action {
        SecretsAction::Get { name } => {
            match ds.secrets_get(&user, &name)? {
                Some(value) => {
                    let text = String::from_utf8_lossy(&value);
                    println!("{text}");
                }
                None => {
                    println!("(not found)");
                }
            }
        }
        SecretsAction::Set { name, value } => {
            let value = match value {
                Some(v) => v,
                None => {
                    use std::io::{IsTerminal, Read};
                    if std::io::stdin().is_terminal() {
                        eprint!("Enter secret value: ");
                        let mut buf = String::new();
                        std::io::stdin().read_line(&mut buf)?;
                        buf.trim_end().to_string()
                    } else {
                        let mut buf = String::new();
                        std::io::stdin().read_to_string(&mut buf)?;
                        buf.trim_end().to_string()
                    }
                }
            };
            ds.secrets_set(&user, &name, value.as_bytes())?;
            println!("OK");
        }
        SecretsAction::List => {
            let names = ds.secrets_list(&user)?;
            if names.is_empty() {
                println!("No secrets stored.");
            } else {
                for name in &names {
                    println!("  {name}");
                }
            }
        }
        SecretsAction::Delete { name } => {
            if ds.secrets_delete(&user, &name)? {
                println!("Deleted.");
            } else {
                println!("(not found)");
            }
        }
    }
    Ok(())
}

/// Handle remote peer operations: `hop <host> secrets/cap/kv/cron ...`
///
/// Opens a QUIC connection to the host, sends a PeerRequest, and displays the response.
async fn cmd_remote_peer_op(target: &str, args: &[String], config_dir: &std::path::Path) -> Result<()> {
    use hop_core::proto::HostMessage;

    // Parse the subcommand and build a PeerRequest
    let subcmd = args.first().context("no subcommand")?;
    let sub_args = &args[1..];

    let request = match subcmd.as_str() {
        "secrets" => parse_remote_secrets(sub_args)?,
        "kv" => parse_remote_kv(sub_args)?,
        "cron" => parse_remote_cron(sub_args)?,
        "cap" => parse_remote_cap(sub_args)?,
        "ext" => parse_remote_ext(sub_args)?,
        "tap" => parse_remote_tap(sub_args)?,
        other => anyhow::bail!("unknown remote subcommand: {other}"),
    };

    // Streaming requests (today: just ExtensionStreamOpen) get a
    // multi-response loop instead of the single-message read.
    let is_streaming = matches!(
        request,
        hop_core::proto::PeerRequest::ExtensionStreamOpen { .. }
    );

    // Connect and send the request
    let (_resolved, send, mut recv) = mux::connect_to_host(
        config_dir,
        target,
        None,
        &hop_core::proto::ClientMessage::RequestPeerOp(request),
    ).await?;

    if !is_streaming {
        let response: HostMessage = hop_core::proto::read_message(&mut recv).await?;
        drop(send);
        return match response {
            HostMessage::PeerResponse(resp) => display_peer_response(subcmd, sub_args, resp),
            HostMessage::SessionError(msg) => anyhow::bail!("host error: {msg}"),
            other => anyhow::bail!("unexpected response: {other:?}"),
        };
    }

    // Streaming path: read PeerResponses until ExtensionStreamClosed
    // or the daemon errors. Each response is rendered immediately so
    // `tap watch` writes bytes to stdout as they arrive.
    loop {
        let response: HostMessage = match hop_core::proto::read_message(&mut recv).await {
            Ok(m) => m,
            Err(e) => {
                // Receiver closed mid-stream — typically the daemon
                // shut the QUIC stream after writing StreamClosed.
                tracing::debug!("stream recv ended: {e:#}");
                break;
            }
        };
        let resp = match response {
            HostMessage::PeerResponse(resp) => resp,
            HostMessage::SessionError(msg) => anyhow::bail!("host error: {msg}"),
            other => anyhow::bail!("unexpected response: {other:?}"),
        };
        let done = matches!(
            &resp,
            hop_core::proto::PeerResponse::ExtensionStreamClosed { .. }
                | hop_core::proto::PeerResponse::Error(_)
        );
        display_peer_response(subcmd, sub_args, resp)?;
        if done {
            break;
        }
    }
    drop(send);
    Ok(())
}

fn parse_remote_secrets(args: &[String]) -> Result<hop_core::proto::PeerRequest> {
    use hop_core::proto::PeerRequest;
    let action = args.first().map(|s| s.as_str()).unwrap_or("");
    match action {
        "get" => {
            let name = args.get(1).context("usage: hop <host> secrets get <name>")?;
            Ok(PeerRequest::SecretsGet { name: name.clone() })
        }
        "set" => {
            let name = args.get(1).context("usage: hop <host> secrets set <name> <value>")?;
            let value = if let Some(v) = args.get(2) {
                v.clone()
            } else {
                use std::io::{IsTerminal, Read};
                if std::io::stdin().is_terminal() {
                    eprint!("Enter secret value: ");
                    let mut buf = String::new();
                    std::io::stdin().read_line(&mut buf)?;
                    buf.trim_end().to_string()
                } else {
                    let mut buf = String::new();
                    std::io::stdin().read_to_string(&mut buf)?;
                    buf.trim_end().to_string()
                }
            };
            Ok(PeerRequest::SecretsSet { name: name.clone(), value: value.into_bytes() })
        }
        "delete" => {
            let name = args.get(1).context("usage: hop <host> secrets delete <name>")?;
            Ok(PeerRequest::SecretsDelete { name: name.clone() })
        }
        "list" => Ok(PeerRequest::SecretsList),
        _ => anyhow::bail!("usage: hop <host> secrets [get|set|delete|list] ..."),
    }
}

fn parse_remote_kv(args: &[String]) -> Result<hop_core::proto::PeerRequest> {
    use hop_core::proto::PeerRequest;
    let action = args.first().map(|s| s.as_str()).unwrap_or("");
    let ns = "default";
    match action {
        "get" => {
            let key = args.get(1).context("usage: hop <host> kv get <key>")?;
            Ok(PeerRequest::KvGet { ns: ns.into(), key: key.clone() })
        }
        "set" => {
            let key = args.get(1).context("usage: hop <host> kv set <key> <value>")?;
            let value = args.get(2).context("usage: hop <host> kv set <key> <value>")?;
            Ok(PeerRequest::KvSet { ns: ns.into(), key: key.clone(), value: value.as_bytes().to_vec() })
        }
        "list" => {
            let prefix = args.get(1).cloned().unwrap_or_default();
            Ok(PeerRequest::KvList { ns: ns.into(), prefix })
        }
        _ => anyhow::bail!("usage: hop <host> kv [get|set|list] ..."),
    }
}

fn parse_remote_cron(args: &[String]) -> Result<hop_core::proto::PeerRequest> {
    use hop_core::proto::PeerRequest;
    let action = args.first().map(|s| s.as_str()).unwrap_or("");
    match action {
        "list" => Ok(PeerRequest::CronList),
        "get" => {
            let id = args.get(1).context("usage: hop <host> cron get <id>")?;
            Ok(PeerRequest::CronGet { id: id.clone() })
        }
        _ => anyhow::bail!("usage: hop <host> cron [list|get] ..."),
    }
}

fn parse_remote_cap(args: &[String]) -> Result<hop_core::proto::PeerRequest> {
    use hop_core::proto::PeerRequest;
    let action = args.first().map(|s| s.as_str()).unwrap_or("");
    match action {
        "status" => Ok(PeerRequest::CapStatus),
        "enable" => {
            let id = args.get(1).context("usage: hop <host> cap enable <id>")?;
            let schedule = args.iter().position(|a| a == "--schedule")
                .and_then(|i| args.get(i + 1)).cloned();
            let targets = args.iter().position(|a| a == "--targets")
                .and_then(|i| args.get(i + 1)).cloned();
            Ok(PeerRequest::CapEnable { id: id.clone(), schedule, targets })
        }
        "disable" => {
            let id = args.get(1).context("usage: hop <host> cap disable <id>")?;
            Ok(PeerRequest::CapDisable { id: id.clone() })
        }
        "run" => {
            let id = args.get(1).context("usage: hop <host> cap run <id>")?;
            let targets = args.iter().position(|a| a == "--targets")
                .and_then(|i| args.get(i + 1)).cloned();
            Ok(PeerRequest::CapRun { id: id.clone(), targets, params: vec![] })
        }
        "list" => Ok(PeerRequest::CapList),
        _ => anyhow::bail!("usage: hop <host> cap [list|enable|disable|status|run] ..."),
    }
}

fn parse_remote_ext(args: &[String]) -> Result<hop_core::proto::PeerRequest> {
    use hop_core::proto::PeerRequest;
    let action = args.first().map(|s| s.as_str()).unwrap_or("");
    match action {
        "list" => Ok(PeerRequest::ExtensionList),
        "call" => {
            let ext_id = args
                .get(1)
                .context("usage: hop <host> ext call <ext_id> [--hex <hex>|--text <str>]")?;
            // Payload is read from --hex or --text. Default: empty payload.
            let payload = if let Some(i) = args.iter().position(|a| a == "--hex") {
                let hex = args.get(i + 1).context("--hex requires an argument")?;
                hex::decode(hex).context("invalid hex payload")?
            } else if let Some(i) = args.iter().position(|a| a == "--text") {
                let text = args.get(i + 1).context("--text requires an argument")?;
                text.as_bytes().to_vec()
            } else {
                Vec::new()
            };
            Ok(PeerRequest::ExtensionCall {
                ext_id: ext_id.clone(),
                payload,
            })
        }
        _ => anyhow::bail!("usage: hop <host> ext [list|call <ext_id> [--hex <hex>|--text <str>]]"),
    }
}

/// `hop <host> tap [list|snapshot N]` — typed convenience wrapper
/// around `ext call tap.terminal`. Encodes a [`hop_tap_protocol::TapRequest`]
/// as the extension payload; the matching response decode lives in
/// [`display_peer_response`] keyed on `subcmd == "tap"`.
///
/// `tap watch` is **not** wired here yet — it requires the
/// extension-stream dispatcher (`ExtensionStreamOpen`/`StreamFrame`/
/// `StreamClosed`) which hop-core marks as "not yet implemented" at
/// the time of writing. Use the bundled `hop-tap-probe watch` for
/// live byte streams against a local daemon.
fn parse_remote_tap(args: &[String]) -> Result<hop_core::proto::PeerRequest> {
    use hop_core::proto::PeerRequest;
    use hop_tap_protocol::TapRequest;

    let action = args.first().map(|s| s.as_str()).unwrap_or("");
    let req = match action {
        "list" => TapRequest::List,
        "snapshot" => {
            let pty = args
                .get(1)
                .context("usage: hop <host> tap snapshot <pty_index>")?
                .parse::<i32>()
                .context("pty_index must be an integer")?;
            TapRequest::Snapshot { pty_index: pty }
        }
        "watch" => {
            use hop_tap_protocol::TapStreamRequest;
            let pty = args
                .get(1)
                .context("usage: hop <host> tap watch <pty_index>")?
                .parse::<i32>()
                .context("pty_index must be an integer")?;
            // hop-tap-d renders the captured pty's grid clipped /
            // padded to the subscriber's viewport; pass our local
            // terminal size so the remote daemon paints frames
            // sized for our window. Fallback to 80x24 if the size
            // syscall fails (non-tty stdout, e.g. piped output).
            let (vp_cols, vp_rows) =
                crossterm::terminal::size().unwrap_or((80, 24));
            let payload = bincode::serde::encode_to_vec(
                &TapStreamRequest::Subscribe {
                    pty_index: pty,
                    viewport_rows: vp_rows,
                    viewport_cols: vp_cols,
                },
                bincode::config::standard(),
            )
            .context("encoding TapStreamRequest")?;
            return Ok(PeerRequest::ExtensionStreamOpen {
                ext_id: "tap.terminal".to_string(),
                payload,
            });
        }
        _ => anyhow::bail!("usage: hop <host> tap [list|snapshot <pty_index>]"),
    };

    let payload = bincode::serde::encode_to_vec(&req, bincode::config::standard())
        .context("encoding TapRequest")?;
    Ok(PeerRequest::ExtensionCall {
        ext_id: "tap.terminal".to_string(),
        payload,
    })
}

fn display_peer_response(subcmd: &str, _args: &[String], resp: hop_core::proto::PeerResponse) -> Result<()> {
    use hop_core::proto::PeerResponse;
    match resp {
        PeerResponse::Ok => {
            println!("OK");
        }
        PeerResponse::Error(msg) => {
            anyhow::bail!("{msg}");
        }
        PeerResponse::SecretValue(Some(value)) => {
            let text = String::from_utf8_lossy(&value);
            println!("{text}");
        }
        PeerResponse::SecretValue(None) => {
            println!("(not found)");
        }
        PeerResponse::SecretNames(names) => {
            if names.is_empty() {
                println!("No secrets stored.");
            } else {
                for name in &names {
                    println!("  {name}");
                }
            }
        }
        PeerResponse::KvEntry(Some(entry)) => {
            let text = String::from_utf8_lossy(&entry.value);
            println!("{text}");
        }
        PeerResponse::KvEntry(None) => {
            println!("(not found)");
        }
        PeerResponse::KvEntries(entries) => {
            if entries.is_empty() {
                println!("No keys found.");
            } else {
                for (key, entry) in &entries {
                    let value = String::from_utf8_lossy(&entry.value);
                    let truncated = if value.len() > 80 { format!("{}...", &value[..77]) } else { value.to_string() };
                    println!("  {key} = {truncated}");
                }
            }
        }
        PeerResponse::CapEntries(caps) => {
            if caps.is_empty() {
                println!("No capabilities available.");
            } else {
                for cap in &caps {
                    println!("  {:20} {} [{}] [{}]", cap.id, cap.description.split('.').next().unwrap_or(""), cap.tier, cap.trigger);
                }
            }
        }
        PeerResponse::CapStatusEntries(jobs) => {
            if jobs.is_empty() {
                println!("No capabilities enabled.");
            } else {
                println!("Enabled capabilities:\n");
                for j in &jobs {
                    let status = if j.enabled { "active" } else { "paused" };
                    let targets = j.targets.as_deref().unwrap_or("local");
                    let last = j.last_run
                        .map(|t| {
                            let ago = unix_now_ms().saturating_sub(t);
                            format!("{}ms ago", ago)
                        })
                        .unwrap_or_else(|| "never".into());
                    println!("  {:30} [{}] targets={} schedule={} last_run={}",
                        j.catalog_id, status, targets, j.schedule, last);
                }
            }
        }
        PeerResponse::CapEnabled { job_id } => {
            println!("Enabled (job {job_id})");
        }
        PeerResponse::CapTriggered { job_id } => {
            println!("Triggered (job {job_id})");
        }
        PeerResponse::CronJobs(jobs) => {
            if jobs.is_empty() {
                println!("No cron jobs.");
            } else {
                for j in &jobs {
                    let status = if j.enabled { "active" } else { "paused" };
                    println!("  {} {:30} [{}] schedule={}", j.id, j.name, status, j.schedule);
                }
            }
        }
        PeerResponse::CronJob(Some(j)) => {
            println!("ID:       {}", j.id);
            println!("Name:     {}", j.name);
            println!("Schedule: {}", j.schedule);
            println!("Enabled:  {}", j.enabled);
            if let Some(last) = j.last_run {
                println!("Last run: {last}");
            }
            println!("Next run: {}", j.next_run);
            if let Some(targets) = &j.targets {
                println!("Targets:  {targets}");
            }
        }
        PeerResponse::CronJob(None) => {
            println!("(not found)");
        }

        // Extension responses are surfaced by the `hop ext` subcommand
        // handler, which formats them appropriately. If we hit this path
        // we got an extension response in a non-extension command — log
        // it and move on.
        PeerResponse::ExtensionEntries(entries) => {
            for e in entries {
                let avail = if e.available { "active" } else { "unavailable" };
                println!("  {} ({})  {}", e.ext_id, avail, e.description);
            }
        }
        PeerResponse::ExtensionResult { ok, payload } => {
            if subcmd == "tap" {
                display_tap_response(ok, &payload)?;
            } else {
                let label = if ok { "ok" } else { "error" };
                println!("[{label}] {} bytes", payload.len());
                if !payload.is_empty() {
                    let preview = String::from_utf8_lossy(&payload);
                    println!("{preview}");
                }
            }
        }
        PeerResponse::ExtensionStreamOpened { stream_id } => {
            // For `tap`, clear the operator's screen so the replay
            // bytes start from a clean state. Other subcommands just
            // get a status line.
            if subcmd == "tap" {
                use std::io::Write as _;
                let mut stdout = std::io::stdout().lock();
                stdout.write_all(b"\x1b[2J\x1b[H").ok();
                stdout.flush().ok();
                eprintln!("(stream {stream_id} opened)");
            } else {
                println!("(stream {stream_id} opened)");
            }
        }
        PeerResponse::ExtensionStreamFrame { stream_id, payload } => {
            if subcmd == "tap" {
                display_tap_stream_frame(stream_id, &payload)?;
            } else {
                println!("(stream {stream_id} frame, {} bytes)", payload.len());
            }
        }
        PeerResponse::ExtensionStreamClosed { stream_id, reason } => {
            // Send to stderr for `tap` so it doesn't interleave with
            // stdout bytes.
            let line = match reason {
                Some(r) => format!("(stream {stream_id} closed: {r})"),
                None => format!("(stream {stream_id} closed)"),
            };
            if subcmd == "tap" {
                eprintln!("{line}");
            } else {
                println!("{line}");
            }
        }
    }
    Ok(())
}

/// Decode a tap.terminal extension response and pretty-print it.
/// `ok=false` from the extension surfaces as a warning prefix; the
/// payload is still expected to be a valid `TapResponse` (typically
/// `TapResponse::Error(msg)`).
fn display_tap_response(ok: bool, payload: &[u8]) -> Result<()> {
    use hop_tap_protocol::TapResponse;

    let (resp, _): (TapResponse, _) =
        bincode::serde::decode_from_slice(payload, bincode::config::standard())
            .context("decoding TapResponse from tap.terminal payload")?;
    if !ok {
        eprintln!("warning: extension returned ok=false");
    }
    match resp {
        TapResponse::SessionList(sessions) => {
            if sessions.is_empty() {
                println!("(no active sessions)");
                return Ok(());
            }
            println!("{} active session(s):", sessions.len());
            for s in sessions {
                let opener = format_user(&s.opener_username, s.opener_uid);
                let writer = format_user(&s.last_username, s.last_uid);
                let identity = if s.opener_uid == s.last_uid && s.opener_pid == s.last_pid {
                    format!("user={opener:<14} comm={:<10}", s.last_comm)
                } else if s.opener_uid == s.last_uid {
                    format!(
                        "user={opener:<14} comm={:<10} (writer={})",
                        s.last_comm, s.last_pid
                    )
                } else {
                    format!(
                        "opener={opener:<14} writer={writer:<14} comm={:<10}",
                        s.last_comm
                    )
                };
                println!(
                    "  pty={:>3}  {identity}  out={}b/{}ev  in={}b/{}ev  \
                     age={}ms idle={}ms",
                    s.pty_index,
                    s.output_bytes,
                    s.output_events,
                    s.input_bytes,
                    s.input_events,
                    s.age_ms,
                    s.idle_ms,
                );
            }
        }
        TapResponse::Snapshot {
            pty_index,
            rows,
            cols,
            contents,
        } => {
            println!("snapshot pty={pty_index} ({rows}x{cols})");
            println!("┌{}┐", "─".repeat(cols as usize));
            for row in contents {
                let trimmed = row.trim_end_matches(' ');
                let padding = (cols as usize).saturating_sub(trimmed.chars().count());
                println!("│{}{}│", trimmed, " ".repeat(padding));
            }
            println!("└{}┘", "─".repeat(cols as usize));
        }
        // The action-style responses (Inject, Kill, Lock, Quarantine,
        // AdminMessage, Reply, ResizeSubscription) come from
        // commands hop-cli currently doesn't expose — only `list`,
        // `snapshot`, and `watch`. If the daemon ever sends one
        // anyway (extension-versioning corner case), surface it
        // briefly rather than panicking.
        TapResponse::Injected { pty_index, bytes_written } => {
            println!("injected {bytes_written} byte(s) into pty {pty_index}");
        }
        TapResponse::Killed { pty_index, pid, signal } => {
            println!("killed pty={pty_index} (pid={pid}, signal={signal})");
        }
        TapResponse::MessageDelivered { pty_index, bytes_written } => {
            println!("message delivered to pty={pty_index} ({bytes_written} bytes)");
        }
        TapResponse::LockSet { pty_index, locked, pgrp } => {
            println!(
                "pty={pty_index} {} (pgrp={pgrp})",
                if locked { "locked" } else { "unlocked" }
            );
        }
        TapResponse::QuarantineSet { pty_index, quarantined, impostor_pid } => {
            if quarantined {
                println!(
                    "pty={pty_index} quarantined (impostor_pid={})",
                    impostor_pid.map(|p| p.to_string()).unwrap_or_else(|| "?".into())
                );
            } else {
                println!("pty={pty_index} released from quarantine");
            }
        }
        TapResponse::SubscriptionResized { stream_id, rows, cols } => {
            eprintln!("(subscription {stream_id} resized to {cols}x{rows})");
        }
        TapResponse::Replied { pty_index, subscribers } => {
            println!("reply on pty={pty_index} delivered to {subscribers} tapper(s)");
        }
        TapResponse::Error(msg) => {
            anyhow::bail!("tap: {msg}");
        }
    }
    Ok(())
}

/// Decode a TapStreamFrame from an `ExtensionStreamFrame.payload` and
/// write its byte content to the operator's terminal. The operator's
/// own terminal interprets the captured escape sequences natively —
/// no client-side emulator round-trip — so the captured session
/// renders the way it would for the original user.
fn display_tap_stream_frame(_stream_id: u64, payload: &[u8]) -> Result<()> {
    use hop_tap_protocol::TapStreamFrame;
    use std::io::Write as _;

    let (frame, _): (TapStreamFrame, _) =
        bincode::serde::decode_from_slice(payload, bincode::config::standard())
            .context("decoding TapStreamFrame")?;
    let mut stdout = std::io::stdout().lock();
    match frame {
        TapStreamFrame::Initial {
            rows,
            cols,
            replay_bytes,
        } => {
            eprintln!("(initial frame: {rows}x{cols}, replay={} bytes)", replay_bytes.len());
            stdout.write_all(&replay_bytes).ok();
            stdout.flush().ok();
        }
        TapStreamFrame::Output(bytes) => {
            stdout.write_all(&bytes).ok();
            stdout.flush().ok();
        }
        TapStreamFrame::Resize { rows, cols } => {
            eprintln!("(resize: {rows}x{cols})");
        }
        TapStreamFrame::UserReply { from, message } => {
            // Captured user replied via `tap reply` on the remote
            // host. Render as a banner mirroring how local tap
            // displays it (cyan, reverse-video header).
            let safe_from: String = from
                .chars()
                .filter(|c| !c.is_control())
                .take(64)
                .collect();
            let safe_msg: String = message
                .chars()
                .map(|c| if c.is_control() && c != '\n' { ' ' } else { c })
                .collect();
            let _ = write!(
                stdout,
                "\r\n\x07\
                 \x1b[1;36;7m  reply: {safe_from}  \x1b[0m\r\n\
                 \x1b[1;36m  {safe_msg}\x1b[0m\r\n\r\n",
            );
            stdout.flush().ok();
        }
    }
    Ok(())
}

fn format_user(username: &Option<String>, uid: u32) -> String {
    match username {
        Some(name) => format!("{}({})", name, uid),
        None => format!("uid={}", uid),
    }
}

fn cmd_ts(config_dir: &std::path::Path, action: TsAction) -> Result<()> {
    let ds = hop_core::datastore::Datastore::connect(config_dir)
        .context("Failed to connect to daemon — is `hop host` running?")?;

    match action {
        TsAction::Latest { metric } => {
            match ds.ts_latest(&metric)? {
                Some((ts, point)) => {
                    let tags_str = if point.tags.is_empty() {
                        String::new()
                    } else {
                        let pairs: Vec<String> = point.tags.iter()
                            .map(|(k, v)| format!("{k}={v}"))
                            .collect();
                        format!(" {{{}}}", pairs.join(", "))
                    };
                    println!("{ts} {}{tags_str}", point.value);
                }
                None => println!("No data for metric '{metric}'"),
            }
        }
        TsAction::Query { metric, last } => {
            let duration_ms = parse_duration_ms(&last)?;
            let now = unix_now_ms();
            let start = now.saturating_sub(duration_ms);

            let query = hop_core::datastore::types::TimeSeriesQuery {
                metric: metric.clone(),
                start,
                end: now,
                tags_filter: None,
                limit: None,
            };
            let points = ds.ts_query(&query)?;
            if points.is_empty() {
                println!("No data for metric '{metric}' in the last {last}");
            } else {
                for (ts, point) in &points {
                    let tags_str = if point.tags.is_empty() {
                        String::new()
                    } else {
                        let pairs: Vec<String> = point.tags.iter()
                            .map(|(k, v)| format!("{k}={v}"))
                            .collect();
                        format!(" {{{}}}", pairs.join(", "))
                    };
                    println!("{ts} {}{tags_str}", point.value);
                }
                println!("({} data points)", points.len());
            }
        }
    }
    Ok(())
}

/// Parse a human-readable duration like "1h", "30m", "7d" into milliseconds.
fn parse_duration_ms(s: &str) -> Result<u64> {
    let s = s.trim();
    if let Some(n) = s.strip_suffix('d') {
        Ok(n.parse::<u64>().context("invalid number")? * 86_400_000)
    } else if let Some(n) = s.strip_suffix('h') {
        Ok(n.parse::<u64>().context("invalid number")? * 3_600_000)
    } else if let Some(n) = s.strip_suffix('m') {
        Ok(n.parse::<u64>().context("invalid number")? * 60_000)
    } else if let Some(n) = s.strip_suffix('s') {
        Ok(n.parse::<u64>().context("invalid number")? * 1_000)
    } else {
        Ok(s.parse::<u64>().context("invalid duration — use a suffix like 1h, 30m, 7d")? * 1_000)
    }
}

fn cmd_config(action: Option<ConfigAction>, config_dir: &std::path::Path) -> Result<()> {
    if let Some(ConfigAction::Path) = action {
        println!("{}", config_dir.display());
        return Ok(());
    }

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
            println!("vpn              {}", if cfg.vpn_enabled { "on" } else { "off" });
            println!("default_role     {}", cfg.default_role);
            println!(
                "tags             {}",
                if cfg.tags.is_empty() { "(none)".to_string() } else { cfg.tags.join(", ") }
            );
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
                "vpn" => {
                    let on = parse_bool_value(&value)?;
                    cfg.vpn_enabled = on;
                    cfg.save(config_dir)?;
                    println!("vpn set to {}", if on { "on" } else { "off" });
                }
                "tags" => {
                    // Comma-separated; empty string clears tags.
                    let tags: Vec<String> = value
                        .split(',')
                        .map(|t| t.trim().to_string())
                        .filter(|t| !t.is_empty())
                        .collect();
                    cfg.tags = tags.clone();
                    cfg.save(config_dir)?;
                    println!("tags set to {tags:?}");
                }
                "default_role" => {
                    let role = value.trim().to_string();
                    anyhow::ensure!(!role.is_empty(), "default_role must not be empty");
                    cfg.default_role = role.clone();
                    cfg.save(config_dir)?;
                    println!("default_role set to {role}");
                }
                _ => {
                    anyhow::bail!(
                        "Unknown config key '{key}'. Valid keys: session_timeout, max_sessions, vpn, tags, default_role"
                    );
                }
            }
            println!("Note: restart the host/daemon for changes to take effect.");
        }
        // Handled by the early return above; arm kept for exhaustiveness.
        Some(ConfigAction::Path) => unreachable!("config path handled before load"),
    }

    Ok(())
}

fn cmd_acl(action: cli::AclAction, config_dir: &std::path::Path) -> Result<()> {
    use cli::AclAction;
    use hop_core::fleet::RolesStore;
    match action {
        AclAction::Import { file, apply } => {
            let text = std::fs::read_to_string(&file)
                .with_context(|| format!("reading {}", file.display()))?;
            let result = hop_core::vpn::tailscale_import::import_tailscale_policy(&text)?;
            print!("{}", result.report());
            if apply {
                let mut store = RolesStore::load(config_dir)?;
                let (mut added, mut updated) = (0u32, 0u32);
                for role in result.roles {
                    if let Some(existing) = store.roles.iter_mut().find(|r| r.name == role.name) {
                        *existing = role;
                        updated += 1;
                    } else {
                        store.roles.push(role);
                        added += 1;
                    }
                }
                store.save(config_dir)?;
                println!("\nApplied to roles.json ({added} added, {updated} updated). Restart the host/daemon to take effect.");
            } else {
                println!("\n(dry run — re-run with --apply to write these roles to roles.json)");
            }
            Ok(())
        }
        AclAction::Check { role, tags } => {
            let store = RolesStore::load(config_dir)?;
            let Some(r) = store.find_role(&role) else {
                anyhow::bail!("unknown role '{role}' (see `hop acl show`)");
            };
            let reaches = hop_core::vpn::acl::role_reaches(&r.host_tags, &tags);
            println!(
                "{} {role} -> host[{}]",
                if reaches { "ALLOW" } else { "DENY " },
                tags.join(",")
            );
            println!(
                "  role reach tags: {}",
                if r.host_tags.is_empty() { "(none — default-deny)".into() } else { r.host_tags.join(", ") }
            );
            Ok(())
        }
        AclAction::Show => {
            let store = RolesStore::load(config_dir)?;
            if store.roles.is_empty() {
                println!("No roles defined (run `hop host` once to seed defaults).");
                return Ok(());
            }
            println!("{:<16} reaches", "role");
            for r in &store.roles {
                let reach = if r.host_tags.iter().any(|t| t == "*") {
                    "* (all hosts)".to_string()
                } else if r.host_tags.is_empty() {
                    "(none — default-deny)".to_string()
                } else {
                    r.host_tags.join(", ")
                };
                println!("{:<16} {reach}", r.name);
            }
            Ok(())
        }
        AclAction::Caps { role } => {
            let store = RolesStore::load(config_dir)?;
            let Some(r) = store.find_role(&role) else {
                anyhow::bail!("unknown role '{role}' (see `hop acl show`)");
            };
            if r.capabilities.is_empty() {
                println!("role '{role}' has no application capability grants");
            } else {
                println!("'{role}' application capabilities:");
                for (name, cfgs) in &r.capabilities {
                    println!("  {name}");
                    for cfg in cfgs {
                        println!("    {}", serde_json::to_string(cfg).unwrap_or_default());
                    }
                }
            }
            Ok(())
        }
    }
}

async fn cmd_warren(
    secret_key: iroh::SecretKey,
    config_dir: &std::path::Path,
    action: cli::WarrenAction,
) -> Result<()> {
    use cli::WarrenAction;
    match action {
        WarrenAction::Join { invite } => {
            // Resolve the warren namespace ticket: from the invite (which now
            // carries it), or from the ticket stored when we connected as a client.
            let (ticket, founder_author, founder_node, redeem) = match invite {
                Some(tok) => {
                    let decoded = hop_core::invite::decode_invite(&tok)
                        .context("invalid invite token")?;
                    let t = decoded.warren_ticket.clone().context(
                        "this invite does not carry a warren — the host has no VPN/warren enabled",
                    )?;
                    (t, decoded.founder_author.clone(), Some(decoded.node_id.clone()), Some(tok))
                }
                None => {
                    let stored = std::fs::read_to_string(config_dir.join("warren-ticket"))
                        .context("no invite given and no stored warren ticket — run `hop warren join <invite>` first")?;
                    let t = stored.trim().to_string();
                    anyhow::ensure!(!t.is_empty(), "stored warren ticket is empty");
                    (t, None, None, None)
                }
            };

            // Write the join ticket so `hop host` imports the warren namespace on
            // its next start (this is what makes the machine a node on the VPN).
            // 0600 — warren *write* ticket; any local reader gains warren write
            // access if this is world-readable (security-audit H7).
            config::write_secret_file(&config_dir.join("netdoc-join.ticket"), &ticket)
                .context("writing warren join ticket")?;

            // Persist the founder's doc author (C1 trust anchor) so the daemon
            // records it as the trusted admin on next start. Plain (non-secret)
            // — it's a public author id, but keep it owner-readable for tidiness.
            if let Some(fa) = founder_author {
                let _ = config::write_secret_file(&config_dir.join("netdoc-founder.author"), &fa);
            }
            // Persist the founder's main node id so the daemon knows whom to send
            // its `AnnounceNetdocAuthor` to on startup (C1 self-key binding).
            if let Some(fnode) = founder_node {
                let _ = config::write_shared_file(&config_dir.join("netdoc-founder.node"), &fnode);
            }

            // Redeem the invite for membership (auth handshake → the inviting host
            // records us in the warren directory with our role).
            if let Some(tok) = redeem {
                println!("Joining warren — redeeming invite for membership...");
                if let Err(e) =
                    cmd_exec(secret_key, &tok, config_dir, &["true".to_string()],
                        hop_core::sandbox::SandboxPolicy::default()).await
                {
                    tracing::warn!("membership redeem failed (namespace still joined): {e:#}");
                }
            }

            // Self-upgrade (install-and-invite-tiers.md Phase 1b): the invite was
            // decoded + redeemed as *this user* above (no root yet — the H10 fix).
            // Becoming a warren node needs a system daemon (root). Offer to set it
            // up now, reusing the battle-tested installer (which verifies the
            // download and promotes the binary to a root-owned path — §5 invariant).
            let cdn = std::env::var("HOP_CDN_URL").unwrap_or_else(|_| "https://hop.keik.ai".to_string());
            println!();
            if system_daemon_installed() {
                println!("Joined. A system daemon is already installed — restart it to pick up the");
                println!("warren (the join ticket is now in place):");
                #[cfg(target_os = "macos")]
                println!("      sudo launchctl kickstart -k system/com.hop.daemon");
                #[cfg(not(target_os = "macos"))]
                println!("      sudo systemctl restart hop");
            } else if std::io::IsTerminal::is_terminal(&std::io::stdin()) {
                println!("To put this machine on the warren VPN it must run as a system daemon");
                println!("(root). Set it up now? This runs the official installer with sudo.");
                print!("  Proceed? [y/N] ");
                let _ = std::io::Write::flush(&mut std::io::stdout());
                let mut answer = String::new();
                let _ = std::io::stdin().read_line(&mut answer);
                if matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
                    // No --invite here: the join ticket is already written, so the
                    // daemon installer must not redeem a second time.
                    let cmd = format!("curl -fsSL {cdn}/install.sh | bash -s -- --host");
                    println!("Running: sudo bash -c \"{cmd}\"");
                    let status = std::process::Command::new("sudo")
                        .args(["bash", "-c", &cmd])
                        .status();
                    match status {
                        Ok(s) if s.success() => println!("Daemon set up — this machine is now on the warren."),
                        _ => {
                            println!("Daemon setup did not complete. The join ticket is saved; finish later with:");
                            println!("      curl -fsSL {cdn}/install.sh | bash -s -- --host");
                        }
                    }
                } else {
                    println!("Skipped. The join ticket is saved; put this machine on the VPN anytime with:");
                    println!("      curl -fsSL {cdn}/install.sh | bash -s -- --host");
                }
            } else {
                // Non-interactive (scripts): never prompt — print the explicit step.
                println!("Joined. This machine will be on the warren once it runs as a system daemon:");
                println!("      curl -fsSL {cdn}/install.sh | bash -s -- --host");
            }
            Ok(())
        }
        WarrenAction::Status => {
            // Membership / namespace.
            let ns = std::fs::read_to_string(config_dir.join("netdoc.json"))
                .ok()
                .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
                .and_then(|v| v.get("namespace").and_then(|n| n.as_str()).map(String::from));
            let has_join = config_dir.join("netdoc-join.ticket").exists()
                || config_dir.join("warren-ticket").exists();
            let vpn_enabled = hop_core::config::HostConfig::load(config_dir)
                .map(|c| c.vpn_enabled)
                .unwrap_or(true);

            match &ns {
                Some(n) => println!("warren namespace  {n}"),
                None if has_join => println!("warren namespace  (pending — joins on next host start)"),
                None => println!("warren namespace  (none — this machine is a client / not on a warren)"),
            }
            println!("vpn (config)      {}", if vpn_enabled { "on" } else { "off" });
            if ns.is_none() && has_join {
                println!();
                println!("A warren ticket is stored. Put this machine on the VPN with:");
                println!("  hop warren join          # uses the stored ticket");
                println!("  curl -fsSL https://hop.keik.ai/install.sh | bash -s -- --host");
            }
            Ok(())
        }
    }
}

/// Parse a boolean-ish config value (on/off, true/false, 1/0, yes/no, enabled/disabled).
fn parse_bool_value(s: &str) -> Result<bool> {
    match s.trim().to_ascii_lowercase().as_str() {
        "on" | "true" | "1" | "yes" | "enable" | "enabled" => Ok(true),
        "off" | "false" | "0" | "no" | "disable" | "disabled" => Ok(false),
        other => anyhow::bail!("expected on/off (got '{other}')"),
    }
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

fn unix_now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn handle_remote_cap_enable(
    datastore: &hop_core::datastore::Datastore,
    id: &str,
    schedule: Option<&str>,
    targets: Option<&str>,
    username: Option<&str>,
) -> hop_core::proto::PeerResponse {
    use hop_mcp::capabilities::CapabilityDefinition;

    let Some(cap) = CapabilityDefinition::find(id) else {
        return hop_core::proto::PeerResponse::Error(format!("Unknown capability: {id}"));
    };
    if !cap.is_schedulable() {
        return hop_core::proto::PeerResponse::Error(format!("'{id}' is on-demand only"));
    }

    let schedule = schedule
        .map(String::from)
        .or_else(|| cap.default_schedule().map(String::from))
        .unwrap_or_default();

    let Ok(sched) = schedule.parse::<cron::Schedule>() else {
        return hop_core::proto::PeerResponse::Error(format!("Invalid schedule: {schedule}"));
    };

    let catalog_id = cap.catalog_id();
    if let Ok(Some(existing)) = datastore.cron_find_by_catalog_id(&catalog_id) {
        return hop_core::proto::PeerResponse::CapEnabled { job_id: existing.id };
    }

    let now = unix_now_ms();
    let next_run = hop_mcp::cron::next_occurrence_ms(&sched, now);
    let job_id = format!("{:08x}", rand::random::<u32>());

    let job = hop_core::datastore::types::CronJob {
        id: job_id.clone(),
        name: format!("cap:{id}"),
        schedule,
        script: cap.script.to_string(),
        enabled: true,
        last_run: None,
        next_run,
        created_at: now,
        tags: vec![format!("cap:{id}")],
        targets: targets.map(String::from),
        catalog_id: Some(catalog_id),
        sandbox: Some(cap.tier.to_sandbox()),
        run_as_user: username.map(String::from),
    };

    match datastore.cron_add(&job) {
        Ok(()) => hop_core::proto::PeerResponse::CapEnabled { job_id },
        Err(e) => hop_core::proto::PeerResponse::Error(format!("Failed to enable: {e}")),
    }
}

fn handle_remote_cap_run(
    datastore: &hop_core::datastore::Datastore,
    id: &str,
    targets: Option<&str>,
    _params: &[(String, String)],
    username: Option<&str>,
) -> hop_core::proto::PeerResponse {
    use hop_mcp::capabilities::CapabilityDefinition;

    let Some(cap) = CapabilityDefinition::find(id) else {
        return hop_core::proto::PeerResponse::Error(format!("Unknown capability: {id}"));
    };

    let now = unix_now_ms();
    let job_id = format!("{:08x}", rand::random::<u32>());
    let job = hop_core::datastore::types::CronJob {
        id: job_id.clone(),
        name: format!("cap:run:{id}"),
        schedule: "0 0 0 1 1 * 2099".to_string(),
        script: cap.script.to_string(),
        enabled: true,
        last_run: None,
        next_run: 0,
        created_at: now,
        tags: vec![],
        targets: targets.map(String::from),
        catalog_id: Some(format!("cap:run:{id}")),
        sandbox: Some(cap.tier.to_sandbox()),
        run_as_user: username.map(String::from),
    };

    match datastore.cron_add(&job) {
        Ok(()) => hop_core::proto::PeerResponse::CapTriggered { job_id },
        Err(e) => hop_core::proto::PeerResponse::Error(format!("Failed to trigger: {e}")),
    }
}

fn unix_now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
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
    fn embedded_daemon_templates_present() {
        // The embedded launchd/systemd templates must exist and target the
        // root-owned binary path; this guards `__install-daemon` against an
        // accidental template move/rename.
        let plist = include_str!("../../../pkg/com.hop.daemon.plist");
        assert!(plist.contains("com.hop.daemon"), "plist label missing");
        assert!(plist.contains("/usr/local/bin/hop"), "plist binary path missing");
        let service = include_str!("../../../pkg/hop.service");
        assert!(service.contains("ExecStart="), "systemd ExecStart missing");
        assert!(service.contains("/usr/local/bin/hop host"), "systemd binary path missing");
    }

    #[test]
    fn parse_invite_tier_values() {
        use hop_core::invite::InviteTier;
        assert_eq!(parse_invite_tier(None).unwrap(), None);
        assert_eq!(parse_invite_tier(Some("client")).unwrap(), Some(InviteTier::Client));
        assert_eq!(parse_invite_tier(Some("warren-only")).unwrap(), Some(InviteTier::WarrenOnly));
        assert_eq!(parse_invite_tier(Some("warren")).unwrap(), Some(InviteTier::WarrenOnly));
        assert_eq!(parse_invite_tier(Some("node")).unwrap(), Some(InviteTier::Node));
        assert_eq!(parse_invite_tier(Some("ADMIN")).unwrap(), Some(InviteTier::Admin));
        assert_eq!(parse_invite_tier(Some("warren_only")).unwrap(), Some(InviteTier::WarrenOnly));
        assert!(parse_invite_tier(Some("bogus")).is_err());
        // Round-trips with as_str.
        for t in [InviteTier::Client, InviteTier::WarrenOnly, InviteTier::Node, InviteTier::Admin] {
            assert_eq!(parse_invite_tier(Some(t.as_str())).unwrap(), Some(t));
        }
    }

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

    // --- parse_external_args tests (Bug 1 regression) ---

    fn s(val: &str) -> String { val.to_string() }

    #[test]
    fn external_args_read_only() {
        let args = vec![s("myhost"), s("--read-only")];
        let ext = parse_external_args(&args).unwrap();
        assert_eq!(ext.target, "myhost");
        assert!(ext.read_only);
        assert!(!ext.no_network);
    }

    #[test]
    fn external_args_no_network() {
        let args = vec![s("myhost"), s("--no-network")];
        let ext = parse_external_args(&args).unwrap();
        assert!(ext.no_network);
        assert!(!ext.read_only);
    }

    #[test]
    fn external_args_preset() {
        let args = vec![s("myhost"), s("--preset"), s("monitor")];
        let ext = parse_external_args(&args).unwrap();
        assert_eq!(ext.preset, Some(s("monitor")));
    }

    #[test]
    fn external_args_name() {
        let args = vec![s("myhost"), s("--name"), s("mybox")];
        let ext = parse_external_args(&args).unwrap();
        assert_eq!(ext.name, Some(s("mybox")));
    }

    #[test]
    fn external_args_scope_multiple() {
        let args = vec![
            s("myhost"), s("--scope"), s("/var/log"), s("--scope"), s("/etc"),
        ];
        let ext = parse_external_args(&args).unwrap();
        assert_eq!(ext.scopes.len(), 2);
        assert_eq!(ext.scopes[0], std::path::PathBuf::from("/var/log"));
        assert_eq!(ext.scopes[1], std::path::PathBuf::from("/etc"));
    }

    #[test]
    fn external_args_allow_command_multiple() {
        let args = vec![
            s("myhost"), s("--allow-command"), s("ps"), s("--allow-command"), s("ls"),
        ];
        let ext = parse_external_args(&args).unwrap();
        assert_eq!(ext.allow_commands, vec!["ps", "ls"]);
    }

    #[test]
    fn external_args_exec_separator() {
        let args = vec![
            s("myhost"), s("--read-only"), s("--"), s("ls"), s("-la"),
        ];
        let ext = parse_external_args(&args).unwrap();
        assert!(ext.read_only);
        assert_eq!(ext.exec_command, Some(vec![s("ls"), s("-la")]));
    }

    #[test]
    fn external_args_no_flags() {
        let args = vec![s("myhost")];
        let ext = parse_external_args(&args).unwrap();
        assert_eq!(ext.target, "myhost");
        assert!(!ext.read_only);
        assert!(!ext.no_network);
        assert!(ext.preset.is_none());
        assert!(ext.name.is_none());
        assert!(ext.scopes.is_empty());
        assert!(ext.allow_commands.is_empty());
        assert!(ext.exec_command.is_none());
    }

    #[test]
    fn external_args_combined_flags() {
        let args = vec![
            s("myhost"), s("--read-only"), s("--no-network"), s("--preset"), s("audit"),
        ];
        let ext = parse_external_args(&args).unwrap();
        assert!(ext.read_only);
        assert!(ext.no_network);
        assert_eq!(ext.preset, Some(s("audit")));
    }

    #[test]
    fn external_args_empty_fails() {
        let args: Vec<String> = vec![];
        assert!(parse_external_args(&args).is_err());
    }

    // --- build_sandbox_policy tests ---

    #[test]
    fn build_policy_read_only_flag() {
        let policy = build_sandbox_policy(None, true, false, &[], &[]).unwrap();
        assert!(policy.read_only);
        assert!(!policy.no_network);
    }

    #[test]
    fn build_policy_preset_monitor() {
        let policy = build_sandbox_policy(Some("monitor"), false, false, &[], &[]).unwrap();
        assert_eq!(policy, SandboxPolicy::preset_monitor());
    }

    #[test]
    fn build_policy_unknown_preset_errors() {
        let result = build_sandbox_policy(Some("bogus"), false, false, &[], &[]);
        assert!(result.is_err());
        let msg = result.unwrap_err().to_string();
        assert!(msg.contains("bogus"), "error should mention the bad preset name");
    }

    #[test]
    fn build_policy_preset_with_overrides() {
        // "deploy" preset has read_only=false; passing read_only=true should override
        let policy = build_sandbox_policy(Some("deploy"), true, false, &[], &[]).unwrap();
        assert!(policy.read_only, "read_only override must apply on top of preset");
    }

    // --- __sandbox-shell clap parsing test (Bug 2 regression) ---

    #[test]
    fn sandbox_shell_clap_parses() {
        use cli::{Cli, Command};
        let policy = SandboxPolicy::preset_monitor();
        let json = serde_json::to_string(&policy).unwrap();
        let parsed = Cli::try_parse_from([
            "hop", "__sandbox-shell", "--policy", &json, "--", "/bin/bash", "-l",
        ]).expect("__sandbox-shell should parse via clap");
        match parsed.command {
            Command::SandboxShell { policy: p, shell_args } => {
                assert_eq!(p, json);
                assert_eq!(shell_args, vec!["/bin/bash", "-l"]);
            }
            _ => panic!("expected SandboxShell variant"),
        }
    }
}
