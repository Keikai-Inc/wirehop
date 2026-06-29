mod agent;
mod audit;
mod cli;
mod cpuprofile;
mod itemize;
mod memprofile;
mod netstats;
mod oauth;
mod mux;
mod progress_ui;
mod reconnect;

use std::collections::HashSet;
use std::io::Read;
use std::time::Duration;

use anyhow::{Context, Result};
use clap::Parser;
use cli::{AdminAction, AgentAction, CapAction, Cli, Command, ConfigAction, CronAction, DebugAction, FleetAction, KvAction, MemProfileAction, PeersAction, RoleAction, SecretsAction, TsAction};
use iroh::endpoint::{RecvStream, SendStream};
use iroh::Watcher;
use tokio::sync::mpsc;
use tracing_subscriber::prelude::*;
use tracing_subscriber::filter::Targets;
use tracing_subscriber::reload;

use hop_core::auth::{self, AuthOutcome};
use hop_core::config::{self, HostConfig, KnownHostsStore, PeerRole, PeersStore};
use hop_core::invite;
use hop_core::net;
use hop_core::proto::{
    self, AdminRequest, AdminResponse, ClientMessage, HostMessage, RoleDefinition, RoleUpdates,
    UserMode, TransferDirection, TransferMode, TransferMsg, TransferRequest,
};
use hop_core::shell::{self, SessionOutcome};
use hop_core::shell::session_registry::{self as session_registry, RegistryHandle};
use hop_core::transfer::{self, PathSpec};

// Heap profiling (build with `--features dhat-heap`): replace the global
// allocator so dhat records every allocation's call-site + live bytes.
#[cfg(feature = "dhat-heap")]
#[global_allocator]
static ALLOC: dhat::Alloc = dhat::Alloc;

// On 64-bit Linux, use jemalloc (compiled with prof support, inactive by default)
// so `hop debug mem-profile` can turn on heap profiling without a special build.
// Negligible overhead until activated via MALLOC_CONF=prof:true. macOS uses the
// system allocator + native MallocStackLogging instead; 32-bit Linux (armv7)
// keeps the system allocator (jemalloc's __ffsdi2 doesn't link there). Skipped
// under dhat-heap.
#[cfg(all(target_os = "linux", target_pointer_width = "64", not(feature = "dhat-heap")))]
#[global_allocator]
static JEMALLOC: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[tokio::main]
async fn main() -> Result<()> {
    // Heap profiler: held for the whole process; on a clean exit (SIGTERM, which
    // the daemon handles by returning) its Drop writes dhat-heap.json.
    #[cfg(feature = "dhat-heap")]
    let _dhat = dhat::Profiler::new_heap();

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
    let default_directives = match cli.verbose {
        0 => "hop=info,hop_core=info,hop_mcp=info",
        1 => "hop=debug,hop_core=debug,hop_mcp=debug",
        _ => "hop=trace,hop_core=trace,hop_mcp=trace",
    };
    // `Targets` parses the same `target=level` syntax as RUST_LOG, without the
    // regex engine `EnvFilter` pulls in. A RUST_LOG that uses EnvFilter-only span
    // or field directives won't parse here → fall back to the verbosity default.
    let initial_filter: Targets = std::env::var("RUST_LOG")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or_else(|| default_directives.parse().expect("valid default directives"));
    let (filter_layer, reload_handle) = reload::Layer::new(initial_filter);
    tracing_subscriber::registry()
        .with(filter_layer)
        .with(tracing_subscriber::fmt::layer())
        .init();

    match cli.command {
        Command::Host { quiet, relay, relay_port } => {
            // The daemon owns the *host* config (identity, peers, warren, netdoc).
            // With --config (how the LaunchDaemon/systemd unit invokes us) this is
            // the override; a manual `hop host` with no --config resolves to the
            // installed daemon dir (/etc/hop) rather than the per-user dir.
            let config_dir = config::ensure_host_config_dir(cli.config.as_deref())?;
            // Privilege separation (privsep-node.md): when HOP_PRIVSEP=1 and we
            // are root and not already the worker, become the monitor — it owns
            // the privileged primitives (TUN, :53) and spawns this same binary
            // as the unprivileged worker. Off by default; the worker re-enters
            // here with HOP_PRIVSEP_WORKER set and falls through to the daemon.
            if std::env::var_os("HOP_PRIVSEP").is_some()
                && std::env::var_os("HOP_PRIVSEP_WORKER").is_none()
                && hop_core::unix_user::is_running_as_root()
            {
                return hop_core::privsep::run_monitor(&config_dir, quiet, relay, relay_port);
            }
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_host(secret_key, &config_dir, quiet, relay, relay_port, reload_handle).await
        }
        Command::Recover { quiet } => cmd_recover(quiet),
        Command::Invite { creator, user, role, tier, max_uses, expiry, name, read_only, no_network, scopes, allow_commands, preset } => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            // `--creator`: print this host's standing creator invite (the former
            // `hop creator-invite`) instead of minting a new one.
            if creator {
                return cmd_creator_invite(&config_dir);
            }
            std::fs::create_dir_all(&config_dir)
                .with_context(|| format!("Failed to create config dir: {}", config_dir.display()))?;
            let sandbox = build_sandbox_policy(preset.as_deref(), read_only, no_network, &scopes, &allow_commands)?;
            let tier = parse_invite_tier(tier.as_deref())?;
            // Don't eagerly read identity.json here — under privsep it's
            // `_hop`-owned. cmd_invite asks the running daemon first (it owns the
            // secrets); only the no-daemon fallback reads config locally.
            let params = hop_core::invite::InviteParams {
                username: user,
                role_name: role,
                tier,
                host_name: name,
                max_uses,
                expiry,
                sandbox,
            };
            cmd_invite(&config_dir, params)
        }
        Command::Connect {
            target, name, read_only, no_network, scopes, allow_commands, preset,
            yes, on_warren_conflict, warren,
        } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            let sandbox = build_sandbox_policy(preset.as_deref(), read_only, no_network, &scopes, &allow_commands)?;
            cmd_connect(
                secret_key, target.as_deref(), &config_dir, name.as_deref(), sandbox,
                ConnectWarrenOpts { yes, on_warren_conflict, warren },
            )
            .await
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
        Command::Tunnel { target, spec } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            cmd_tunnel(&config_dir, &target, &spec).await
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
            // `warren join/status` operate on the *daemon's* warren membership
            // and target the host config dir — not the per-user client dir.
            // (Previously this used the client dir, so `warren status` reported
            // "not on a warren" on a machine whose daemon was on one.)
            //
            // Do NOT eagerly load the host identity here: `identity.json` is
            // root-only (0600), so reading it fails for a non-root user on a
            // machine running the daemon. `status` only reads group-readable
            // state files and never needs the key; `join` loads it lazily, and
            // only when it actually redeems an invite.
            let config_dir = config::ensure_host_config_dir(cli.config.as_deref())?;
            cmd_warren(&config_dir, action).await
        }
        Command::Acl { action } => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            cmd_acl(action, &config_dir)
        }
        Command::Lan { action } => {
            let config_dir = config::ensure_host_config_dir(cli.config.as_deref())?;
            cmd_lan(action, &config_dir)
        }
        Command::Peers { action } => {
            let host_config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            let user_config_dir = config::default_config_dir()?;
            cmd_peers(action, &host_config_dir, &user_config_dir)
        }
        Command::Admin { target, action } => {
            let config_dir = config::ensure_config_dir(cli.config.as_deref())?;
            let secret_key = config::load_or_generate_identity(&config_dir)?;
            cmd_admin(secret_key, &target, &config_dir, action).await
        }
        Command::Fleet { action } => {
            // The daemon writes the warren snapshot to ITS config dir: honor an
            // explicit --config (the daemon ran with it), else the system daemon
            // dir. Known-hosts (a client concern) live in the user dir.
            let host_dir = match cli.config.as_deref() {
                Some(p) => p.to_path_buf(),
                None => config::resolve_host_config_dir(None)?,
            };
            let user_dir = config::ensure_config_dir(cli.config.as_deref())?;
            cmd_fleet(&host_dir, &user_dir, action).await
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
        Command::Audit { since, category, actor, limit, json } => {
            let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
            audit::run(
                &config_dir,
                since.as_deref(),
                category.as_deref(),
                actor.as_deref(),
                limit,
                json,
            )
        }
        Command::Id => {
            // Print the *host* node id. Ask the running daemon first (privsep §6:
            // it owns the `_hop` identity, so no root needed); fall back to reading
            // identity.json directly when no daemon is up (a client-only machine).
            let config_dir = config::ensure_host_config_dir(cli.config.as_deref())?;
            if let Some(node_id) = id_via_daemon(&config_dir)? {
                println!("{node_id}");
            } else {
                let secret_key = config::load_or_generate_identity(&config_dir)?;
                println!("{}", secret_key.public());
            }
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
        Command::Debug { action } => match action {
            DebugAction::MemProfile { action } => {
                let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
                let act = match action {
                    MemProfileAction::On => memprofile::Action::On,
                    MemProfileAction::Off => memprofile::Action::Off,
                    MemProfileAction::Snapshot { out } => memprofile::Action::Snapshot { out },
                    MemProfileAction::Watchdog { deadline } => {
                        memprofile::Action::Watchdog { deadline_secs: deadline }
                    }
                };
                memprofile::run(act, &config_dir)
            }
            DebugAction::CpuProfile { secs, pid, out } => cpuprofile::run(secs, pid, out),
            DebugAction::NetStats { watch, interval, json } => {
                let config_dir = config::resolve_host_config_dir(cli.config.as_deref())?;
                netstats::run(&config_dir, watch, interval, json)
            }
        },
        Command::SandboxShell { policy, shell_args } => {
            cmd_sandbox_shell(&policy, &shell_args)
        }
        Command::Ps => {
            cmd_ps()
        }
        Command::InstallDaemon { stage, vpn, tier, default_role, tags, promote_from, no_promote } => {
            cmd_install_daemon(InstallDaemonArgs {
                stage, vpn, tier, default_role, tags, promote_from, no_promote,
            })
        }
        #[cfg(unix)]
        Command::PrivsepProbe { uid, gid } => cmd_privsep_probe(uid, gid),
        #[cfg(unix)]
        Command::PrivsepProbeChild { sock_fd } => {
            std::process::exit(hop_core::privsep::run_tun_fd_probe_child(sock_fd));
        }
        #[cfg(not(unix))]
        Command::PrivsepProbe { .. } | Command::PrivsepProbeChild { .. } => {
            anyhow::bail!("privsep probe is unix-only")
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
                // The catch-all `hop <target>` is connect; a warren-carrying invite
                // still auto-joins, with default (prompted) consent.
                cmd_connect(
                    secret_key, Some(&ext.target), &config_dir, ext.name.as_deref(), sandbox,
                    ConnectWarrenOpts { yes: false, on_warren_conflict: None, warren: false },
                )
                .await
            }
        }
    }
}

/// Type alias for the reload handle used by the SIGUSR1 debug toggle.
type ReloadHandle = reload::Handle<Targets, tracing_subscriber::Registry>;

/// Outcome of the host-daemon restart attempted by `hop recover`.
enum DaemonRestart {
    Restarted,
    NotInstalled,
    NeedsRoot,
}

/// `hop recover`: clean up stale runtime state and restart the host daemon onto
/// the current binary. Idempotent and SAFE — it never touches identity.json or
/// warren membership (that's the KISS boundary). It (1) kills leftover
/// `hop agent` processes, which share the machine's node-id and so collide with
/// the daemon at the relay; (2) removes stale agent sockets/pidfiles; (3)
/// restarts the host daemon so it rebinds the mux socket and client connects
/// route through its single endpoint. Also invoked by install.sh after an
/// upgrade, so installing == recovering.
fn cmd_recover(quiet: bool) -> Result<()> {
    // 1. Kill stray client agents. The `[h]op` pattern matches the real process
    //    but NOT the pgrep/pkill cmdline itself (classic self-match guard).
    let mut killed = 0usize;
    #[cfg(unix)]
    {
        const PAT: &str = "[h]op agent --daemon";
        if let Ok(out) = std::process::Command::new("pgrep").args(["-f", PAT]).output() {
            killed = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter(|l| !l.trim().is_empty())
                .count();
        }
        let _ = std::process::Command::new("pkill").args(["-f", PAT]).status();
    }

    // 2. Remove stale agent sockets/pidfiles (the killed agents'). The daemon
    //    rebinds its own mux socket on restart, so only the user dir matters here.
    if let Ok(dir) = config::default_config_dir() {
        for f in ["agent.sock", "agent.pid"] {
            let _ = std::fs::remove_file(dir.join(f));
        }
    }

    // 3. Restart the host daemon onto the current binary (if installed).
    let daemon = restart_host_daemon();

    if !quiet {
        let ver = env!("CARGO_PKG_VERSION");
        let daemon_msg = match daemon {
            DaemonRestart::Restarted => "daemon restarted",
            DaemonRestart::NotInstalled => "no host daemon installed",
            DaemonRestart::NeedsRoot => "daemon NOT restarted — re-run with `sudo hop recover`",
        };
        let plural = if killed == 1 { "" } else { "s" };
        println!("hop recovered (v{ver}) — cleared {killed} stale agent{plural}; {daemon_msg}");
    }
    Ok(())
}

#[cfg(target_os = "macos")]
fn restart_host_daemon() -> DaemonRestart {
    if !std::path::Path::new("/Library/LaunchDaemons/com.hop.daemon.plist").exists() {
        return DaemonRestart::NotInstalled;
    }
    if !hop_core::unix_user::is_running_as_root() {
        return DaemonRestart::NeedsRoot;
    }
    let _ = std::process::Command::new("launchctl")
        .args(["kickstart", "-k", "system/com.hop.daemon"])
        .status();
    DaemonRestart::Restarted
}

#[cfg(target_os = "linux")]
fn restart_host_daemon() -> DaemonRestart {
    let installed = std::process::Command::new("systemctl")
        .args(["list-unit-files", "hop.service"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).contains("hop.service"))
        .unwrap_or(false);
    if !installed {
        return DaemonRestart::NotInstalled;
    }
    if !hop_core::unix_user::is_running_as_root() {
        return DaemonRestart::NeedsRoot;
    }
    let _ = std::process::Command::new("systemctl").args(["restart", "hop"]).status();
    DaemonRestart::Restarted
}

#[cfg(not(any(target_os = "macos", target_os = "linux")))]
fn restart_host_daemon() -> DaemonRestart {
    DaemonRestart::NotInstalled
}

/// Restart the installed system daemon from an UNPRIVILEGED context (the
/// self-upgrade path runs as the user, not root), escalating via `sudo`. Used so
/// consuming a warren invite actually brings the warren up on a machine that
/// already runs the daemon — the restart re-imports the new join ticket. Returns
/// whether the restart command succeeded. If already root, runs the privileged
/// restart directly (no sudo).
fn restart_system_daemon_privileged() -> bool {
    #[cfg(target_os = "macos")]
    let argv: &[&str] = &["launchctl", "kickstart", "-k", "system/com.hop.daemon"];
    #[cfg(target_os = "linux")]
    let argv: &[&str] = &["systemctl", "restart", "hop"];
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    let argv: &[&str] = &[];

    if argv.is_empty() {
        return false;
    }
    let mut cmd = if hop_core::unix_user::is_running_as_root() {
        let mut c = std::process::Command::new(argv[0]);
        c.args(&argv[1..]);
        c
    } else {
        let mut c = std::process::Command::new("sudo");
        c.args(argv);
        c
    };
    matches!(cmd.status(), Ok(s) if s.success())
}

/// Rebuild the BYO relay's admit-set from the warren roster + this host's own id.
/// Endpoints not in the set are denied at the relay handshake. Best-effort: a
/// roster read failure leaves the previous set in place (fail-closed-ish).
async fn refresh_relay_members(
    net: &hop_core::netdoc::NetDoc,
    host_node_id: &str,
    members: &net::relay::MemberSet,
) {
    let mut set = std::collections::HashSet::new();
    // Self: BOTH the main host node-id (hop/3 connect) and the netdoc/VPN endpoint
    // id (iroh-docs sync + hop/vpn/1 data plane). Each hop node registers BOTH
    // endpoints with its home relay, so the relay must admit both or it denies its
    // own (and every member's) netdoc/VPN traffic.
    if let Ok(id) = host_node_id.parse() {
        set.insert(id);
    }
    set.insert(net.netdoc_endpoint_id());
    // The netdoc/VPN endpoint id is the first whitespace-separated token of the
    // `peer/N.vpn_endpoint` value ("{endpoint_id} {relay_url}").
    let vpn_ep_id = |v: &str| v.split_whitespace().next().and_then(|t| t.parse().ok());
    match net.list_peers().await {
        Ok(peers) => {
            for p in peers {
                if let Ok(id) = p.node_id.parse() {
                    set.insert(id);
                }
                if let Some(id) = p.vpn_endpoint.as_deref().and_then(vpn_ep_id) {
                    set.insert(id);
                }
            }
        }
        Err(e) => {
            tracing::debug!("relay: roster read failed, keeping previous member set: {e:#}");
            return;
        }
    }
    let n = set.len();
    *members.write().await = set;
    tracing::debug!("relay: admit-set refreshed ({n} endpoints)");
}

async fn cmd_host(secret_key: iroh::SecretKey, config_dir: &std::path::Path, quiet: bool, relay: bool, relay_port: Option<u16>, reload_handle: ReloadHandle) -> Result<()> {
    // If we are the privsep worker, watch the monitor-liveness pipe: should the
    // monitor die, shut down promptly so the datastore lock + TUN are released
    // (otherwise a stranded worker wedges every restart). No-op otherwise.
    hop_core::privsep::spawn_monitor_liveness_watcher();
    let public_key = secret_key.public();
    let secrets_key = hop_core::datastore::derive_secrets_key(&secret_key.to_bytes());

    // One-worker guard (Layer 3): acquire the datastore lock BEFORE binding the
    // iroh endpoint. redb takes an exclusive file lock on open; if another live
    // worker still holds it, fail here and exit WITHOUT ever binding the endpoint.
    // Binding first (the old order) briefly put a second endpoint with this
    // machine's node-id on the relay while a predecessor was still alive, and the
    // relay prune-storms the two against each other — the collision that interrupts
    // netdoc sync and black-holes the VPN until a human restarts. The lock is what
    // guarantees exactly one worker owns the node-id, so it must come first.
    let ds_path = config_dir.join("datastore.redb");
    let datastore = hop_core::datastore::Datastore::open_with_secrets(&ds_path, secrets_key)
        .with_context(|| {
            format!(
                "could not open datastore at {} — another hop host is already running and holds \
                 the lock. Refusing to start a second worker (it would collide this machine's \
                 node-id at the relay). If no daemon is running, remove a stale lock and retry.",
                ds_path.display()
            )
        })?;

    // Per-node audit & flow log (G4): install the global audit sink so the deep
    // hook points (auth, shell, transfer, reach) can record with one non-blocking
    // call. The drain thread writes to THIS daemon's datastore — no central
    // collector. Level: HOP_AUDIT_LEVEL overrides the host config (default
    // `connections`). A periodic retention purge + an opt-in flow summary ride on
    // top. `init` is a no-op when level is `off`, leaving recording inert.
    {
        use hop_core::audit::AuditLevel;
        let host_cfg = hop_core::config::HostConfig::load(config_dir).unwrap_or_default();
        let level = std::env::var("HOP_AUDIT_LEVEL")
            .ok()
            .and_then(|s| AuditLevel::parse(&s))
            .unwrap_or(host_cfg.audit_level);
        if level != AuditLevel::Off {
            let ds_drain = datastore.clone();
            hop_core::audit::init(level, move |ev| {
                if let Err(e) = ds_drain.audit_append(&ev) {
                    tracing::debug!("audit: append failed: {e:#}");
                }
            });
            tracing::info!("audit: per-node log enabled (level {})", level.as_str());

            // Retention: purge audit events older than HOP_AUDIT_RETENTION_DAYS
            // (default 30) hourly. Best-effort, off the hot path.
            let retain_days: u64 = std::env::var("HOP_AUDIT_RETENTION_DAYS")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(30)
                .max(1);
            let ds_ret = datastore.clone();
            tokio::spawn(async move {
                let mut tick = tokio::time::interval(std::time::Duration::from_secs(3600));
                loop {
                    tick.tick().await;
                    let cutoff = hop_core::audit::now_ms()
                        .saturating_sub(retain_days * 24 * 3600 * 1000);
                    let ds = ds_ret.clone();
                    let _ = tokio::task::spawn_blocking(move || ds.audit_purge_before(cutoff))
                        .await;
                }
            });

            // Flow summary (only materializes at the `flows` level): persist the
            // net-stats data-plane counters into the flow log every 60s, so the
            // ephemeral `hop debug net-stats` counters become a queryable history.
            if level >= AuditLevel::Flows {
                tokio::spawn(async move {
                    let mut tick = tokio::time::interval(std::time::Duration::from_secs(60));
                    let (mut last_tx, mut last_rx) = (0u64, 0u64);
                    loop {
                        tick.tick().await;
                        let s = hop_core::netstats::NET_STATS.snapshot();
                        let (tx, rx) = (s.eg_tun_bytes, s.in_bytes);
                        // Record the per-interval delta (a flow, not a gauge).
                        let (dtx, drx) = (tx.saturating_sub(last_tx), rx.saturating_sub(last_rx));
                        last_tx = tx;
                        last_rx = rx;
                        if dtx == 0 && drx == 0 {
                            continue; // idle interval — don't spam the log
                        }
                        let drops = s.eg_drop_reach
                            + s.eg_drop_noroute
                            + s.eg_drop_send_closed
                            + s.in_drop_unknown_peer
                            + s.in_drop_spoof;
                        hop_core::audit::record(
                            hop_core::audit::AuditEvent::new(
                                hop_core::audit::AuditCategory::Flow,
                                "flow.summary",
                                hop_core::audit::AuditOutcome::Info,
                            )
                            .bytes(dtx, drx)
                            .detail(format!("60s: drops={drops}")),
                        );
                    }
                });
            }
        }
    }

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
    let _relay_health = net::netmon::spawn_relay_health_watcher(endpoint.clone(), None);

    // Serve `hop connect` through THIS daemon's endpoint: a machine running the
    // daemon must not let the client spawn a second iroh endpoint under the same
    // node-id (the relay prunes the two against each other every few seconds —
    // the identity collision). Routing client connects through the daemon's sole
    // endpoint is the fix. Additive + non-fatal: if it can't bind, clients fall
    // back to their own agent (collision returns, but the daemon is unharmed).
    if let Err(e) = agent::spawn_mux_listener(endpoint.clone(), config_dir.join("agent.sock")) {
        tracing::warn!("daemon mux service unavailable (clients will spawn their own agent): {e:#}");
    }

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
                    let mut roles_store =
                        hop_core::fleet::RolesStore::load(&cfg).unwrap_or_default();
                    // Self-heal: ensure the `member` role exists so admitted
                    // members aren't stranded by a roles.json that predates it
                    // (the founder writes it into the warren doc via reconcile).
                    if roles_store.ensure_member() {
                        tracing::info!(
                            "netdoc: seeded missing `member` role (warren reach) — self-heal"
                        );
                        let _ = roles_store.save(&cfg);
                    }
                    let roles = roles_store.roles;
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

                    // Least-surprise safety net: `open_or_create` reopens an
                    // existing namespace and ignores a join ticket. If a pending
                    // `netdoc-join.ticket` names a DIFFERENT warren than the one we
                    // just opened, the operator joined but we kept the old warren —
                    // make that visible instead of silently stranding them.
                    if let Ok(t) = std::fs::read_to_string(cfg.join("netdoc-join.ticket"))
                        && let Ok(pending_ns) = hop_core::netdoc::namespace_of_ticket(t.trim())
                        && pending_ns != net.namespace().to_string()
                    {
                        tracing::warn!(
                            "netdoc: a pending join ticket is for warren {} but this node is on \
                             warren {} (kept). To switch: `hop connect <invite> --on-warren-conflict replace`",
                            &pending_ns[..8.min(pending_ns.len())],
                            &net.namespace().to_string()[..8]
                        );
                    }

                    // Publish a READ ticket too (#3b Phase 4): node/warren-only
                    // invites embed this instead of the write ticket, so members
                    // import the admin doc read-only (write scope = admin only).
                    if let Ok(rt) = net.read_ticket().await {
                        let _ = config::write_secret_file(&cfg.join("netdoc-read.ticket"), &rt);
                    }

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

                    // BYO relay (`hop host --relay`): run a member-only iroh relay
                    // on this host. Only warren members (the roster + self) may use
                    // it — the "open relay" fix. Independent of the VPN data plane:
                    // members use it for NAT traversal / fallback transport (point
                    // their HOP_RELAY_URL at http://<this-host>:<port>). Best-effort;
                    // a bind failure just means members fall back to the public relay.
                    if relay {
                        let port = relay_port.unwrap_or(net::relay::DEFAULT_RELAY_PORT);
                        let bind = std::net::SocketAddr::from((std::net::Ipv4Addr::UNSPECIFIED, port));
                        let members: net::relay::MemberSet = std::sync::Arc::new(
                            tokio::sync::RwLock::new(std::collections::HashSet::new()),
                        );
                        // Seed before spawning so the first dials are admitted.
                        refresh_relay_members(&net, &host_node_id, &members).await;
                        match net::relay::spawn_member_relay(bind, members.clone()).await {
                            Ok(server) => {
                                tracing::info!(
                                    "relay: member-only BYO relay up on http://0.0.0.0:{port} \
                                     (members point HOP_RELAY_URL here)"
                                );
                                let net_r = net.clone();
                                let hid = host_node_id.clone();
                                // Refresh cadence (HOP_RELAY_REFRESH_SECS, default
                                // 15) — how fast a freshly-joined member becomes
                                // admittable. Lowered in e2e for tight timing.
                                let refresh_secs = std::env::var("HOP_RELAY_REFRESH_SECS")
                                    .ok()
                                    .and_then(|s| s.parse().ok())
                                    .unwrap_or(15u64)
                                    .max(1);
                                tokio::spawn(async move {
                                    // Hold the server for the process lifetime and
                                    // keep the admit-set in sync with the roster.
                                    let _server = server;
                                    let mut tick = tokio::time::interval(
                                        std::time::Duration::from_secs(refresh_secs),
                                    );
                                    loop {
                                        tick.tick().await;
                                        refresh_relay_members(&net_r, &hid, &members).await;
                                    }
                                });
                            }
                            Err(e) => tracing::warn!(
                                "relay: BYO relay failed to start, members fall back to public relay: {e:#}"
                            ),
                        }
                    }

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

                    // Warren-first fleet: export a read-only membership snapshot
                    // (warren-members.json) of the replicated netdoc every 30s so
                    // `hop fleet list/status` can read the full warren view (the
                    // netdoc store itself is daemon-exclusive). First tick fires
                    // immediately, so the snapshot exists shortly after startup.
                    {
                        let net_snap = net.clone();
                        let cfg_snap = cfg.clone();
                        let secs = std::env::var("HOP_WARREN_SNAPSHOT_SECS")
                            .ok()
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(30u64)
                            .max(1);
                        tokio::spawn(async move {
                            let mut tick =
                                tokio::time::interval(std::time::Duration::from_secs(secs));
                            loop {
                                tick.tick().await;
                                hop_core::fleet::export_warren_snapshot(net_snap.as_ref(), &cfg_snap)
                                    .await;
                            }
                        });
                    }

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
                            // Authored Cedar reach policy, if an admin saved one
                            // locally with `hop acl policy set` (published to the
                            // warren by enable_vpn; admin-gated under C1 enforce).
                            let authored_policy =
                                std::fs::read_to_string(cfg.join("acl_policy.cedar")).ok();
                            match net
                                .enable_vpn(&host_node_id, &host_tags, authored_policy.as_deref())
                                .await
                            {
                                Ok(ip) => tracing::info!(
                                    "vpn: enabled, virtual IP {ip}, tags {host_tags:?}"
                                ),
                                Err(e) => tracing::warn!(
                                    "vpn: bringup failed, continuing without it (core access unaffected): {e:#}"
                                ),
                            }
                            // Tier 1 LAN bridging: if this host advertises gateway
                            // routes (routes.json), publish them to the warren and
                            // program forwarding. Inert when routes.json is empty.
                            let routes =
                                hop_core::fleet::RoutesStore::load(&cfg).unwrap_or_default();
                            net.setup_gateway_routes(&host_node_id, &routes.routes).await;
                            // Split-DNS (P4): point each configured domain at its
                            // LAN nameserver (reachable via a warren route), reusing
                            // the same resolver primitive as MagicDNS.
                            for sd in &routes.split_dns {
                                match sd.nameserver.parse::<std::net::Ipv4Addr>() {
                                    Ok(ns) => {
                                        if let Err(e) =
                                            hop_core::privsep::configure_resolver(&sd.domain, ns)
                                        {
                                            tracing::warn!(
                                                "split-dns: .{} → {ns} failed: {e:#}",
                                                sd.domain
                                            );
                                        } else {
                                            tracing::info!("split-dns: .{} → {ns}:53", sd.domain);
                                        }
                                    }
                                    Err(_) => tracing::warn!(
                                        "split-dns: invalid nameserver {:?}",
                                        sd.nameserver
                                    ),
                                }
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
                        // founder records peer/N.self_doc (per-member self-docs),
                        // and its static VPN endpoint so the founder records
                        // peer/N.vpn_endpoint (the roster routing path).
                        let self_doc = net.self_doc_read_ticket().await.ok();
                        let vpn_endpoint = Some(net.own_vpn_endpoint_value());
                        if !fnode.is_empty() && fnode != host_node_id {
                            let ep = main_endpoint.clone();
                            tokio::spawn(async move {
                                announce_netdoc_author_with_retry(ep, &fnode, &author, self_doc, vpn_endpoint).await;
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
                None, // single-use
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
                            println!("Re-read with: hop invite --creator");
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

    // (datastore was opened at the top of cmd_host — its lock is the one-worker
    // guard that must be held before the endpoint is bound. Shared below with the
    // socket listener, cron scheduler, and admin handler.)

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
    // and operator-admin ops (the local CLI mints invites / reads identity through
    // the daemon, so it needs no root or `_hop`-owned config — privsep §6).
    let _socket_listener =
        hop_core::datastore::socket::spawn_listener(config_dir, datastore.clone(), public_key)
            .await?;

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
    // SIGUSR2: write a heap snapshot (paired with `hop debug mem-profile`).
    let mut sigusr2 = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::user_defined2())
        .context("failed to register SIGUSR2 handler")?;
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
                    "hop=debug,hop_core=debug,hop_mcp=debug,iroh=debug,iroh_relay=debug"
                        .parse::<Targets>().expect("valid directives")
                } else {
                    tracing::info!("Debug logging DISABLED (back to info level)");
                    "hop=info,hop_core=info,hop_mcp=info".parse::<Targets>().expect("valid directives")
                };
                if let Err(e) = reload_handle.reload(new_filter) {
                    tracing::error!("Failed to reload log filter: {e}");
                }
            }
            _ = sigusr2.recv() => {
                // Heap snapshot on demand. Runs the platform profiler
                // (malloc_history on macOS, jemalloc prof.dump on Linux) off the
                // reactor so it can't stall connection handling.
                if memprofile::in_profiling_mode() {
                    tokio::task::spawn_blocking(|| match memprofile::self_snapshot() {
                        Ok(path) => tracing::info!("heap snapshot written to {}", path.display()),
                        Err(e) => tracing::warn!("heap snapshot failed: {e:#}"),
                    });
                } else {
                    tracing::warn!(
                        "SIGUSR2 heap snapshot ignored: daemon not in profiling mode \
                         (start it with `hop debug mem-profile on`)"
                    );
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

    // Tear down automatic split-DNS if *we* applied it (non-privsep: worker is
    // root, so configure_resolver wrote it directly). Under privsep the monitor
    // owns teardown and reverts it on exit, and an unprivileged worker can't undo
    // it anyway — so skip there. Idempotent and best-effort.
    if !hop_core::privsep::is_privsep_worker()
        && !hop_core::vpn::resolver::auto_resolver_disabled()
        && let Some(nd) = netdoc_cell.get()
    {
        let domain = nd.network_domain().await;
        if let Err(e) = hop_core::vpn::resolver::remove(&domain) {
            tracing::warn!("vpn: reverting automatic DNS config failed: {e:#}");
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
    vpn_endpoint: Option<String>,
) {
    let founder_id: iroh::PublicKey = match founder_node_hex.parse() {
        Ok(id) => id,
        Err(e) => {
            tracing::warn!("netdoc announce: invalid founder node id {founder_node_hex:?}: {e}");
            return;
        }
    };
    // Retry until the founder records BOTH our author binding and our self-doc
    // ticket (the ack reflects both), then re-publish on a slow cadence so a
    // founder restart, a late membership replication, or a refreshed self-doc
    // ticket (new addresses after a relay change) re-publishes without needing a
    // daemon restart. The old version gave up after 8 attempts, so a member that
    // couldn't reach the founder in its first ~40 min never published its VPN
    // endpoint until it was restarted — a key reason self-docs were missing.
    const REFRESH_INTERVAL: std::time::Duration = std::time::Duration::from_secs(3600);
    let mut delay = std::time::Duration::from_secs(5);
    let mut attempt = 0u32;
    loop {
        attempt += 1;
        match announce_netdoc_author_once(&endpoint, founder_id, author_hex, self_doc.as_deref(), vpn_endpoint.as_deref()).await {
            Ok(true) => {
                tracing::info!("netdoc announce: founder recorded our author binding + self-doc + vpn endpoint");
                // Recorded — refresh periodically rather than stopping.
                tokio::time::sleep(REFRESH_INTERVAL).await;
                delay = std::time::Duration::from_secs(5);
            }
            Ok(false) => {
                tracing::debug!("netdoc announce: acked but not yet recorded (attempt {attempt}); retrying");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(std::time::Duration::from_secs(300));
            }
            Err(e) => {
                tracing::debug!("netdoc announce: attempt {attempt} failed: {e:#}");
                tokio::time::sleep(delay).await;
                delay = (delay * 2).min(std::time::Duration::from_secs(300));
            }
        }
    }
}

/// One announce round-trip over the main endpoint.
async fn announce_netdoc_author_once(
    endpoint: &iroh::Endpoint,
    founder_id: iroh::PublicKey,
    author_hex: &str,
    self_doc: Option<&str>,
    vpn_endpoint: Option<&str>,
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
            vpn_endpoint: vpn_endpoint.map(String::from),
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
                | ClientMessage::RequestTunnel { .. }
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
        Some(ClientMessage::RequestTunnel { port }) => {
            // A tunnel is network access on the host's behalf — honor the session's
            // network policy (don't let a no-network peer bypass it). Same root
            // guard as exec/transfer otherwise.
            if sandbox.no_network {
                tracing::warn!("Tunnel denied: session sandbox blocks network");
                return Ok(());
            }
            if let Err(e) = shell::check_shell_security(username) {
                tracing::warn!("Tunnel denied: {e:#}");
                return Err(e);
            }
            tracing::info!("Starting tunnel session -> 127.0.0.1:{port}");
            shell::host_tunnel_session(send, recv, port, protocol_version).await?;
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
                // Refresh the fleet snapshot immediately so the admin change
                // shows in `hop fleet list` without waiting for the 30s tick.
                hop_core::fleet::export_warren_snapshot(nd.as_ref(), config_dir).await;
            }
            proto::write_message(&mut send, &proto::HostMessage::AdminResponse(response)).await?;
        }
        Some(ClientMessage::AnnounceNetdocAuthor { author, self_doc, vpn_endpoint }) => {
            // A warren member announced its doc author (+ self-doc read ticket).
            // Only the founder/admin (the C1 trust anchor) records the admin-owned
            // bindings; any other receiver acks without recording so the member
            // keeps retrying until it reaches the anchor. Best-effort.
            let recorded = if let Some(nd) = &netdoc {
                let author_ok = match nd.record_peer_author(peer_id, &author).await {
                    Ok(r) => r,
                    Err(e) => {
                        tracing::warn!("netdoc: record_peer_author for {peer_id} failed: {e:#}");
                        false
                    }
                };
                // Record the member's self-doc ticket (per-member self-docs) and
                // FOLD it into the ack: the announce now retries until BOTH the
                // author binding AND the self-doc are recorded. Previously the ack
                // reflected only the author, so a member could "succeed" with its
                // self-doc unrecorded — leaving its VPN endpoint unresolvable to
                // every peer (the live "no self_doc ticket recorded yet" symptom).
                let self_doc_ok = match self_doc.as_deref() {
                    Some(ticket) => match nd.record_peer_self_doc(peer_id, ticket).await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("netdoc: record_peer_self_doc for {peer_id} failed: {e:#}");
                            false
                        }
                    },
                    None => true,
                };
                // Record the member's static VPN endpoint in the roster
                // (peer/N.vpn_endpoint) — the reliable routing path — and fold it
                // into the ack so the announce retries until it's recorded too.
                let vpn_endpoint_ok = match vpn_endpoint.as_deref() {
                    Some(val) => match nd.record_peer_vpn_endpoint(peer_id, val).await {
                        Ok(r) => r,
                        Err(e) => {
                            tracing::warn!("netdoc: record_peer_vpn_endpoint for {peer_id} failed: {e:#}");
                            false
                        }
                    },
                    None => true,
                };
                author_ok && self_doc_ok && vpn_endpoint_ok
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

/// Mint an invite through the running daemon's local socket (privsep §6) — the
/// daemon owns identity + netdoc, so the operator needs no root and never reads
/// `_hop`-owned config. `Ok(None)` ⇒ no daemon reachable (caller mints locally);
/// `Ok(Some)` ⇒ token; `Err` ⇒ the daemon refused (authoritative, don't retry).
fn invite_via_daemon(
    config_dir: &std::path::Path,
    params: &hop_core::invite::InviteParams,
) -> Result<Option<String>> {
    use hop_core::datastore::protocol::{DsRequest, DsResponse};
    use hop_core::datastore::socket::DaemonConnection;
    let conn = match DaemonConnection::connect(config_dir) {
        Ok(c) => c,
        Err(_) => return Ok(None), // no daemon → local fallback
    };
    let req = DsRequest::Admin(Box::new(AdminRequest::CreateInviteFull(Box::new(params.clone()))));
    match conn.request(&req)? {
        DsResponse::Admin(resp) => match *resp {
            AdminResponse::InviteCreated { token } => Ok(Some(token)),
            AdminResponse::Error { message } => anyhow::bail!("daemon refused invite: {message}"),
            other => anyhow::bail!("unexpected admin response from daemon: {other:?}"),
        },
        other => anyhow::bail!("unexpected daemon response: {other:?}"),
    }
}

/// Ask the running daemon for this host's node id (privsep §6). `Ok(None)` ⇒ no
/// daemon (caller reads identity.json directly).
fn id_via_daemon(config_dir: &std::path::Path) -> Result<Option<String>> {
    use hop_core::datastore::protocol::{DsRequest, DsResponse};
    use hop_core::datastore::socket::DaemonConnection;
    let conn = match DaemonConnection::connect(config_dir) {
        Ok(c) => c,
        Err(_) => return Ok(None),
    };
    let req = DsRequest::Admin(Box::new(AdminRequest::HostIdentity));
    match conn.request(&req)? {
        DsResponse::Admin(resp) => match *resp {
            AdminResponse::HostIdentity { node_id } => Ok(Some(node_id)),
            AdminResponse::Error { message } => anyhow::bail!("daemon error: {message}"),
            other => anyhow::bail!("unexpected admin response from daemon: {other:?}"),
        },
        other => anyhow::bail!("unexpected daemon response: {other:?}"),
    }
}

fn cmd_invite(config_dir: &std::path::Path, mut params: hop_core::invite::InviteParams) -> Result<()> {

    // Default the bound user to the *operator* running this command — resolved
    // here, not in the daemon (which runs as `_hop`).
    #[cfg(unix)]
    if params.username.is_none() {
        params.username = hop_core::unix_user::current_username();
    }

    // Prefer the running daemon: it owns identity + netdoc, so it mints the token
    // and the operator CLI needs no root and never reads `_hop`-owned config
    // (privsep §6). Fall back to local minting only when no daemon is reachable.
    let token = match invite_via_daemon(config_dir, &params)? {
        Some(t) => t,
        None => {
            let secret_key = config::load_or_generate_identity(config_dir)?;
            let relay_url = std::fs::read_to_string(config_dir.join("relay_url"))
                .ok()
                .or_else(|| Some(hop_core::net::HOP_RELAY_URL.to_string()));
            hop_core::invite::build_invite_token(
                &secret_key.public(),
                config_dir,
                relay_url.as_deref(),
                &params,
            )?
        }
    };

    // Re-bind locals the printing block below expects.
    let tier = params.tier;
    let max_uses = params.max_uses;
    let expiry = params.expiry;
    let sandbox = &params.sandbox;

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
    let exp_secs = expiry.unwrap_or(15 * 60);
    let exp_human = if exp_secs.is_multiple_of(3600) {
        format!("{} hour(s)", exp_secs / 3600)
    } else if exp_secs.is_multiple_of(60) {
        format!("{} minute(s)", exp_secs / 60)
    } else {
        format!("{exp_secs} seconds")
    };
    match max_uses {
        Some(n) if n > 1 => println!(
            "This invite expires in {exp_human} and is reusable up to {n} times\n\
             (one token N hosts redeem to join the warren)."
        ),
        _ => println!("This invite expires in {exp_human} and is single-use."),
    }
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
/// Arguments to the native daemon installer (`hop __install-daemon`).
struct InstallDaemonArgs {
    /// User-owned dir holding staged primer files to copy into the system dir.
    stage: Option<std::path::PathBuf>,
    /// "on"/"off" for the warren VPN data plane.
    vpn: Option<String>,
    /// Capability tier (informational; reserved for future role mapping).
    tier: Option<String>,
    /// Default invite role.
    default_role: Option<String>,
    /// Comma-separated host tags.
    tags: Option<String>,
    /// Verified binary bytes to promote to /usr/local/bin/hop.
    promote_from: Option<std::path::PathBuf>,
    /// Skip promotion (binary already root-owned at /usr/local/bin/hop).
    no_promote: bool,
}

/// The root-owned path the launchd plist / systemd unit execute. The daemon
/// must only ever run a root-owned, root-only-writable binary (decision 7).
#[cfg(any(target_os = "macos", target_os = "linux"))]
const DAEMON_BIN_PATH: &str = "/usr/local/bin/hop";

/// Copy verified binary bytes into the root-owned daemon path and lock down
/// ownership/permissions (root:wheel 0755 on macOS, root:root 0755 on Linux).
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn promote_binary(source: &std::path::Path, target: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Skip a self-copy when the running binary already IS the target (a host
    // re-install) — copying a file onto itself truncates it.
    let same = std::fs::canonicalize(source).ok() == std::fs::canonicalize(target).ok()
        && target.exists();
    if !same {
        std::fs::copy(source, target)
            .with_context(|| format!("promoting {} -> {}", source.display(), target.display()))?;
    }
    std::fs::set_permissions(target, std::fs::Permissions::from_mode(0o755))
        .with_context(|| format!("chmod 0755 {}", target.display()))?;
    #[cfg(target_os = "macos")]
    let owner = "root:wheel";
    #[cfg(target_os = "linux")]
    let owner = "root:root";
    let status = std::process::Command::new("chown")
        .arg(owner)
        .arg(target)
        .status()
        .context("running chown")?;
    anyhow::ensure!(status.success(), "chown {owner} {} failed", target.display());
    Ok(())
}

/// Copy staged primer files (written by the unprivileged user) into the system
/// config dir with correct perms. Validates the join ticket before trusting it.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn copy_staged_primers(stage: &std::path::Path, sysdir: &std::path::Path) -> Result<()> {
    // (filename, is_secret) — secrets 0600, shared 0660.
    let files: &[(&str, bool)] = &[
        ("netdoc-join.ticket", true),
        ("netdoc-founder.author", true),
        ("netdoc-founder.node", false),
    ];
    for (name, secret) in files {
        let src = stage.join(name);
        if !src.exists() {
            continue;
        }
        let data = std::fs::read_to_string(&src)
            .with_context(|| format!("reading staged {}", src.display()))?;
        if *name == "netdoc-join.ticket" {
            anyhow::ensure!(!data.trim().is_empty(), "staged netdoc-join.ticket is empty");
        }
        let dst = sysdir.join(name);
        if *secret {
            hop_core::config::write_secret_file(&dst, &data)?;
        } else {
            hop_core::config::write_shared_file(&dst, &data)?;
        }
    }
    Ok(())
}

/// Map the running platform to its published release artifact base name
/// (e.g. `hop-darwin-arm64`), matching `install.sh`'s naming.
fn release_artifact_name() -> Result<String> {
    let os = match std::env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        other => anyhow::bail!("unsupported OS for self-upgrade: {other}"),
    };
    let arch = match std::env::consts::ARCH {
        "aarch64" => "arm64",
        "x86_64" => "x86_64",
        "arm" => "armv7",
        other => anyhow::bail!("unsupported arch for self-upgrade: {other}"),
    };
    Ok(format!("hop-{os}-{arch}"))
}

/// Verify the running binary against its published release checksum and stage a
/// trusted copy into a temp dir, returning its path. The privileged installer
/// then promotes THESE bytes (never the user-writable original) to the
/// root-owned daemon path — the §5 verify-then-promote invariant.
///
/// `HOP_PROMOTE_ALLOW_UNVERIFIED=1` stages the running binary without a network
/// check, for locally-built binaries / the e2e (which pass `--promote-from`).
fn verify_and_stage_binary(cdn: &str) -> Result<std::path::PathBuf> {
    use sha2::{Digest, Sha256};
    let exe = std::env::current_exe().context("resolving current executable")?;
    let bytes = std::fs::read(&exe).with_context(|| format!("reading {}", exe.display()))?;

    if std::env::var("HOP_PROMOTE_ALLOW_UNVERIFIED").is_err() {
        let artifact = release_artifact_name()?;
        let version = env!("CARGO_PKG_VERSION");
        let url = format!("{cdn}/v{version}/{artifact}.sha256");
        let published = reqwest::blocking::get(&url)
            .and_then(|r| r.error_for_status())
            .and_then(|r| r.text())
            .with_context(|| format!(
                "fetching release checksum {url} (set HOP_PROMOTE_ALLOW_UNVERIFIED=1 for a local build)"
            ))?;
        let published_hash = published.split_whitespace().next().unwrap_or("").to_lowercase();
        let actual_hash = hex::encode(Sha256::digest(&bytes));
        anyhow::ensure!(
            !published_hash.is_empty() && published_hash == actual_hash,
            "binary checksum mismatch (refusing to promote an unverified binary as root)"
        );
    }

    // Stage into a fresh, user-owned temp dir (caller cleans it up).
    let dir = std::env::temp_dir().join(format!("hop-upgrade-{}", std::process::id()));
    std::fs::create_dir_all(&dir)
        .with_context(|| format!("creating stage dir {}", dir.display()))?;
    let staged = dir.join("hop");
    std::fs::write(&staged, &bytes)
        .with_context(|| format!("staging verified binary to {}", staged.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&staged, std::fs::Permissions::from_mode(0o755));
    }
    Ok(staged)
}

fn cmd_install_daemon(args: InstallDaemonArgs) -> Result<()> {
    #[cfg(not(any(target_os = "macos", target_os = "linux")))]
    {
        let _ = args;
        anyhow::bail!("__install-daemon is only supported on macOS and Linux");
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        anyhow::ensure!(
            hop_core::unix_user::is_running_as_root(),
            "__install-daemon must run as root (it installs a system service)"
        );
        let run = |cmd: &str, cmd_args: &[&str]| -> Result<()> {
            let status = std::process::Command::new(cmd)
                .args(cmd_args)
                .status()
                .with_context(|| format!("running {cmd}"))?;
            anyhow::ensure!(status.success(), "{cmd} {} failed ({status})", cmd_args.join(" "));
            Ok(())
        };

        // Step A — verify-then-promote the binary the service unit runs.
        let target = std::path::Path::new(DAEMON_BIN_PATH);
        if args.no_promote {
            anyhow::ensure!(
                target.exists(),
                "--no-promote given but {DAEMON_BIN_PATH} does not exist"
            );
        } else {
            let source = match args.promote_from.clone() {
                Some(p) => p,
                None => std::env::current_exe().context("resolving binary to promote")?,
            };
            promote_binary(&source, target)?;
        }

        // Step B — ensure the SYSTEM config dir (the path the unit's --config
        // points at) — not the per-user dir resolve_host_config_dir would pick
        // before a system identity exists.
        let sysdir = hop_core::config::system_config_dir();
        std::fs::create_dir_all(&sysdir)
            .with_context(|| format!("creating {}", sysdir.display()))?;
        #[cfg(target_os = "linux")]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::process::Command::new("groupadd").args(["--system", "hop"]).status();
            let _ = std::process::Command::new("chown").arg("root:hop").arg(&sysdir).status();
            // setgid so files created here inherit the hop group.
            let _ = std::fs::set_permissions(&sysdir, std::fs::Permissions::from_mode(0o2770));
        }

        // Step C — copy staged primer files into the system dir.
        if let Some(stage) = &args.stage {
            copy_staged_primers(stage, &sysdir)?;
        }

        // Step D — apply scalar primers in-process (one Rust path; no shelling
        // out to `hop config set`).
        if let Some(v) = &args.vpn {
            println!("{}", set_host_config_value(&sysdir, "vpn", v)?);
        }
        if let Some(t) = &args.tags {
            println!("{}", set_host_config_value(&sysdir, "tags", t)?);
        }
        if let Some(r) = &args.default_role {
            println!("{}", set_host_config_value(&sysdir, "default_role", r)?);
        }
        let _ = &args.tier; // informational; reserved for future role mapping.

        // Step D2 — create the privsep service account the worker drops to, so
        // the plist's HOP_PRIVSEP_DROP actually takes effect (otherwise the
        // monitor finds no service user and keeps the worker root). Idempotent;
        // non-fatal — privsep degrades to a root worker if creation fails.
        ensure_service_user();

        // Step E — write the service file + start it. The service file is
        // always written; only the service *start* is skipped under
        // HOP_INSTALL_DAEMON_NO_START (lets the e2e validate file-laying +
        // promote + primers in a container with no init system).
        let no_start = std::env::var("HOP_INSTALL_DAEMON_NO_START").is_ok();
        #[cfg(target_os = "macos")]
        {
            const PLIST: &str = include_str!("../../../pkg/com.hop.daemon.plist");
            const PLIST_PATH: &str = "/Library/LaunchDaemons/com.hop.daemon.plist";
            std::fs::write(PLIST_PATH, PLIST)
                .with_context(|| format!("writing {PLIST_PATH}"))?;
            if no_start {
                println!("hop daemon plist written (start skipped: HOP_INSTALL_DAEMON_NO_START).");
            } else {
                // bootstrap/enable are idempotent-ish; only kickstart must succeed.
                let _ = run("launchctl", &["bootstrap", "system", PLIST_PATH]);
                let _ = run("launchctl", &["enable", "system/com.hop.daemon"]);
                run("launchctl", &["kickstart", "-k", "system/com.hop.daemon"])?;
                println!("hop daemon installed + started (launchd: com.hop.daemon).");
            }
        }
        #[cfg(target_os = "linux")]
        {
            const SERVICE: &str = include_str!("../../../pkg/hop.service");
            const UNIT_PATH: &str = "/etc/systemd/system/hop.service";
            std::fs::create_dir_all("/etc/systemd/system").ok();
            std::fs::write(UNIT_PATH, SERVICE).with_context(|| format!("writing {UNIT_PATH}"))?;
            if no_start {
                println!("hop systemd unit written (start skipped: HOP_INSTALL_DAEMON_NO_START).");
            } else {
                run("systemctl", &["daemon-reload"])?;
                run("systemctl", &["enable", "--now", "hop"])?;
                println!("hop daemon installed + started (systemd: hop.service).");
            }
        }
    }
    Ok(())
}

/// Create the privsep service account (`_hop` on macOS, `hop` on Linux) if it
/// doesn't already exist, mirroring the `.pkg` postinstall so the native
/// installer (`install-daemon.sh` → `__install-daemon`) fully activates
/// HOP_PRIVSEP_DROP. Idempotent and non-fatal: privsep falls back to a root
/// worker (and the monitor's crash-loop fallback) if the account is absent.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn ensure_service_user() {
    if hop_core::privsep::service_user_ids().is_some() {
        return; // already present
    }
    #[cfg(target_os = "macos")]
    {
        // Pick a free system UID in [200, 400) just above the highest existing.
        let mut uid: u32 = 300;
        if let Ok(out) = std::process::Command::new("dscl")
            .args([".", "-list", "/Users", "UniqueID"])
            .output()
            && let Some(m) = String::from_utf8_lossy(&out.stdout)
                .lines()
                .filter_map(|l| l.split_whitespace().nth(1).and_then(|n| n.parse::<u32>().ok()))
                .filter(|u| (200..400).contains(u))
                .max()
        {
            uid = m + 1;
        }
        let uid_s = uid.to_string();
        let dscl = |a: &[&str]| {
            let _ = std::process::Command::new("dscl").args(a).status();
        };
        dscl(&[".", "-create", "/Groups/_hop"]);
        dscl(&[".", "-create", "/Groups/_hop", "PrimaryGroupID", &uid_s]);
        dscl(&[".", "-create", "/Groups/_hop", "RealName", "hop service"]);
        dscl(&[".", "-create", "/Users/_hop"]);
        dscl(&[".", "-create", "/Users/_hop", "UserShell", "/usr/bin/false"]);
        dscl(&[".", "-create", "/Users/_hop", "RealName", "hop service"]);
        dscl(&[".", "-create", "/Users/_hop", "UniqueID", &uid_s]);
        dscl(&[".", "-create", "/Users/_hop", "PrimaryGroupID", &uid_s]);
        dscl(&[".", "-create", "/Users/_hop", "NFSHomeDirectory", "/var/empty"]);
        dscl(&[".", "-create", "/Users/_hop", "IsHidden", "1"]);
        println!("Created _hop service account (uid {uid}).");
    }
    #[cfg(target_os = "linux")]
    {
        // The `hop` system group is created in Step B; add the matching user.
        let ok = std::process::Command::new("useradd")
            .args(["--system", "-g", "hop", "-s", "/usr/sbin/nologin", "-M", "hop"])
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if ok {
            println!("Created hop service account.");
        }
    }
}

/// Run the privsep Phase-0 feasibility gate (privsep-node.md §8.1). Resolves an
/// unprivileged uid/gid (defaulting to the invoking user via `$SUDO_UID`),
/// creates a TUN as root, and reports whether a non-root process can do I/O on
/// the passed fd — the decision point for the whole privilege-separated design.
#[cfg(unix)]
fn cmd_privsep_probe(uid: Option<u32>, gid: Option<u32>) -> Result<()> {
    let uid = uid
        .or_else(|| std::env::var("SUDO_UID").ok().and_then(|s| s.parse().ok()))
        .context("could not determine an unprivileged uid — pass --uid, or run via sudo so $SUDO_UID is set")?;
    let gid = gid
        .or_else(|| std::env::var("SUDO_GID").ok().and_then(|s| s.parse().ok()))
        .unwrap_or(uid);
    anyhow::ensure!(uid != 0, "refusing to probe with uid 0 — the child must be unprivileged");

    println!("privsep Phase-0 gate: creating a TUN as root; testing fd I/O as uid={uid} gid={gid} …");
    if hop_core::privsep::run_tun_fd_probe(uid, gid)? {
        println!();
        println!("PASS — a non-root process read/wrote the root-created TUN fd.");
        println!("The privilege-separated node design (privsep-node.md, option B) is viable here.");
        Ok(())
    } else {
        println!();
        println!("FAIL — the kernel denied non-root I/O on the passed TUN fd.");
        println!("B-full is not viable as designed; fall back to B-lite (packet I/O stays in the");
        println!("root monitor) or option A (userspace netstack). See privsep-node.md §8.1/§10.");
        anyhow::bail!("privsep Phase-0 gate failed")
    }
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

/// Warren-related options for `hop connect` (consolidates the old `hop warren
/// join` flags onto `connect`).
struct ConnectWarrenOpts {
    /// Consent to the privileged node setup without prompting.
    yes: bool,
    /// How to resolve a conflict with a different, populated warren.
    on_warren_conflict: Option<cli::OnWarrenConflict>,
    /// Resume warren membership from the stored ticket (no target / invite).
    warren: bool,
}

async fn cmd_connect(
    _secret_key: iroh::SecretKey,
    target: Option<&str>,
    config_dir: &std::path::Path,
    cli_name: Option<&str>,
    sandbox: hop_core::sandbox::SandboxPolicy,
    warren_opts: ConnectWarrenOpts,
) -> Result<()> {
    // `--warren` means "join the warren (no shell session)": from the invite given
    // as the target, else from the ticket stored by a prior connection. This is
    // the explicit, headless join that replaces `hop warren join [<invite>]`.
    if warren_opts.warren {
        return do_warren_join(
            config_dir,
            target.map(String::from),
            warren_opts.yes,
            warren_opts.on_warren_conflict,
        )
        .await;
    }
    let Some(target) = target else {
        anyhow::bail!(
            "specify a target (host / invite / alias), or `--warren` to join the warren \
             from an invite or a stored ticket"
        );
    };

    // Choose the protocol variant based on whether sandbox is restricted
    let session_msg: ClientMessage = if sandbox.is_restricted() {
        ClientMessage::RequestShellV3 { session_id: None, sandbox }
    } else {
        ClientMessage::RequestShellV2 { session_id: None }
    };

    // Resolve the target first — fast and local. Prints the "Resolved … /
    // Connecting to …" banner in cooked mode before we switch to raw mode.
    let plan = mux::resolve_target(config_dir, target, cli_name)?;

    // Own raw mode and start the stdin reader BEFORE the dial — held for the
    // WHOLE interactive lifecycle (initial connect + sessions + reconnect
    // dialogs). The initial connect used to set these up only AFTER a blocking
    // dial returned, so nothing read the keyboard while connecting: `q`/Enter
    // did nothing and a hung dial trapped the user. Now the connect is polled
    // alongside stdin from the first moment, exactly like reconnect. The guard's
    // Drop restores the terminal on `?`/panic; the `process::exit` paths below
    // disable it explicitly first, since exit() skips Drop.
    let mut stdin_rx = spawn_stdin_reader();
    let _raw = shell::RawModeGuard::enable()?;

    // Responsive initial connect: live spinner, instant q/Ctrl+C, bounded
    // per-attempt deadline, backoff, and wedged-agent self-heal.
    let (first_send, first_recv) =
        match reconnect::run_initial_connect(config_dir, &plan, &session_msg, &mut stdin_rx).await? {
            reconnect::InitialConnectOutcome::Connected { send, recv } => (send, recv),
            reconnect::InitialConnectOutcome::Quit => {
                let _ = crossterm::terminal::disable_raw_mode();
                return Ok(());
            }
        };
    let resolved = plan.resolved();

    // Convention: consuming a warren-carrying invite puts this machine on the
    // warren (self-upgrade to a daemon) — no separate command, no `--host`. The
    // connection above authorized us, which is the membership redeem. A
    // client-tier invite is a no-op. Best-effort: a failure here must not block
    // the shell session the user asked for.
    if let Err(e) = maybe_upgrade_warren_on_connect(
        config_dir, target, warren_opts.yes, warren_opts.on_warren_conflict,
    ) {
        eprint!("warren upgrade skipped: {e:#}\r\n");
    }

    // Bracketed-paste / lost-chunk state, shared across reconnections so a
    // paste interrupted by a reconnect is completed rather than stranded.
    let mut replay = shell::InputReplay::default();

    // Run the first shell session
    let (mut session_id, mut outcome) =
        shell::client_shell_session_v2(first_send, first_recv, &mut stdin_rx, &mut replay).await?;

    // Anti-flapping state: track recent reconnections to detect rapid cycling
    let mut last_reconnect_time: Option<std::time::Instant> = None;
    let mut flap_attempt_offset: u32 = 0;

    // Reconnection loop
    loop {
        match outcome {
            SessionOutcome::Exited(code) => {
                let _ = crossterm::terminal::disable_raw_mode();
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

                // Shared across both reconnect tiers so paste typed during the
                // quick blip survives an escalation into the full dialog.
                let mut pending: Vec<u8> = Vec::new();

                let quick_result = if flap_attempt_offset == 0 {
                    reconnect::try_quick_reconnect(
                        config_dir,
                        &resolved,
                        &reconnect_msg,
                        Duration::from_secs(5),
                        &mut stdin_rx,
                        &mut pending,
                    )
                    .await
                } else {
                    None
                };

                // Tier 1 is an invisible blip (<5s): deliver buffered input
                // as-is so brief reconnects "just work". Tier 2 is a visible
                // dialog: apply the paste-aware filter so a flood of keystrokes
                // typed while waiting isn't dumped into the shell.
                let via_quick = quick_result.is_some();
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
                        &mut pending,
                    )
                    .await
                };

                match reconnect_result {
                    reconnect::ReconnectAction::ReconnectedViaAgent {
                        send,
                        recv,
                        new_session_id,
                        buffered_input,
                    } => {
                        last_reconnect_time = Some(std::time::Instant::now());

                        // Rebuild the post-disconnect input stream: the chunk
                        // lost in flight, followed by whatever was buffered.
                        let mut stream = replay.take_unsent();
                        stream.extend_from_slice(&buffered_input);
                        let to_send = if via_quick {
                            stream
                        } else {
                            replay.filter_replay(&stream)
                        };

                        // The reconnect function already sent setup messages
                        // (WindowSize + SetEnv) and consumed SessionInfo, so
                        // use the loop-only variant that skips the handshake.
                        let out = shell::client_shell_loop_resumed(
                            send,
                            recv,
                            &mut stdin_rx,
                            &mut replay,
                            to_send,
                        )
                        .await?;
                        session_id = new_session_id.or(session_id);
                        outcome = out;
                    }
                    reconnect::ReconnectAction::Quit => {
                        let _ = crossterm::terminal::disable_raw_mode();
                        std::process::exit(1);
                    }
                }
            }
        }
    }
}

/// Run `command` on `target` **through the daemon mux** and CAPTURE its combined
/// output + exit code (instead of streaming to the terminal like `cmd_exec`).
///
/// Routing via `mux::connect_to_host` reuses the machine's single endpoint — on a
/// host machine that's the daemon's endpoint, on a pure client it's the agent's —
/// so a fleet one-shot like `cap deploy` no longer mints a SECOND canonical iroh
/// endpoint that briefly collides with the host endpoint at the relay
/// (endpoint-unification follow-up).
async fn exec_capture_via_mux(
    config_dir: &std::path::Path,
    target: &str,
    command: &str,
) -> Result<(i32, String)> {
    let exec_msg = ClientMessage::RequestExec { command: command.to_string() };
    // `_send` is kept alive (not `_`) so the IPC connection stays open while we
    // read; the command we run is non-interactive, so we never write stdin.
    let (_resolved, _send, mut recv) =
        mux::connect_to_host(config_dir, target, None, &exec_msg).await?;
    let mut out = Vec::new();
    loop {
        match proto::read_message::<HostMessage>(&mut recv).await {
            Ok(HostMessage::Output(data)) => out.extend_from_slice(&data),
            Ok(HostMessage::Exit(code)) => {
                return Ok((code, String::from_utf8_lossy(&out).into_owned()));
            }
            Ok(_) => {}
            Err(e) => anyhow::bail!("exec stream error: {e}"),
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

/// Parse a `hop tunnel` port spec: `<port>` (local==remote) or `<localport>:<remoteport>`.
fn parse_tunnel_spec(spec: &str) -> Result<(u16, u16)> {
    if let Some((l, r)) = spec.split_once(':') {
        let lport = l.parse().with_context(|| format!("invalid local port '{l}'"))?;
        let rport = r.parse().with_context(|| format!("invalid remote port '{r}'"))?;
        Ok((lport, rport))
    } else {
        let p = spec.parse().with_context(|| format!("invalid port '{spec}'"))?;
        Ok((p, p))
    }
}

/// `hop tunnel` (local forward, like `ssh -L`): bind `localhost:<localport>` and
/// forward each TCP connection to the host's `127.0.0.1:<remoteport>` over the
/// encrypted P2P link. One QUIC stream per TCP connection (QUIC-native multiplex).
async fn cmd_tunnel(config_dir: &std::path::Path, target: &str, spec: &str) -> Result<()> {
    let (lport, rport) = parse_tunnel_spec(spec)?;
    let listener = tokio::net::TcpListener::bind(("127.0.0.1", lport))
        .await
        .with_context(|| format!("cannot bind localhost:{lport}"))?;
    println!("Tunnel: localhost:{lport} -> {target}:{rport}  (Ctrl-C to stop)");
    loop {
        let (mut tcp, _peer) = listener.accept().await.context("accept failed")?;
        let config_dir = config_dir.to_path_buf();
        let target = target.to_string();
        tokio::spawn(async move {
            match mux::connect_to_host(
                &config_dir,
                &target,
                None,
                &ClientMessage::RequestTunnel { port: rport },
            )
            .await
            {
                Ok((_resolved, write, read)) => {
                    // The stream is now a transparent pipe to the host's TCP dial;
                    // bridge the local TCP connection across it.
                    let mut peer = tokio::io::join(read, write);
                    if let Err(e) = tokio::io::copy_bidirectional(&mut tcp, &mut peer).await {
                        tracing::debug!("tunnel connection closed: {e}");
                    }
                }
                Err(e) => eprintln!("hop tunnel: failed to reach {target}: {e:#}"),
            }
        });
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
        AdminResponse::HostIdentity { node_id } => {
            println!("{node_id}");
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
    host_config_dir: &std::path::Path,
    user_config_dir: &std::path::Path,
    action: FleetAction,
) -> Result<()> {
    match action {
        FleetAction::Status { fleet: _ } => {
            // Warren-first: read the daemon's replicated-netdoc snapshot
            // (warren-members.json) from the host config dir. Every node has the
            // same view — no orchestrator.
            let snap = hop_core::fleet::WarrenSnapshot::load(host_config_dir).unwrap_or_default();
            match &snap.namespace {
                Some(ns) => {
                    println!("warren namespace  {ns}");
                    println!("members           {}", snap.members.len());
                    println!("roles             {}", snap.roles.len());
                    if snap.updated_at > 0 {
                        let age = unix_now_secs().saturating_sub(snap.updated_at);
                        println!("snapshot age      {age}s");
                    }
                }
                None => {
                    println!(
                        "Not on a warren (no membership snapshot — is the daemon running and joined?)."
                    );
                }
            }
            Ok(())
        }
        FleetAction::Add { name, tags } => {
            // Read from user's known_hosts
            let host = KnownHostsStore::load(user_config_dir)?
                .hosts
                .iter()
                .find(|h| h.name == name)
                .cloned()
                .with_context(|| format!("Host '{name}' not found in known_hosts"))?;

            // Write to daemon's fleet.json (legacy; warren-first views read the
            // netdoc snapshot — `fleet add` is retained until P4).
            let mut fleet = hop_core::fleet::FleetStore::load(host_config_dir)?;
            fleet.add_member(hop_core::fleet::FleetMember {
                node_id: host.node_id.clone(),
                hostname: name.clone(),
                tags: tags.clone(),
                registered_at: unix_now_secs().to_string(),
                last_heartbeat: None,
                relay_url: host.relay_url.clone(),
                online: false,
            });
            fleet.save(host_config_dir)?;

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

            // 1. Warren members — from the replicated netdoc snapshot (daemon's
            // warren-members.json), the same view on every node.
            let snap = hop_core::fleet::WarrenSnapshot::load(host_config_dir).unwrap_or_default();
            // Mark which member is this node by node-id (best-effort via the
            // daemon — members carry their real hostname now, not the string
            // "self"). No daemon → no marker, not an error.
            let self_id = id_via_daemon(host_config_dir).ok().flatten();
            if let Some(ns) = &snap.namespace {
                println!("warren {} — {} member(s)", &ns[..8.min(ns.len())], snap.members.len());
            }
            for m in &snap.members {
                let matches = group.as_ref().map(|g| m.tags.iter().any(|t| t == g)).unwrap_or(true);
                if !matches { continue; }
                seen.insert(m.node_id.clone());
                let id = &m.node_id[..10.min(m.node_id.len())];
                let vip = m.vip.as_deref().map(|v| format!("  {v}")).unwrap_or_default();
                let tags = if m.tags.is_empty() { String::new() } else { format!("  [{}]", m.tags.join(", ")) };
                let me = if self_id.as_deref() == Some(m.node_id.as_str()) { "  (this node)" } else { "" };
                println!("  {id}  {}  role={}{vip}{tags}{me}", m.name, m.role);
                any = true;
            }

            // 2. KnownHostsStore (user's known_hosts) — hosts you've connected to
            // that aren't warren members; shown with groups, dupes skipped.
            let hosts = KnownHostsStore::load(user_config_dir)?;
            for h in &hosts.hosts {
                if seen.contains(&h.node_id) { continue; }
                let matches = group.as_ref().map(|g| h.groups.contains(g)).unwrap_or(true);
                if !matches { continue; }
                let groups = if h.groups.is_empty() {
                    String::new()
                } else {
                    format!("  [{}]", h.groups.join(", "))
                };
                println!("  {}  {} (known host){groups}", &h.node_id[..10.min(h.node_id.len())], h.name);
                any = true;
            }

            if !any {
                println!("No warren members or known hosts found.");
            }
            Ok(())
        }
        FleetAction::Exec { selector, command } => {
            // Build the target set: warren members (from the replicated netdoc
            // snapshot) whose role or tags match the selector, plus known-host
            // groups (legacy). Each target is (connect_target, display_name) —
            // warren members connect by node_id, known hosts by alias.
            let mut seen = HashSet::new();
            let mut targets: Vec<(String, String)> = Vec::new();

            let snap = hop_core::fleet::WarrenSnapshot::load(host_config_dir).unwrap_or_default();
            for m in &snap.members {
                let hit = m.role == selector || m.tags.iter().any(|t| t == &selector);
                if hit && seen.insert(m.node_id.clone()) {
                    targets.push((m.node_id.clone(), m.name.clone()));
                }
            }
            let hosts = KnownHostsStore::load(user_config_dir)?;
            for h in &hosts.hosts {
                if h.groups.contains(&selector) && seen.insert(h.node_id.clone()) {
                    targets.push((h.name.clone(), h.name.clone())); // connect by alias
                }
            }

            if targets.is_empty() {
                println!("No warren members or known hosts match '{selector}'.");
                return Ok(());
            }
            println!("Running on {} host(s) matching '{selector}':", targets.len());
            let command_str = command.join(" ");
            let (mut ok, mut failed) = (0u32, 0u32);
            for (target, name) in &targets {
                println!("--- {name} ({}) ---", &target[..10.min(target.len())]);
                match mux::connect_to_host(
                    user_config_dir,
                    target,
                    None,
                    &ClientMessage::RequestExec { command: command_str.clone() },
                )
                .await
                {
                    Ok((_resolved, send, recv)) => {
                        let mut stdin_rx = spawn_stdin_reader();
                        let outcome = shell::client_exec_session(send, recv, &mut stdin_rx).await?;
                        match outcome {
                            SessionOutcome::Exited(0) => ok += 1,
                            SessionOutcome::Exited(code) => {
                                eprintln!("Exit code: {code}");
                                failed += 1;
                            }
                            SessionOutcome::Disconnected => {
                                eprintln!("Connection lost");
                                failed += 1;
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("Failed to connect: {e:#}");
                        failed += 1;
                    }
                }
                println!();
            }
            println!("Done: {ok} ok, {failed} failed.");
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
            let _cap = CapabilityDefinition::find(&id)
                .ok_or_else(|| anyhow::anyhow!("Unknown capability: '{id}'"))?;

            // Resolve the fleet group locally (same FleetStore the backend reads),
            // then run `hop cap enable <id>` on each target THROUGH THE DAEMON MUX
            // (exec_capture_via_mux). This reuses the machine's single endpoint
            // instead of minting a second canonical client endpoint that briefly
            // collides with the host endpoint at the relay (endpoint-unification).
            let fleet = hop_core::fleet::FleetStore::load(config_dir)?;
            let hosts: Vec<&hop_core::fleet::FleetMember> = fleet
                .members
                .iter()
                .filter(|m| targets == "*" || m.tags.iter().any(|t| t == &targets))
                .collect();
            if hosts.is_empty() {
                anyhow::bail!("No fleet hosts match targets '{targets}'");
            }

            let cmd = format!("hop cap enable {id}");
            println!(
                "Deploying capability '{}' to '{}' ({} hosts)...",
                id,
                targets,
                hosts.len()
            );
            let mut ok = 0usize;
            for m in &hosts {
                match exec_capture_via_mux(config_dir, &m.node_id, &cmd).await {
                    Ok((0, _)) => {
                        println!("  {}: ok", m.hostname);
                        ok += 1;
                    }
                    Ok((code, out)) => {
                        eprintln!("  {}: failed (exit {}): {}", m.hostname, code, out.trim());
                    }
                    Err(e) => eprintln!("  {}: connection error: {e}", m.hostname),
                }
            }
            println!("Deployed to {}/{} hosts", ok, hosts.len());
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
pub(crate) fn parse_duration_ms(s: &str) -> Result<u64> {
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

    let cfg = HostConfig::load(config_dir)?;

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
            let confirmation = set_host_config_value(config_dir, &key, &value)?;
            println!("{confirmation}");
            println!("Note: restart the host/daemon for changes to take effect.");
        }
        // Handled by the early return above; arm kept for exhaustiveness.
        Some(ConfigAction::Path) => unreachable!("config path handled before load"),
    }

    Ok(())
}

/// Apply a single host-config key=value, persisting it, and return a
/// human-readable confirmation. Shared by `hop config set` and the native
/// daemon installer (which applies vpn/tags/default_role primers in-process
/// rather than shelling out to `hop config set`).
fn set_host_config_value(config_dir: &std::path::Path, key: &str, value: &str) -> Result<String> {
    let mut cfg = HostConfig::load(config_dir)?;
    let msg = match key {
        "session_timeout" => {
            let secs: u64 = parse_duration_value(value)?;
            cfg.session_timeout_secs = secs;
            format!("session_timeout set to {secs}s")
        }
        "max_sessions" => {
            let n: usize = value.parse().context("max_sessions must be a positive integer")?;
            cfg.max_sessions = n;
            format!("max_sessions set to {n}")
        }
        "vpn" => {
            let on = parse_bool_value(value)?;
            cfg.vpn_enabled = on;
            format!("vpn set to {}", if on { "on" } else { "off" })
        }
        "tags" => {
            // Comma-separated; empty string clears tags.
            let tags: Vec<String> = value
                .split(',')
                .map(|t| t.trim().to_string())
                .filter(|t| !t.is_empty())
                .collect();
            cfg.tags = tags.clone();
            format!("tags set to {tags:?}")
        }
        "default_role" => {
            let role = value.trim().to_string();
            anyhow::ensure!(!role.is_empty(), "default_role must not be empty");
            cfg.default_role = role.clone();
            format!("default_role set to {role}")
        }
        _ => anyhow::bail!(
            "Unknown config key '{key}'. Valid keys: session_timeout, max_sessions, vpn, tags, default_role"
        ),
    };
    cfg.save(config_dir)?;
    Ok(msg)
}

/// `hop lan` — manage gateway subnet/exit routes (Tier 1 LAN bridging). File-based
/// (`routes.json`); the daemon materializes routes into the warren and sets up
/// forwarding on (re)start, mirroring how `roles.json` is applied.
fn cmd_lan(action: cli::LanAction, config_dir: &std::path::Path) -> Result<()> {
    use cli::LanAction;
    use hop_core::fleet::{RouteConfig, RoutesStore};
    match action {
        LanAction::Advertise { cidr, tags, no_snat, exit } => {
            if !exit {
                let Some(ref c) = cidr else {
                    anyhow::bail!(
                        "a CIDR is required (e.g. `hop lan advertise 192.168.1.0/24`), or pass --exit"
                    );
                };
                if hop_core::vpn::parse_cidr_v4(c).is_none() {
                    anyhow::bail!("invalid CIDR '{c}' — expected a.b.c.d/n (e.g. 192.168.1.0/24)");
                }
            }
            let mut store = RoutesStore::load(config_dir)?;
            let rc = RouteConfig {
                cidr: cidr.unwrap_or_else(|| "0.0.0.0/0".to_string()),
                tags,
                snat: !no_snat,
                exit,
                domain: None,
            };
            let eff = RoutesStore::effective_cidr(&rc);
            // Replace any existing advert for the same effective CIDR.
            store.routes.retain(|r| RoutesStore::effective_cidr(r) != eff);
            store.routes.push(rc);
            store.save(config_dir)?;
            println!(
                "Advertising {eff} (snat={}). Takes effect on next daemon start \
                 (data-plane forwarding lands in a later slice).",
                !no_snat
            );
            Ok(())
        }
        LanAction::Withdraw { cidr } => {
            let mut store = RoutesStore::load(config_dir)?;
            let before = store.routes.len();
            store
                .routes
                .retain(|r| RoutesStore::effective_cidr(r) != cidr && r.cidr != cidr);
            if store.routes.len() == before {
                println!("No advertised route matching '{cidr}'.");
            } else {
                store.save(config_dir)?;
                println!("Withdrew {cidr}. Takes effect on next daemon start.");
            }
            Ok(())
        }
        LanAction::Ls => {
            let store = RoutesStore::load(config_dir)?;
            if store.routes.is_empty() {
                println!(
                    "This machine advertises no LAN routes.\n\
                     Add one with `hop lan advertise 192.168.1.0/24`."
                );
            } else {
                println!("Routes advertised by this machine (routes.json):");
                for r in &store.routes {
                    let tags = if r.tags.is_empty() {
                        "(host tags)".to_string()
                    } else {
                        r.tags.join(",")
                    };
                    let (what, kind) = match &r.domain {
                        Some(d) => (d.clone(), "connector"),
                        None if r.exit => ("0.0.0.0/0".to_string(), "exit"),
                        None => (RoutesStore::effective_cidr(r), "subnet"),
                    };
                    println!("  {what:<22} {kind:<9} snat={:<5} tags={tags}", r.snat);
                }
            }
            Ok(())
        }
        LanAction::Connector { domain, tags } => {
            let mut store = RoutesStore::load(config_dir)?;
            store.routes.retain(|r| r.domain.as_deref() != Some(domain.as_str()));
            store.routes.push(RouteConfig {
                cidr: String::new(),
                tags,
                snat: true,
                exit: false,
                domain: Some(domain.clone()),
            });
            store.save(config_dir)?;
            let probe = RouteConfig {
                cidr: String::new(),
                tags: vec![],
                snat: true,
                exit: false,
                domain: Some(domain.clone()),
            };
            let ips = probe.resolved_cidrs();
            println!(
                "App connector for {domain} → {}. Takes effect on next daemon start.",
                if ips.is_empty() {
                    "(no IPv4 resolved yet)".to_string()
                } else {
                    ips.join(", ")
                }
            );
            Ok(())
        }
        LanAction::Dns { domain, nameserver } => {
            if nameserver.parse::<std::net::Ipv4Addr>().is_err() {
                anyhow::bail!("invalid nameserver IP '{nameserver}' — expected an IPv4 address");
            }
            let mut store = RoutesStore::load(config_dir)?;
            store.split_dns.retain(|s| s.domain != domain);
            store.split_dns.push(hop_core::fleet::SplitDns {
                domain: domain.clone(),
                nameserver: nameserver.clone(),
            });
            store.save(config_dir)?;
            println!(
                "Split-DNS: .{domain} → {nameserver}:53. Takes effect on next daemon start \
                 (make sure this node has a warren route to {nameserver})."
            );
            Ok(())
        }
    }
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
        AclAction::Policy { action } => cmd_acl_policy(action, config_dir),
    }
}

/// `hop acl policy set|show|test` — author the warren's Cedar reach policy. The
/// authored policy is saved locally to `acl_policy.cedar` (mirroring the roles.json
/// pattern); the daemon publishes it to the replicated `acl/cedar` on (re)start,
/// where C1 enforce restricts the write to an admin author. `test` is fully offline.
fn cmd_acl_policy(action: cli::AclPolicyAction, config_dir: &std::path::Path) -> Result<()> {
    use cli::AclPolicyAction;
    use hop_core::fleet::RolesStore;
    let policy_path = config_dir.join("acl_policy.cedar");
    match action {
        AclPolicyAction::Set { file } => {
            let text = match file {
                Some(f) => std::fs::read_to_string(&f)
                    .with_context(|| format!("reading {}", f.display()))?,
                None => {
                    use std::io::Read;
                    let mut s = String::new();
                    std::io::stdin()
                        .read_to_string(&mut s)
                        .context("reading policy from stdin")?;
                    s
                }
            };
            hop_core::vpn::cedar::validate_policy(&text).context("invalid Cedar policy")?;
            std::fs::write(&policy_path, text.as_bytes())
                .with_context(|| format!("writing {}", policy_path.display()))?;
            println!("Saved authored policy to {}", policy_path.display());
            println!(
                "The daemon publishes it to the warren on (re)start (admin only). \
                 Restart the host/daemon to apply."
            );
            Ok(())
        }
        AclPolicyAction::Show => match std::fs::read_to_string(&policy_path) {
            Ok(t) => {
                print!("{t}");
                Ok(())
            }
            Err(_) => {
                println!("(no authored policy saved; the default reach policy applies)");
                Ok(())
            }
        },
        AclPolicyAction::Test { role, tags, posture, policy } => {
            use hop_core::config::{Peer, PeerRole};
            // Resolve the authored policy: explicit --policy, else the saved one.
            let authored: Option<String> = match policy {
                Some(f) => Some(
                    std::fs::read_to_string(&f)
                        .with_context(|| format!("reading {}", f.display()))?,
                ),
                None => std::fs::read_to_string(&policy_path).ok(),
            };
            // Parse posture k=v pairs.
            let mut posture_attrs = std::collections::BTreeMap::new();
            for kv in &posture {
                let (k, v) = kv
                    .split_once('=')
                    .with_context(|| format!("--posture must be K=V, got '{kv}'"))?;
                posture_attrs.insert(k.to_string(), v.to_string());
            }
            // Synthetic principal (the role under test) + a synthetic tagged host.
            let principal = Peer {
                node_id: "test-principal".into(),
                name: "test-principal".into(),
                authorized_at: "1970-01-01T00:00:00Z".into(),
                last_seen: None,
                username: None,
                role: PeerRole::Peer,
                role_name: Some(role.clone()),
                netdoc_author: None,
                self_doc: None,
                vip: None,
                vpn_endpoint: None,
                site_id: None,
                sandbox: Default::default(),
            };
            let roles = RolesStore::load(config_dir)?.roles;
            let mut host_tags = std::collections::HashMap::new();
            host_tags.insert("test-host".to_string(), tags.clone());
            let mut posture_map = std::collections::HashMap::new();
            posture_map.insert("test-principal".to_string(), posture_attrs);
            let engine = hop_core::vpn::cedar::AclEngine::build(
                std::slice::from_ref(&principal),
                &roles,
                &host_tags,
                &posture_map,
                authored.as_deref(),
            )
            .context("building reach engine")?;
            let allowed = engine.is_reach_allowed("test-principal", "test-host", None);
            let post = if posture.is_empty() { "(none)".to_string() } else { posture.join(", ") };
            println!(
                "{} role={role} posture=[{post}] -> host[tags: {}]",
                if allowed { "ALLOW" } else { "DENY " },
                if tags.is_empty() { "(none)".into() } else { tags.join(", ") }
            );
            Ok(())
        }
    }
}

/// Offer to upgrade this machine to a warren node (a system daemon). The invite
/// has already been decoded + redeemed as the unprivileged user (the H10
/// invariant); this is the consent + escalate step. Uses the native, embedded
/// installer (`hop __install-daemon`) when `HOP_NATIVE_DAEMON_INSTALL` is set,
/// otherwise the proven shell installer (the default until the macOS
/// daemon-install e2e greenlights flipping native on).
fn self_upgrade_to_node(
    config_dir: &std::path::Path,
    tier: hop_core::invite::InviteTier,
    assume_yes: bool,
) -> Result<()> {
    let cdn = std::env::var("HOP_CDN_URL").unwrap_or_else(|_| "https://hop.keikai.ai".to_string());
    println!();

    if system_daemon_installed() {
        // A daemon is already installed: the join ticket we just wrote only takes
        // effect when the daemon restarts and re-imports the namespace. RESTART it
        // (privileged, via sudo) so the machine actually lands on the warren —
        // previously this only printed a hint and returned, which is why a
        // `hop connect <invite>` join silently never completed on an existing node.
        println!("A system daemon is already installed — restarting it to bring up the warren...");
        if restart_system_daemon_privileged() {
            println!("Restarted the daemon — this machine is now on the warren.");
        } else {
            println!("Could not restart the daemon automatically. Finish the join with:");
            #[cfg(target_os = "macos")]
            println!("      sudo launchctl kickstart -k system/com.hop.daemon");
            #[cfg(not(target_os = "macos"))]
            println!("      sudo systemctl restart hop");
        }
        return Ok(());
    }

    let interactive = std::io::IsTerminal::is_terminal(&std::io::stdin());
    let proceed = if assume_yes {
        true
    } else if interactive {
        println!(
            "To put this machine on the warren VPN as a {} it must run as a system",
            tier.as_str()
        );
        println!("daemon (root). Set it up now? This installs the hop daemon with sudo.");
        print!("  Proceed? [y/N] ");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut answer = String::new();
        let _ = std::io::stdin().read_line(&mut answer);
        matches!(answer.trim().to_ascii_lowercase().as_str(), "y" | "yes")
    } else {
        // Non-interactive without --yes: never escalate silently.
        false
    };

    if !proceed {
        println!("The join ticket is saved; put this machine on the VPN anytime with:");
        println!("      curl -fsSL {cdn}/install.sh | bash -s -- --host");
        return Ok(());
    }

    let finish_later = || {
        println!("Daemon setup did not complete. The join ticket is saved; finish later with:");
        println!("      curl -fsSL {cdn}/install.sh | bash -s -- --host");
    };

    if std::env::var("HOP_NATIVE_DAEMON_INSTALL").is_ok() {
        // Native: verify+stage the running binary, then promote+install as root.
        // The primer files Join wrote into config_dir are the stage.
        let staged = verify_and_stage_binary(&cdn)?;
        let vpn = if tier.is_warren_node() { "on" } else { "off" };
        let status = std::process::Command::new("sudo")
            .arg(&staged)
            .arg("__install-daemon")
            .arg("--promote-from")
            .arg(&staged)
            .arg("--stage")
            .arg(config_dir)
            .arg("--vpn")
            .arg(vpn)
            .arg("--tier")
            .arg(tier.as_str())
            .status()
            .context("running sudo hop __install-daemon")?;
        if let Some(parent) = staged.parent() {
            let _ = std::fs::remove_dir_all(parent); // best-effort temp cleanup
        }
        if status.success() {
            println!("Daemon set up natively — this machine is now on the warren.");
        } else {
            finish_later();
        }
    } else {
        let cmd = format!("curl -fsSL {cdn}/install.sh | bash -s -- --host");
        println!("Running: sudo bash -c \"{cmd}\"");
        match std::process::Command::new("sudo").args(["bash", "-c", &cmd]).status() {
            Ok(s) if s.success() => {
                println!("Daemon set up — this machine is now on the warren.")
            }
            _ => finish_later(),
        }
    }
    Ok(())
}

/// Decide how to resolve consuming a *different* warren's invite while the
/// current warren still has members. The default is **Keep** (never switch a
/// populated warren out from under the user); switching requires an explicit
/// choice. Non-interactive requires the `--on-warren-conflict` flag — never
/// destroy warren state implicitly. `member_count` is the current warren's size
/// (incl. self) if known, used only to make the prompt concrete.
fn resolve_warren_conflict(
    existing: &str,
    incoming: &str,
    flag: Option<cli::OnWarrenConflict>,
    member_count: Option<usize>,
) -> Result<cli::OnWarrenConflict> {
    use cli::OnWarrenConflict;
    let short = |s: &str| s[..8.min(s.len())].to_string();
    if let Some(choice) = flag {
        return Ok(choice);
    }
    if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
        anyhow::bail!(
            "already on warren {} (it has members) but this invite is for warren {}; \
             it won't be switched automatically — pass --on-warren-conflict switch|abort",
            short(existing),
            short(incoming)
        );
    }
    println!();
    match member_count {
        Some(n) if n > 1 => println!(
            "This machine is already on warren {} with {} other member(s).",
            short(existing),
            n - 1
        ),
        _ => println!("This machine is already on warren {}.", short(existing)),
    }
    println!("The invite you're consuming is for a different warren {}.", short(incoming));
    println!("  [K] Keep    — stay on {} (default)", short(existing));
    println!(
        "  [S] Switch  — leave {} and join {} (deletes warren state, with backup)",
        short(existing),
        short(incoming)
    );
    println!("  (multi-home — run both at once: not yet available)");
    print!("Choice [K]: ");
    let _ = std::io::Write::flush(&mut std::io::stdout());
    let mut answer = String::new();
    let _ = std::io::stdin().read_line(&mut answer);
    match answer.trim().to_ascii_lowercase().as_str() {
        "" | "k" | "keep" | "a" | "abort" => Ok(OnWarrenConflict::Abort),
        "s" | "switch" | "r" | "replace" => Ok(OnWarrenConflict::Replace),
        "m" | "merge" | "multi-home" | "multihome" => {
            anyhow::bail!("multi-home / merge are not yet available; choose Keep or Switch")
        }
        other => anyhow::bail!("unrecognized choice '{other}'"),
    }
}

/// Tear down this machine's warren state so it can join a different warren (or
/// just leave). Backup-first and idempotent; stops the daemon (if installed) so
/// the iroh-docs store is released before removal.
fn leave_warren(config_dir: &std::path::Path, yes: bool, no_backup: bool) -> Result<()> {
    let Some(ns) = hop_core::netdoc::read_namespace(config_dir) else {
        println!("Not on a warren — nothing to leave.");
        return Ok(());
    };
    let short = &ns[..8.min(ns.len())];

    if !yes {
        if !std::io::IsTerminal::is_terminal(&std::io::stdin()) {
            anyhow::bail!("refusing to leave warren {short} non-interactively without --yes");
        }
        print!("Leave warren {short}? Removes local warren state (with backup). [y/N] ");
        let _ = std::io::Write::flush(&mut std::io::stdout());
        let mut a = String::new();
        let _ = std::io::stdin().read_line(&mut a);
        if !matches!(a.trim().to_ascii_lowercase().as_str(), "y" | "yes") {
            println!("Aborted; still on warren {short}.");
            return Ok(());
        }
    }

    // Stop the daemon so it releases the store and stops re-publishing the vIP.
    if system_daemon_installed() {
        #[cfg(target_os = "macos")]
        let _ = std::process::Command::new("sudo")
            .args(["launchctl", "bootout", "system/com.hop.daemon"])
            .status();
        #[cfg(target_os = "linux")]
        let _ = std::process::Command::new("sudo").args(["systemctl", "stop", "hop"]).status();
    }

    // The warren state set. Removing the `netdoc/` store drops the self-doc too
    // (they share one store). vIP/MagicDNS are doc-coordinated, not local files.
    let files = [
        "netdoc.json",
        "netdoc-join.ticket",
        "netdoc.ticket",
        "netdoc-read.ticket",
        "warren-ticket",
        "netdoc-founder.author",
        "netdoc-founder.node",
    ];
    let store_dir = config_dir.join("netdoc");

    if no_backup {
        for f in files {
            let _ = std::fs::remove_file(config_dir.join(f));
        }
        let _ = std::fs::remove_dir_all(&store_dir);
    } else {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let backup = config_dir.join(format!(".warren-backup-{ts}"));
        std::fs::create_dir_all(&backup)
            .with_context(|| format!("creating {}", backup.display()))?;
        for f in files {
            let p = config_dir.join(f);
            if p.exists() {
                let _ = std::fs::rename(&p, backup.join(f));
            }
        }
        if store_dir.exists() {
            let _ = std::fs::rename(&store_dir, backup.join("netdoc"));
        }
        println!("Backed up warren state to {}", backup.display());
    }
    // A-scoped peer entries (authors/vIPs) would pollute B's reconcile; clear
    // them. roles.json / fleet.json are warren-agnostic and kept.
    let _ = std::fs::remove_file(config_dir.join("peers.json"));

    println!("Left warren {short}.");
    Ok(())
}

/// Resolve a multi-warren conflict (if any) and write the warren join primers
/// into `config_dir`. Returns `false` if the user aborted (caller should stop).
/// Shared by `hop connect <invite>` (auto-upgrade) and `hop connect --warren`.
fn prepare_warren_join(
    config_dir: &std::path::Path,
    ticket: &str,
    founder_author: Option<&str>,
    founder_node: Option<&str>,
    conflict_flag: Option<cli::OnWarrenConflict>,
) -> Result<bool> {
    use cli::OnWarrenConflict;
    let incoming_ns = hop_core::netdoc::namespace_of_ticket(ticket)?;
    match hop_core::netdoc::classify_warren_conflict(config_dir, &incoming_ns) {
        hop_core::netdoc::WarrenConflict::Same => {
            println!("Already on this warren — refreshing membership.");
        }
        hop_core::netdoc::WarrenConflict::None => {}
        hop_core::netdoc::WarrenConflict::Conflict { existing } => {
            let short_ex = &existing[..8.min(existing.len())];
            let short_in = &incoming_ns[..8.min(incoming_ns.len())];
            // Auto-adopt ONLY when we're confident the current warren is solo —
            // the daemon's snapshot is for this exact warren and shows just this
            // node (count == 1). A populated warren is never switched without an
            // explicit choice (principle of least surprise). An unknown count
            // (no/stale snapshot) is treated as "not solo" → ask.
            let member_count = hop_core::fleet::warren_member_count(config_dir, &existing);
            if conflict_flag.is_none() && member_count == Some(1) {
                println!(
                    "Current warren {short_ex} has no other members — adopting the \
                     invite's warren {short_in}."
                );
                leave_warren(config_dir, true, false)?;
            } else {
                match resolve_warren_conflict(&existing, &incoming_ns, conflict_flag, member_count)? {
                    OnWarrenConflict::Replace => leave_warren(config_dir, true, false)?,
                    OnWarrenConflict::Abort => {
                        println!("Staying on warren {short_ex}.");
                        return Ok(false);
                    }
                    OnWarrenConflict::Merge | OnWarrenConflict::MultiHome => anyhow::bail!(
                        "merge / multi-home are not yet available; use --on-warren-conflict replace"
                    ),
                }
            }
        }
    }
    // Write the join ticket so `hop host` imports the namespace on next start.
    // 0600 — warren ticket (security-audit H7). Founder author = C1 trust anchor;
    // founder node = the AnnounceNetdocAuthor target.
    config::write_secret_file(&config_dir.join("netdoc-join.ticket"), ticket)
        .context("writing warren join ticket")?;
    if let Some(fa) = founder_author {
        let _ = config::write_secret_file(&config_dir.join("netdoc-founder.author"), fa);
    }
    if let Some(fnode) = founder_node {
        let _ = config::write_shared_file(&config_dir.join("netdoc-founder.node"), fnode);
    }
    Ok(true)
}

/// Put this machine on the warren from an invite token (which carries the warren
/// ticket) or, with `invite = None`, from the ticket stored by a prior connection.
/// This is the canonical join used by `hop connect --warren` (no target) — the
/// former `hop warren join`. Writes the join primers, redeems membership when an
/// invite is supplied, then escalates to a system daemon (the H10-safe
/// self-upgrade).
async fn do_warren_join(
    config_dir: &std::path::Path,
    invite: Option<String>,
    yes: bool,
    on_warren_conflict: Option<cli::OnWarrenConflict>,
) -> Result<()> {
    let (ticket, founder_author, founder_node, redeem, tier) = match invite {
        Some(tok) => {
            let decoded = hop_core::invite::decode_invite(&tok).context("invalid invite token")?;
            let t = decoded.warren_ticket.clone().context(
                "this invite does not carry a warren — the host has no VPN/warren enabled",
            )?;
            let tier = decoded.effective_tier();
            (t, decoded.founder_author.clone(), Some(decoded.node_id.clone()), Some(tok), tier)
        }
        None => {
            let stored = std::fs::read_to_string(config_dir.join("warren-ticket")).context(
                "no stored warren ticket — connect with a warren invite first (`hop connect <invite>`)",
            )?;
            let t = stored.trim().to_string();
            anyhow::ensure!(!t.is_empty(), "stored warren ticket is empty");
            (t, None, None, None, hop_core::invite::InviteTier::Node)
        }
    };

    // Multi-warren resolution (KISS default = replace) + write the join primers.
    // Runs in the unprivileged user context, before the daemon.
    if !prepare_warren_join(
        config_dir,
        &ticket,
        founder_author.as_deref(),
        founder_node.as_deref(),
        on_warren_conflict,
    )? {
        return Ok(());
    }

    // Redeem for membership (auth handshake → the inviting host records us).
    if let Some(tok) = redeem {
        println!("Joining warren — redeeming invite for membership...");
        let secret_key = config::load_or_generate_identity(config_dir)?;
        if let Err(e) = cmd_exec(
            secret_key, &tok, config_dir, &["true".to_string()],
            hop_core::sandbox::SandboxPolicy::default(),
        )
        .await
        {
            tracing::warn!("membership redeem failed (namespace still joined): {e:#}");
        }
        // The redeem started a mux agent (it holds this config dir's datastore
        // lock). Stop it so the node daemon we're about to bring up can acquire
        // the datastore — otherwise `hop host` refuses to start (lock contention).
        let _ = agent::stop_agent(config_dir);
    }

    // Consent + escalate to a system daemon (the H10-safe self-upgrade).
    self_upgrade_to_node(config_dir, tier, yes)
}

/// When `hop connect <target>` consumes an invite that carries a warren, put
/// this machine on the warren (the "consume → on the warren, no --host"
/// convention). A client-tier invite (no warren ticket) is a no-op. Runs after
/// the connection authorized us (that handshake is the membership redeem).
fn maybe_upgrade_warren_on_connect(
    config_dir: &std::path::Path,
    target: &str,
    yes: bool,
    on_warren_conflict: Option<cli::OnWarrenConflict>,
) -> Result<()> {
    if !hop_core::invite::is_invite_token(target) {
        return Ok(());
    }
    let Ok(decoded) = hop_core::invite::decode_invite(target) else {
        return Ok(());
    };
    let Some(ticket) = decoded.warren_ticket.as_deref() else {
        return Ok(()); // client tier — reach only, never upgrades
    };
    println!();
    println!("This invite carries a warren — putting this machine on it.");
    if !prepare_warren_join(
        config_dir,
        ticket,
        decoded.founder_author.as_deref(),
        Some(&decoded.node_id),
        on_warren_conflict,
    )? {
        return Ok(());
    }
    self_upgrade_to_node(config_dir, decoded.effective_tier(), yes)
}

async fn cmd_warren(
    config_dir: &std::path::Path,
    action: cli::WarrenAction,
) -> Result<()> {
    use cli::WarrenAction;
    match action {
        WarrenAction::Leave { yes, no_backup } => leave_warren(config_dir, yes, no_backup),
        WarrenAction::Status => {
            // Membership / namespace. netdoc.json stores the namespace as a
            // NamespaceId (a JSON byte array), so use the typed reader rather
            // than parsing it as a string (which always missed and reported
            // "not on a warren" even for a host that was).
            let ns = hop_core::netdoc::read_namespace(config_dir);
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
                println!("  hop connect --warren     # uses the stored ticket");
                println!("  curl -fsSL https://hop.keikai.ai/install.sh | bash -s -- --host");
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
    fn tunnel_spec_parses_both_forms() {
        // `<port>` → same local + remote
        assert_eq!(parse_tunnel_spec("3000").unwrap(), (3000, 3000));
        // `<localport>:<remoteport>`
        assert_eq!(parse_tunnel_spec("8080:3000").unwrap(), (8080, 3000));
        // junk is rejected (not silently mis-forwarded)
        assert!(parse_tunnel_spec("nope").is_err());
        assert!(parse_tunnel_spec("8080:nope").is_err());
        assert!(parse_tunnel_spec("99999").is_err()); // > u16
    }

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

    /// The daemon-install binary path the plist/unit run must match the
    /// promote target — a drift here would point the service at a binary the
    /// installer never wrote.
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn daemon_bin_path_matches_templates() {
        assert_eq!(DAEMON_BIN_PATH, "/usr/local/bin/hop");
        assert!(include_str!("../../../pkg/com.hop.daemon.plist").contains(DAEMON_BIN_PATH));
        assert!(include_str!("../../../pkg/hop.service").contains(DAEMON_BIN_PATH));
    }

    /// Staged primer files are copied into the system dir; the join ticket is
    /// validated and a missing optional file is skipped (not an error).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn install_daemon_copies_staged_primers() {
        let stage = tempfile::tempdir().unwrap();
        let sysdir = tempfile::tempdir().unwrap();
        std::fs::write(stage.path().join("netdoc-join.ticket"), "ticket-abc").unwrap();
        std::fs::write(stage.path().join("netdoc-founder.author"), "author-xyz").unwrap();
        // netdoc-founder.node intentionally absent — must be skipped, not fail.

        copy_staged_primers(stage.path(), sysdir.path()).unwrap();

        assert_eq!(
            std::fs::read_to_string(sysdir.path().join("netdoc-join.ticket")).unwrap(),
            "ticket-abc"
        );
        assert_eq!(
            std::fs::read_to_string(sysdir.path().join("netdoc-founder.author")).unwrap(),
            "author-xyz"
        );
        assert!(!sysdir.path().join("netdoc-founder.node").exists());
    }

    /// An empty staged join ticket is rejected (never poison the system dir).
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn install_daemon_rejects_empty_join_ticket() {
        let stage = tempfile::tempdir().unwrap();
        let sysdir = tempfile::tempdir().unwrap();
        std::fs::write(stage.path().join("netdoc-join.ticket"), "   ").unwrap();
        assert!(copy_staged_primers(stage.path(), sysdir.path()).is_err());
    }

    /// Leaving a warren backs up and clears the warren state (namespace gone),
    /// while keeping warren-agnostic role/fleet files.
    #[test]
    fn leave_warren_backs_up_and_clears_state() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path();
        // Stand up a fake warren state.
        let ns_hex = "38b534260368fb961765edbdd9ca90b712e107952a8ab7e3948662c2b1dfc230";
        let meta = serde_json::json!({
            "namespace": hex::decode(ns_hex).unwrap(), "federated": false, "self_namespace": null,
        });
        std::fs::write(p.join("netdoc.json"), meta.to_string()).unwrap();
        std::fs::write(p.join("netdoc-join.ticket"), "tkt").unwrap();
        std::fs::write(p.join("netdoc-founder.author"), "auth").unwrap();
        std::fs::write(p.join("peers.json"), "{}").unwrap();
        std::fs::write(p.join("roles.json"), "{}").unwrap();
        std::fs::create_dir_all(p.join("netdoc")).unwrap();

        leave_warren(p, true, false).unwrap();

        // Warren state gone; no longer on a warren.
        assert!(hop_core::netdoc::read_namespace(p).is_none());
        assert!(!p.join("netdoc.json").exists());
        assert!(!p.join("netdoc-join.ticket").exists());
        assert!(!p.join("netdoc").exists());
        assert!(!p.join("peers.json").exists(), "A-scoped peers cleared");
        // Warren-agnostic config kept.
        assert!(p.join("roles.json").exists(), "roles.json preserved");
        // A backup dir was created holding the moved state.
        let backup = std::fs::read_dir(p)
            .unwrap()
            .filter_map(|e| e.ok())
            .find(|e| e.file_name().to_string_lossy().starts_with(".warren-backup-"));
        assert!(backup.is_some(), "backup dir created");

        // Idempotent: a second leave is a clean no-op.
        leave_warren(p, true, false).unwrap();
    }

    /// Scalar primers are applied to host_config.json in-process.
    #[test]
    fn set_host_config_value_applies_scalars() {
        let dir = tempfile::tempdir().unwrap();
        set_host_config_value(dir.path(), "vpn", "on").unwrap();
        set_host_config_value(dir.path(), "default_role", "developer").unwrap();
        set_host_config_value(dir.path(), "tags", "prod, web").unwrap();
        let cfg = hop_core::config::HostConfig::load(dir.path()).unwrap();
        assert!(cfg.vpn_enabled);
        assert_eq!(cfg.default_role, "developer");
        assert_eq!(cfg.tags, vec!["prod".to_string(), "web".to_string()]);
        assert!(set_host_config_value(dir.path(), "bogus", "x").is_err());
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
