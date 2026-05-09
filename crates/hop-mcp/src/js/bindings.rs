//! Rust functions exposed as hop.* JS globals.
//!
//! These bindings bridge JS calls to the OrchestratorBackend trait.
//! The JS runtime runs on a dedicated OS thread; async backend calls
//! will be bridged via a channel back to the tokio runtime (Phase 2+).

use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use hop_core::datastore::types::{KvEntry, MetricPoint, TimeSeriesQuery};
use hop_core::datastore::Datastore;
use rquickjs::{Ctx, Function, Object, Value};
use tokio::runtime::Handle;

use crate::backend::OrchestratorBackend;
use hop_core::sandbox::SandboxPolicy;

/// Default timeout for `block_on` calls from the JS thread.
/// `Handle::block_on` + `tokio::time::timeout` doesn't reliably deliver
/// timer wakeups to a parked std thread. We use a thread-level timeout
/// (oneshot channel with `recv_timeout`) as the true deadline.
const BLOCK_ON_TIMEOUT: Duration = Duration::from_secs(60);

/// Run an async future on the tokio runtime from a std thread, with a hard
/// timeout that works even if the tokio timer doesn't wake the blocked thread.
fn block_on_with_timeout<F, T>(handle: &Handle, timeout: Duration, fut: F) -> Result<T>
where
    F: std::future::Future<Output = Result<T>> + Send + 'static,
    T: Send + 'static,
{
    let (tx, rx) = std::sync::mpsc::sync_channel(1);
    handle.spawn(async move {
        let result = fut.await;
        let _ = tx.send(result);
    });
    match rx.recv_timeout(timeout) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
            tracing::warn!("block_on_with_timeout: timed out after {}s", timeout.as_secs());
            Err(anyhow::anyhow!("operation timed out after {}s", timeout.as_secs()))
        }
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
            tracing::warn!("block_on_with_timeout: channel disconnected (task panicked?)");
            Err(anyhow::anyhow!("operation failed: task panicked or was cancelled"))
        }
    }
}

/// Create a rquickjs error with an owned message.
fn js_err(msg: String) -> rquickjs::Error {
    rquickjs::Error::new_from_js_message("function", "value", msg)
}

/// Install the `hop` global object with all bindings.
///
/// When `backend` is `Some`, hop.exec/fleet/admin/roles/fs are wired to the
/// real OrchestratorBackend via `handle.block_on()`. When `None` (cron jobs),
/// they remain as stubs that throw errors.
pub fn install_hop_bindings(
    ctx: &Ctx<'_>,
    datastore: Option<&Datastore>,
    backend: Option<(Arc<dyn OrchestratorBackend>, Handle)>,
    sandbox: Option<&SandboxPolicy>,
    run_as_user: Option<&str>,
) -> Result<()> {
    let globals = ctx.globals();

    let hop = Object::new(ctx.clone())
        .map_err(|e| anyhow::anyhow!("Failed to create hop object: {e}"))?;

    // hop.log(message) — write to stderr (visible to operator, not to MCP client)
    hop.set(
        "log",
        Function::new(ctx.clone(), |_ctx: Ctx<'_>, args: rquickjs::function::Rest<Value<'_>>| -> rquickjs::Result<()> {
            let msg = args
                .0
                .iter()
                .map(|v| {
                    v.as_string()
                        .map(|s| s.to_string().unwrap_or_default())
                        .unwrap_or_else(|| format!("{v:?}"))
                })
                .collect::<Vec<_>>()
                .join(" ");
            eprintln!("[hop.log] {msg}");
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // hop.sleep(ms)
    hop.set(
        "sleep",
        Function::new(ctx.clone(), |_ctx: Ctx<'_>, ms: f64| -> rquickjs::Result<()> {
            std::thread::sleep(std::time::Duration::from_millis(ms as u64));
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // hop.writeFile(path, content) — write a string to a file (for temp files, prompts, etc.)
    hop.set(
        "writeFile",
        Function::new(ctx.clone(), |_ctx: Ctx<'_>, path: String, content: String| -> rquickjs::Result<()> {
            std::fs::write(&path, content.as_bytes())
                .map_err(|e| js_err(format!("hop.writeFile({path}) failed: {e}")))
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // hop.readFile(path) — read a file as a string
    hop.set(
        "readFile",
        Function::new(ctx.clone(), |_ctx: Ctx<'_>, path: String| -> rquickjs::Result<String> {
            std::fs::read_to_string(&path)
                .map_err(|e| js_err(format!("hop.readFile({path}) failed: {e}")))
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    if let Some((ref _b, ref _h)) = backend {
        // Set hop.id with the real backend before globals assignment
        let b = Arc::clone(_b);
        hop.set(
            "id",
            Function::new(ctx.clone(), move || -> rquickjs::Result<String> {
                b.whoami()
                    .map(|u| u.node_id)
                    .map_err(|e| js_err(format!("hop.id() failed: {e}")))
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    } else {
        install_stub_bindings(ctx, &hop)?;
    }

    // Set hop on globals BEFORE installing JS wrappers (they reference the hop global)
    globals
        .set("hop", hop)
        .map_err(|e| anyhow::anyhow!("Failed to set hop global: {e}"))?;

    if let Some((backend, handle)) = backend {
        install_live_raw_bindings(ctx, backend, handle, sandbox.cloned())?;
        install_backend_js_wrappers(ctx)?;
    }

    // Install hop.local() binding — runs commands on the local machine with sandbox
    install_local_binding(ctx, sandbox.cloned(), run_as_user.map(String::from))?;

    // Install hop.http() binding — makes HTTP requests from JS
    install_http_binding(ctx, sandbox)?;

    // Install datastore bindings via JS wrapper
    if let Some(ds) = datastore {
        install_datastore_raw(ctx, ds, run_as_user)?;
        install_datastore_js_wrappers(ctx)?;
    } else {
        install_datastore_stubs(ctx)?;
    }

    // Install hop.claude() binding — AI inference via Claude CLI
    install_claude_binding(ctx, datastore, sandbox, run_as_user)?;

    remove_dangerous_globals(ctx)?;

    Ok(())
}

/// Install raw __hop_* functions backed by a real OrchestratorBackend.
///
/// Each binding calls `handle.block_on(backend.method())` to bridge the
/// async backend into the synchronous QuickJS thread. This is safe because
/// the JS thread is a plain OS thread, not a tokio worker thread.
///
/// Must be called AFTER `hop` is set on globals (the JS wrappers reference it).
fn install_live_raw_bindings(
    ctx: &Ctx<'_>,
    backend: Arc<dyn OrchestratorBackend>,
    handle: Handle,
    sandbox: Option<SandboxPolicy>,
) -> Result<()> {
    // __hop_exec(host, command) → JSON string
    // When sandbox is set, uses exec_sandboxed to enforce the policy on the remote host.
    {
        let b = Arc::clone(&backend);
        let h = handle.clone();
        let sb = sandbox.clone();
        ctx.globals().set("__hop_exec",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, host: String, command: String| -> rquickjs::Result<String> {
                let b2 = Arc::clone(&b);
                let host2 = host.clone();
                let result = if let Some(policy) = sb.clone() {
                    block_on_with_timeout(&h, BLOCK_ON_TIMEOUT, async move { b2.exec_sandboxed(&host2, &command, &policy).await })
                } else {
                    block_on_with_timeout(&h, BLOCK_ON_TIMEOUT, async move { b2.exec(&host2, &command).await })
                };
                match result {
                    Ok(result) => serde_json::to_string(&result)
                        .map_err(|e| js_err(format!("serialize exec result: {e}"))),
                    Err(e) => Err(js_err(format!("hop.exec({host}, ...) failed: {e}"))),
                }
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_fleet_list(tag?) → JSON string
    {
        let b = Arc::clone(&backend);
        let h = handle.clone();
        ctx.globals().set("__hop_fleet_list",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, tag: rquickjs::function::Opt<String>| -> rquickjs::Result<String> {
                let b2 = Arc::clone(&b);
                let tag2 = tag.0.clone();
                match block_on_with_timeout(&h, BLOCK_ON_TIMEOUT, async move { b2.list_hosts(tag2.as_deref()).await }) {
                    Ok(hosts) => serde_json::to_string(&hosts)
                        .map_err(|e| js_err(format!("serialize fleet list: {e}"))),
                    Err(e) => Err(js_err(format!("hop.fleet.list() failed: {e}"))),
                }
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_fleet_exec(group, command) → JSON string
    // When sandbox is set, uses fleet_exec_sandboxed.
    {
        let b = Arc::clone(&backend);
        let h = handle.clone();
        let sb = sandbox.clone();
        ctx.globals().set("__hop_fleet_exec",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, group: String, command: String| -> rquickjs::Result<String> {
                let b2 = Arc::clone(&b);
                let result = if let Some(policy) = sb.clone() {
                    block_on_with_timeout(&h, BLOCK_ON_TIMEOUT, async move { b2.fleet_exec_sandboxed(&group, &command, &policy).await })
                } else {
                    block_on_with_timeout(&h, BLOCK_ON_TIMEOUT, async move { b2.fleet_exec(&group, &command).await })
                };
                match result {
                    Ok(results) => serde_json::to_string(&results)
                        .map_err(|e| js_err(format!("serialize fleet exec: {e}"))),
                    Err(e) => Err(js_err(format!("hop.fleet.exec() failed: {e}"))),
                }
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_admin_status(host) → JSON string
    {
        let b = Arc::clone(&backend);
        let h = handle.clone();
        ctx.globals().set("__hop_admin_status",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, host: String| -> rquickjs::Result<String> {
                let b2 = Arc::clone(&b);
                let host2 = host.clone();
                match block_on_with_timeout(&h, BLOCK_ON_TIMEOUT, async move { b2.admin_status(&host2).await }) {
                    Ok(status) => serde_json::to_string(&status)
                        .map_err(|e| js_err(format!("serialize admin status: {e}"))),
                    Err(e) => Err(js_err(format!("hop.admin.status({host}) failed: {e}"))),
                }
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_admin_peers(host) → JSON string
    {
        let b = Arc::clone(&backend);
        let h = handle.clone();
        ctx.globals().set("__hop_admin_peers",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, host: String| -> rquickjs::Result<String> {
                let b2 = Arc::clone(&b);
                let host2 = host.clone();
                match block_on_with_timeout(&h, BLOCK_ON_TIMEOUT, async move { b2.admin_peers(&host2).await }) {
                    Ok(peers) => serde_json::to_string(&peers)
                        .map_err(|e| js_err(format!("serialize admin peers: {e}"))),
                    Err(e) => Err(js_err(format!("hop.admin.peers({host}) failed: {e}"))),
                }
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_admin_invite(host, username?, role?) → string (token)
    {
        let b = Arc::clone(&backend);
        let h = handle.clone();
        ctx.globals().set("__hop_admin_invite",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, host: String, username: rquickjs::function::Opt<String>, role: rquickjs::function::Opt<String>| -> rquickjs::Result<String> {
                let b2 = Arc::clone(&b);
                let host2 = host.clone();
                let u = username.0.clone();
                let r = role.0.clone();
                match block_on_with_timeout(&h, BLOCK_ON_TIMEOUT, async move { b2.admin_invite(&host2, u.as_deref(), r.as_deref()).await }) {
                    Ok(token) => Ok(token),
                    Err(e) => Err(js_err(format!("hop.admin.invite({host}) failed: {e}"))),
                }
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_admin_remove_peer(host, nodeIdPrefix) → JSON string
    {
        let b = Arc::clone(&backend);
        let h = handle.clone();
        ctx.globals().set("__hop_admin_remove_peer",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, host: String, prefix: String| -> rquickjs::Result<String> {
                let b2 = Arc::clone(&b);
                let host2 = host.clone();
                match block_on_with_timeout(&h, BLOCK_ON_TIMEOUT, async move { b2.admin_remove_peer(&host2, &prefix).await }) {
                    Ok(success) => Ok(serde_json::json!({"success": success}).to_string()),
                    Err(e) => Err(js_err(format!("hop.admin.removePeer({host}) failed: {e}"))),
                }
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_roles_list(host) → JSON string
    {
        let b = Arc::clone(&backend);
        let h = handle.clone();
        ctx.globals().set("__hop_roles_list",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, host: String| -> rquickjs::Result<String> {
                let b2 = Arc::clone(&b);
                let host2 = host.clone();
                match block_on_with_timeout(&h, BLOCK_ON_TIMEOUT, async move { b2.list_roles(&host2).await }) {
                    Ok(roles) => serde_json::to_string(&roles)
                        .map_err(|e| js_err(format!("serialize roles: {e}"))),
                    Err(e) => Err(js_err(format!("hop.roles.list({host}) failed: {e}"))),
                }
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_roles_delete(host, name) → void
    {
        let b = Arc::clone(&backend);
        let h = handle.clone();
        ctx.globals().set("__hop_roles_delete",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, host: String, name: String| -> rquickjs::Result<()> {
                let b2 = Arc::clone(&b);
                let host2 = host.clone();
                let name2 = name.clone();
                block_on_with_timeout(&h, BLOCK_ON_TIMEOUT, async move { b2.delete_role(&host2, &name2).await })
                    .map_err(|e| js_err(format!("hop.roles.delete({host}, {name}) failed: {e}")))
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_metrics_push(pointsJson) → JSON string
    {
        let b = Arc::clone(&backend);
        let h = handle.clone();
        ctx.globals().set("__hop_metrics_push",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, points_json: String| -> rquickjs::Result<String> {
                let points: Vec<hop_core::proto::PushMetricPoint> = serde_json::from_str(&points_json)
                    .map_err(|e| js_err(format!("invalid points JSON: {e}")))?;
                let b2 = Arc::clone(&b);
                match block_on_with_timeout(&h, BLOCK_ON_TIMEOUT, async move { b2.push_metrics(points).await }) {
                    Ok(count) => Ok(serde_json::json!({"count": count}).to_string()),
                    Err(e) => Err(js_err(format!("hop.metrics.push() failed: {e}"))),
                }
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    Ok(())
}

/// Install JS wrappers over the raw __hop_* functions.
fn install_backend_js_wrappers(ctx: &Ctx<'_>) -> Result<()> {
    let js_code = r#"
        hop.exec = function(host, command) {
            return JSON.parse(__hop_exec(host, command));
        };
        hop.fleet = {
            list: function(tag) {
                if (tag !== undefined) {
                    return JSON.parse(__hop_fleet_list(tag));
                }
                return JSON.parse(__hop_fleet_list());
            },
            exec: function(group, command) {
                return JSON.parse(__hop_fleet_exec(group, command));
            }
        };
        hop.admin = {
            status: function(host) {
                return JSON.parse(__hop_admin_status(host));
            },
            peers: function(host) {
                return JSON.parse(__hop_admin_peers(host));
            },
            invite: function(host, username, role) {
                return __hop_admin_invite(host, username, role);
            },
            removePeer: function(host, prefix) {
                return JSON.parse(__hop_admin_remove_peer(host, prefix));
            }
        };
        hop.roles = {
            list: function(host) {
                return JSON.parse(__hop_roles_list(host));
            },
            delete: function(host, name) {
                __hop_roles_delete(host, name);
            }
        };
        hop.fs = {
            push: function() { throw new Error("hop.fs.push not yet implemented in MCP mode"); },
            pull: function() { throw new Error("hop.fs.pull not yet implemented in MCP mode"); }
        };
        hop.metrics = {
            push: function(points) {
                return JSON.parse(__hop_metrics_push(JSON.stringify(points)));
            }
        };
    "#;

    ctx.eval::<(), _>(js_code)
        .map_err(|e| anyhow::anyhow!("Failed to install backend JS wrappers: {e}"))?;

    Ok(())
}

/// Install the `hop.local(command)` binding for running commands on the local machine.
///
/// When a sandbox policy is set, commands are run through `spawn_sandboxed_command`.
/// When no sandbox is set, commands are run unsandboxed via `/bin/sh -c`.
/// Returns `{ stdout, stderr, exit_code }` — same shape as `hop.exec()`.
fn install_local_binding(ctx: &Ctx<'_>, sandbox: Option<SandboxPolicy>, run_as_user: Option<String>) -> Result<()> {
    let globals = ctx.globals();

    // Clone before first closure moves them
    let sandbox2 = sandbox.clone();
    let run_as_user2 = run_as_user.clone();

    globals.set("__hop_local",
        Function::new(ctx.clone(), move |_ctx: Ctx<'_>, command: String| -> rquickjs::Result<String> {
            let result = run_local_command_sync(&command, sandbox.as_ref(), run_as_user.as_deref());
            match result {
                Ok(exec_result) => serde_json::to_string(&exec_result)
                    .map_err(|e| js_err(format!("serialize local result: {e}"))),
                Err(e) => Err(js_err(format!("hop.local() failed: {e}"))),
            }
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    ).map_err(|e| anyhow::anyhow!("{e}"))?;

    // hop.script(code) — run a script piped through stdin (no quoting issues)
    globals.set("__hop_script",
        Function::new(ctx.clone(), move |_ctx: Ctx<'_>, script: String| -> rquickjs::Result<String> {
            let result = run_local_script_sync(&script, sandbox2.as_ref(), run_as_user2.as_deref());
            match result {
                Ok(exec_result) => serde_json::to_string(&exec_result)
                    .map_err(|e| js_err(format!("serialize script result: {e}"))),
                Err(e) => Err(js_err(format!("hop.script() failed: {e}"))),
            }
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    ).map_err(|e| anyhow::anyhow!("{e}"))?;

    // JS wrappers
    ctx.eval::<(), _>(r#"
        hop.local = function(command) {
            return JSON.parse(__hop_local(command));
        };
        hop.script = function(code) {
            return JSON.parse(__hop_script(code));
        };
    "#)
    .map_err(|e| anyhow::anyhow!("Failed to install hop.local/script wrapper: {e}"))?;

    Ok(())
}

/// Run a command locally using std::process::Command (synchronous, for the JS thread).
///
/// When `username` is set and the daemon is root, drops privileges via
/// `login -fp <user>` (macOS) or `su - <user> -c` (Linux) — the same
/// mechanism used by peer sessions in `sandbox/mod.rs`.
///
/// Security: refuses to execute if the daemon is root and no username is set,
/// preventing cron jobs from accidentally running commands as root.
fn run_local_command_sync(
    command: &str,
    sandbox: Option<&SandboxPolicy>,
    username: Option<&str>,
) -> Result<crate::js::types::ExecResult> {
    use crate::js::types::ExecResult;

    // Safety: when running as root with no user to drop to, refuse execution
    if username.is_none() && hop_core::unix_user::is_running_as_root() {
        tracing::warn!(
            "hop.local() refused: daemon is root but job has no run_as_user — command: {command}"
        );
        return Ok(ExecResult {
            stdout: String::new(),
            stderr: "hop.local() refused: daemon is root but job has no run_as_user. \
                     Re-create the job to set a user automatically."
                .to_string(),
            exit_code: -1,
        });
    }

    // Validate command against sandbox policy
    if let Some(policy) = sandbox
        && policy.is_restricted()
        && let Err(e) = hop_core::sandbox::validate_command(command, policy)
    {
        return Ok(ExecResult {
            stdout: String::new(),
            stderr: format!("command denied: {e}"),
            exit_code: -1,
        });
    }

    let restricted = sandbox.is_some_and(|p| p.is_restricted());

    // Resolve the user's login shell. Use their actual shell (zsh, bash, etc.)
    // in login mode (-lc) so the profile is sourced and PATH includes nvm/brew/etc.
    // This matches what `hop exec` does — the agent tests commands in the same
    // environment the cron job will use.
    let user_shell = username
        .map(hop_core::unix_user::user_login_shell)
        .unwrap_or_else(|| std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string()));

    // Wrap command to source the user's rc file (e.g. .zshrc) for full PATH.
    let wrapped = hop_core::sandbox::with_rc_source(command, &user_shell);
    let command = wrapped.as_str();

    // Build the command with privilege dropping and optional sandboxing.
    let output = match (restricted, username) {
        // Sandboxed + username: drop privileges then sandbox
        (true, Some(user)) => {
            let policy = sandbox.unwrap();
            #[cfg(target_os = "macos")]
            {
                let profile = hop_core::sandbox::macos::generate_sbpl_profile(policy);
                std::process::Command::new("login")
                    .args(["-fpq", user, "/usr/bin/sandbox-exec", "-p"])
                    .arg(&profile)
                    .args([&user_shell, "-lc", command])
                    .output()
            }
            #[cfg(target_os = "linux")]
            {
                let policy_clone = policy.clone();
                let mut cmd = std::process::Command::new("su");
                cmd.args(["-", user, "-s", &user_shell, "-c", command]);
                unsafe {
                    use std::os::unix::process::CommandExt;
                    cmd.pre_exec(move || {
                        hop_core::sandbox::linux::apply_sandbox(&policy_clone);
                        Ok(())
                    });
                }
                cmd.output()
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                let _ = user;
                std::process::Command::new(&user_shell)
                    .args(["-lc", command])
                    .output()
            }
        }

        // Unsandboxed + username: drop privileges only
        (false, Some(user)) => {
            #[cfg(target_os = "macos")]
            {
                std::process::Command::new("login")
                    .args(["-fpq", user, &user_shell, "-lc", command])
                    .output()
            }
            #[cfg(all(unix, not(target_os = "macos")))]
            {
                std::process::Command::new("su")
                    .args(["-", user, "-s", &user_shell, "-c", command])
                    .output()
            }
            #[cfg(not(unix))]
            {
                let _ = user;
                std::process::Command::new(&user_shell)
                    .args(["-lc", command])
                    .output()
            }
        }

        // Sandboxed + no username: sandbox only (not root, or legacy fallback)
        (true, None) => {
            let policy = sandbox.unwrap();
            #[cfg(target_os = "macos")]
            {
                let profile = hop_core::sandbox::macos::generate_sbpl_profile(policy);
                std::process::Command::new("/usr/bin/sandbox-exec")
                    .args(["-p", &profile, &user_shell, "-lc", command])
                    .output()
            }
            #[cfg(target_os = "linux")]
            {
                let policy_clone = policy.clone();
                let mut cmd = std::process::Command::new(&user_shell);
                cmd.args(["-lc", command]);
                unsafe {
                    use std::os::unix::process::CommandExt;
                    cmd.pre_exec(move || {
                        hop_core::sandbox::linux::apply_sandbox(&policy_clone);
                        Ok(())
                    });
                }
                cmd.output()
            }
            #[cfg(not(any(target_os = "macos", target_os = "linux")))]
            {
                std::process::Command::new(&user_shell)
                    .args(["-lc", command])
                    .output()
            }
        }

        // No sandbox, no username, not root: plain execution
        (false, None) => {
            std::process::Command::new(&user_shell)
                .args(["-lc", command])
                .output()
        }
    };

    match output {
        Ok(o) => Ok(ExecResult {
            stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
            exit_code: o.status.code().unwrap_or(-1),
        }),
        Err(e) => Ok(ExecResult {
            stdout: String::new(),
            stderr: format!("failed to spawn: {e}"),
            exit_code: -1,
        }),
    }
}

/// Run a script via stdin — no shell quoting of the script content.
///
/// The script is piped to the user's login shell via stdin. This avoids
/// all quoting issues with complex scripts (quotes, newlines, special chars).
/// The shell sources the user's profile first for the full environment.
fn run_local_script_sync(
    script: &str,
    sandbox: Option<&SandboxPolicy>,
    username: Option<&str>,
) -> Result<crate::js::types::ExecResult> {
    use crate::js::types::ExecResult;
    use std::io::Write;

    // Safety: when running as root with no user to drop to, refuse execution
    if username.is_none() && hop_core::unix_user::is_running_as_root() {
        return Ok(ExecResult {
            stdout: String::new(),
            stderr: "hop.script() refused: daemon is root but job has no run_as_user.".to_string(),
            exit_code: -1,
        });
    }

    let user_shell = username
        .map(hop_core::unix_user::user_login_shell)
        .unwrap_or_else(|| std::env::var("SHELL").unwrap_or_else(|_| "/bin/sh".to_string()));

    // Build the rc source prefix
    let rc_source = hop_core::sandbox::with_rc_source("", &user_shell);
    let full_script = if rc_source.is_empty() {
        script.to_string()
    } else {
        // rc_source ends with "; " — append the script
        format!("{rc_source}\n{script}")
    };

    // Spawn shell reading from stdin — no -c, no command string on argv
    let child = match username {
        Some(user) => {
            #[cfg(target_os = "macos")]
            {
                std::process::Command::new("login")
                    .args(["-fpq", user, &user_shell, "-l"])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
            }
            #[cfg(all(unix, not(target_os = "macos")))]
            {
                std::process::Command::new("su")
                    .args(["-", user, "-s", &user_shell])
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
            }
            #[cfg(not(unix))]
            {
                let _ = user;
                std::process::Command::new(&user_shell)
                    .stdin(std::process::Stdio::piped())
                    .stdout(std::process::Stdio::piped())
                    .stderr(std::process::Stdio::piped())
                    .spawn()
            }
        }
        None => {
            std::process::Command::new(&user_shell)
                .arg("-l")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped())
                .spawn()
        }
    };

    let _ = sandbox; // sandbox enforcement happens at OS level via login/su

    match child {
        Ok(mut child) => {
            // Write script to stdin
            if let Some(mut stdin) = child.stdin.take() {
                let _ = stdin.write_all(full_script.as_bytes());
                // Drop stdin to close it — shell will read EOF and execute
            }
            match child.wait_with_output() {
                Ok(o) => Ok(ExecResult {
                    stdout: String::from_utf8_lossy(&o.stdout).into_owned(),
                    stderr: String::from_utf8_lossy(&o.stderr).into_owned(),
                    exit_code: o.status.code().unwrap_or(-1),
                }),
                Err(e) => Ok(ExecResult {
                    stdout: String::new(),
                    stderr: format!("wait failed: {e}"),
                    exit_code: -1,
                }),
            }
        }
        Err(e) => Ok(ExecResult {
            stdout: String::new(),
            stderr: format!("failed to spawn: {e}"),
            exit_code: -1,
        }),
    }
}

/// Install `hop.http()` binding for making HTTP requests from JS.
///
/// Uses `reqwest::blocking` — safe because JS runs on a plain OS thread, not
/// inside the tokio runtime. Respects `SandboxPolicy.no_network`.
fn install_http_binding(ctx: &Ctx<'_>, sandbox: Option<&SandboxPolicy>) -> Result<()> {
    let globals = ctx.globals();

    if sandbox.is_some_and(|s| s.no_network) {
        ctx.eval::<(), _>(
            r#"
            hop.http = function() { throw new Error("hop.http: network access denied by sandbox policy"); };
        "#,
        )
        .map_err(|e| anyhow::anyhow!("Failed to install hop.http stub: {e}"))?;
        return Ok(());
    }

    // Raw binding: __hop_http(url, method, headersJson, body?) → JSON string
    globals
        .set(
            "__hop_http",
            Function::new(
                ctx.clone(),
                |_ctx: Ctx<'_>,
                 url: String,
                 method: String,
                 headers_json: String,
                 body: rquickjs::function::Opt<String>|
                 -> rquickjs::Result<String> {
                    let client = reqwest::blocking::Client::builder()
                        .timeout(std::time::Duration::from_secs(30))
                        .build()
                        .map_err(|e| js_err(format!("http client error: {e}")))?;

                    let mut req = match method.as_str() {
                        "GET" => client.get(&url),
                        "POST" => client.post(&url),
                        "PUT" => client.put(&url),
                        "DELETE" => client.delete(&url),
                        "PATCH" => client.patch(&url),
                        "HEAD" => client.head(&url),
                        other => return Err(js_err(format!("unsupported HTTP method: {other}"))),
                    };

                    if let Ok(headers) =
                        serde_json::from_str::<std::collections::HashMap<String, String>>(
                            &headers_json,
                        )
                    {
                        for (k, v) in headers {
                            req = req.header(&k, &v);
                        }
                    }

                    if let Some(body) = body.0 {
                        req = req.body(body);
                    }

                    let resp = req
                        .send()
                        .map_err(|e| js_err(format!("http request failed: {e}")))?;

                    let status = resp.status().as_u16();
                    let resp_headers: std::collections::HashMap<String, String> = resp
                        .headers()
                        .iter()
                        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
                        .collect();
                    let body_text = resp
                        .text()
                        .map_err(|e| js_err(format!("http read body failed: {e}")))?;

                    Ok(serde_json::json!({
                        "status": status,
                        "headers": resp_headers,
                        "body": body_text,
                    })
                    .to_string())
                },
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;

    // JS wrapper with convenience methods
    ctx.eval::<(), _>(r#"
        hop.http = function(url, options) {
            options = options || {};
            var method = (options.method || "GET").toUpperCase();
            var headers = options.headers || {};
            if (options.bearer) headers["Authorization"] = "Bearer " + options.bearer;
            var body = null;
            if (options.json !== undefined) {
                if (!headers["Content-Type"] && !headers["content-type"]) {
                    headers["Content-Type"] = "application/json";
                }
                body = JSON.stringify(options.json);
            } else if (options.body !== undefined) {
                body = options.body;
            }
            var r = (body !== null)
                ? JSON.parse(__hop_http(url, method, JSON.stringify(headers), body))
                : JSON.parse(__hop_http(url, method, JSON.stringify(headers)));
            r.json = function() { return JSON.parse(r.body); };
            return r;
        };
        hop.http.get = function(url, opts) { opts = opts || {}; opts.method = "GET"; return hop.http(url, opts); };
        hop.http.post = function(url, opts) { opts = opts || {}; opts.method = "POST"; return hop.http(url, opts); };
        hop.http.put = function(url, opts) { opts = opts || {}; opts.method = "PUT"; return hop.http(url, opts); };
        hop.http.delete = function(url, opts) { opts = opts || {}; opts.method = "DELETE"; return hop.http(url, opts); };
    "#)
    .map_err(|e| anyhow::anyhow!("Failed to install hop.http wrapper: {e}"))?;

    Ok(())
}

/// Install `hop.claude(prompt)` binding for AI inference via Claude CLI.
///
/// Handles credential management (token refresh), binary resolution (with
/// auto-download), and direct subprocess invocation (no shell quoting).
fn install_claude_binding(
    ctx: &Ctx<'_>,
    datastore: Option<&Datastore>,
    sandbox: Option<&SandboxPolicy>,
    run_as_user: Option<&str>,
) -> Result<()> {
    if sandbox.is_some_and(|s| s.no_network) {
        ctx.eval::<(), _>(
            r#"hop.claude = function() { throw new Error("hop.claude: network access denied by sandbox policy"); };"#,
        ).map_err(|e| anyhow::anyhow!("Failed to install hop.claude stub: {e}"))?;
        return Ok(());
    }

    let ds = datastore.cloned();
    let username = run_as_user.map(String::from);
    let globals = ctx.globals();

    globals.set("__hop_claude",
        Function::new(ctx.clone(), move |_ctx: Ctx<'_>, prompt: String, max_turns: rquickjs::function::Opt<u32>| -> rquickjs::Result<String> {
            let max_turns = max_turns.0.unwrap_or(1);

            // Get token from secrets (with refresh if needed)
            let user = username.as_deref().unwrap_or("default");
            let token = match &ds {
                Some(ds) => claude_get_token(ds, user)
                    .map_err(|e| js_err(format!("hop.claude: {e}")))?,
                None => return Err(js_err("hop.claude: no datastore available (requires daemon mode)".into())),
            };

            // Resolve claude binary
            let claude_bin = claude_resolve_binary(username.as_deref())
                .map_err(|e| js_err(format!("hop.claude: {e}")))?;

            // Spawn claude directly — no shell, no quoting. Retries transient failures.
            claude_invoke_with_retry(&claude_bin, &token, &prompt, max_turns, username.as_deref())
                .map_err(|e| {
                    let token_hint = if token.len() >= 8 {
                        format!("{}...{}", &token[..4], &token[token.len()-4..])
                    } else {
                        "****".to_string()
                    };
                    js_err(format!(
                        "hop.claude: {e} [binary={}, token={token_hint}]",
                        claude_bin.display(),
                    ))
                })
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    ).map_err(|e| anyhow::anyhow!("{e}"))?;

    ctx.eval::<(), _>(r#"
        hop.claude = function(prompt, options) {
            options = options || {};
            var maxTurns = options.maxTurns || 1;
            return __hop_claude(prompt, maxTurns);
        };
    "#)
    .map_err(|e| anyhow::anyhow!("Failed to install hop.claude wrapper: {e}"))?;

    Ok(())
}

/// Anthropic OAuth token refresh endpoint and client ID.
const ANTHROPIC_TOKEN_URL: &str = "https://platform.claude.com/v1/oauth/token";
const ANTHROPIC_CLIENT_ID: &str = "https://claude.ai/oauth/claude-code-client-metadata";

/// Get a valid Anthropic token, refreshing if expired.
///
/// Sources (in order):
/// 1. hop secrets store — checks expiry, refreshes via OAuth if expired
/// 2. Local ~/.claude/.credentials.json (fallback if no stored token)
fn claude_get_token(ds: &Datastore, username: &str) -> Result<String> {
    // Try 1: stored token (check expiry)
    if let Ok(Some(token_bytes)) = ds.secrets_get(username, "ANTHROPIC_API_KEY") {
        if let Ok(token) = String::from_utf8(token_bytes) {
            if !token.is_empty() {
                // Check if token is expired
                let expiry = ds
                    .secrets_get(username, "anthropic_token_expiry")
                    .ok()
                    .flatten()
                    .and_then(|b| String::from_utf8(b).ok())
                    .and_then(|s| s.parse::<u64>().ok())
                    .unwrap_or(u64::MAX); // no expiry stored = assume valid

                let now_ms = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_millis() as u64;

                if now_ms < expiry.saturating_sub(300_000) {
                    // Token still valid (with 5-min buffer)
                    return Ok(token);
                }

                // Token expired — try to refresh
                tracing::info!("Anthropic token expired, attempting refresh");
                if let Some(refreshed) = refresh_anthropic_token(ds, username) {
                    return Ok(refreshed);
                }
                // Refresh failed — fall through to local credentials
                tracing::warn!("Anthropic token refresh failed, trying local credentials");
            }
        }
    }

    // Try 2: local credentials file (if Claude Code is installed and logged in)
    if let Some(token) = read_local_claude_token() {
        return Ok(token);
    }

    anyhow::bail!("no Anthropic credentials for {username}. Run: hop auth anthropic");
}

/// Refresh an expired Anthropic OAuth token using the stored refresh token.
///
/// On success, updates ANTHROPIC_API_KEY and anthropic_token_expiry in secrets.
/// Returns the new access token, or None on failure.
fn refresh_anthropic_token(ds: &Datastore, username: &str) -> Option<String> {
    let refresh_token = ds
        .secrets_get(username, "anthropic_refresh_token")
        .ok()
        .flatten()
        .and_then(|b| String::from_utf8(b).ok())?;

    if refresh_token.is_empty() {
        tracing::warn!("No anthropic_refresh_token stored — cannot refresh");
        return None;
    }

    let client = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()
        .ok()?;

    let body = serde_json::json!({
        "grant_type": "refresh_token",
        "refresh_token": refresh_token,
        "client_id": ANTHROPIC_CLIENT_ID,
    });

    let resp = client
        .post(ANTHROPIC_TOKEN_URL)
        .header("Content-Type", "application/json")
        .body(body.to_string())
        .send()
        .ok()?;

    if !resp.status().is_success() {
        let status = resp.status();
        let body = resp.text().unwrap_or_default();
        tracing::warn!("Anthropic token refresh failed ({status}): {body}");
        return None;
    }

    let resp_text = resp.text().ok()?;
    let json: serde_json::Value = serde_json::from_str(&resp_text).ok()?;
    let access_token = json.get("access_token")?.as_str()?.to_string();
    let expires_in = json.get("expires_in").and_then(|v| v.as_u64()).unwrap_or(3600);

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    let new_expiry = now_ms + expires_in * 1000;

    // Update stored secrets
    let _ = ds.secrets_set(username, "ANTHROPIC_API_KEY", access_token.as_bytes());
    let _ = ds.secrets_set(
        username,
        "anthropic_token_expiry",
        new_expiry.to_string().as_bytes(),
    );

    // Update refresh token if a new one was issued
    if let Some(new_refresh) = json.get("refresh_token").and_then(|v| v.as_str()) {
        let _ = ds.secrets_set(username, "anthropic_refresh_token", new_refresh.to_string().as_bytes());
    }

    tracing::info!(
        "Anthropic token refreshed, expires in {}s",
        expires_in
    );

    Some(access_token)
}

/// Read a valid token from the local ~/.claude/.credentials.json file.
/// Claude Code auto-refreshes this file, so it's always the freshest source.
/// Returns None if the file doesn't exist, can't be parsed, or token is expired.
fn read_local_claude_token() -> Option<String> {
    let home = std::env::var("HOME").ok()?;
    let path = std::path::PathBuf::from(&home).join(".claude/.credentials.json");
    let data = std::fs::read_to_string(&path).ok()?;
    let json: serde_json::Value = serde_json::from_str(&data).ok()?;
    let oauth = json.get("claudeAiOauth")?;
    let token = oauth.get("accessToken")?.as_str()?.to_string();
    let expires_at = oauth.get("expiresAt")?.as_u64()?;

    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_millis() as u64;

    // Valid with 5 min buffer
    if now_ms < expires_at.saturating_sub(300_000) {
        Some(token)
    } else {
        None
    }
}

/// Resolve the claude CLI binary path by checking known locations directly.
/// Avoids shell invocation (which can hang in daemon contexts).
fn claude_resolve_binary(username: Option<&str>) -> Result<std::path::PathBuf> {
    let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    #[cfg(target_os = "macos")]
    let user_home = username
        .map(|u| format!("/Users/{u}"))
        .unwrap_or_else(|| home.clone());
    #[cfg(not(target_os = "macos"))]
    let user_home = username
        .map(|u| format!("/home/{u}"))
        .unwrap_or_else(|| home.clone());

    // Check known installation locations
    let search_dirs = [&user_home, &home];
    let known_paths = [
        ".local/bin/claude",
        ".hop/bin/claude",
        ".nvm/versions/node/*/bin/claude", // nvm-installed (glob not supported, check below)
    ];

    for dir in &search_dirs {
        for rel in &known_paths[..2] {
            let candidate = std::path::PathBuf::from(dir).join(rel);
            if candidate.exists() {
                return Ok(candidate);
            }
        }
        // Check nvm directories (glob manually)
        let nvm_dir = std::path::PathBuf::from(dir).join(".nvm/versions/node");
        if nvm_dir.is_dir() && let Ok(entries) = std::fs::read_dir(&nvm_dir) {
            for entry in entries.flatten() {
                let candidate = entry.path().join("bin/claude");
                if candidate.exists() {
                    return Ok(candidate);
                }
            }
        }
    }

    // Also check /usr/local/bin
    let usr_local = std::path::PathBuf::from("/usr/local/bin/claude");
    if usr_local.exists() {
        return Ok(usr_local);
    }

    // 3. Auto-download
    tracing::info!("hop.claude: claude CLI not found, downloading...");
    let hop_bin_dir = std::path::PathBuf::from(&user_home).join(".hop/bin");
    let dest = hop_bin_dir.join("claude");
    if dest.exists() {
        return Ok(dest);
    }

    let _ = std::fs::create_dir_all(&hop_bin_dir);
    let install_result = std::process::Command::new("bash")
        .args([
            "-c",
            &format!(
                "curl -fsSL https://claude.ai/install.sh | INSTALL_DIR={} bash",
                hop_bin_dir.display()
            ),
        ])
        .stdin(std::process::Stdio::null())
        .output();

    match install_result {
        Ok(out) if dest.exists() => Ok(dest),
        Ok(out) => {
            let stderr = String::from_utf8_lossy(&out.stderr);
            anyhow::bail!("claude download failed: {stderr}")
        }
        Err(e) => anyhow::bail!("claude download failed: {e}"),
    }
}

/// Invoke claude CLI directly as a subprocess — no shell, no quoting.
fn claude_invoke(
    claude_bin: &std::path::Path,
    token: &str,
    prompt: &str,
    max_turns: u32,
    username: Option<&str>,
) -> Result<String> {
    let mut cmd = std::process::Command::new(claude_bin);
    cmd.args([
        "-p", "-",
        "--output-format", "text",
        "--max-turns", &max_turns.to_string(),
        "--no-session-persistence",
        "--disable-slash-commands",
        "--tools", "",
    ])
    .env("CLAUDE_CODE_OAUTH_TOKEN", token)
    .stdin(std::process::Stdio::piped())
    .stdout(std::process::Stdio::piped())
    .stderr(std::process::Stdio::piped());

    // Drop privileges if running as root with a target user
    #[cfg(unix)]
    if let Some(user) = username
        && hop_core::unix_user::is_running_as_root()
        && let Ok((uid, gid)) = hop_core::transfer::helper::lookup_uid_gid(user)
    {
        use std::os::unix::process::CommandExt;
        cmd.uid(uid);
        cmd.gid(gid);
        // Set HOME for claude to find its config
        #[cfg(target_os = "macos")]
        cmd.env("HOME", format!("/Users/{user}"));
        #[cfg(not(target_os = "macos"))]
        cmd.env("HOME", format!("/home/{user}"));
    }

    let mut child = cmd.spawn()
        .map_err(|e| anyhow::anyhow!("failed to spawn claude: {e}"))?;

    // Write prompt to stdin
    if let Some(mut stdin) = child.stdin.take() {
        use std::io::Write;
        let _ = stdin.write_all(prompt.as_bytes());
        // stdin is dropped here, closing the pipe so claude knows input is done
    }

    // Wait with timeout (240s per call). Read stdout/stderr in threads
    // so we can enforce a deadline without blocking forever.
    let timeout = std::time::Duration::from_secs(240);
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();

    let stdout_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = stdout {
            use std::io::Read;
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });
    let stderr_thread = std::thread::spawn(move || {
        let mut buf = Vec::new();
        if let Some(mut r) = stderr {
            use std::io::Read;
            let _ = r.read_to_end(&mut buf);
        }
        buf
    });

    // Wait for the process with a deadline
    let start = std::time::Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => break,
            Ok(None) => {
                if start.elapsed() > timeout {
                    let _ = child.kill();
                    anyhow::bail!("claude timed out after {}s", timeout.as_secs());
                }
                std::thread::sleep(std::time::Duration::from_millis(100));
            }
            Err(e) => anyhow::bail!("claude wait error: {e}"),
        }
    }

    let status = child.wait()?;
    let stdout_bytes = stdout_thread.join().unwrap_or_default();
    let stderr_bytes = stderr_thread.join().unwrap_or_default();

    let output = std::process::Output {
        status,
        stdout: stdout_bytes,
        stderr: stderr_bytes,
    };

    if output.status.success() {
        let text = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if text.is_empty() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("claude returned empty response. stderr: {stderr}");
        }
        Ok(text)
    } else {
        let stderr = String::from_utf8_lossy(&output.stderr).trim().to_string();
        let stdout = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let detail = match (stderr.is_empty(), stdout.is_empty()) {
            (false, false) => {
                let stdout_trunc = if stdout.len() > 500 {
                    format!("{}...", &stdout[..500])
                } else {
                    stdout
                };
                format!("stderr: {stderr}; stdout: {stdout_trunc}")
            }
            (false, true) => format!("stderr: {stderr}"),
            (true, false) => {
                let stdout_trunc = if stdout.len() > 500 {
                    format!("{}...", &stdout[..500])
                } else {
                    stdout
                };
                format!("stdout: {stdout_trunc}")
            }
            (true, true) => "(no output on stdout or stderr)".to_string(),
        };
        anyhow::bail!("claude failed (exit {}): {}", output.status, detail)
    }
}

/// Retry transient claude CLI failures with short backoff.
///
/// Retries up to 2 times (3 attempts total) with 3s/8s delays for transient
/// failures (non-zero exit with generic output). Does NOT retry permanent
/// failures: missing binary, timeouts, or missing credentials.
fn claude_invoke_with_retry(
    claude_bin: &std::path::Path,
    token: &str,
    prompt: &str,
    max_turns: u32,
    username: Option<&str>,
) -> Result<String> {
    const BACKOFFS: [u64; 2] = [3, 8];

    let mut last_err = None;
    for attempt in 0..3u32 {
        if attempt > 0 {
            tracing::warn!(
                "hop.claude: retry {attempt}/2 after {}s backoff",
                BACKOFFS[(attempt - 1) as usize]
            );
            std::thread::sleep(std::time::Duration::from_secs(
                BACKOFFS[(attempt - 1) as usize],
            ));
        }
        match claude_invoke(claude_bin, token, prompt, max_turns, username) {
            Ok(result) => return Ok(result),
            Err(e) => {
                let msg = format!("{e}");
                // Don't retry permanent failures
                if msg.contains("failed to spawn")
                    || msg.contains("timed out")
                    || msg.contains("no Anthropic credentials")
                {
                    return Err(e);
                }
                tracing::warn!("hop.claude attempt {}: {msg}", attempt + 1);
                last_err = Some(e);
            }
        }
    }
    Err(last_err.unwrap())
}

/// Install stub bindings (no backend available, e.g. cron jobs).
fn install_stub_bindings<'js>(ctx: &Ctx<'js>, hop: &Object<'js>) -> Result<()> {
    // hop.id()
    hop.set(
        "id",
        Function::new(ctx.clone(), || -> rquickjs::Result<String> {
            Ok("(node-id-placeholder)".to_string())
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // hop.exec stub
    hop.set(
        "exec",
        Function::new(ctx.clone(), |_ctx: Ctx<'_>| -> rquickjs::Result<Value<'_>> {
            Err(rquickjs::Error::new_from_js("function", "hop.exec requires a connected backend"))
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // hop.fleet stub namespace
    let fleet = Object::new(ctx.clone()).map_err(|e| anyhow::anyhow!("{e}"))?;
    for method in &["list", "exec"] {
        fleet
            .set(
                *method,
                Function::new(ctx.clone(), |_ctx: Ctx<'_>| -> rquickjs::Result<Value<'_>> {
                    Err(rquickjs::Error::new_from_js("function", "hop.fleet.* requires a connected backend"))
                })
                .map_err(|e| anyhow::anyhow!("{e}"))?,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    hop.set("fleet", fleet).map_err(|e| anyhow::anyhow!("{e}"))?;

    // hop.admin stub namespace
    let admin = Object::new(ctx.clone()).map_err(|e| anyhow::anyhow!("{e}"))?;
    for method in &["status", "peers", "invite", "createUser", "removePeer"] {
        admin
            .set(
                *method,
                Function::new(ctx.clone(), |_ctx: Ctx<'_>| -> rquickjs::Result<Value<'_>> {
                    Err(rquickjs::Error::new_from_js("function", "hop.admin.* requires a connected backend"))
                })
                .map_err(|e| anyhow::anyhow!("{e}"))?,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    hop.set("admin", admin).map_err(|e| anyhow::anyhow!("{e}"))?;

    // hop.roles stub namespace
    let roles = Object::new(ctx.clone()).map_err(|e| anyhow::anyhow!("{e}"))?;
    for method in &["list", "create", "update", "delete"] {
        roles
            .set(
                *method,
                Function::new(ctx.clone(), |_ctx: Ctx<'_>| -> rquickjs::Result<Value<'_>> {
                    Err(rquickjs::Error::new_from_js("function", "hop.roles.* requires a connected backend"))
                })
                .map_err(|e| anyhow::anyhow!("{e}"))?,
            )
            .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    hop.set("roles", roles).map_err(|e| anyhow::anyhow!("{e}"))?;

    // hop.fs stub namespace
    let fs = Object::new(ctx.clone()).map_err(|e| anyhow::anyhow!("{e}"))?;
    for method in &["push", "pull"] {
        fs.set(
            *method,
            Function::new(ctx.clone(), |_ctx: Ctx<'_>| -> rquickjs::Result<Value<'_>> {
                Err(rquickjs::Error::new_from_js("function", "hop.fs.* requires a connected backend"))
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    }
    hop.set("fs", fs).map_err(|e| anyhow::anyhow!("{e}"))?;

    Ok(())
}

/// Install raw __hop_kv_* and __hop_ts_* functions that return JSON strings.
fn install_datastore_raw(ctx: &Ctx<'_>, ds: &Datastore, run_as_user: Option<&str>) -> Result<()> {
    let secrets_user = run_as_user.unwrap_or("default").to_string();
    let globals = ctx.globals();

    // __hop_kv_get(ns, key) → JSON string or "null"
    {
        let ds = ds.clone();
        globals.set("__hop_kv_get",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, ns: String, key: String| -> rquickjs::Result<String> {
                match ds.kv_get(&ns, &key) {
                    Ok(Some(entry)) => {
                        let value_str = String::from_utf8_lossy(&entry.value);
                        Ok(format!(
                            r#"{{"value":{},"contentType":{},"updatedAt":{}}}"#,
                            value_str,
                            serde_json::to_string(&entry.content_type).unwrap_or_default(),
                            entry.updated_at
                        ))
                    }
                    Ok(None) => Ok("null".to_string()),
                    Err(e) => Err(js_err(format!("hop.kv.get failed: {e}"))),
                }
            }).map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_kv_set(ns, key, valueJson, contentType) → void
    {
        let ds = ds.clone();
        globals.set("__hop_kv_set",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, ns: String, key: String, value_json: String, content_type: rquickjs::function::Opt<String>| -> rquickjs::Result<()> {
                let ct = content_type.0.unwrap_or_else(|| "application/json".to_string());
                let now = now_ms();
                let entry = KvEntry {
                    value: value_json.into_bytes(),
                    content_type: ct,
                    updated_at: now,
                };
                ds.kv_set(&ns, &key, &entry).map_err(|e| js_err(format!("hop.kv.set failed: {e}")))
            }).map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_kv_delete(ns, key) → boolean
    {
        let ds = ds.clone();
        globals.set("__hop_kv_delete",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, ns: String, key: String| -> rquickjs::Result<bool> {
                ds.kv_delete(&ns, &key).map_err(|e| js_err(format!("hop.kv.delete failed: {e}")))
            }).map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_kv_list(ns, prefix) → JSON string
    {
        let ds = ds.clone();
        globals.set("__hop_kv_list",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, ns: String, prefix: rquickjs::function::Opt<String>| -> rquickjs::Result<String> {
                let prefix = prefix.0.unwrap_or_default();
                match ds.kv_list(&ns, &prefix) {
                    Ok(entries) => {
                        let items: Vec<serde_json::Value> = entries
                            .into_iter()
                            .map(|(key, entry)| {
                                let value_str = String::from_utf8_lossy(&entry.value);
                                let parsed: serde_json::Value = serde_json::from_str(&value_str)
                                    .unwrap_or(serde_json::Value::String(value_str.into_owned()));
                                serde_json::json!({
                                    "key": key,
                                    "value": parsed,
                                    "contentType": entry.content_type,
                                    "updatedAt": entry.updated_at,
                                })
                            })
                            .collect();
                        Ok(serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string()))
                    }
                    Err(e) => Err(js_err(format!("hop.kv.list failed: {e}"))),
                }
            }).map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_ts_insert(metric, value, tagsJson) → void
    {
        let ds = ds.clone();
        globals.set("__hop_ts_insert",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, metric: String, value: f64, tags_json: rquickjs::function::Opt<String>| -> rquickjs::Result<()> {
                let tags: BTreeMap<String, String> = match tags_json.0 {
                    Some(ref s) if !s.is_empty() => serde_json::from_str(s).unwrap_or_default(),
                    _ => BTreeMap::new(),
                };
                let point = MetricPoint { value, tags };
                ds.ts_insert(&metric, &point).map_err(|e| js_err(format!("hop.ts.insert failed: {e}")))
            }).map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_ts_query(metric, start, end, optionsJson) → JSON string
    {
        let ds = ds.clone();
        globals.set("__hop_ts_query",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, metric: String, start: f64, end: f64, options_json: rquickjs::function::Opt<String>| -> rquickjs::Result<String> {
                let mut limit = None;
                let mut tags_filter = None;
                if let Some(ref opts) = options_json.0
                    && let Ok(v) = serde_json::from_str::<serde_json::Value>(opts)
                {
                    if let Some(l) = v.get("limit").and_then(|l| l.as_u64()) {
                        limit = Some(l as usize);
                    }
                    if let Some(t) = v.get("tags").and_then(|t| t.as_object()) {
                        let mut m = BTreeMap::new();
                        for (k, v) in t {
                            if let Some(s) = v.as_str() {
                                m.insert(k.clone(), s.to_string());
                            }
                        }
                        if !m.is_empty() {
                            tags_filter = Some(m);
                        }
                    }
                }
                let query = TimeSeriesQuery {
                    metric,
                    start: start as u64,
                    end: end as u64,
                    tags_filter,
                    limit,
                };
                match ds.ts_query(&query) {
                    Ok(points) => {
                        let items: Vec<serde_json::Value> = points
                            .into_iter()
                            .map(|(ts, p)| serde_json::json!({"timestamp": ts, "value": p.value, "tags": p.tags}))
                            .collect();
                        Ok(serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string()))
                    }
                    Err(e) => Err(js_err(format!("hop.ts.query failed: {e}"))),
                }
            }).map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_ts_latest(metric) → JSON string or "null"
    {
        let ds = ds.clone();
        globals.set("__hop_ts_latest",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, metric: String| -> rquickjs::Result<String> {
                match ds.ts_latest(&metric) {
                    Ok(Some((ts, p))) => {
                        Ok(serde_json::json!({"timestamp": ts, "value": p.value, "tags": p.tags}).to_string())
                    }
                    Ok(None) => Ok("null".to_string()),
                    Err(e) => Err(js_err(format!("hop.ts.latest failed: {e}"))),
                }
            }).map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_cron_list() → JSON string
    {
        let ds = ds.clone();
        globals.set("__hop_cron_list",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>| -> rquickjs::Result<String> {
                match ds.cron_list() {
                    Ok(jobs) => {
                        let items: Vec<serde_json::Value> = jobs
                            .iter()
                            .map(|j| serde_json::json!({"id": j.id, "name": j.name, "schedule": j.schedule, "enabled": j.enabled}))
                            .collect();
                        Ok(serde_json::to_string(&items).unwrap_or_else(|_| "[]".to_string()))
                    }
                    Err(e) => Err(js_err(format!("hop.cron.list failed: {e}"))),
                }
            }).map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_secrets_get(name) → value string or "null"
    {
        let ds = ds.clone();
        let user = secrets_user.clone();
        globals.set("__hop_secrets_get",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, name: String| -> rquickjs::Result<String> {
                match ds.secrets_get(&user, &name) {
                    Ok(Some(value)) => Ok(String::from_utf8_lossy(&value).to_string()),
                    Ok(None) => Ok("null".to_string()),
                    Err(e) => Err(js_err(format!("hop.secrets.get failed: {e}"))),
                }
            }).map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_secrets_set(name, value) → void
    {
        let ds = ds.clone();
        let user = secrets_user.clone();
        globals.set("__hop_secrets_set",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, name: String, value: String| -> rquickjs::Result<()> {
                ds.secrets_set(&user, &name, value.as_bytes())
                    .map_err(|e| js_err(format!("hop.secrets.set failed: {e}")))
            }).map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_secrets_delete(name) → boolean
    {
        let ds = ds.clone();
        let user = secrets_user.clone();
        globals.set("__hop_secrets_delete",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, name: String| -> rquickjs::Result<bool> {
                ds.secrets_delete(&user, &name)
                    .map_err(|e| js_err(format!("hop.secrets.delete failed: {e}")))
            }).map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_secrets_list() → JSON array of names
    {
        let ds = ds.clone();
        let user = secrets_user.clone();
        globals.set("__hop_secrets_list",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>| -> rquickjs::Result<String> {
                match ds.secrets_list(&user) {
                    Ok(names) => Ok(serde_json::to_string(&names).unwrap_or_else(|_| "[]".to_string())),
                    Err(e) => Err(js_err(format!("hop.secrets.list failed: {e}"))),
                }
            }).map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    Ok(())
}

/// Install JS wrappers that parse JSON from the raw functions.
fn install_datastore_js_wrappers(ctx: &Ctx<'_>) -> Result<()> {
    let js_code = r#"
        hop.kv = {
            get: function(ns, key) {
                var r = __hop_kv_get(ns, key);
                if (r === "null") return null;
                var entry = JSON.parse(r);
                return entry.value;
            },
            set: function(ns, key, value, contentType) {
                if (contentType !== undefined) {
                    __hop_kv_set(ns, key, JSON.stringify(value), contentType);
                } else {
                    __hop_kv_set(ns, key, JSON.stringify(value));
                }
            },
            delete: function(ns, key) {
                return __hop_kv_delete(ns, key);
            },
            list: function(ns, prefix) {
                if (prefix !== undefined) {
                    return JSON.parse(__hop_kv_list(ns, prefix));
                }
                return JSON.parse(__hop_kv_list(ns));
            }
        };
        hop.ts = {
            insert: function(metric, value, tags) {
                if (tags !== undefined) {
                    __hop_ts_insert(metric, value, JSON.stringify(tags));
                } else {
                    __hop_ts_insert(metric, value);
                }
            },
            query: function(metric, start, end, options) {
                if (options !== undefined) {
                    return JSON.parse(__hop_ts_query(metric, start, end, JSON.stringify(options)));
                }
                return JSON.parse(__hop_ts_query(metric, start, end));
            },
            latest: function(metric) {
                var r = __hop_ts_latest(metric);
                return r === "null" ? null : JSON.parse(r);
            }
        };
        hop.cron = {
            list: function() {
                return JSON.parse(__hop_cron_list());
            }
        };
        hop.secrets = {
            get: function(name) {
                var r = __hop_secrets_get(name);
                return r === "null" ? null : r;
            },
            set: function(name, value) {
                __hop_secrets_set(name, String(value));
            },
            delete: function(name) {
                return __hop_secrets_delete(name);
            },
            list: function() {
                return JSON.parse(__hop_secrets_list());
            }
        };
    "#;

    ctx.eval::<(), _>(js_code)
        .map_err(|e| anyhow::anyhow!("Failed to install datastore JS wrappers: {e}"))?;

    Ok(())
}

/// Install stubs when no datastore is available.
fn install_datastore_stubs(ctx: &Ctx<'_>) -> Result<()> {
    let js_code = r#"
        hop.kv = {
            get: function() { throw new Error("hop.kv.* requires a datastore (run in host mode)"); },
            set: function() { throw new Error("hop.kv.* requires a datastore (run in host mode)"); },
            delete: function() { throw new Error("hop.kv.* requires a datastore (run in host mode)"); },
            list: function() { throw new Error("hop.kv.* requires a datastore (run in host mode)"); }
        };
        hop.ts = {
            insert: function() { throw new Error("hop.ts.* requires a datastore (run in host mode)"); },
            query: function() { throw new Error("hop.ts.* requires a datastore (run in host mode)"); },
            latest: function() { throw new Error("hop.ts.* requires a datastore (run in host mode)"); }
        };
        hop.cron = {
            list: function() { throw new Error("hop.cron.* requires a datastore (run in host mode)"); }
        };
        hop.secrets = {
            get: function() { throw new Error("hop.secrets.* requires a datastore (run in host mode)"); },
            set: function() { throw new Error("hop.secrets.* requires a datastore (run in host mode)"); },
            delete: function() { throw new Error("hop.secrets.* requires a datastore (run in host mode)"); },
            list: function() { throw new Error("hop.secrets.* requires a datastore (run in host mode)"); }
        };
    "#;

    ctx.eval::<(), _>(js_code)
        .map_err(|e| anyhow::anyhow!("Failed to install datastore stubs: {e}"))?;

    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// Remove globals that could escape the sandbox.
fn remove_dangerous_globals(ctx: &Ctx<'_>) -> Result<()> {
    let globals = ctx.globals();
    let dangerous = ["require", "process", "Deno", "Bun"];
    for name in dangerous {
        let _ = globals.remove::<String>(name.to_string());
    }
    Ok(())
}
