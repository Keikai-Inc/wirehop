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
        install_datastore_raw(ctx, ds)?;
        install_datastore_js_wrappers(ctx)?;
    } else {
        install_datastore_stubs(ctx)?;
    }

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

    // JS wrapper
    ctx.eval::<(), _>(r#"
        hop.local = function(command) {
            return JSON.parse(__hop_local(command));
        };
    "#)
    .map_err(|e| anyhow::anyhow!("Failed to install hop.local wrapper: {e}"))?;

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
fn install_datastore_raw(ctx: &Ctx<'_>, ds: &Datastore) -> Result<()> {
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
        globals.set("__hop_secrets_get",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, name: String| -> rquickjs::Result<String> {
                match ds.secrets_get(&name) {
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
        globals.set("__hop_secrets_set",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, name: String, value: String| -> rquickjs::Result<()> {
                ds.secrets_set(&name, value.as_bytes())
                    .map_err(|e| js_err(format!("hop.secrets.set failed: {e}")))
            }).map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_secrets_delete(name) → boolean
    {
        let ds = ds.clone();
        globals.set("__hop_secrets_delete",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>, name: String| -> rquickjs::Result<bool> {
                ds.secrets_delete(&name)
                    .map_err(|e| js_err(format!("hop.secrets.delete failed: {e}")))
            }).map_err(|e| anyhow::anyhow!("{e}"))?,
        ).map_err(|e| anyhow::anyhow!("{e}"))?;
    }

    // __hop_secrets_list() → JSON array of names
    {
        let ds = ds.clone();
        globals.set("__hop_secrets_list",
            Function::new(ctx.clone(), move |_ctx: Ctx<'_>| -> rquickjs::Result<String> {
                match ds.secrets_list() {
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
