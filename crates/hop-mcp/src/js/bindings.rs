//! Rust functions exposed as hop.* JS globals.
//!
//! These bindings bridge JS calls to the OrchestratorBackend trait.
//! The JS runtime runs on a dedicated OS thread; async backend calls
//! will be bridged via a channel back to the tokio runtime (Phase 2+).

use anyhow::Result;
use rquickjs::{Ctx, Function, Object, Value};

/// Install the `hop` global object with all bindings.
pub fn install_hop_bindings(ctx: &Ctx<'_>) -> Result<()> {
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

    // hop.sleep(ms) — returns a resolved value (blocking sleep in spawn_blocking)
    hop.set(
        "sleep",
        Function::new(ctx.clone(), |_ctx: Ctx<'_>, ms: f64| -> rquickjs::Result<()> {
            std::thread::sleep(std::time::Duration::from_millis(ms as u64));
            Ok(())
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // hop.id() — returns the local NodeId as a string
    hop.set(
        "id",
        Function::new(ctx.clone(), || -> rquickjs::Result<String> {
            Ok("(node-id-placeholder)".to_string())
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // NOTE: hop.exec(), hop.fleet.*, hop.admin.*, hop.roles.*, hop.fs.*
    // These are async operations that need the backend. They're injected
    // separately when the runtime has a backend reference. For now, we
    // install stubs that explain how to use the API.

    // Install hop.exec stub
    hop.set(
        "exec",
        Function::new(ctx.clone(), |_ctx: Ctx<'_>| -> rquickjs::Result<Value<'_>> {
            Err(rquickjs::Error::new_from_js("function", "hop.exec requires a connected backend"))
        })
        .map_err(|e| anyhow::anyhow!("{e}"))?,
    )
    .map_err(|e| anyhow::anyhow!("{e}"))?;

    // Install hop.fleet stub namespace
    let fleet = Object::new(ctx.clone()).map_err(|e| anyhow::anyhow!("{e}"))?;
    fleet
        .set(
            "list",
            Function::new(ctx.clone(), |_ctx: Ctx<'_>| -> rquickjs::Result<Value<'_>> {
                Err(rquickjs::Error::new_from_js("function", "hop.fleet.list requires a connected backend"))
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    fleet
        .set(
            "exec",
            Function::new(ctx.clone(), |_ctx: Ctx<'_>| -> rquickjs::Result<Value<'_>> {
                Err(rquickjs::Error::new_from_js("function", "hop.fleet.exec requires a connected backend"))
            })
            .map_err(|e| anyhow::anyhow!("{e}"))?,
        )
        .map_err(|e| anyhow::anyhow!("{e}"))?;
    hop.set("fleet", fleet).map_err(|e| anyhow::anyhow!("{e}"))?;

    // Install hop.admin stub namespace
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

    // Install hop.roles stub namespace
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

    // Install hop.fs stub namespace
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

    globals
        .set("hop", hop)
        .map_err(|e| anyhow::anyhow!("Failed to set hop global: {e}"))?;

    // Remove dangerous globals
    remove_dangerous_globals(ctx)?;

    Ok(())
}

/// Remove globals that could escape the sandbox.
fn remove_dangerous_globals(ctx: &Ctx<'_>) -> Result<()> {
    let globals = ctx.globals();

    // These should not exist in QuickJS by default, but be defensive
    let dangerous = ["require", "process", "Deno", "Bun"];
    for name in dangerous {
        let _ = globals.remove::<String>(name.to_string());
    }

    Ok(())
}
