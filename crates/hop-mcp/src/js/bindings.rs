//! Rust functions exposed as hop.* JS globals.
//!
//! These bindings bridge JS calls to the OrchestratorBackend trait.
//! The JS runtime runs on a dedicated OS thread; async backend calls
//! will be bridged via a channel back to the tokio runtime (Phase 2+).

use anyhow::Result;
use hop_core::datastore::types::{KvEntry, MetricPoint, TimeSeriesQuery};
use hop_core::datastore::Datastore;
use rquickjs::{Ctx, Function, Object, Value};
use std::collections::BTreeMap;

/// Create a rquickjs error with an owned message.
fn js_err(msg: String) -> rquickjs::Error {
    rquickjs::Error::new_from_js_message("function", "value", msg)
}

/// Install the `hop` global object with all bindings.
pub fn install_hop_bindings(ctx: &Ctx<'_>, datastore: Option<&Datastore>) -> Result<()> {
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

    globals
        .set("hop", hop)
        .map_err(|e| anyhow::anyhow!("Failed to set hop global: {e}"))?;

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

    Ok(())
}

/// Install JS wrappers that parse JSON from the raw functions.
fn install_datastore_js_wrappers(ctx: &Ctx<'_>) -> Result<()> {
    let js_code = r#"
        hop.kv = {
            get: function(ns, key) {
                var r = __hop_kv_get(ns, key);
                return r === "null" ? null : JSON.parse(r);
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
