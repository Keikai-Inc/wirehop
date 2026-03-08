//! hop_data tool: KV and time-series datastore operations.

use std::collections::BTreeMap;

use serde::Deserialize;
use serde_json::{json, Value};

use hop_core::datastore::types::{KvEntry, MetricPoint, TimeSeriesQuery};
use hop_core::datastore::Datastore;

use crate::protocol::{ToolCallResult, ToolDefinition};

#[derive(Debug, Deserialize)]
struct DataArgs {
    action: String,
    namespace: Option<String>,
    key: Option<String>,
    value: Option<Value>,
    content_type: Option<String>,
    prefix: Option<String>,
    metric: Option<String>,
    start: Option<u64>,
    end: Option<u64>,
    tags: Option<BTreeMap<String, String>>,
    limit: Option<usize>,
}

pub fn tool_definition() -> ToolDefinition {
    ToolDefinition {
        name: "hop_data".into(),
        description: "Store and query data in hop's embedded datastore. Supports key-value storage (namespaced) and time-series metrics. Data persists across restarts.".into(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["kv_get", "kv_set", "kv_delete", "kv_list", "ts_insert", "ts_query", "ts_latest"],
                    "description": "The datastore operation to perform"
                },
                "namespace": {
                    "type": "string",
                    "description": "KV namespace (required for kv_* actions)"
                },
                "key": {
                    "type": "string",
                    "description": "KV key (required for kv_get, kv_set, kv_delete)"
                },
                "value": {
                    "description": "Value to store. For kv_set: any JSON value. For ts_insert: a number."
                },
                "content_type": {
                    "type": "string",
                    "description": "MIME type for kv_set (default: application/json)"
                },
                "prefix": {
                    "type": "string",
                    "description": "Key prefix filter for kv_list"
                },
                "metric": {
                    "type": "string",
                    "description": "Metric name (required for ts_* actions)"
                },
                "start": {
                    "type": "integer",
                    "description": "Start timestamp in unix ms (for ts_query)"
                },
                "end": {
                    "type": "integer",
                    "description": "End timestamp in unix ms (for ts_query)"
                },
                "tags": {
                    "type": "object",
                    "description": "Tags for ts_insert or tag filter for ts_query",
                    "additionalProperties": { "type": "string" }
                },
                "limit": {
                    "type": "integer",
                    "description": "Max results for ts_query"
                }
            },
            "required": ["action"]
        }),
    }
}

pub fn call(datastore: &Datastore, args: Value) -> ToolCallResult {
    let args: DataArgs = match serde_json::from_value(args) {
        Ok(a) => a,
        Err(e) => return ToolCallResult::error(format!("Invalid arguments: {e}")),
    };

    match args.action.as_str() {
        "kv_get" => kv_get(datastore, &args),
        "kv_set" => kv_set(datastore, &args),
        "kv_delete" => kv_delete(datastore, &args),
        "kv_list" => kv_list(datastore, &args),
        "ts_insert" => ts_insert(datastore, &args),
        "ts_query" => ts_query(datastore, &args),
        "ts_latest" => ts_latest(datastore, &args),
        other => ToolCallResult::error(format!("Unknown action: {other}")),
    }
}

fn kv_get(ds: &Datastore, args: &DataArgs) -> ToolCallResult {
    let ns = match args.namespace.as_deref() {
        Some(ns) => ns,
        None => return ToolCallResult::error("namespace is required for kv_get"),
    };
    let key = match args.key.as_deref() {
        Some(k) => k,
        None => return ToolCallResult::error("key is required for kv_get"),
    };

    match ds.kv_get(ns, key) {
        Ok(Some(entry)) => {
            let value_str = String::from_utf8_lossy(&entry.value);
            ToolCallResult::text(json!({
                "value": try_parse_json(&value_str),
                "contentType": entry.content_type,
                "updatedAt": entry.updated_at,
            }).to_string())
        }
        Ok(None) => ToolCallResult::text("null"),
        Err(e) => ToolCallResult::error(format!("kv_get failed: {e}")),
    }
}

fn kv_set(ds: &Datastore, args: &DataArgs) -> ToolCallResult {
    let ns = match args.namespace.as_deref() {
        Some(ns) => ns,
        None => return ToolCallResult::error("namespace is required for kv_set"),
    };
    let key = match args.key.as_deref() {
        Some(k) => k,
        None => return ToolCallResult::error("key is required for kv_set"),
    };
    let value = match &args.value {
        Some(v) => v,
        None => return ToolCallResult::error("value is required for kv_set"),
    };

    let content_type = args
        .content_type
        .clone()
        .unwrap_or_else(|| "application/json".to_string());
    let value_bytes = serde_json::to_vec(value).unwrap_or_default();
    let now = now_ms();

    let entry = KvEntry {
        value: value_bytes,
        content_type,
        updated_at: now,
    };

    match ds.kv_set(ns, key, &entry) {
        Ok(()) => ToolCallResult::text(json!({"ok": true}).to_string()),
        Err(e) => ToolCallResult::error(format!("kv_set failed: {e}")),
    }
}

fn kv_delete(ds: &Datastore, args: &DataArgs) -> ToolCallResult {
    let ns = match args.namespace.as_deref() {
        Some(ns) => ns,
        None => return ToolCallResult::error("namespace is required for kv_delete"),
    };
    let key = match args.key.as_deref() {
        Some(k) => k,
        None => return ToolCallResult::error("key is required for kv_delete"),
    };

    match ds.kv_delete(ns, key) {
        Ok(deleted) => ToolCallResult::text(json!({"deleted": deleted}).to_string()),
        Err(e) => ToolCallResult::error(format!("kv_delete failed: {e}")),
    }
}

fn kv_list(ds: &Datastore, args: &DataArgs) -> ToolCallResult {
    let ns = match args.namespace.as_deref() {
        Some(ns) => ns,
        None => return ToolCallResult::error("namespace is required for kv_list"),
    };
    let prefix = args.prefix.as_deref().unwrap_or("");

    match ds.kv_list(ns, prefix) {
        Ok(entries) => {
            let items: Vec<Value> = entries
                .into_iter()
                .map(|(key, entry)| {
                    let value_str = String::from_utf8_lossy(&entry.value);
                    json!({
                        "key": key,
                        "value": try_parse_json(&value_str),
                        "contentType": entry.content_type,
                        "updatedAt": entry.updated_at,
                    })
                })
                .collect();
            ToolCallResult::text(serde_json::to_string_pretty(&items).unwrap_or_default())
        }
        Err(e) => ToolCallResult::error(format!("kv_list failed: {e}")),
    }
}

fn ts_insert(ds: &Datastore, args: &DataArgs) -> ToolCallResult {
    let metric = match args.metric.as_deref() {
        Some(m) => m,
        None => return ToolCallResult::error("metric is required for ts_insert"),
    };
    let value = match &args.value {
        Some(Value::Number(n)) => n.as_f64().unwrap_or(0.0),
        Some(v) => return ToolCallResult::error(format!("value must be a number for ts_insert, got: {v}")),
        None => return ToolCallResult::error("value is required for ts_insert"),
    };

    let point = MetricPoint {
        value,
        tags: args.tags.clone().unwrap_or_default(),
    };

    match ds.ts_insert(metric, &point) {
        Ok(()) => ToolCallResult::text(json!({"ok": true}).to_string()),
        Err(e) => ToolCallResult::error(format!("ts_insert failed: {e}")),
    }
}

fn ts_query(ds: &Datastore, args: &DataArgs) -> ToolCallResult {
    let metric = match args.metric.as_deref() {
        Some(m) => m,
        None => return ToolCallResult::error("metric is required for ts_query"),
    };
    let start = args.start.unwrap_or(0);
    let end = args.end.unwrap_or(u64::MAX);

    let query = TimeSeriesQuery {
        metric: metric.to_string(),
        start,
        end,
        tags_filter: args.tags.clone(),
        limit: args.limit,
    };

    match ds.ts_query(&query) {
        Ok(points) => {
            let items: Vec<Value> = points
                .into_iter()
                .map(|(ts, p)| {
                    json!({
                        "timestamp": ts,
                        "value": p.value,
                        "tags": p.tags,
                    })
                })
                .collect();
            ToolCallResult::text(serde_json::to_string_pretty(&items).unwrap_or_default())
        }
        Err(e) => ToolCallResult::error(format!("ts_query failed: {e}")),
    }
}

fn ts_latest(ds: &Datastore, args: &DataArgs) -> ToolCallResult {
    let metric = match args.metric.as_deref() {
        Some(m) => m,
        None => return ToolCallResult::error("metric is required for ts_latest"),
    };

    match ds.ts_latest(metric) {
        Ok(Some((ts, point))) => ToolCallResult::text(
            json!({
                "timestamp": ts,
                "value": point.value,
                "tags": point.tags,
            })
            .to_string(),
        ),
        Ok(None) => ToolCallResult::text("null"),
        Err(e) => ToolCallResult::error(format!("ts_latest failed: {e}")),
    }
}

fn try_parse_json(s: &str) -> Value {
    serde_json::from_str(s).unwrap_or_else(|_| Value::String(s.to_string()))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
