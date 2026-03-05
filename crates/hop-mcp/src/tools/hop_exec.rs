//! hop_exec tool: sandboxed JavaScript execution with hop.* bindings.

use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Value};

use crate::backend::BoxedBackend;
use crate::js::JsRuntime;
use crate::protocol::{ToolCallResult, ToolDefinition};

#[derive(Debug, Deserialize)]
struct ExecArgs {
    code: String,
    timeout_secs: Option<u64>,
}

pub fn tool_definition() -> ToolDefinition {
    ToolDefinition {
        name: "hop_exec".into(),
        description: "Execute JavaScript code in a sandboxed runtime with hop fleet management bindings. The 'hop' global object provides exec(), fleet, admin, roles, and file transfer APIs. Call hop_skills first to learn the API.".into(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "code": {
                    "type": "string",
                    "description": "JavaScript code to execute. Use the global 'hop' object for fleet operations. Top-level await is supported."
                },
                "timeout_secs": {
                    "type": "integer",
                    "description": "Execution timeout in seconds (default: 30, max: 300)"
                }
            },
            "required": ["code"]
        }),
    }
}

pub async fn call(runtime: &JsRuntime, backend: &BoxedBackend, args: Value) -> ToolCallResult {
    let args: ExecArgs = match serde_json::from_value(args) {
        Ok(a) => a,
        Err(e) => return ToolCallResult::error(format!("Invalid arguments: {e}")),
    };

    // Enforce timeout limits
    let timeout_secs = args.timeout_secs.unwrap_or(30).min(300);
    let timeout = Duration::from_secs(timeout_secs);

    let start = Instant::now();

    match runtime.execute(&args.code, backend, Some(timeout)).await {
        Ok(result) => {
            let elapsed = start.elapsed();
            tracing::debug!("hop_exec completed in {:?}", elapsed);
            ToolCallResult::text(result)
        }
        Err(e) => {
            let msg = format!("{e}");
            if msg.contains("timed out") || msg.contains("Interrupted") {
                ToolCallResult::error(format!(
                    "Execution timed out after {timeout_secs}s. Consider increasing timeout_secs or simplifying the code."
                ))
            } else if msg.contains("out of memory") || msg.contains("memory limit") {
                ToolCallResult::error(
                    "Out of memory (64MB limit). Reduce data size or process in chunks.",
                )
            } else {
                ToolCallResult::error(format!("Execution error: {e}"))
            }
        }
    }
}
