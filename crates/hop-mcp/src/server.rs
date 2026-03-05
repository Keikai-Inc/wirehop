//! MCP stdio server event loop.
//!
//! Reads newline-delimited JSON-RPC 2.0 from stdin, dispatches to tools,
//! writes responses to stdout. All tracing/logging goes to stderr.


use anyhow::{Context, Result};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::protocol::*;
use crate::tools::ToolRegistry;

/// Run the MCP server, reading from stdin and writing to stdout.
pub async fn run(registry: &ToolRegistry) -> Result<()> {
    let stdin = tokio::io::stdin();
    let mut stdout = tokio::io::stdout();
    let mut reader = BufReader::new(stdin);
    let mut line = String::new();

    tracing::info!("MCP server ready, waiting for requests on stdin");

    loop {
        line.clear();
        let n = reader
            .read_line(&mut line)
            .await
            .context("Failed to read from stdin")?;

        if n == 0 {
            // EOF — client disconnected
            tracing::info!("stdin closed, shutting down");
            break;
        }

        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        // Parse JSON-RPC request
        let request: JsonRpcRequest = match serde_json::from_str(trimmed) {
            Ok(r) => r,
            Err(e) => {
                let resp = JsonRpcResponse::error(None, PARSE_ERROR, format!("Parse error: {e}"));
                write_response(&mut stdout, &resp).await?;
                continue;
            }
        };

        // Dispatch
        let response = dispatch(registry, request).await;

        // Notifications (no id) don't get responses
        if let Some(ref resp) = response {
            write_response(&mut stdout, resp).await?;
        }
    }

    Ok(())
}

async fn dispatch(registry: &ToolRegistry, request: JsonRpcRequest) -> Option<JsonRpcResponse> {
    let id = request.id.clone();

    // Notifications have no id — don't respond
    if id.is_none() {
        match request.method.as_str() {
            "notifications/initialized" => {
                tracing::info!("Client initialized");
            }
            "notifications/cancelled" => {
                tracing::debug!("Client cancelled request");
            }
            other => {
                tracing::debug!("Unknown notification: {other}");
            }
        }
        return None;
    }

    let response = match request.method.as_str() {
        "initialize" => handle_initialize(id),

        "tools/list" => handle_tools_list(registry, id),

        "tools/call" => handle_tools_call(registry, id, request.params).await,

        "ping" => JsonRpcResponse::success(id, serde_json::json!({})),

        method => {
            tracing::warn!("Unknown method: {method}");
            JsonRpcResponse::error(id, METHOD_NOT_FOUND, format!("Method not found: {method}"))
        }
    };

    Some(response)
}

fn handle_initialize(id: Option<serde_json::Value>) -> JsonRpcResponse {
    let result = InitializeResult {
        protocol_version: "2024-11-05".into(),
        capabilities: ServerCapabilities {
            tools: ToolsCapability {},
        },
        server_info: ServerInfo {
            name: "hop-mcp".into(),
            version: env!("CARGO_PKG_VERSION").into(),
        },
    };

    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

fn handle_tools_list(
    registry: &ToolRegistry,
    id: Option<serde_json::Value>,
) -> JsonRpcResponse {
    let tools = registry.list_tools();
    let result = ToolsListResult { tools };
    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

async fn handle_tools_call(
    registry: &ToolRegistry,
    id: Option<serde_json::Value>,
    params: Option<serde_json::Value>,
) -> JsonRpcResponse {
    let params = match params {
        Some(p) => p,
        None => {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing params");
        }
    };

    let tool_name = match params.get("name").and_then(|v| v.as_str()) {
        Some(name) => name.to_string(),
        None => {
            return JsonRpcResponse::error(id, INVALID_PARAMS, "Missing tool name");
        }
    };

    let arguments = params
        .get("arguments")
        .cloned()
        .unwrap_or(serde_json::json!({}));

    tracing::info!("tools/call: {tool_name}");

    let result = registry.call_tool(&tool_name, arguments).await;
    JsonRpcResponse::success(id, serde_json::to_value(result).unwrap())
}

async fn write_response(
    stdout: &mut tokio::io::Stdout,
    response: &JsonRpcResponse,
) -> Result<()> {
    let json = serde_json::to_string(response).context("Failed to serialize response")?;
    stdout
        .write_all(json.as_bytes())
        .await
        .context("Failed to write to stdout")?;
    stdout
        .write_all(b"\n")
        .await
        .context("Failed to write newline")?;
    stdout.flush().await.context("Failed to flush stdout")?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::local::LocalBackend;
    use crate::backend::BoxedBackend;

    fn test_registry() -> ToolRegistry {
        let backend: BoxedBackend = Box::new(LocalBackend::new(
            std::path::PathBuf::from("/tmp/hop-mcp-test"),
        ));
        ToolRegistry::new(backend)
    }

    #[tokio::test]
    async fn dispatch_initialize() {
        let registry = test_registry();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(serde_json::json!(1)),
            method: "initialize".into(),
            params: Some(serde_json::json!({})),
        };
        let resp = dispatch(&registry, req).await.unwrap();
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert_eq!(result["protocolVersion"], "2024-11-05");
        assert_eq!(result["serverInfo"]["name"], "hop-mcp");
    }

    #[tokio::test]
    async fn dispatch_tools_list() {
        let registry = test_registry();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(serde_json::json!(2)),
            method: "tools/list".into(),
            params: None,
        };
        let resp = dispatch(&registry, req).await.unwrap();
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        let tools = result["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0]["name"], "hop_exec");
        assert_eq!(tools[1]["name"], "hop_skills");
    }

    #[tokio::test]
    async fn dispatch_unknown_method() {
        let registry = test_registry();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(serde_json::json!(3)),
            method: "nonexistent".into(),
            params: None,
        };
        let resp = dispatch(&registry, req).await.unwrap();
        assert!(resp.error.is_some());
        assert_eq!(resp.error.unwrap().code, METHOD_NOT_FOUND);
    }

    #[tokio::test]
    async fn dispatch_notification_no_response() {
        let registry = test_registry();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: None,
            method: "notifications/initialized".into(),
            params: None,
        };
        let resp = dispatch(&registry, req).await;
        assert!(resp.is_none());
    }

    #[tokio::test]
    async fn dispatch_tools_call_skills() {
        let registry = test_registry();
        let req = JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(serde_json::json!(4)),
            method: "tools/call".into(),
            params: Some(serde_json::json!({
                "name": "hop_skills",
                "arguments": {}
            })),
        };
        let resp = dispatch(&registry, req).await.unwrap();
        assert!(resp.result.is_some());
        let result = resp.result.unwrap();
        assert!(result["content"][0]["text"]
            .as_str()
            .unwrap()
            .contains("Categories"));
    }
}
