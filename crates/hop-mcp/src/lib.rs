//! hop MCP server: AI agent interface for hop fleet management.
//!
//! Exposes hop operations via the Model Context Protocol (MCP) over stdio.
//! AI agents (Claude Code, Cursor, etc.) can orchestrate hop fleets through
//! the `hop_exec` (sandboxed JS) and `hop_skills` (documentation) tools.

pub mod audit;
pub mod backend;
pub mod js;
pub mod policy;
pub mod protocol;
pub mod server;
pub mod skills;
pub mod tools;

use std::path::Path;

use anyhow::Result;
use hop_core::datastore::Datastore;

use backend::local::LocalBackend;
use backend::BoxedBackend;
use tools::ToolRegistry;

/// Entry point: run the MCP server over stdio.
///
/// Called by `hop mcp` CLI command. Reads JSON-RPC 2.0 from stdin,
/// dispatches to tools, writes responses to stdout. All logs go to stderr.
pub async fn run_stdio_server(config_dir: &Path) -> Result<()> {
    run_stdio_server_with_datastore(config_dir, None).await
}

/// Entry point with optional datastore for data and cron tools.
pub async fn run_stdio_server_with_datastore(
    config_dir: &Path,
    datastore: Option<Datastore>,
) -> Result<()> {
    let backend: BoxedBackend = Box::new(LocalBackend::new(config_dir.to_path_buf()));
    let mut registry = ToolRegistry::new(backend);
    if let Some(ds) = datastore {
        registry = registry.with_datastore(ds);
    }
    server::run(&registry).await
}
