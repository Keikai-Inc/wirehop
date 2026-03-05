//! Tool registry and dispatch for MCP tools.

pub mod hop_exec;
pub mod hop_skills;

use serde_json::Value;

use crate::protocol::{ToolCallResult, ToolDefinition};
use crate::skills::SkillStore;
use crate::js::JsRuntime;
use crate::backend::BoxedBackend;

/// Central tool dispatcher.
pub struct ToolRegistry {
    skill_store: SkillStore,
    js_runtime: JsRuntime,
    backend: BoxedBackend,
}

impl ToolRegistry {
    pub fn new(backend: BoxedBackend) -> Self {
        Self {
            skill_store: SkillStore::new(),
            js_runtime: JsRuntime::new(),
            backend,
        }
    }

    /// Return all tool definitions for tools/list.
    pub fn list_tools(&self) -> Vec<ToolDefinition> {
        vec![
            hop_exec::tool_definition(),
            hop_skills::tool_definition(),
        ]
    }

    /// Dispatch a tool call.
    pub async fn call_tool(&self, name: &str, args: Value) -> ToolCallResult {
        match name {
            "hop_exec" => hop_exec::call(&self.js_runtime, &self.backend, args).await,
            "hop_skills" => hop_skills::call(&self.skill_store, args),
            _ => ToolCallResult::error(format!("Unknown tool: {name}")),
        }
    }
}
