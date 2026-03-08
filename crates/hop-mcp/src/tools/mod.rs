//! Tool registry and dispatch for MCP tools.

pub mod hop_cron;
pub mod hop_data;
pub mod hop_exec;
pub mod hop_skills;

use serde_json::Value;

use hop_core::datastore::Datastore;

use crate::backend::BoxedBackend;
use crate::js::JsRuntime;
use crate::protocol::{ToolCallResult, ToolDefinition};
use crate::skills::SkillStore;

/// Central tool dispatcher.
pub struct ToolRegistry {
    skill_store: SkillStore,
    js_runtime: JsRuntime,
    backend: BoxedBackend,
    datastore: Option<Datastore>,
}

impl ToolRegistry {
    pub fn new(backend: BoxedBackend) -> Self {
        Self {
            skill_store: SkillStore::new(),
            js_runtime: JsRuntime::new(),
            backend,
            datastore: None,
        }
    }

    /// Set the datastore for data/cron tools and JS bindings.
    pub fn with_datastore(mut self, datastore: Datastore) -> Self {
        self.js_runtime.set_datastore(datastore.clone());
        self.datastore = Some(datastore);
        self
    }

    /// Return all tool definitions for tools/list.
    pub fn list_tools(&self) -> Vec<ToolDefinition> {
        let mut tools = vec![
            hop_exec::tool_definition(),
            hop_skills::tool_definition(),
        ];
        if self.datastore.is_some() {
            tools.push(hop_data::tool_definition());
            tools.push(hop_cron::tool_definition());
        }
        tools
    }

    /// Dispatch a tool call.
    pub async fn call_tool(&self, name: &str, args: Value) -> ToolCallResult {
        match name {
            "hop_exec" => hop_exec::call(&self.js_runtime, &self.backend, args).await,
            "hop_skills" => hop_skills::call(&self.skill_store, args),
            "hop_data" => match &self.datastore {
                Some(ds) => hop_data::call(ds, args),
                None => ToolCallResult::error("Datastore not available. Start hop in host mode to enable data storage."),
            },
            "hop_cron" => match &self.datastore {
                Some(ds) => hop_cron::call(ds, args),
                None => ToolCallResult::error("Datastore not available. Start hop in host mode to enable cron jobs."),
            },
            _ => ToolCallResult::error(format!("Unknown tool: {name}")),
        }
    }
}
