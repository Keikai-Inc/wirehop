//! Built-in capabilities: health monitoring, log search, security scanning.
//!
//! Each capability is a self-contained definition with a JS script, sandbox tier,
//! trigger mode, and data pattern. The framework handles enabling, disabling,
//! deploying, and running capabilities as cron jobs.

pub mod registry;

use hop_core::sandbox::SandboxPolicy;

/// How the capability is triggered.
pub enum TriggerMode {
    /// Runs on a cron schedule.
    Scheduled { default_schedule: &'static str },
    /// Runs on-demand only (no cron job).
    OnDemand,
    /// Can be both scheduled and run on-demand.
    Both { default_schedule: &'static str },
}

/// Permission tier — maps to a SandboxPolicy preset.
#[derive(Clone, Copy)]
pub enum PermissionTier {
    /// Read-only, no network, system paths only.
    Observe,
    /// Read-only, no network, full filesystem read.
    Audit,
    /// Read-only, network allowed (API integrations).
    Connect,
    /// Write + network, deny destructive.
    Operate,
}

impl PermissionTier {
    /// Convert to a concrete SandboxPolicy.
    pub fn to_sandbox(self) -> SandboxPolicy {
        match self {
            PermissionTier::Observe => SandboxPolicy::preset_monitor(),
            PermissionTier::Audit => SandboxPolicy::preset_audit(),
            PermissionTier::Connect => SandboxPolicy::preset_connect(),
            PermissionTier::Operate => SandboxPolicy::preset_deploy(),
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            PermissionTier::Observe => "monitor",
            PermissionTier::Audit => "audit",
            PermissionTier::Connect => "connect",
            PermissionTier::Operate => "deploy",
        }
    }
}

/// Data flow pattern for the capability.
pub enum DataPattern {
    /// Node collects locally, pushes summary to orchestrator.
    Push,
    /// Orchestrator dispatches query, nodes filter, aggregate results.
    FanOut,
}

/// A parameter definition for on-demand capabilities.
pub struct ParamDef {
    pub name: &'static str,
    pub description: &'static str,
    pub required: bool,
    pub default: Option<&'static str>,
}

/// A built-in capability definition.
pub struct CapabilityDefinition {
    pub id: &'static str,
    pub name: &'static str,
    pub description: &'static str,
    pub tier: PermissionTier,
    pub trigger: TriggerMode,
    pub data_pattern: DataPattern,
    pub script: &'static str,
    pub category: &'static str,
    pub params: &'static [ParamDef],
}

impl CapabilityDefinition {
    /// Look up a capability by ID.
    pub fn find(id: &str) -> Option<&'static CapabilityDefinition> {
        registry::builtin_capabilities().iter().find(|c| c.id == id)
    }

    /// Get the default schedule for scheduled capabilities.
    pub fn default_schedule(&self) -> Option<&'static str> {
        match &self.trigger {
            TriggerMode::Scheduled { default_schedule } => Some(default_schedule),
            TriggerMode::Both { default_schedule } => Some(default_schedule),
            TriggerMode::OnDemand => None,
        }
    }

    /// Whether this capability can be scheduled (enabled as a cron job).
    pub fn is_schedulable(&self) -> bool {
        matches!(self.trigger, TriggerMode::Scheduled { .. } | TriggerMode::Both { .. })
    }

    /// Whether this capability can be run on-demand.
    pub fn is_on_demand(&self) -> bool {
        matches!(self.trigger, TriggerMode::OnDemand | TriggerMode::Both { .. })
    }

    /// Generate the catalog_id for this capability's cron job.
    pub fn catalog_id(&self) -> String {
        format!("cap:{}", self.id)
    }
}
