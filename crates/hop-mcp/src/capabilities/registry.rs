//! Registry of built-in capabilities.

use super::*;

/// Returns all built-in capability definitions.
pub fn builtin_capabilities() -> &'static [CapabilityDefinition] {
    &[
        CapabilityDefinition {
            id: "health",
            name: "Health Monitor",
            description: "Collects CPU load, memory, disk usage, and uptime. Dual-mode: orchestrator fans out to targets, or node monitors itself locally.",
            tier: PermissionTier::Observe,
            trigger: TriggerMode::Scheduled { default_schedule: "0 */5 * * * *" },
            data_pattern: DataPattern::Push,
            script: include_str!("scripts/health.js"),
            category: "monitor",
            params: &[],
        },
        CapabilityDefinition {
            id: "log-search",
            name: "Log Search",
            description: "Searches system logs across fleet nodes. Fan-out: each node greps locally, returns matching lines.",
            tier: PermissionTier::Observe,
            trigger: TriggerMode::OnDemand,
            data_pattern: DataPattern::FanOut,
            script: include_str!("scripts/log_search.js"),
            category: "operations",
            params: &[
                ParamDef {
                    name: "query",
                    description: "Search term to grep for in system logs",
                    required: true,
                    default: None,
                },
            ],
        },
        CapabilityDefinition {
            id: "security-baseline",
            name: "Security Baseline",
            description: "Audits SUID binaries, open ports, failed auth attempts, SSH keys, and world-writable files. Dual-mode with push.",
            tier: PermissionTier::Audit,
            trigger: TriggerMode::Both { default_schedule: "0 0 3 * * *" },
            data_pattern: DataPattern::Push,
            script: include_str!("scripts/security_baseline.js"),
            category: "security",
            params: &[],
        },
    ]
}
