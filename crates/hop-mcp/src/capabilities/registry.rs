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
            auth_requirements: &[],
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
            auth_requirements: &[],
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
            auth_requirements: &[],
        },
        CapabilityDefinition {
            id: "email-monitor",
            name: "Email Monitor",
            description: "Hourly email + calendar monitor with SMS alerts. Full briefing at \
                configured hour (email + SMS summary). Other hours: checks for new URGENT \
                emails and upcoming calendar events, sends SMS only if needed. Classifies \
                emails (URGENT/ACTION/FYI/JUNK), marks read, archives junk.",
            tier: PermissionTier::Connect,
            trigger: TriggerMode::Both { default_schedule: "0 0 * * * *" },
            data_pattern: DataPattern::Push,
            script: include_str!("scripts/email_monitor.js"),
            category: "automation",
            params: &[],
            auth_requirements: &[
                AuthRequirement { provider: "gmail", description: "Gmail" },
                AuthRequirement { provider: "anthropic", description: "Anthropic" },
            ],
        },
        CapabilityDefinition {
            id: "log-insights",
            name: "Log Insights (AI)",
            description: "AI-aggregated federated log search: fans a READ-ONLY search \
                across target nodes (each greps its own logs locally — no central \
                collector), then asks Claude to reduce the matches into one summary of \
                patterns, anomalies, and the key finding. `--param query=<pattern> \
                [--param source=audit|system|<path>]`, `--targets <group>`.",
            tier: PermissionTier::Connect,
            trigger: TriggerMode::OnDemand,
            data_pattern: DataPattern::FanOut,
            script: include_str!("scripts/log_insights.js"),
            category: "operations",
            params: &[
                ParamDef {
                    name: "query",
                    description: "Search pattern (literal substring) to find across nodes",
                    required: true,
                    default: None,
                },
                ParamDef {
                    name: "source",
                    description: "Where each node searches: audit, system (default), or a file path",
                    required: false,
                    default: Some("system"),
                },
            ],
            auth_requirements: &[AuthRequirement { provider: "anthropic", description: "Anthropic" }],
        },
        CapabilityDefinition {
            id: "event-webhook",
            name: "Event Webhook",
            description: "Fires a local HTTP POST to a secret-stored URL on warren \
                events: a new member joins, this node's device posture fails (disk \
                encryption / firewall off), or rejected-connection/reach-denial \
                activity crosses a threshold. Polls THIS node's audit log (no central \
                collector); each node reports its own events. Set the target with \
                `hop secrets set webhook_url <https-url>`.",
            tier: PermissionTier::Connect,
            trigger: TriggerMode::Both { default_schedule: "0 */5 * * * *" },
            data_pattern: DataPattern::Push,
            script: include_str!("scripts/event_webhook.js"),
            category: "automation",
            params: &[
                ParamDef {
                    name: "deny_threshold",
                    description: "Fire a summary alert when this many rejected/denied events accumulate since the last run (default 5)",
                    required: false,
                    default: Some("5"),
                },
            ],
            auth_requirements: &[],
        },
    ]
}
