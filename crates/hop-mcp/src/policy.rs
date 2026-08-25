//! MCP policy enforcement.
//!
//! Loads mcp_policy.json and checks host operations against it.

use std::collections::HashMap;
use std::path::Path;

use anyhow::Result;
use serde::{Deserialize, Serialize};

/// Policy decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PolicyDecision {
    Allow,
    Deny,
    Prompt,
}

/// Per-host policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostPolicy {
    #[serde(default = "default_prompt")]
    pub exec: PolicyDecision,
    #[serde(default = "default_prompt")]
    pub read_file: PolicyDecision,
    #[serde(default = "default_prompt")]
    pub write_file: PolicyDecision,
}

fn default_prompt() -> PolicyDecision {
    PolicyDecision::Prompt
}

/// JS sandbox limits from policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct JsSandboxPolicy {
    #[serde(default = "default_memory_limit")]
    pub memory_limit_mb: usize,
    #[serde(default = "default_timeout")]
    pub timeout_secs: u64,
    #[serde(default = "default_rate_limit")]
    pub max_exec_per_minute: u32,
}

fn default_memory_limit() -> usize { 64 }
fn default_timeout() -> u64 { 30 }
fn default_rate_limit() -> u32 { 10 }

impl Default for JsSandboxPolicy {
    fn default() -> Self {
        Self {
            memory_limit_mb: 64,
            timeout_secs: 30,
            max_exec_per_minute: 10,
        }
    }
}

/// Full MCP policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpPolicy {
    #[serde(default = "default_prompt")]
    pub default_policy: PolicyDecision,
    #[serde(default)]
    pub host_policies: HashMap<String, HostPolicy>,
    #[serde(default)]
    pub js_sandbox: JsSandboxPolicy,
}

impl Default for McpPolicy {
    fn default() -> Self {
        Self {
            default_policy: PolicyDecision::Prompt,
            host_policies: HashMap::new(),
            js_sandbox: JsSandboxPolicy::default(),
        }
    }
}

impl McpPolicy {
    /// Load policy from config directory. Returns default if no file exists.
    pub fn load(config_dir: &Path) -> Result<Self> {
        let path = config_dir.join("mcp_policy.json");
        if path.exists() {
            let data = std::fs::read_to_string(&path)?;
            Ok(serde_json::from_str(&data)?)
        } else {
            Ok(Self::default())
        }
    }

    /// Check policy for a specific operation on a host.
    pub fn check(&self, host: &str, operation: &str) -> PolicyDecision {
        // Check host-specific policies (supports glob patterns like "production-*")
        for (pattern, policy) in &self.host_policies {
            if matches_pattern(pattern, host) {
                return match operation {
                    "exec" => policy.exec.clone(),
                    "read_file" => policy.read_file.clone(),
                    "write_file" => policy.write_file.clone(),
                    _ => self.default_policy.clone(),
                };
            }
        }

        self.default_policy.clone()
    }
}

/// Simple glob matching (only supports trailing *).
fn matches_pattern(pattern: &str, host: &str) -> bool {
    if let Some(prefix) = pattern.strip_suffix('*') {
        host.starts_with(prefix)
    } else {
        pattern == host
    }
}

/// Defense-in-depth command blocklist.
/// Returns Some(reason) if the command should be blocked.
pub fn check_command_blocklist(command: &str) -> Option<&'static str> {
    let cmd = command.trim();

    let blocked_patterns = [
        ("rm -rf /", "Recursive deletion of root filesystem"),
        ("rm -rf /*", "Recursive deletion of root filesystem"),
        ("mkfs", "Filesystem formatting"),
        ("dd if=/dev/zero of=/dev/sd", "Disk overwrite"),
        ("dd if=/dev/zero of=/dev/nvme", "Disk overwrite"),
        ("dd if=/dev/urandom of=/dev/sd", "Disk overwrite"),
        (":(){ :|:& };:", "Fork bomb"),
        ("chmod -R 777 /", "Recursive permission change on root"),
        ("chown -R", "Recursive ownership change"),
        ("> /dev/sda", "Direct device write"),
        ("mv /* /dev/null", "Move root to null"),
    ];

    for (pattern, reason) in &blocked_patterns {
        if cmd.contains(pattern) {
            return Some(reason);
        }
    }

    None
}

/// Check if a command looks destructive (requires confirmation).
pub fn is_destructive_command(command: &str) -> bool {
    let cmd = command.to_lowercase();
    let destructive_patterns = [
        "rm -r",
        "rm -f",
        "rmdir",
        "drop database",
        "drop table",
        "truncate table",
        "systemctl stop",
        "systemctl disable",
        "service stop",
        "kill -9",
        "killall",
        "pkill",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "init 0",
        "init 6",
        "iptables -F",
        "ufw disable",
    ];

    destructive_patterns.iter().any(|p| cmd.contains(p))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_policy() {
        let policy = McpPolicy::default();
        assert_eq!(policy.check("any-host", "exec"), PolicyDecision::Prompt);
    }

    #[test]
    fn pattern_matching() {
        assert!(matches_pattern("prod-*", "prod-web-01"));
        assert!(!matches_pattern("prod-*", "staging-web-01"));
        assert!(matches_pattern("exact-host", "exact-host"));
    }

    #[test]
    fn blocklist() {
        assert!(check_command_blocklist("rm -rf /").is_some());
        assert!(check_command_blocklist("ls -la").is_none());
    }

    #[test]
    fn destructive_detection() {
        assert!(is_destructive_command("rm -rf /tmp/stuff"));
        assert!(is_destructive_command("systemctl stop nginx"));
        assert!(!is_destructive_command("ls -la"));
        assert!(!is_destructive_command("cat /etc/hosts"));
    }
}
