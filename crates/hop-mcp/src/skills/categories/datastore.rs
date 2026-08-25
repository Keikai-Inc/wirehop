use crate::skills::Skill;
use super::super::data::{s, tags, ex};

pub fn skills() -> Vec<Skill> {
    vec![
        Skill {
            id: s("datastore/kv-basics"),
            category: s("datastore"),
            title: s("Key-Value Store Basics"),
            description: s("Store and retrieve key-value data using hop's embedded datastore. Data is organized by namespace and persists across restarts."),
            tags: tags(&["kv", "key-value", "store", "get", "set", "data"]),
            prerequisites: vec![],
            examples: vec![
                ex(
                    "Store and retrieve a value via JS",
                    r#"hop.kv.set("config", "app_version", "2.1.0");
const entry = hop.kv.get("config", "app_version");
return entry.value;  // "2.1.0""#,
                    Some("2.1.0"),
                ),
                ex(
                    "Store structured data",
                    r#"hop.kv.set("hosts", "web-1", { ip: "10.0.1.5", role: "web", status: "healthy" });
const host = hop.kv.get("hosts", "web-1");
return host.value.status;  // "healthy""#,
                    Some("healthy"),
                ),
                ex(
                    "Store and retrieve via MCP tool",
                    r#"// Use hop_data tool with action: "kv_set"
// { "action": "kv_set", "namespace": "config", "key": "app_version", "value": "2.1.0" }
//
// Retrieve with action: "kv_get"
// { "action": "kv_get", "namespace": "config", "key": "app_version" }"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("Values are stored as JSON — non-serializable data will fail."),
                s("Namespace separates data logically but shares the same underlying database."),
            ],
            related: tags(&["datastore/kv-listing", "datastore/timeseries-basics"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("datastore/kv-listing"),
            category: s("datastore"),
            title: s("Key-Value Listing and Prefix Queries"),
            description: s("List keys in a namespace, optionally filtered by prefix. Useful for discovering stored data and iterating over related entries."),
            tags: tags(&["kv", "list", "prefix", "keys", "iterate", "data"]),
            prerequisites: vec![s("datastore/kv-basics")],
            examples: vec![
                ex(
                    "List all keys in a namespace",
                    r#"hop.kv.set("hosts", "web-1", { ip: "10.0.1.5" });
hop.kv.set("hosts", "web-2", { ip: "10.0.1.6" });
hop.kv.set("hosts", "db-1", { ip: "10.0.2.1" });
const all = hop.kv.list("hosts");
return all.length;  // 3"#,
                    Some("3"),
                ),
                ex(
                    "List keys by prefix",
                    r#"const webHosts = hop.kv.list("hosts", "web-");
for (const entry of webHosts) {
    hop.log(entry.key + ": " + JSON.stringify(entry.value));
}"#,
                    Some("web-1: {\"ip\":\"10.0.1.5\"}\nweb-2: {\"ip\":\"10.0.1.6\"}"),
                ),
            ],
            pitfalls: vec![
                s("Prefix queries use lexicographic ordering — 'web-10' sorts before 'web-2'."),
            ],
            related: tags(&["datastore/kv-basics"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("datastore/timeseries-basics"),
            category: s("datastore"),
            title: s("Time-Series Data Collection"),
            description: s("Insert and query time-series metric data with optional tags. Ideal for storing monitoring data like CPU, memory, disk usage over time."),
            tags: tags(&["timeseries", "metrics", "insert", "query", "monitoring", "data"]),
            prerequisites: vec![],
            examples: vec![
                ex(
                    "Record and retrieve a metric",
                    r#"hop.ts.insert("cpu.usage", 42.5, { host: "web-1" });
hop.ts.insert("cpu.usage", 38.2, { host: "web-2" });
const latest = hop.ts.latest("cpu.usage");
return latest.value;  // 38.2 (most recent insert)"#,
                    Some("38.2"),
                ),
                ex(
                    "Query metric history",
                    r#"// Query last hour of CPU data
const now = Date.now();
const oneHourAgo = now - 3600000;
const points = hop.ts.query("cpu.usage", oneHourAgo, now);
for (const p of points) {
    hop.log(new Date(p.timestamp).toISOString() + " " + p.value + "% " + JSON.stringify(p.tags));
}"#,
                    Some("2026-03-08T10:00:00.000Z 42.5% {\"host\":\"web-1\"}\n2026-03-08T10:05:00.000Z 38.2% {\"host\":\"web-2\"}"),
                ),
                ex(
                    "Insert metric via MCP tool",
                    r#"// Use hop_data tool with action: "ts_insert"
// { "action": "ts_insert", "metric": "cpu.usage", "value": 42.5, "tags": { "host": "web-1" } }"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("Timestamps are Unix milliseconds — use Date.now() in JS, not seconds."),
                s("Tag filtering on queries happens post-read — keep tag cardinality reasonable."),
            ],
            related: tags(&["datastore/kv-basics", "datastore/cron-scheduling"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("datastore/cron-scheduling"),
            category: s("datastore"),
            title: s("Cron Job Scheduling"),
            description: s("Create and manage scheduled JS scripts that run periodically. Jobs are stored in the datastore and executed by the hop daemon on schedule."),
            tags: tags(&["cron", "schedule", "periodic", "job", "automation"]),
            prerequisites: vec![s("datastore/timeseries-basics")],
            examples: vec![
                ex(
                    "Create a monitoring cron job via MCP",
                    r#"// Use hop_cron tool with action: "create"
// {
//   "action": "create",
//   "name": "CPU Monitor",
//   "schedule": "0 */5 * * * *",
//   "script": "const r = await hop.exec('web-1', 'uptime'); hop.ts.insert('load.1m', parseFloat(r.stdout.match(/load average: ([\\d.]+)/)[1]), {host: 'web-1'});"
// }"#,
                    None,
                ),
                ex(
                    "List and manage cron jobs",
                    r#"// List all jobs: { "action": "list" }
// Get job details: { "action": "get", "job_id": "abc123" }
// Disable a job: { "action": "disable", "job_id": "abc123" }
// Enable a job: { "action": "enable", "job_id": "abc123" }
// Delete a job: { "action": "delete", "job_id": "abc123" }"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("Cron expressions use 6 fields (sec min hour day month weekday) — not the usual 5-field format."),
                s("Scripts execute in a sandboxed QuickJS runtime with resource limits."),
            ],
            related: tags(&["datastore/timeseries-basics", "monitor/cpu-usage"]),
            sub_skills: vec![],
        },
        Skill {
            id: s("datastore/monitoring-patterns"),
            category: s("datastore"),
            title: s("Monitoring Patterns with Datastore"),
            description: s("Combine hop's remote execution, time-series storage, and cron scheduling to build a decentralized monitoring system. Collect metrics from fleet hosts and store them locally."),
            tags: tags(&["monitoring", "pattern", "collect", "store", "fleet", "dashboard"]),
            prerequisites: vec![s("datastore/timeseries-basics"), s("datastore/cron-scheduling")],
            examples: vec![
                ex(
                    "Collect and store CPU metrics from fleet",
                    r#"// JS script for a cron job that monitors CPU across fleet
const results = await hop.fleet.exec("*", `
    os=$(uname -s)
    if [ "$os" = "Darwin" ]; then
        sysctl -n vm.loadavg | awk '{print $2}'
    else
        awk '{print $1}' /proc/loadavg
    fi
`);
for (const r of results) {
    const load = parseFloat(r.stdout.trim());
    hop.ts.insert("cpu.load1m", load, { host: r.host });
    if (load > 4.0) {
        hop.kv.set("alerts", "high-cpu-" + r.host, {
            host: r.host, load: load,
            timestamp: Date.now(), severity: "warning"
        });
    }
}"#,
                    None,
                ),
                ex(
                    "Build a simple fleet dashboard query",
                    r#"// Query recent metrics for all hosts
const now = Date.now();
const fiveMinAgo = now - 300000;

const cpuPoints = hop.ts.query("cpu.load1m", fiveMinAgo, now);
const alerts = hop.kv.list("alerts", "high-cpu-");

hop.log("=== Fleet CPU Status ===");
for (const p of cpuPoints) {
    const status = p.value > 4.0 ? "HIGH" : "OK";
    hop.log("[" + status + "] " + p.tags.host + ": " + p.value);
}
if (alerts.length > 0) {
    hop.log("\n=== Active Alerts ===");
    for (const a of alerts) {
        hop.log(a.key + ": load=" + a.value.load);
    }
}"#,
                    None,
                ),
            ],
            pitfalls: vec![
                s("Time-series data grows over time — use retention policies (ts_purge_before) to manage storage."),
                s("Fleet exec may timeout on unreachable hosts — handle errors in monitoring scripts."),
            ],
            related: tags(&["monitor/cpu-usage", "monitor/memory-usage", "datastore/cron-scheduling"]),
            sub_skills: vec![],
        },
    ]
}
