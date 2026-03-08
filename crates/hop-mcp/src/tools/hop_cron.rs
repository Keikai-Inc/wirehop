//! hop_cron tool: cron job management for scheduled JS script execution.

use serde::Deserialize;
use serde_json::{json, Value};

use hop_core::datastore::types::CronJob;
use hop_core::datastore::Datastore;

use crate::protocol::{ToolCallResult, ToolDefinition};

#[derive(Debug, Deserialize)]
struct CronArgs {
    action: String,
    job_id: Option<String>,
    name: Option<String>,
    schedule: Option<String>,
    script: Option<String>,
    tags: Option<Vec<String>>,
    tag_filter: Option<String>,
}

pub fn tool_definition() -> ToolDefinition {
    ToolDefinition {
        name: "hop_cron".into(),
        description: "Manage scheduled cron jobs that execute JavaScript in hop's sandboxed runtime. Jobs persist across restarts. Use standard cron expressions (e.g. '*/5 * * * * *' for every 5 seconds, '0 */5 * * * *' for every 5 minutes).".into(),
        input_schema: json!({
            "type": "object",
            "properties": {
                "action": {
                    "type": "string",
                    "enum": ["create", "delete", "list", "get", "enable", "disable"],
                    "description": "The cron management operation"
                },
                "job_id": {
                    "type": "string",
                    "description": "Job ID (required for delete, get, enable, disable)"
                },
                "name": {
                    "type": "string",
                    "description": "Human-readable job name (required for create)"
                },
                "schedule": {
                    "type": "string",
                    "description": "Cron expression (required for create). Uses 6-field format: sec min hour day month weekday. Example: '0 */5 * * * *' = every 5 minutes"
                },
                "script": {
                    "type": "string",
                    "description": "JavaScript code to execute (required for create)"
                },
                "tags": {
                    "type": "array",
                    "items": { "type": "string" },
                    "description": "Tags for fleet targeting (optional, for create)"
                },
                "tag_filter": {
                    "type": "string",
                    "description": "Filter jobs by tag (optional, for list)"
                }
            },
            "required": ["action"]
        }),
    }
}

pub fn call(datastore: &Datastore, args: Value) -> ToolCallResult {
    let args: CronArgs = match serde_json::from_value(args) {
        Ok(a) => a,
        Err(e) => return ToolCallResult::error(format!("Invalid arguments: {e}")),
    };

    match args.action.as_str() {
        "create" => cron_create(datastore, &args),
        "delete" => cron_delete(datastore, &args),
        "list" => cron_list(datastore, &args),
        "get" => cron_get(datastore, &args),
        "enable" => cron_toggle(datastore, &args, true),
        "disable" => cron_toggle(datastore, &args, false),
        other => ToolCallResult::error(format!("Unknown action: {other}")),
    }
}

fn cron_create(ds: &Datastore, args: &CronArgs) -> ToolCallResult {
    let name = match args.name.as_deref() {
        Some(n) => n,
        None => return ToolCallResult::error("name is required for create"),
    };
    let schedule = match args.schedule.as_deref() {
        Some(s) => s,
        None => return ToolCallResult::error("schedule is required for create"),
    };
    let script = match args.script.as_deref() {
        Some(s) => s,
        None => return ToolCallResult::error("script is required for create"),
    };

    // Validate schedule by parsing
    let parsed = match schedule.parse::<cron::Schedule>() {
        Ok(s) => s,
        Err(e) => {
            return ToolCallResult::error(format!(
                "Invalid cron expression '{schedule}': {e}. Use 6-field format: sec min hour day month weekday"
            ))
        }
    };

    let now = now_ms();
    let next_run = next_occurrence_ms(&parsed, now);
    let job_id = generate_id();

    let job = CronJob {
        id: job_id.clone(),
        name: name.to_string(),
        schedule: schedule.to_string(),
        script: script.to_string(),
        enabled: true,
        last_run: None,
        next_run,
        created_at: now,
        tags: args.tags.clone().unwrap_or_default(),
    };

    match ds.cron_add(&job) {
        Ok(()) => ToolCallResult::text(
            json!({
                "job_id": job_id,
                "name": name,
                "schedule": schedule,
                "enabled": true,
                "next_run": next_run,
            })
            .to_string(),
        ),
        Err(e) => ToolCallResult::error(format!("Failed to create cron job: {e}")),
    }
}

fn cron_delete(ds: &Datastore, args: &CronArgs) -> ToolCallResult {
    let job_id = match args.job_id.as_deref() {
        Some(id) => id,
        None => return ToolCallResult::error("job_id is required for delete"),
    };

    match ds.cron_remove(job_id) {
        Ok(true) => ToolCallResult::text(json!({"deleted": true}).to_string()),
        Ok(false) => ToolCallResult::error(format!("Cron job not found: {job_id}")),
        Err(e) => ToolCallResult::error(format!("Failed to delete cron job: {e}")),
    }
}

fn cron_list(ds: &Datastore, args: &CronArgs) -> ToolCallResult {
    match ds.cron_list() {
        Ok(jobs) => {
            let filtered: Vec<&CronJob> = if let Some(ref tag_filter) = args.tag_filter {
                jobs.iter()
                    .filter(|j| j.tags.iter().any(|t| t == tag_filter))
                    .collect()
            } else {
                jobs.iter().collect()
            };

            let items: Vec<Value> = filtered
                .into_iter()
                .map(|j| {
                    json!({
                        "id": j.id,
                        "name": j.name,
                        "schedule": j.schedule,
                        "enabled": j.enabled,
                        "last_run": j.last_run,
                        "next_run": j.next_run,
                        "tags": j.tags,
                    })
                })
                .collect();
            ToolCallResult::text(serde_json::to_string_pretty(&items).unwrap_or_default())
        }
        Err(e) => ToolCallResult::error(format!("Failed to list cron jobs: {e}")),
    }
}

fn cron_get(ds: &Datastore, args: &CronArgs) -> ToolCallResult {
    let job_id = match args.job_id.as_deref() {
        Some(id) => id,
        None => return ToolCallResult::error("job_id is required for get"),
    };

    match ds.cron_get(job_id) {
        Ok(Some(job)) => ToolCallResult::text(
            json!({
                "id": job.id,
                "name": job.name,
                "schedule": job.schedule,
                "script": job.script,
                "enabled": job.enabled,
                "last_run": job.last_run,
                "next_run": job.next_run,
                "created_at": job.created_at,
                "tags": job.tags,
            })
            .to_string(),
        ),
        Ok(None) => ToolCallResult::error(format!("Cron job not found: {job_id}")),
        Err(e) => ToolCallResult::error(format!("Failed to get cron job: {e}")),
    }
}

fn cron_toggle(ds: &Datastore, args: &CronArgs, enable: bool) -> ToolCallResult {
    let job_id = match args.job_id.as_deref() {
        Some(id) => id,
        None => {
            return ToolCallResult::error(format!(
                "job_id is required for {}",
                if enable { "enable" } else { "disable" }
            ))
        }
    };

    // Read the job, update enabled flag, write it back
    let job = match ds.cron_get(job_id) {
        Ok(Some(j)) => j,
        Ok(None) => return ToolCallResult::error(format!("Cron job not found: {job_id}")),
        Err(e) => return ToolCallResult::error(format!("Failed to read cron job: {e}")),
    };

    let mut updated = job;
    updated.enabled = enable;

    // If enabling, recompute next_run
    if enable
        && let Ok(schedule) = updated.schedule.parse::<cron::Schedule>()
    {
        updated.next_run = next_occurrence_ms(&schedule, now_ms());
    }

    match ds.cron_add(&updated) {
        Ok(()) => ToolCallResult::text(
            json!({
                "id": updated.id,
                "enabled": updated.enabled,
                "next_run": updated.next_run,
            })
            .to_string(),
        ),
        Err(e) => ToolCallResult::error(format!("Failed to update cron job: {e}")),
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn next_occurrence_ms(schedule: &cron::Schedule, after_ms: u64) -> u64 {
    crate::cron::next_occurrence_ms(schedule, after_ms)
}

fn generate_id() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("cron_{ts:x}")
}
