//! Peer operation handler — requests any authenticated peer can perform.
//!
//! Handles remote secrets, KV, cron, and capability management without
//! requiring the Creator role.

use std::path::Path;

use crate::datastore::Datastore;
use crate::proto::{
    CapJobInfo, CronJobSummary, PeerRequest, PeerResponse,
};

/// Handle a peer operation request.
///
/// Any authenticated peer (Peer or Creator) can call these. The datastore
/// must be opened with secrets support (open_with_secrets).
pub fn handle_peer_request(
    request: PeerRequest,
    _config_dir: &Path,
    datastore: &Datastore,
    username: &str,
) -> PeerResponse {
    match request {
        // Served by the host connection loop, which owns the registry handle.
        PeerRequest::ListSessions => PeerResponse::Error("session listing is served by the host connection".to_string()),
        // --- Secrets (scoped to peer's username) ---
        PeerRequest::SecretsGet { name } => match datastore.secrets_get(username, &name) {
            Ok(value) => PeerResponse::SecretValue(value),
            Err(e) => PeerResponse::Error(format!("secrets_get: {e}")),
        },
        PeerRequest::SecretsSet { name, value } => match datastore.secrets_set(username, &name, &value) {
            Ok(()) => PeerResponse::Ok,
            Err(e) => PeerResponse::Error(format!("secrets_set: {e}")),
        },
        PeerRequest::SecretsDelete { name } => match datastore.secrets_delete(username, &name) {
            Ok(true) => PeerResponse::Ok,
            Ok(false) => PeerResponse::Error("secret not found".into()),
            Err(e) => PeerResponse::Error(format!("secrets_delete: {e}")),
        },
        PeerRequest::SecretsList => match datastore.secrets_list(username) {
            Ok(names) => PeerResponse::SecretNames(names),
            Err(e) => PeerResponse::Error(format!("secrets_list: {e}")),
        },

        // --- KV ---
        PeerRequest::KvGet { ns, key } => match datastore.kv_get(&ns, &key) {
            Ok(entry) => PeerResponse::KvEntry(entry),
            Err(e) => PeerResponse::Error(format!("kv_get: {e}")),
        },
        PeerRequest::KvSet { ns, key, value } => {
            let entry = crate::datastore::types::KvEntry {
                value,
                content_type: "application/json".to_string(),
                updated_at: now_ms(),
            };
            match datastore.kv_set(&ns, &key, &entry) {
                Ok(()) => PeerResponse::Ok,
                Err(e) => PeerResponse::Error(format!("kv_set: {e}")),
            }
        }
        PeerRequest::KvList { ns, prefix } => match datastore.kv_list(&ns, &prefix) {
            Ok(entries) => PeerResponse::KvEntries(entries),
            Err(e) => PeerResponse::Error(format!("kv_list: {e}")),
        },

        // --- Cron ---
        PeerRequest::CronList => match datastore.cron_list() {
            Ok(jobs) => PeerResponse::CronJobs(
                jobs.iter()
                    .map(|j| CronJobSummary {
                        id: j.id.clone(),
                        name: j.name.clone(),
                        schedule: j.schedule.clone(),
                        enabled: j.enabled,
                        last_run: j.last_run,
                        next_run: j.next_run,
                        targets: j.targets.clone(),
                    })
                    .collect(),
            ),
            Err(e) => PeerResponse::Error(format!("cron_list: {e}")),
        },
        PeerRequest::CronGet { id } => match datastore.cron_get(&id) {
            Ok(Some(j)) => PeerResponse::CronJob(Some(CronJobSummary {
                id: j.id,
                name: j.name,
                schedule: j.schedule,
                enabled: j.enabled,
                last_run: j.last_run,
                next_run: j.next_run,
                targets: j.targets,
            })),
            Ok(None) => PeerResponse::CronJob(None),
            Err(e) => PeerResponse::Error(format!("cron_get: {e}")),
        },

        // --- Capabilities ---
        PeerRequest::CapList => {
            // This is handled by the CLI binary since CapabilityDefinition
            // lives in hop-mcp, not hop-core. Return empty — the CLI
            // dispatches cap list locally using the embedded registry.
            PeerResponse::CapEntries(Vec::new())
        }
        PeerRequest::CapEnable {
            id,
            schedule,
            targets,
        } => handle_cap_enable(datastore, &id, schedule.as_deref(), targets.as_deref()),
        PeerRequest::CapDisable { id } => handle_cap_disable(datastore, &id),
        PeerRequest::CapStatus => handle_cap_status(datastore),
        PeerRequest::CapRun {
            id,
            targets,
            params,
        } => handle_cap_run(datastore, &id, targets.as_deref(), &params),

        // Extension routing — handled in a separate async dispatcher upstream
        // of this sync function. If we reach here, the dispatcher above us
        // didn't intercept; surface a clear error rather than silently
        // succeeding.
        PeerRequest::ExtensionList
        | PeerRequest::ExtensionCall { .. }
        | PeerRequest::ExtensionStreamOpen { .. }
        | PeerRequest::ExtensionStreamInput { .. }
        | PeerRequest::ExtensionStreamClose { .. } => {
            PeerResponse::Error(
                "extension request reached sync handler; \
                 should have been routed via the async extension registry"
                    .into(),
            )
        }
    }
}

fn handle_cap_enable(
    _datastore: &Datastore,
    id: &str,
    _schedule: Option<&str>,
    _targets: Option<&str>,
) -> PeerResponse {
    // We can't access CapabilityDefinition here (it's in hop-mcp).
    // The client sends the schedule and the host creates a cron job.
    // The client is responsible for resolving the capability and its script.
    // For now, return an error — the full implementation requires the CLI
    // to send the script content along with the enable request.
    PeerResponse::Error(format!(
        "Remote cap enable for '{id}' not yet supported — use local: hop cap enable {id}"
    ))
}

fn handle_cap_disable(datastore: &Datastore, id: &str) -> PeerResponse {
    let catalog_id = format!("cap:{id}");
    match datastore.cron_find_by_catalog_id(&catalog_id) {
        Ok(Some(job)) => match datastore.cron_remove(&job.id) {
            Ok(_) => PeerResponse::Ok,
            Err(e) => PeerResponse::Error(format!("cap disable: {e}")),
        },
        Ok(None) => PeerResponse::Error(format!("capability '{id}' is not enabled")),
        Err(e) => PeerResponse::Error(format!("cap disable: {e}")),
    }
}

fn handle_cap_status(datastore: &Datastore) -> PeerResponse {
    match datastore.cron_list() {
        Ok(jobs) => {
            let cap_jobs: Vec<CapJobInfo> = jobs
                .iter()
                .filter(|j| {
                    j.catalog_id
                        .as_deref()
                        .is_some_and(|id| id.starts_with("cap:"))
                })
                .map(|j| CapJobInfo {
                    catalog_id: j.catalog_id.clone().unwrap_or_default(),
                    enabled: j.enabled,
                    schedule: j.schedule.clone(),
                    targets: j.targets.clone(),
                    last_run: j.last_run,
                })
                .collect();
            PeerResponse::CapStatusEntries(cap_jobs)
        }
        Err(e) => PeerResponse::Error(format!("cap status: {e}")),
    }
}

fn handle_cap_run(
    _datastore: &Datastore,
    id: &str,
    _targets: Option<&str>,
    _params: &[(String, String)],
) -> PeerResponse {
    // Similar to cap enable — requires the script content from hop-mcp.
    PeerResponse::Error(format!(
        "Remote cap run for '{id}' not yet supported — use local: hop cap run {id}"
    ))
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
