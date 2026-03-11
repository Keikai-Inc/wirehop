//! Cron scheduler: polls for due jobs and executes their JS scripts.
//!
//! Design follows the Kubernetes CronJob `Forbid` / APScheduler `max_instances=1`
//! pattern: only one instance of a given job runs at a time. If a job is still
//! running when its next fire time arrives, that tick is skipped. Missed runs
//! (e.g. daemon was down) are coalesced into a single execution on startup.

use std::collections::HashSet;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use hop_core::datastore::Datastore;
use tokio::task::JoinHandle;

use crate::backend::OrchestratorBackend;
use crate::js::JsRuntime;

/// Compute the next occurrence (in epoch milliseconds) of a cron schedule
/// after the given timestamp.
pub fn next_occurrence_ms(schedule: &cron::Schedule, after_ms: u64) -> u64 {
    use chrono::{TimeZone, Utc};
    let dt = Utc.timestamp_millis_opt(after_ms as i64).single();
    match dt {
        Some(dt) => schedule
            .after(&dt)
            .next()
            .map(|next| next.timestamp_millis() as u64)
            .unwrap_or(after_ms + 60_000),
        None => after_ms + 60_000,
    }
}

/// Spawn the cron scheduler loop. Polls for due jobs at `poll_interval`.
///
/// When `backend` is provided, cron jobs can use `hop.exec()` / `hop.fleet.exec()`
/// and jobs with `targets` will have `hop.targets` injected.
pub fn spawn_cron_scheduler(
    datastore: Datastore,
    poll_interval: Duration,
    backend: Option<Arc<dyn OrchestratorBackend>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        // Track which jobs are currently executing. Checked synchronously on
        // each tick before spawning — prevents duplicate runs entirely.
        let running: Arc<std::sync::Mutex<HashSet<String>>> =
            Arc::new(std::sync::Mutex::new(HashSet::new()));

        let mut interval = tokio::time::interval(poll_interval);
        loop {
            interval.tick().await;
            if let Err(e) =
                run_due_jobs(&datastore, backend.as_ref(), &running).await
            {
                tracing::error!("Cron scheduler error: {e:#}");
            }
        }
    })
}

/// Query for due jobs and spawn a task for each one (skipping in-flight jobs).
async fn run_due_jobs(
    datastore: &Datastore,
    backend: Option<&Arc<dyn OrchestratorBackend>>,
    running: &Arc<std::sync::Mutex<HashSet<String>>>,
) -> Result<()> {
    let now = now_ms();
    let due_jobs = datastore.cron_get_due(now)?;

    for job in due_jobs {
        // --- Concurrency guard: skip if already running ---
        {
            let set = running.lock().unwrap();
            if set.contains(&job.id) {
                tracing::debug!(
                    "Cron: skipping '{}' ({}) — already running",
                    job.name,
                    job.id
                );
                continue;
            }
        }

        // Advance next_run before spawning so cron_get_due won't return this
        // job again even if the running set check somehow races.
        let next_run = job
            .schedule
            .parse::<cron::Schedule>()
            .map(|s| next_occurrence_ms(&s, now))
            .unwrap_or(now + 60_000);
        datastore.cron_update_last_run(&job.id, now, next_run)?;

        // Mark as running before spawning the task.
        {
            let mut set = running.lock().unwrap();
            set.insert(job.id.clone());
        }

        let ds = datastore.clone();
        let be = backend.cloned();
        let running = Arc::clone(running);
        let job_id = job.id.clone();

        tokio::spawn(async move {
            // RAII guard: clears the running flag on drop, even if the task
            // panics (e.g. from iroh-quinn connection bugs). Without this,
            // a panicked task would leave the job permanently stuck.
            let _guard = RunningGuard {
                set: Arc::clone(&running),
                id: job_id,
            };
            if let Err(e) = execute_cron_job(&ds, &job, be.as_ref()).await {
                tracing::error!("Cron job '{}' ({}) failed: {e:#}", job.name, job.id);
            }
        });
    }

    Ok(())
}

/// Execute a single cron job's JS script.
async fn execute_cron_job(
    datastore: &Datastore,
    job: &hop_core::datastore::types::CronJob,
    backend: Option<&Arc<dyn OrchestratorBackend>>,
) -> Result<()> {
    tracing::info!("Cron: executing job '{}' ({})", job.name, job.id);

    let mut runtime = JsRuntime::new();
    runtime.set_datastore(datastore.clone());

    // Apply sandbox policy if the job specifies one
    if let Some(ref sandbox) = job.sandbox {
        runtime.set_sandbox(sandbox.clone());
    }

    // Build the script, optionally prepending hop.targets injection
    let script = if let (Some(tag), Some(be)) = (&job.targets, backend) {
        let hosts = be.list_hosts(Some(tag)).await.unwrap_or_default();
        let hosts_json = serde_json::to_string(&hosts).unwrap_or_else(|_| "[]".to_string());
        format!("hop.targets = {};\n{}", hosts_json, job.script)
    } else {
        job.script.clone()
    };

    // Timeout must exceed the 60s exec timeout in LocalBackend so that
    // hop.exec() can fire its own timeout error instead of the JS runtime
    // killing the script silently.
    let js_timeout = Duration::from_secs(120);

    let result = if let Some(be) = backend {
        runtime.execute(&script, be, Some(js_timeout)).await
    } else {
        runtime.execute_script(&script, Some(js_timeout)).await
    };

    match &result {
        Ok(output) => tracing::info!(
            "Cron job '{}' completed: {}",
            job.name,
            truncate(output, 200)
        ),
        Err(e) => tracing::error!("Cron job '{}' script error: {e:#}", job.name),
    }

    Ok(())
}

/// RAII guard that removes a job ID from the running set on drop.
/// Ensures cleanup even if the spawned task panics (e.g. from iroh-quinn bugs).
struct RunningGuard {
    set: Arc<std::sync::Mutex<HashSet<String>>>,
    id: String,
}

impl Drop for RunningGuard {
    fn drop(&mut self) {
        self.set.lock().unwrap().remove(&self.id);
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() <= max {
        return s;
    }
    // Find the largest char boundary at or before `max`
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    &s[..end]
}

#[cfg(test)]
mod tests {
    use super::*;
    use hop_core::datastore::types::CronJob;

    fn make_job(id: &str, schedule: &str, script: &str, enabled: bool, next_run: u64) -> CronJob {
        CronJob {
            id: id.to_string(),
            name: format!("Job {id}"),
            schedule: schedule.to_string(),
            script: script.to_string(),
            enabled,
            last_run: None,
            next_run,
            created_at: 1000,
            tags: vec![],
            targets: None,
            catalog_id: None,
            sandbox: None,
        }
    }

    #[test]
    fn next_occurrence_computes_future_timestamp() {
        let schedule: cron::Schedule = "0 * * * * *".parse().unwrap();
        let now = now_ms();
        let next = next_occurrence_ms(&schedule, now);
        assert!(next > now, "next_occurrence should be in the future");
    }

    #[tokio::test]
    async fn run_due_jobs_executes_script_writes_kv() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        let running = Arc::new(std::sync::Mutex::new(HashSet::new()));

        let job = make_job(
            "j1",
            "0 * * * * *",
            "hop.kv.set('cron_test', 'proof', 'it_ran')",
            true,
            0,
        );
        ds.cron_add(&job).unwrap();

        run_due_jobs(&ds, None, &running).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;

        let entry = ds.kv_get("cron_test", "proof").unwrap();
        assert!(entry.is_some(), "KV entry should exist after cron execution");
        assert_eq!(entry.unwrap().value, b"\"it_ran\"");
    }

    #[tokio::test]
    async fn run_due_jobs_handles_failing_script() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        let running = Arc::new(std::sync::Mutex::new(HashSet::new()));

        let job = make_job("j_fail", "0 * * * * *", "throw new Error('boom')", true, 0);
        ds.cron_add(&job).unwrap();

        run_due_jobs(&ds, None, &running).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;

        let updated = ds.cron_get("j_fail").unwrap().unwrap();
        assert!(
            updated.last_run.is_some(),
            "last_run should be set even on failure"
        );
    }

    #[tokio::test]
    async fn disabled_jobs_are_not_executed() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        let running = Arc::new(std::sync::Mutex::new(HashSet::new()));

        let job = make_job(
            "j_disabled",
            "0 * * * * *",
            "hop.kv.set('cron_test', 'disabled', 'should_not_run')",
            false,
            0,
        );
        ds.cron_add(&job).unwrap();

        run_due_jobs(&ds, None, &running).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let entry = ds.kv_get("cron_test", "disabled").unwrap();
        assert!(entry.is_none(), "Disabled job should not execute");
    }

    #[tokio::test]
    async fn skips_already_running_job() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        let running = Arc::new(std::sync::Mutex::new(HashSet::new()));

        // Simulate a long-running job by pre-inserting its ID in the running set
        let job = make_job(
            "j_slow",
            "0 * * * * *",
            "hop.kv.set('cron_test', 'slow', 'should_not_run_twice')",
            true,
            0,
        );
        ds.cron_add(&job).unwrap();

        // Mark as already running
        running.lock().unwrap().insert("j_slow".to_string());

        // This tick should skip it
        run_due_jobs(&ds, None, &running).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let entry = ds.kv_get("cron_test", "slow").unwrap();
        assert!(entry.is_none(), "Already-running job should be skipped");
    }

    #[tokio::test]
    async fn running_flag_cleared_after_completion() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        let running = Arc::new(std::sync::Mutex::new(HashSet::new()));

        let job = make_job(
            "j_clear",
            "0 * * * * *",
            "hop.kv.set('cron_test', 'clear', 'done')",
            true,
            0,
        );
        ds.cron_add(&job).unwrap();

        run_due_jobs(&ds, None, &running).await.unwrap();
        tokio::time::sleep(Duration::from_millis(500)).await;

        // After completion, the running set should be empty
        assert!(
            !running.lock().unwrap().contains("j_clear"),
            "Running flag should be cleared after job completes"
        );
    }

    #[tokio::test]
    async fn spawn_scheduler_executes_due_job() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        let job = make_job(
            "j_sched",
            "0 * * * * *",
            "hop.kv.set('cron_test', 'sched', 'scheduler_ran')",
            true,
            0,
        );
        ds.cron_add(&job).unwrap();

        let handle = spawn_cron_scheduler(ds.clone(), Duration::from_millis(100), None);
        tokio::time::sleep(Duration::from_millis(800)).await;
        handle.abort();

        let entry = ds.kv_get("cron_test", "sched").unwrap();
        assert!(
            entry.is_some(),
            "Scheduler should have executed the due job"
        );

        let updated = ds.cron_get("j_sched").unwrap().unwrap();
        assert!(updated.next_run > 0, "next_run should be advanced");
        assert!(
            updated.last_run.is_some(),
            "last_run should be set after execution"
        );
    }
}
