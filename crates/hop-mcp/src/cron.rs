//! Cron scheduler: polls for due jobs and executes their JS scripts.

use std::time::Duration;

use anyhow::Result;
use hop_core::datastore::Datastore;
use tokio::task::JoinHandle;

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
pub fn spawn_cron_scheduler(datastore: Datastore, poll_interval: Duration) -> JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(poll_interval);
        loop {
            interval.tick().await;
            if let Err(e) = run_due_jobs(&datastore).await {
                tracing::error!("Cron scheduler error: {e:#}");
            }
        }
    })
}

/// Query for due jobs and spawn a task for each one.
async fn run_due_jobs(datastore: &Datastore) -> Result<()> {
    let now = now_ms();
    let due_jobs = datastore.cron_get_due(now)?;

    if !due_jobs.is_empty() {
        tracing::info!("Cron: {} job(s) due for execution", due_jobs.len());
    }

    for job in due_jobs {
        let ds = datastore.clone();
        tokio::spawn(async move {
            if let Err(e) = execute_cron_job(&ds, &job).await {
                tracing::error!("Cron job '{}' ({}) failed: {e:#}", job.name, job.id);
            }
        });
    }

    Ok(())
}

/// Execute a single cron job's JS script and update last_run/next_run.
async fn execute_cron_job(
    datastore: &Datastore,
    job: &hop_core::datastore::types::CronJob,
) -> Result<()> {
    let now = now_ms();

    tracing::info!("Cron: executing job '{}' ({})", job.name, job.id);

    let mut runtime = JsRuntime::new();
    runtime.set_datastore(datastore.clone());

    let result = runtime
        .execute_script(&job.script, Some(Duration::from_secs(30)))
        .await;

    match &result {
        Ok(output) => tracing::info!(
            "Cron job '{}' completed: {}",
            job.name,
            truncate(output, 200)
        ),
        Err(e) => tracing::error!("Cron job '{}' script error: {e:#}", job.name),
    }

    // Always update last_run/next_run, even on script failure
    let next_run = job
        .schedule
        .parse::<cron::Schedule>()
        .map(|s| next_occurrence_ms(&s, now))
        .unwrap_or(now + 60_000);

    datastore.cron_update_last_run(&job.id, now, next_run)?;

    Ok(())
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn truncate(s: &str, max: usize) -> &str {
    if s.len() > max {
        &s[..max]
    } else {
        s
    }
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

        // Create a due job that writes to KV
        let job = make_job(
            "j1",
            "0 * * * * *",
            "hop.kv.set('cron_test', 'proof', 'it_ran')",
            true,
            0, // next_run=0 means it's always due
        );
        ds.cron_add(&job).unwrap();

        run_due_jobs(&ds).await.unwrap();

        // Give the spawned task a moment to complete
        tokio::time::sleep(Duration::from_millis(500)).await;

        let entry = ds.kv_get("cron_test", "proof").unwrap();
        assert!(entry.is_some(), "KV entry should exist after cron execution");
        // JS strings are stored JSON-encoded (with quotes)
        assert_eq!(entry.unwrap().value, b"\"it_ran\"");
    }

    #[tokio::test]
    async fn run_due_jobs_handles_failing_script() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        // Create a due job with invalid JS
        let job = make_job("j_fail", "0 * * * * *", "throw new Error('boom')", true, 0);
        ds.cron_add(&job).unwrap();

        // Should not panic
        run_due_jobs(&ds).await.unwrap();

        // Give the spawned task time to complete
        tokio::time::sleep(Duration::from_millis(500)).await;

        // last_run should still be updated
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

        // Create a disabled job
        let job = make_job(
            "j_disabled",
            "0 * * * * *",
            "hop.kv.set('cron_test', 'disabled', 'should_not_run')",
            false,
            0,
        );
        ds.cron_add(&job).unwrap();

        run_due_jobs(&ds).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;

        let entry = ds.kv_get("cron_test", "disabled").unwrap();
        assert!(entry.is_none(), "Disabled job should not execute");
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

        // Spawn scheduler with a short interval
        let handle = spawn_cron_scheduler(ds.clone(), Duration::from_millis(100));

        // Wait for at least one tick
        tokio::time::sleep(Duration::from_millis(800)).await;

        handle.abort();

        let entry = ds.kv_get("cron_test", "sched").unwrap();
        assert!(
            entry.is_some(),
            "Scheduler should have executed the due job"
        );

        // Verify next_run was advanced
        let updated = ds.cron_get("j_sched").unwrap().unwrap();
        assert!(updated.next_run > 0, "next_run should be advanced");
        assert!(
            updated.last_run.is_some(),
            "last_run should be set after execution"
        );
    }
}
