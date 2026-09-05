//! Cron scheduler: polls for due jobs and executes their JS scripts.
//!
//! Design follows the Kubernetes CronJob `Forbid` / APScheduler `max_instances=1`
//! pattern: only one instance of a given job runs at a time. If a job is still
//! running when its next fire time arrives, that tick is skipped. Missed runs
//! (e.g. daemon was down) are coalesced into a single execution on startup.

use hop_core::datastore::types::CronRunStatus;
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
        // A run cannot outlive the daemon that started it: anything still
        // marked running in the history was cut off by a restart.
        match datastore.cron_runs_mark_interrupted(now_ms()) {
            Ok(n) if n > 0 => eprintln!("[hop.cron] {n} run(s) were interrupted by the last daemon restart"),
            Err(e) => tracing::warn!("cron: could not reconcile run history: {e:#}"),
            _ => {}
        }
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
        let started = now;
        if let Err(e) = datastore.cron_run_start(&job.id, started) {
            tracing::warn!("cron: could not record run start for {}: {e:#}", job.id);
        }

        tokio::spawn(async move {
            // RAII guard: clears the running flag on drop, even if the task
            // panics (e.g. from iroh-quinn connection bugs). Without this,
            // a panicked task would leave the job permanently stuck.
            let _guard = RunningGuard {
                set: Arc::clone(&running),
                id: job_id,
            };
            let limit = job_timeout(&job);
            // Hard deadline around the whole run. The JS interrupt handler
            // only fires between statements, so a script stuck inside a
            // blocking call (an HTTP request that never returns, a child
            // process that never exits) would otherwise hang the job forever
            // and invisibly. Past the deadline the run is recorded as timed
            // out and the job is released for its next tick; the abandoned
            // thread finishes or dies with the process.
            let grace = Duration::from_secs(30);
            let outcome = tokio::time::timeout(limit + grace, execute_cron_job(&ds, &job, be.as_ref(), limit)).await;
            let ended = now_ms();
            let (status, message) = match outcome {
                Ok(Ok(output)) => (CronRunStatus::Ok, truncate(&output, 500).to_string()),
                Ok(Err(e)) => {
                    let msg = format!("{e:#}");
                    // The runtime reports its own deadline as "interrupted"
                    // (the QuickJS interrupt handler) or "timed out" (pending
                    // jobs); either way the run hit its limit.
                    let elapsed = Duration::from_millis(ended.saturating_sub(started));
                    let hit_limit = msg.contains("timed out") || msg.contains("interrupted") || elapsed >= limit;
                    if hit_limit {
                        (CronRunStatus::Timeout, format!("exceeded the {}s run limit after {:.1}s ({msg})", limit.as_secs(), elapsed.as_secs_f64()))
                    } else {
                        (CronRunStatus::Error, msg)
                    }
                }
                Err(_) => (
                    CronRunStatus::Timeout,
                    format!(
                        "still running after {}s: a blocking call inside the script did not return; the run was abandoned",
                        (limit + grace).as_secs()
                    ),
                ),
            };
            if let Err(e) = ds.cron_run_finish(&job.id, started, ended, status, &message) {
                tracing::warn!("cron: could not record run end for {}: {e:#}", job.id);
            }
            match status {
                CronRunStatus::Ok => {
                    tracing::info!("Cron job '{}' completed: {}", job.name, truncate(&message, 200));
                    eprintln!("[hop.cron] {} completed: {}", job.name, truncate(&message, 200));
                }
                _ => {
                    let msg = format!("Cron job '{}' ({}) {}: {message}", job.name, job.id, status.as_str());
                    tracing::error!("{msg}");
                    eprintln!("[hop.cron] ERROR: {msg}");
                    store_cron_error(&ds, &job.id, &msg);
                    notify_cron_failure(&ds, &job, &msg).await;
                }
            }
        });
    }

    Ok(())
}

/// The scheduler's default wall-clock limit for one run. Must exceed the 60 s
/// `hop.exec()` timeout so that fires first with a clear error, and is long
/// enough for jobs that call `hop.claude()` a few times.
pub const DEFAULT_JOB_TIMEOUT: Duration = Duration::from_secs(300);

/// The run limit for a job: its own `timeout_secs`, else the default.
pub fn job_timeout(job: &hop_core::datastore::types::CronJob) -> Duration {
    job.timeout_secs
        .filter(|s| *s > 0)
        .map(Duration::from_secs)
        .unwrap_or(DEFAULT_JOB_TIMEOUT)
}

/// Execute a single cron job's JS script and return its output. Errors,
/// including the runtime's own timeout, come back as `Err`; the caller
/// records the run either way.
async fn execute_cron_job(
    datastore: &Datastore,
    job: &hop_core::datastore::types::CronJob,
    backend: Option<&Arc<dyn OrchestratorBackend>>,
    js_timeout: Duration,
) -> Result<String> {
    tracing::info!("Cron: executing job '{}' ({})", job.name, job.id);

    let mut runtime = JsRuntime::new();
    runtime.set_datastore(datastore.clone());

    // Apply sandbox policy if the job specifies one
    if let Some(ref sandbox) = job.sandbox {
        runtime.set_sandbox(sandbox.clone());
    }

    // Set user for privilege dropping in hop.local()
    if let Some(ref user) = job.run_as_user {
        runtime.set_run_as_user(user.clone());
    }

    // Build the script, optionally prepending hop.targets injection
    let script = if let (Some(tag), Some(be)) = (&job.targets, backend) {
        let hosts = be.list_hosts(Some(tag)).await.unwrap_or_default();
        let hosts_json = serde_json::to_string(&hosts).unwrap_or_else(|_| "[]".to_string());
        format!("hop.targets = {};\n{}", hosts_json, job.script)
    } else {
        job.script.clone()
    };

    if let Some(be) = backend {
        runtime.execute(&script, be, Some(js_timeout)).await
    } else {
        runtime.execute_script(&script, Some(js_timeout)).await
    }
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

/// Store a cron error with timestamp, keeping at most 10 entries per job.
fn store_cron_error(ds: &Datastore, job_id: &str, msg: &str) {
    const MAX_ERRORS_PER_JOB: usize = 10;

    let ts = now_ms();
    let key = format!("{job_id}:{ts:016}");
    let _ = ds.kv_set(
        "cron_errors",
        &key,
        &hop_core::datastore::types::KvEntry {
            value: msg.as_bytes().to_vec(),
            content_type: "text/plain".to_string(),
            updated_at: ts,
        },
    );

    // Prune oldest entries if over the limit
    if let Ok(entries) = ds.kv_list("cron_errors", &format!("{job_id}:"))
        && entries.len() > MAX_ERRORS_PER_JOB
    {
        for (old_key, _) in entries.iter().take(entries.len() - MAX_ERRORS_PER_JOB) {
            let _ = ds.kv_delete("cron_errors", old_key);
        }
    }
}

/// Best-effort SMS notification on cron failure.
///
/// Sends an SMS via the Gmail API / carrier email gateway, reusing secrets
/// already configured for the email-monitor capability. Rate-limited to
/// one SMS per job per hour to prevent spam on recurring failures.
async fn notify_cron_failure(
    ds: &Datastore,
    job: &hop_core::datastore::types::CronJob,
    msg: &str,
) {
    // Check cooldown: at most one SMS per job per hour
    let cooldown_key = format!("sms_cooldown:{}", job.id);
    let now = now_ms();
    if let Ok(Some(entry)) = ds.kv_get("cron_notify", &cooldown_key)
        && now.saturating_sub(entry.updated_at) < 3_600_000
    {
        tracing::debug!("Cron failure SMS skipped (cooldown): {}", job.name);
        return;
    }

    // Truncate message for SMS (max ~300 chars)
    let sms_body = if msg.len() > 280 {
        format!("[hop] {} failed: {}...", job.name, &msg[..250])
    } else {
        format!("[hop] {msg}")
    };

    let sms_msg_json = serde_json::to_string(&sms_body).unwrap_or_else(|_| "\"cron job failed\"".into());
    let script = format!(
        "var __sms_message = {sms_msg_json};\n{SMS_NOTIFY_JS}",
    );

    let mut runtime = crate::js::JsRuntime::new();
    runtime.set_datastore(ds.clone());
    if let Some(ref user) = job.run_as_user {
        runtime.set_run_as_user(user.clone());
    }

    match runtime
        .execute_script(&script, Some(Duration::from_secs(30)))
        .await
    {
        Ok(result) => tracing::info!("Cron failure SMS for '{}': {result}", job.name),
        Err(e) => tracing::warn!("Cron failure SMS for '{}' failed: {e:#}", job.name),
    }

    // Update cooldown timestamp
    let _ = ds.kv_set(
        "cron_notify",
        &cooldown_key,
        &hop_core::datastore::types::KvEntry {
            value: b"1".to_vec(),
            content_type: "text/plain".to_string(),
            updated_at: now,
        },
    );
}

/// Minimal JS to send an SMS via Gmail API + carrier email gateway.
/// Expects `__sms_message` global to be set before evaluation.
const SMS_NOTIFY_JS: &str = r#"
(function() {
    var GATEWAYS = {
        "tmobile": "@tmomail.net", "att": "@txt.att.net",
        "verizon": "@vtext.com", "sprint": "@messaging.sprintpcs.com",
        "googlefi": "@msg.fi.google.com", "mint": "@tmomail.net",
        "visible": "@vtext.com", "uscellular": "@email.uscc.net"
    };
    var phone = hop.secrets.get("sms_phone");
    var carrier = hop.secrets.get("sms_carrier");
    if (!phone || !carrier) return "no sms config";
    var gateway = GATEWAYS[carrier.toLowerCase()];
    if (!gateway) gateway = carrier.indexOf("@") === 0 ? carrier : "@" + carrier;
    var addr = phone + gateway;
    var msg = __sms_message;
    if (msg.length > 300) msg = msg.substring(0, 297) + "...";

    var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    function base64url(str) {
        var bytes = [];
        for (var i = 0; i < str.length; i++) {
            var c = str.charCodeAt(i);
            if (c < 128) bytes.push(c);
            else if (c < 2048) { bytes.push(192 | (c >> 6)); bytes.push(128 | (c & 63)); }
            else if (c < 65536) { bytes.push(224 | (c >> 12)); bytes.push(128 | ((c >> 6) & 63)); bytes.push(128 | (c & 63)); }
            else { bytes.push(240 | (c >> 18)); bytes.push(128 | ((c >> 12) & 63)); bytes.push(128 | ((c >> 6) & 63)); bytes.push(128 | (c & 63)); }
        }
        var b64 = "";
        for (var i = 0; i < bytes.length; i += 3) {
            var b0 = bytes[i], b1 = bytes[i + 1] || 0, b2 = bytes[i + 2] || 0;
            var n = (b0 << 16) | (b1 << 8) | b2;
            b64 += chars[(n >> 18) & 63];
            b64 += chars[(n >> 12) & 63];
            b64 += (i + 1 < bytes.length) ? chars[(n >> 6) & 63] : "";
            b64 += (i + 2 < bytes.length) ? chars[n & 63] : "";
        }
        return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    }

    var content = "To: " + addr + "\r\nSubject: hop alert\r\nContent-Type: text/plain; charset=utf-8\r\n\r\n" + msg;
    var token = hop.secrets.get("gmail_access_token");
    if (!token) return "no gmail token for SMS";
    try {
        hop.http.post("https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
            { bearer: token, json: { raw: base64url(content) } });
        return "sms sent to " + addr;
    } catch(e) {
        return "sms failed: " + e.message;
    }
})();
"#;

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
            run_as_user: None,
            timeout_secs: None,
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
    #[tokio::test]
    async fn run_history_records_ok_and_error() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        let running = Arc::new(std::sync::Mutex::new(HashSet::new()));
        ds.cron_add(&make_job("ok", "0 * * * * *", "return 'fine'", true, 0)).unwrap();
        ds.cron_add(&make_job("bad", "0 * * * * *", "throw new Error('boom')", true, 0)).unwrap();
        run_due_jobs(&ds, None, &running).await.unwrap();
        tokio::time::sleep(Duration::from_millis(800)).await;
        let ok = ds.cron_runs("ok", 5).unwrap();
        assert_eq!(ok.len(), 1);
        assert_eq!(ok[0].status, CronRunStatus::Ok);
        assert_eq!(ok[0].message, "fine");
        assert!(ok[0].duration_ms().is_some());
        let bad = ds.cron_runs("bad", 5).unwrap();
        assert_eq!(bad[0].status, CronRunStatus::Error);
        assert!(bad[0].message.contains("boom"), "{}", bad[0].message);
    }

    #[tokio::test]
    async fn run_history_records_timeout() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        let running = Arc::new(std::sync::Mutex::new(HashSet::new()));
        let mut job = make_job("spin", "0 * * * * *", "while (true) {}", true, 0);
        job.timeout_secs = Some(1);
        ds.cron_add(&job).unwrap();
        run_due_jobs(&ds, None, &running).await.unwrap();
        tokio::time::sleep(Duration::from_millis(2500)).await;
        let runs = ds.cron_runs("spin", 5).unwrap();
        assert_eq!(runs.len(), 1);
        assert_eq!(runs[0].status, CronRunStatus::Timeout, "{}", runs[0].message);
        assert!(!running.lock().unwrap().contains("spin"), "job released after timeout");
    }

}
