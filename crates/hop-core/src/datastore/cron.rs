//! Cron job CRUD operations on the embedded datastore.

use std::collections::HashSet;
use std::sync::{Mutex, OnceLock};

use anyhow::Result;
#[allow(unused_imports)]
use redb::ReadableTable;

use super::protocol::{DsRequest, DsResponse};
use super::remote_dispatch;
use super::tables::{CRON_RUNS_TABLE, CRON_TABLE};
use super::types::{CronJob, CronRun, CronRunStatus};
use super::Datastore;

/// Decode a stored `CronJob`, accepting records written by older builds.
///
/// bincode is not self-describing and ignores `#[serde(default)]`, so each
/// field appended to `CronJob` since the first release leaves records written
/// before it one field short: a plain decode fails with `UnexpectedEnd` and
/// the job looks corrupt (0.9.38 lost every existing job this way). So on
/// failure decode the original layout, then each appended field only while
/// bytes remain. Returns the job and whether it used an older layout (so the
/// caller can rewrite it). A new field appended to `CronJob` needs one more
/// `tail` line here, in field order.
fn decode_job(bytes: &[u8]) -> Result<(CronJob, bool)> {
    let cfg = bincode::config::standard();
    if let Ok((job, _)) = bincode::serde::decode_from_slice::<CronJob, _>(bytes, cfg) {
        return Ok((job, false));
    }
    let (v0, mut pos): (legacy::CronJobV0, usize) =
        bincode::serde::decode_from_slice(bytes, cfg)?;
    let targets = legacy::tail(bytes, &mut pos)?;
    let catalog_id = legacy::tail(bytes, &mut pos)?;
    let sandbox = legacy::tail(bytes, &mut pos)?;
    let run_as_user = legacy::tail(bytes, &mut pos)?;
    let timeout_secs = legacy::tail(bytes, &mut pos)?;
    if pos != bytes.len() {
        anyhow::bail!(
            "cron record has {} trailing byte(s) after every known field",
            bytes.len() - pos
        );
    }
    Ok((
        CronJob {
            id: v0.id,
            name: v0.name,
            schedule: v0.schedule,
            script: v0.script,
            enabled: v0.enabled,
            last_run: v0.last_run,
            next_run: v0.next_run,
            created_at: v0.created_at,
            tags: v0.tags,
            targets,
            catalog_id,
            sandbox,
            run_as_user,
            timeout_secs,
        },
        true,
    ))
}

mod legacy {
    use anyhow::Result;
    use serde::de::DeserializeOwned;
    use serde::Deserialize;

    /// `CronJob` as first shipped; every later field was appended after `tags`.
    #[derive(Deserialize)]
    pub(super) struct CronJobV0 {
        pub id: String,
        pub name: String,
        pub schedule: String,
        pub script: String,
        pub enabled: bool,
        pub last_run: Option<u64>,
        pub next_run: u64,
        pub created_at: u64,
        pub tags: Vec<String>,
    }

    /// Decode the next appended field at `pos`, or its default once the
    /// record is exhausted (the record predates the field).
    pub(super) fn tail<T: DeserializeOwned + Default>(bytes: &[u8], pos: &mut usize) -> Result<T> {
        if *pos >= bytes.len() {
            return Ok(T::default());
        }
        let (value, n) =
            bincode::serde::decode_from_slice(&bytes[*pos..], bincode::config::standard())?;
        *pos += n;
        Ok(value)
    }
}

/// Keys we have already warned about decoding (one warn per daemon lifetime
/// per key). Prevents log spam when the scheduler polls every 15s.
fn warned_corrupt_keys() -> &'static Mutex<HashSet<String>> {
    static W: OnceLock<Mutex<HashSet<String>>> = OnceLock::new();
    W.get_or_init(|| Mutex::new(HashSet::new()))
}

impl Datastore {
    /// Add a cron job. Overwrites if the ID already exists.
    pub fn cron_add(&self, job: &CronJob) -> Result<()> {
        remote_dispatch!(self,
            DsRequest::CronAdd { job: job.clone() },
            DsResponse::Ok => ()
        );
        // Validate the cron expression
        job.schedule.parse::<cron::Schedule>().map_err(|e| {
            anyhow::anyhow!("Invalid cron expression '{}': {e}", job.schedule)
        })?;

        let bytes = bincode::serde::encode_to_vec(job, bincode::config::standard())?;
        let txn = self.local_db().begin_write()?;
        {
            let mut table = txn.open_table(CRON_TABLE)?;
            table.insert(job.id.as_str(), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Remove a cron job. Returns true if it existed.
    pub fn cron_remove(&self, id: &str) -> Result<bool> {
        remote_dispatch!(self,
            DsRequest::CronRemove { id: id.into() },
            DsResponse::Bool(b) => b
        );
        let txn = self.local_db().begin_write()?;
        let existed = {
            let mut table = txn.open_table(CRON_TABLE)?;
            table.remove(id)?.is_some()
        };
        if existed {
            // Drop its run history in the same transaction: the runs table is
            // Local-only, so a remote `hop cron delete` has no other way.
            let mut runs = txn.open_table(CRON_RUNS_TABLE)?;
            let started: Vec<u64> = runs
                .range((id, 0u64)..(id, u64::MAX))?
                .map(|item| item.map(|(k, _)| k.value().1))
                .collect::<Result<_, _>>()?;
            for ts in started {
                runs.remove((id, ts))?;
            }
        }
        txn.commit()?;
        Ok(existed)
    }

    /// List all cron jobs. Undecodable entries (e.g. from schema-breaking
    /// changes to `CronJob`) are skipped with a one-time warning per key,
    /// so a single bad record can't poison the whole scheduler.
    pub fn cron_list(&self) -> Result<Vec<CronJob>> {
        remote_dispatch!(self,
            DsRequest::CronList,
            DsResponse::CronJobs(jobs) => jobs
        );
        let txn = self.local_db().begin_read()?;
        let table = match txn.open_table(CRON_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut jobs = Vec::new();
        for item in table.iter()? {
            let (key_guard, val_guard) = item?;
            let key = key_guard.value();
            let bytes = val_guard.value();
            match decode_job(bytes) {
                Ok((job, _)) => jobs.push(job),
                Err(e) => {
                    let mut warned = warned_corrupt_keys().lock().unwrap();
                    if warned.insert(key.to_string()) {
                        tracing::warn!(
                            "Corrupt cron entry '{key}' skipped: {e}. \
                             Remove it with `hop cron delete {key}` or call \
                             `Datastore::cron_purge_corrupt`.",
                        );
                    }
                }
            }
        }
        Ok(jobs)
    }

    /// Delete all cron entries that fail to decode with the current schema.
    /// Returns the keys that were purged. Intended as a manual repair path
    /// after schema-breaking changes to `CronJob`.
    pub fn cron_purge_corrupt(&self) -> Result<Vec<String>> {
        remote_dispatch!(self,
            DsRequest::CronPurgeCorrupt,
            DsResponse::StringList(keys) => keys
        );
        let mut corrupt: Vec<String> = Vec::new();
        {
            let txn = self.local_db().begin_read()?;
            let table = match txn.open_table(CRON_TABLE) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(e.into()),
            };
            for item in table.iter()? {
                let (key_guard, val_guard) = item?;
                let key = key_guard.value().to_string();
                let bytes = val_guard.value();
                if decode_job(bytes).is_err() {
                    corrupt.push(key);
                }
            }
        }
        if !corrupt.is_empty() {
            let txn = self.local_db().begin_write()?;
            {
                let mut table = txn.open_table(CRON_TABLE)?;
                for key in &corrupt {
                    table.remove(key.as_str())?;
                }
            }
            txn.commit()?;
            // Reset the warn-set so future corruption surfaces a fresh warning.
            warned_corrupt_keys().lock().unwrap().clear();
        }
        Ok(corrupt)
    }

    /// Rewrite every record still in an older `CronJob` layout in the current
    /// one, so later reads take the fast path and a future field append only
    /// has one layout to bridge. Local only: the daemon runs it when it opens
    /// the datastore. Returns the ids rewritten.
    pub fn cron_migrate_legacy(&self) -> Result<Vec<String>> {
        let mut rewrite: Vec<(String, Vec<u8>)> = Vec::new();
        {
            let txn = self.local_db().begin_read()?;
            let table = match txn.open_table(CRON_TABLE) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
                Err(e) => return Err(e.into()),
            };
            for item in table.iter()? {
                let (key_guard, val_guard) = item?;
                if let Ok((job, true)) = decode_job(val_guard.value()) {
                    let bytes =
                        bincode::serde::encode_to_vec(&job, bincode::config::standard())?;
                    rewrite.push((key_guard.value().to_string(), bytes));
                }
            }
        }
        if rewrite.is_empty() {
            return Ok(Vec::new());
        }
        let txn = self.local_db().begin_write()?;
        {
            let mut table = txn.open_table(CRON_TABLE)?;
            for (key, bytes) in &rewrite {
                table.insert(key.as_str(), bytes.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(rewrite.into_iter().map(|(k, _)| k).collect())
    }

    /// Get a cron job by ID.
    pub fn cron_get(&self, id: &str) -> Result<Option<CronJob>> {
        remote_dispatch!(self,
            DsRequest::CronGet { id: id.into() },
            DsResponse::CronJob(j) => *j
        );
        let txn = self.local_db().begin_read()?;
        let table = match txn.open_table(CRON_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(id)? {
            Some(guard) => {
                let (job, _) = decode_job(guard.value())?;
                Ok(Some(job))
            }
            None => Ok(None),
        }
    }

    /// Find a cron job by its catalog ID. Returns the first match.
    pub fn cron_find_by_catalog_id(&self, catalog_id: &str) -> Result<Option<CronJob>> {
        remote_dispatch!(self,
            DsRequest::CronFindByCatalogId { catalog_id: catalog_id.into() },
            DsResponse::CronJob(j) => *j
        );
        let jobs = self.cron_list()?;
        Ok(jobs
            .into_iter()
            .find(|j| j.catalog_id.as_deref() == Some(catalog_id)))
    }

    /// Get all enabled cron jobs that are due for execution.
    pub fn cron_get_due(&self, now: u64) -> Result<Vec<CronJob>> {
        remote_dispatch!(self,
            DsRequest::CronGetDue { now_ms: now },
            DsResponse::CronJobs(jobs) => jobs
        );
        let jobs = self.cron_list()?;
        Ok(jobs
            .into_iter()
            .filter(|j| j.enabled && j.next_run <= now)
            .collect())
    }

    /// Update the last_run timestamp and compute the next_run for a cron job.
    pub fn cron_update_last_run(&self, id: &str, timestamp: u64, next_run: u64) -> Result<()> {
        remote_dispatch!(self,
            DsRequest::CronUpdateLastRun { id: id.into(), ts: timestamp, next_run },
            DsResponse::Ok => ()
        );
        let txn = self.local_db().begin_write()?;
        {
            let mut table = txn.open_table(CRON_TABLE)?;
            let guard = table
                .get(id)?
                .ok_or_else(|| anyhow::anyhow!("Cron job not found: {id}"))?;
            let (mut job, _) = decode_job(guard.value())?;
            drop(guard);

            job.last_run = Some(timestamp);
            job.next_run = next_run;

            let new_bytes = bincode::serde::encode_to_vec(&job, bincode::config::standard())?;
            table.insert(id, new_bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }
}

/// Runs kept per job; older ones are pruned when a run finishes.
pub const CRON_RUNS_KEEP: usize = 50;
/// Longest message stored with a run.
pub const CRON_RUN_MESSAGE_MAX: usize = 500;

impl Datastore {
    /// Record that a run of `job_id` started at `started_ms` (Local only; the
    /// scheduler runs inside the daemon).
    pub fn cron_run_start(&self, job_id: &str, started_ms: u64) -> Result<()> {
        let run = CronRun {
            job_id: job_id.to_string(),
            started_ms,
            ended_ms: None,
            status: CronRunStatus::Running,
            message: String::new(),
        };
        self.cron_run_put(&run)
    }

    /// Finish the run started at `started_ms` with a status and message
    /// (truncated to [`CRON_RUN_MESSAGE_MAX`]), then prune to
    /// [`CRON_RUNS_KEEP`] runs for the job.
    pub fn cron_run_finish(
        &self,
        job_id: &str,
        started_ms: u64,
        ended_ms: u64,
        status: CronRunStatus,
        message: &str,
    ) -> Result<()> {
        let run = CronRun {
            job_id: job_id.to_string(),
            started_ms,
            ended_ms: Some(ended_ms),
            status,
            message: truncate_chars(message, CRON_RUN_MESSAGE_MAX),
        };
        self.cron_run_put(&run)?;
        self.cron_runs_prune(job_id, CRON_RUNS_KEEP)?;
        Ok(())
    }

    fn cron_run_put(&self, run: &CronRun) -> Result<()> {
        let txn = self.local_db().begin_write()?;
        {
            let mut table = txn.open_table(CRON_RUNS_TABLE)?;
            let bytes = bincode::serde::encode_to_vec(run, bincode::config::standard())?;
            table.insert((run.job_id.as_str(), run.started_ms), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// The most recent `limit` runs of `job_id`, newest first.
    pub fn cron_runs(&self, job_id: &str, limit: usize) -> Result<Vec<CronRun>> {
        remote_dispatch!(self,
            DsRequest::CronRuns { id: job_id.to_string(), limit: limit as u32 },
            DsResponse::CronRuns(runs) => runs
        );
        let txn = self.local_db().begin_read()?;
        let table = match txn.open_table(CRON_RUNS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut runs = Vec::new();
        for item in table.range((job_id, 0u64)..(job_id, u64::MAX))?.rev() {
            let (_, v) = item?;
            if let Ok((run, _)) = bincode::serde::decode_from_slice::<CronRun, _>(v.value(), bincode::config::standard()) {
                runs.push(run);
            }
            if runs.len() >= limit {
                break;
            }
        }
        Ok(runs)
    }

    /// Drop all but the newest `keep` runs of `job_id`.
    pub fn cron_runs_prune(&self, job_id: &str, keep: usize) -> Result<usize> {
        let txn = self.local_db().begin_write()?;
        let removed = {
            let mut table = txn.open_table(CRON_RUNS_TABLE)?;
            let mut keys: Vec<u64> = Vec::new();
            for item in table.range((job_id, 0u64)..(job_id, u64::MAX))? {
                let (k, _) = item?;
                keys.push(k.value().1);
            }
            let mut removed = 0;
            if keys.len() > keep {
                for started in &keys[..keys.len() - keep] {
                    table.remove((job_id, *started))?;
                    removed += 1;
                }
            }
            removed
        };
        txn.commit()?;
        Ok(removed)
    }

    /// Mark runs still `Running` as `Interrupted`: called once when the
    /// scheduler starts, since a run cannot survive the daemon that ran it.
    pub fn cron_runs_mark_interrupted(&self, now_ms: u64) -> Result<usize> {
        let txn = self.local_db().begin_write()?;
        let fixed = {
            let mut table = match txn.open_table(CRON_RUNS_TABLE) {
                Ok(t) => t,
                Err(_) => return Ok(0),
            };
            let mut stale: Vec<CronRun> = Vec::new();
            for item in table.iter()? {
                let (_, v) = item?;
                if let Ok((run, _)) = bincode::serde::decode_from_slice::<CronRun, _>(v.value(), bincode::config::standard())
                    && run.status == CronRunStatus::Running
                {
                    stale.push(run);
                }
            }
            for mut run in stale.iter().cloned() {
                run.status = CronRunStatus::Interrupted;
                run.ended_ms = Some(now_ms);
                run.message = "the daemon restarted while this run was in flight".to_string();
                let bytes = bincode::serde::encode_to_vec(&run, bincode::config::standard())?;
                table.insert((run.job_id.as_str(), run.started_ms), bytes.as_slice())?;
            }
            stale.len()
        };
        txn.commit()?;
        Ok(fixed)
    }
}

fn truncate_chars(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    let mut out: String = s.chars().take(max).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_job(id: &str, schedule: &str, enabled: bool, next_run: u64) -> CronJob {
        CronJob {
            id: id.to_string(),
            name: format!("Job {id}"),
            schedule: schedule.to_string(),
            script: "return 'ok'".to_string(),
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
    fn cron_crud() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        // Add
        let job = make_job("j1", "0 * * * * *", true, 5000);
        ds.cron_add(&job).unwrap();

        // Get
        let got = ds.cron_get("j1").unwrap().unwrap();
        assert_eq!(got.name, "Job j1");

        // List
        let list = ds.cron_list().unwrap();
        assert_eq!(list.len(), 1);

        // Remove
        assert!(ds.cron_remove("j1").unwrap());
        assert!(!ds.cron_remove("j1").unwrap());
        assert!(ds.cron_get("j1").unwrap().is_none());
    }

    #[test]
    fn cron_get_due_filters() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        ds.cron_add(&make_job("j1", "0 * * * * *", true, 1000)).unwrap();
        ds.cron_add(&make_job("j2", "0 * * * * *", true, 5000)).unwrap();
        ds.cron_add(&make_job("j3", "0 * * * * *", false, 1000)).unwrap(); // disabled

        let due = ds.cron_get_due(3000).unwrap();
        assert_eq!(due.len(), 1);
        assert_eq!(due[0].id, "j1");
    }

    #[test]
    fn cron_update_last_run() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        ds.cron_add(&make_job("j1", "0 * * * * *", true, 1000)).unwrap();
        ds.cron_update_last_run("j1", 2000, 3000).unwrap();

        let job = ds.cron_get("j1").unwrap().unwrap();
        assert_eq!(job.last_run, Some(2000));
        assert_eq!(job.next_run, 3000);
    }

    #[test]
    fn cron_find_by_catalog_id_works() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        let mut job = make_job("j1", "0 * * * * *", true, 5000);
        job.catalog_id = Some("fleet-metrics".to_string());
        ds.cron_add(&job).unwrap();

        ds.cron_add(&make_job("j2", "0 * * * * *", true, 5000)).unwrap();

        let found = ds.cron_find_by_catalog_id("fleet-metrics").unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().id, "j1");

        let not_found = ds.cron_find_by_catalog_id("nonexistent").unwrap();
        assert!(not_found.is_none());
    }

    #[test]
    fn cron_list_skips_corrupt_entries_and_returns_rest() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        ds.cron_add(&make_job("good1", "0 * * * * *", true, 1000))
            .unwrap();
        ds.cron_add(&make_job("good2", "0 * * * * *", true, 2000))
            .unwrap();

        // Inject a corrupt (truncated) entry directly into the table.
        {
            let txn = ds.local_db().begin_write().unwrap();
            {
                let mut table = txn.open_table(CRON_TABLE).unwrap();
                table.insert("corrupt", &b"\x00\x01\x02"[..]).unwrap();
            }
            txn.commit().unwrap();
        }

        let jobs = ds.cron_list().unwrap();
        let ids: Vec<_> = jobs.iter().map(|j| j.id.as_str()).collect();
        assert_eq!(jobs.len(), 2, "corrupt entry should be skipped, got {ids:?}");
        assert!(ids.contains(&"good1"));
        assert!(ids.contains(&"good2"));

        let due = ds.cron_get_due(5000).unwrap();
        assert_eq!(due.len(), 2, "cron_get_due must also tolerate corruption");
    }

    #[test]
    fn cron_purge_corrupt_removes_bad_entries() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        ds.cron_add(&make_job("keep", "0 * * * * *", true, 1000))
            .unwrap();

        {
            let txn = ds.local_db().begin_write().unwrap();
            {
                let mut table = txn.open_table(CRON_TABLE).unwrap();
                table.insert("bad1", &b"\xff\xff"[..]).unwrap();
                table.insert("bad2", &b"\x01"[..]).unwrap();
            }
            txn.commit().unwrap();
        }

        let purged = ds.cron_purge_corrupt().unwrap();
        assert_eq!(purged.len(), 2);
        assert!(purged.contains(&"bad1".to_string()));
        assert!(purged.contains(&"bad2".to_string()));

        let jobs = ds.cron_list().unwrap();
        assert_eq!(jobs.len(), 1);
        assert_eq!(jobs[0].id, "keep");
    }

    #[test]
    fn cron_invalid_schedule_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        let job = make_job("bad", "not a cron expr", true, 1000);
        assert!(ds.cron_add(&job).is_err());
    }
    #[test]
    fn cron_runs_record_finish_prune_and_interrupt() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("t.redb")).unwrap();
        ds.cron_run_start("j1", 1000).unwrap();
        let running = ds.cron_runs("j1", 10).unwrap();
        assert_eq!(running.len(), 1);
        assert_eq!(running[0].status, CronRunStatus::Running);
        ds.cron_run_finish("j1", 1000, 1500, CronRunStatus::Ok, "done").unwrap();
        let runs = ds.cron_runs("j1", 10).unwrap();
        assert_eq!(runs[0].status, CronRunStatus::Ok);
        assert_eq!(runs[0].duration_ms(), Some(500));
        assert_eq!(runs[0].message, "done");
        // Newest first, bounded by limit.
        for t in 2000..2060u64 {
            ds.cron_run_start("j1", t).unwrap();
            ds.cron_run_finish("j1", t, t + 1, CronRunStatus::Error, "boom").unwrap();
        }
        let runs = ds.cron_runs("j1", 5).unwrap();
        assert_eq!(runs.len(), 5);
        assert_eq!(runs[0].started_ms, 2059);
        assert!(ds.cron_runs("j1", 1000).unwrap().len() <= CRON_RUNS_KEEP);
        // Other jobs are untouched; a stale Running run is marked interrupted.
        ds.cron_run_start("j2", 5000).unwrap();
        assert_eq!(ds.cron_runs_mark_interrupted(6000).unwrap(), 1);
        let j2 = ds.cron_runs("j2", 1).unwrap();
        assert_eq!(j2[0].status, CronRunStatus::Interrupted);
        assert_eq!(j2[0].ended_ms, Some(6000));
        // Long messages are truncated.
        let long = "x".repeat(2000);
        ds.cron_run_finish("j2", 5000, 6001, CronRunStatus::Error, &long).unwrap();
        assert!(ds.cron_runs("j2", 1).unwrap()[0].message.chars().count() <= CRON_RUN_MESSAGE_MAX + 1);
        assert_eq!(ds.cron_runs_prune("j2", 0).unwrap(), 1);
        assert!(ds.cron_runs("j2", 1).unwrap().is_empty());
    }

    /// `CronJob` as written by 0.9.37 and earlier: everything but `timeout_secs`.
    #[derive(serde::Serialize)]
    struct CronJobBefore0938 {
        id: String,
        name: String,
        schedule: String,
        script: String,
        enabled: bool,
        last_run: Option<u64>,
        next_run: u64,
        created_at: u64,
        tags: Vec<String>,
        targets: Option<String>,
        catalog_id: Option<String>,
        sandbox: Option<crate::sandbox::SandboxPolicy>,
        run_as_user: Option<String>,
    }

    fn insert_raw(ds: &Datastore, id: &str, bytes: &[u8]) {
        let txn = ds.local_db().begin_write().unwrap();
        {
            let mut table = txn.open_table(CRON_TABLE).unwrap();
            table.insert(id, bytes).unwrap();
        }
        txn.commit().unwrap();
    }

    fn raw_decodes_as_current(ds: &Datastore, id: &str) -> bool {
        let txn = ds.local_db().begin_read().unwrap();
        let table = txn.open_table(CRON_TABLE).unwrap();
        let guard = table.get(id).unwrap().unwrap();
        bincode::serde::decode_from_slice::<CronJob, _>(guard.value(), bincode::config::standard())
            .is_ok()
    }

    #[test]
    fn cron_reads_records_written_before_fields_were_appended() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        let cfg = bincode::config::standard();

        // 0.9.37 layout: one field short of the current struct.
        let v2 = CronJobBefore0938 {
            id: "mail".into(),
            name: "cap:email-monitor".into(),
            schedule: "0 0 * * * *".into(),
            script: "return 'mail'".into(),
            enabled: true,
            last_run: Some(5),
            next_run: 10,
            created_at: 1,
            tags: vec!["t".into()],
            targets: None,
            catalog_id: Some("cat".into()),
            sandbox: None,
            run_as_user: Some("jason".into()),
        };
        insert_raw(&ds, "mail", &bincode::serde::encode_to_vec(&v2, cfg).unwrap());
        // First-release layout: nothing after `tags`.
        let v0 = (
            "old".to_string(),
            "Relay Health".to_string(),
            "0 */5 * * * *".to_string(),
            "return 1".to_string(),
            true,
            None::<u64>,
            20u64,
            2u64,
            Vec::<String>::new(),
        );
        insert_raw(&ds, "old", &bincode::serde::encode_to_vec(&v0, cfg).unwrap());
        // Real garbage must still be rejected, not mis-read as a job.
        insert_raw(&ds, "bad", b"\x01\x02");

        assert!(!raw_decodes_as_current(&ds, "mail"));
        assert!(!raw_decodes_as_current(&ds, "old"));

        let mut jobs = ds.cron_list().unwrap();
        jobs.sort_by(|a, b| a.id.cmp(&b.id));
        assert_eq!(jobs.len(), 2);
        assert_eq!(jobs[0].id, "mail");
        assert_eq!(jobs[0].run_as_user.as_deref(), Some("jason"));
        assert_eq!(jobs[0].catalog_id.as_deref(), Some("cat"));
        assert_eq!(jobs[0].timeout_secs, None);
        assert_eq!(jobs[1].id, "old");
        assert_eq!(jobs[1].next_run, 20);
        assert_eq!(jobs[1].run_as_user, None);

        assert_eq!(ds.cron_get("mail").unwrap().unwrap().name, "cap:email-monitor");
        assert_eq!(ds.cron_get_due(15).unwrap().len(), 1);
        ds.cron_update_last_run("old", 21, 30).unwrap();
        assert_eq!(ds.cron_get("old").unwrap().unwrap().next_run, 30);

        // Purge removes only what no layout can decode.
        assert_eq!(ds.cron_purge_corrupt().unwrap(), vec!["bad".to_string()]);
        assert_eq!(ds.cron_list().unwrap().len(), 2);
    }

    #[test]
    fn cron_legacy_records_are_rewritten_on_open() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");
        let cfg = bincode::config::standard();
        {
            let ds = Datastore::open(&path).unwrap();
            let v2 = CronJobBefore0938 {
                id: "mail".into(),
                name: "mail".into(),
                schedule: "0 0 * * * *".into(),
                script: "return 1".into(),
                enabled: true,
                last_run: None,
                next_run: 10,
                created_at: 1,
                tags: vec![],
                targets: None,
                catalog_id: None,
                sandbox: None,
                run_as_user: Some("jason".into()),
            };
            insert_raw(&ds, "mail", &bincode::serde::encode_to_vec(&v2, cfg).unwrap());
            ds.cron_add(&make_job("fresh", "0 * * * * *", true, 1)).unwrap();
            assert!(!raw_decodes_as_current(&ds, "mail"));
        }
        // Reopening (what the daemon does on start) migrates in place.
        let ds = Datastore::open(&path).unwrap();
        assert!(raw_decodes_as_current(&ds, "mail"));
        assert!(raw_decodes_as_current(&ds, "fresh"));
        assert_eq!(ds.cron_migrate_legacy().unwrap(), Vec::<String>::new());
        let mail = ds.cron_get("mail").unwrap().unwrap();
        assert_eq!(mail.run_as_user.as_deref(), Some("jason"));
        assert_eq!(mail.timeout_secs, None);
    }

    #[test]
    fn cron_remove_drops_run_history() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        ds.cron_add(&make_job("j", "0 * * * * *", true, 1)).unwrap();
        ds.cron_run_start("j", 100).unwrap();
        ds.cron_run_finish("j", 100, 110, CronRunStatus::Ok, "fine").unwrap();
        assert_eq!(ds.cron_runs("j", 10).unwrap().len(), 1);
        assert!(ds.cron_remove("j").unwrap());
        assert!(ds.cron_runs("j", 10).unwrap().is_empty());
        assert!(!ds.cron_remove("j").unwrap());
    }
}
