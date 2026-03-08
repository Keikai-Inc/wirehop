//! Cron job CRUD operations on the embedded datastore.

use anyhow::Result;
#[allow(unused_imports)]
use redb::ReadableTable;

use super::tables::CRON_TABLE;
use super::types::CronJob;
use super::Datastore;

impl Datastore {
    /// Add a cron job. Overwrites if the ID already exists.
    pub fn cron_add(&self, job: &CronJob) -> Result<()> {
        // Validate the cron expression
        job.schedule.parse::<cron::Schedule>().map_err(|e| {
            anyhow::anyhow!("Invalid cron expression '{}': {e}", job.schedule)
        })?;

        let bytes = bincode::serde::encode_to_vec(job, bincode::config::standard())?;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(CRON_TABLE)?;
            table.insert(job.id.as_str(), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Remove a cron job. Returns true if it existed.
    pub fn cron_remove(&self, id: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(CRON_TABLE)?;
            table.remove(id)?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    /// List all cron jobs.
    pub fn cron_list(&self) -> Result<Vec<CronJob>> {
        let txn = self.db.begin_read()?;
        let table = match txn.open_table(CRON_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut jobs = Vec::new();
        for item in table.iter()? {
            let (_, val_guard) = item?;
            let bytes = val_guard.value();
            let (job, _): (CronJob, _) =
                bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
            jobs.push(job);
        }
        Ok(jobs)
    }

    /// Get a cron job by ID.
    pub fn cron_get(&self, id: &str) -> Result<Option<CronJob>> {
        let txn = self.db.begin_read()?;
        let table = match txn.open_table(CRON_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(id)? {
            Some(guard) => {
                let bytes = guard.value();
                let (job, _): (CronJob, _) =
                    bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
                Ok(Some(job))
            }
            None => Ok(None),
        }
    }

    /// Get all enabled cron jobs that are due for execution.
    pub fn cron_get_due(&self, now: u64) -> Result<Vec<CronJob>> {
        let jobs = self.cron_list()?;
        Ok(jobs
            .into_iter()
            .filter(|j| j.enabled && j.next_run <= now)
            .collect())
    }

    /// Update the last_run timestamp and compute the next_run for a cron job.
    pub fn cron_update_last_run(&self, id: &str, timestamp: u64, next_run: u64) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(CRON_TABLE)?;
            let guard = table
                .get(id)?
                .ok_or_else(|| anyhow::anyhow!("Cron job not found: {id}"))?;
            let bytes = guard.value();
            let (mut job, _): (CronJob, _) =
                bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
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
    fn cron_invalid_schedule_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        let job = make_job("bad", "not a cron expr", true, 1000);
        assert!(ds.cron_add(&job).is_err());
    }
}
