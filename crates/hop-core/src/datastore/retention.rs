//! TTL-based cleanup for time-series data.

use anyhow::Result;
#[allow(unused_imports)]
use redb::ReadableTable;

use super::tables::TS_TABLE;
use super::Datastore;

impl Datastore {
    /// Purge time-series data points older than the given timestamp (exclusive).
    /// Returns the number of deleted points.
    pub fn ts_purge_before(&self, metric: &str, before: u64) -> Result<u64> {
        // Phase 1: read keys to delete
        let keys_to_delete = {
            let txn = self.db.begin_read()?;
            let table = match txn.open_table(TS_TABLE) {
                Ok(t) => t,
                Err(redb::TableError::TableDoesNotExist(_)) => return Ok(0),
                Err(e) => return Err(e.into()),
            };
            let start = (metric, 0u64);
            let end = (metric, before);
            let iter = table.range(start..end)?;
            let mut keys = Vec::new();
            for item in iter {
                let (key_guard, _) = item?;
                let (m, ts) = key_guard.value();
                if m != metric {
                    break;
                }
                keys.push(ts);
            }
            keys
        };

        if keys_to_delete.is_empty() {
            return Ok(0);
        }

        // Phase 2: delete collected keys
        let count = keys_to_delete.len() as u64;
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(TS_TABLE)?;
            for ts in keys_to_delete {
                table.remove((metric, ts))?;
            }
        }
        txn.commit()?;
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::super::types::MetricPoint;
    use super::*;

    #[test]
    fn purge_old_data() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        let point = MetricPoint {
            value: 1.0,
            tags: BTreeMap::new(),
        };

        for i in 0..10 {
            ds.ts_insert_at("cpu", i * 1000, &point).unwrap();
        }

        // Purge points before ts=5000 (exclusive)
        let deleted = ds.ts_purge_before("cpu", 5000).unwrap();
        assert_eq!(deleted, 5); // 0, 1000, 2000, 3000, 4000

        // Verify remaining
        let query = super::super::types::TimeSeriesQuery {
            metric: "cpu".to_string(),
            start: 0,
            end: u64::MAX,
            tags_filter: None,
            limit: None,
        };
        let remaining = ds.ts_query(&query).unwrap();
        assert_eq!(remaining.len(), 5);
        assert_eq!(remaining[0].0, 5000);
    }

    #[test]
    fn purge_nonexistent_metric() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        let deleted = ds.ts_purge_before("nonexistent", 5000).unwrap();
        assert_eq!(deleted, 0);
    }
}
