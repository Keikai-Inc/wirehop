//! Time-series operations on the embedded datastore.

use anyhow::Result;
#[allow(unused_imports)]
use redb::ReadableTable;

use super::protocol::{DsRequest, DsResponse};
use super::remote_dispatch;
use super::tables::TS_TABLE;
use super::types::{MetricPoint, TimeSeriesQuery};
use super::Datastore;

impl Datastore {
    /// Insert a time-series data point at the current time.
    pub fn ts_insert(&self, metric: &str, point: &MetricPoint) -> Result<()> {
        remote_dispatch!(self,
            DsRequest::TsInsert { metric: metric.into(), point: point.clone() },
            DsResponse::Ok => ()
        );
        self.ts_insert_at(metric, now_ms(), point)
    }

    /// Insert a time-series data point at a specific timestamp.
    pub fn ts_insert_at(&self, metric: &str, timestamp: u64, point: &MetricPoint) -> Result<()> {
        remote_dispatch!(self,
            DsRequest::TsInsertAt { metric: metric.into(), ts: timestamp, point: point.clone() },
            DsResponse::Ok => ()
        );
        let bytes = bincode::serde::encode_to_vec(point, bincode::config::standard())?;
        let txn = self.local_db().begin_write()?;
        {
            let mut table = txn.open_table(TS_TABLE)?;
            table.insert((metric, timestamp), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Query time-series data points in a range.
    pub fn ts_query(&self, query: &TimeSeriesQuery) -> Result<Vec<(u64, MetricPoint)>> {
        remote_dispatch!(self,
            DsRequest::TsQuery { query: query.clone() },
            DsResponse::TsPoints(pts) => pts
        );
        let txn = self.local_db().begin_read()?;
        let table = match txn.open_table(TS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let start = (query.metric.as_str(), query.start);
        let end = (query.metric.as_str(), query.end);
        let iter = table.range(start..=end)?;

        let mut results = Vec::new();
        for item in iter {
            let (key_guard, val_guard) = item?;
            let (item_metric, timestamp) = key_guard.value();
            if item_metric != query.metric {
                break;
            }

            let bytes = val_guard.value();
            let (point, _): (MetricPoint, _) =
                bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;

            // Apply tag filter if specified
            if let Some(ref filter) = query.tags_filter
                && !filter.iter().all(|(k, v)| point.tags.get(k) == Some(v))
            {
                continue;
            }

            results.push((timestamp, point));

            if let Some(limit) = query.limit
                && results.len() >= limit
            {
                break;
            }
        }

        Ok(results)
    }

    /// Get the latest data point for a metric.
    pub fn ts_latest(&self, metric: &str) -> Result<Option<(u64, MetricPoint)>> {
        remote_dispatch!(self,
            DsRequest::TsLatest { metric: metric.into() },
            DsResponse::TsLatest(v) => v
        );
        let txn = self.local_db().begin_read()?;
        let table = match txn.open_table(TS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };

        // Scan backwards from the maximum possible timestamp for this metric
        let start = (metric, 0u64);
        let end = (metric, u64::MAX);
        let iter = table.range(start..=end)?;

        let mut latest: Option<(u64, MetricPoint)> = None;
        for item in iter {
            let (key_guard, val_guard) = item?;
            let (item_metric, timestamp) = key_guard.value();
            if item_metric != metric {
                break;
            }
            let bytes = val_guard.value();
            let (point, _): (MetricPoint, _) =
                bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
            latest = Some((timestamp, point));
        }

        Ok(latest)
    }
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;

    #[test]
    fn ts_insert_and_query() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        let point = MetricPoint {
            value: 42.5,
            tags: BTreeMap::new(),
        };
        ds.ts_insert_at("cpu.usage", 1000, &point).unwrap();
        ds.ts_insert_at("cpu.usage", 2000, &MetricPoint { value: 55.0, tags: BTreeMap::new() }).unwrap();
        ds.ts_insert_at("cpu.usage", 3000, &MetricPoint { value: 30.0, tags: BTreeMap::new() }).unwrap();
        // Different metric
        ds.ts_insert_at("mem.usage", 1500, &MetricPoint { value: 80.0, tags: BTreeMap::new() }).unwrap();

        let query = TimeSeriesQuery {
            metric: "cpu.usage".to_string(),
            start: 1000,
            end: 2500,
            tags_filter: None,
            limit: None,
        };
        let results = ds.ts_query(&query).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, 1000);
        assert_eq!(results[0].1.value, 42.5);
        assert_eq!(results[1].0, 2000);
    }

    #[test]
    fn ts_latest() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        assert!(ds.ts_latest("cpu.usage").unwrap().is_none());

        ds.ts_insert_at("cpu.usage", 1000, &MetricPoint { value: 10.0, tags: BTreeMap::new() }).unwrap();
        ds.ts_insert_at("cpu.usage", 3000, &MetricPoint { value: 30.0, tags: BTreeMap::new() }).unwrap();
        ds.ts_insert_at("cpu.usage", 2000, &MetricPoint { value: 20.0, tags: BTreeMap::new() }).unwrap();

        let (ts, point) = ds.ts_latest("cpu.usage").unwrap().unwrap();
        assert_eq!(ts, 3000);
        assert_eq!(point.value, 30.0);
    }

    #[test]
    fn ts_query_with_tags_filter() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        let mut tags1 = BTreeMap::new();
        tags1.insert("host".to_string(), "web-1".to_string());
        let mut tags2 = BTreeMap::new();
        tags2.insert("host".to_string(), "web-2".to_string());

        ds.ts_insert_at("cpu", 1000, &MetricPoint { value: 10.0, tags: tags1.clone() }).unwrap();
        ds.ts_insert_at("cpu", 2000, &MetricPoint { value: 20.0, tags: tags2 }).unwrap();
        ds.ts_insert_at("cpu", 3000, &MetricPoint { value: 30.0, tags: tags1 }).unwrap();

        let query = TimeSeriesQuery {
            metric: "cpu".to_string(),
            start: 0,
            end: u64::MAX,
            tags_filter: Some({
                let mut f = BTreeMap::new();
                f.insert("host".to_string(), "web-1".to_string());
                f
            }),
            limit: None,
        };
        let results = ds.ts_query(&query).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].1.value, 10.0);
        assert_eq!(results[1].1.value, 30.0);
    }

    #[test]
    fn ts_query_with_limit() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        for i in 0..10 {
            ds.ts_insert_at("m", i * 1000, &MetricPoint { value: i as f64, tags: BTreeMap::new() }).unwrap();
        }

        let query = TimeSeriesQuery {
            metric: "m".to_string(),
            start: 0,
            end: u64::MAX,
            tags_filter: None,
            limit: Some(3),
        };
        let results = ds.ts_query(&query).unwrap();
        assert_eq!(results.len(), 3);
    }
}
