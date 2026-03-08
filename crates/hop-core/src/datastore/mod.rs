//! Embedded datastore: KV, time-series, and cron job storage backed by redb.

pub mod cron;
pub mod kv;
pub mod retention;
pub mod tables;
pub mod timeseries;
pub mod types;

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

/// Embedded datastore wrapping a redb database.
///
/// Thread-safe via `Arc<redb::Database>` — clone freely across tokio tasks.
#[derive(Clone)]
pub struct Datastore {
    db: Arc<redb::Database>,
}

impl Datastore {
    /// Open (or create) a datastore at the given file path.
    pub fn open(path: &Path) -> Result<Self> {
        let db = redb::Database::create(path)
            .with_context(|| format!("Failed to open datastore at {}", path.display()))?;
        Ok(Self { db: Arc::new(db) })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn open_and_reopen() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.redb");

        // Create
        let ds = Datastore::open(&path).unwrap();
        ds.kv_set(
            "test",
            "key",
            &types::KvEntry {
                value: b"value".to_vec(),
                content_type: "text/plain".to_string(),
                updated_at: 1000,
            },
        )
        .unwrap();
        drop(ds);

        // Reopen and read
        let ds2 = Datastore::open(&path).unwrap();
        let entry = ds2.kv_get("test", "key").unwrap().unwrap();
        assert_eq!(entry.value, b"value");
    }

    #[test]
    fn clone_is_shared() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        let ds2 = ds.clone();

        ds.kv_set(
            "ns",
            "k",
            &types::KvEntry {
                value: b"v".to_vec(),
                content_type: "text/plain".to_string(),
                updated_at: 0,
            },
        )
        .unwrap();

        // Clone sees the same data
        assert!(ds2.kv_get("ns", "k").unwrap().is_some());
    }
}
