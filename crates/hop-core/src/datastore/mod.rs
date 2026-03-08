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

        // If the parent directory has the setgid bit, make the file group-writable
        // so unprivileged users in the same group can open it. Ignore errors —
        // non-owners can't chmod, but a prior daemon run will have fixed it.
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            use std::os::unix::fs::PermissionsExt;
            if let Some(parent) = path.parent()
                && let Ok(dir_meta) = std::fs::metadata(parent)
                && dir_meta.mode() & 0o2000 != 0
                && let Ok(file_meta) = std::fs::metadata(path)
            {
                let current = file_meta.mode() & 0o777;
                if current != 0o660 {
                    let _ = std::fs::set_permissions(
                        path,
                        std::fs::Permissions::from_mode(0o660),
                    );
                }
            }
        }

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
