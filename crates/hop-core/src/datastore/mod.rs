//! Embedded datastore: KV, time-series, and cron job storage backed by redb.
//!
//! Supports two modes:
//! - **Local**: direct access to a redb database file (used by the daemon).
//! - **Remote**: connects to the daemon's Unix socket (used by `hop mcp`).

pub mod cron;
pub mod kv;
pub mod protocol;
pub mod retention;
pub mod secrets;
pub mod socket;
pub mod tables;
pub mod timeseries;
pub mod types;

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};

/// Embedded datastore wrapping a redb database or a daemon socket connection.
///
/// Thread-safe — clone freely across tokio tasks.
#[derive(Clone)]
pub struct Datastore {
    inner: Arc<DatastoreInner>,
}

pub(crate) enum DatastoreInner {
    Local {
        db: redb::Database,
        secrets_key: Option<[u8; 32]>,
    },
    Remote(socket::DaemonConnection),
}

/// Derive the AEAD encryption key for secrets from an Ed25519 secret key.
///
/// Uses SHA-256 with a domain separator to prevent cross-protocol key reuse.
pub fn derive_secrets_key(identity_key: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(b"hop-secrets-v1");
    hasher.update(identity_key);
    hasher.finalize().into()
}

/// Dispatch a request to the daemon socket and extract the expected response variant.
///
/// Usage:
/// ```ignore
/// remote_dispatch!(self,
///     DsRequest::KvGet { ns: ns.into(), key: key.into() },
///     DsResponse::KvEntry(e) => e
/// );
/// ```
macro_rules! remote_dispatch {
    ($self:ident, $req:expr, $pat:pat => $val:expr) => {
        if let $crate::datastore::DatastoreInner::Remote(conn) = $self.inner.as_ref() {
            let resp = conn.request(&$req)?;
            return match resp {
                $pat => Ok($val),
                $crate::datastore::protocol::DsResponse::Error(msg) => Err(anyhow::anyhow!("{msg}")),
                other => Err(anyhow::anyhow!("unexpected response: {other:?}")),
            };
        }
    };
}
pub(crate) use remote_dispatch;

impl Datastore {
    /// Open (or create) a datastore at the given file path (Local mode).
    pub fn open(path: &Path) -> Result<Self> {
        Self::open_inner(path, None)
    }

    /// Open (or create) a datastore with an encryption key for secrets.
    ///
    /// The key should be derived via [`derive_secrets_key`] from the Ed25519 identity.
    pub fn open_with_secrets(path: &Path, secrets_key: [u8; 32]) -> Result<Self> {
        Self::open_inner(path, Some(secrets_key))
    }

    fn open_inner(path: &Path, secrets_key: Option<[u8; 32]>) -> Result<Self> {
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

        Ok(Self {
            inner: Arc::new(DatastoreInner::Local { db, secrets_key }),
        })
    }

    /// Connect to the daemon's Unix socket (Remote mode).
    pub fn connect(config_dir: &Path) -> Result<Self> {
        let conn = socket::DaemonConnection::connect(config_dir)?;
        Ok(Self {
            inner: Arc::new(DatastoreInner::Remote(conn)),
        })
    }

    /// Get a reference to the local redb database.
    ///
    /// # Panics
    /// Panics if called on a Remote datastore (should never happen — Remote
    /// methods return early via `remote_dispatch!`).
    fn local_db(&self) -> &redb::Database {
        match self.inner.as_ref() {
            DatastoreInner::Local { db, .. } => db,
            DatastoreInner::Remote(_) => unreachable!("local_db() called on Remote datastore"),
        }
    }

    /// Get the secrets encryption key (Local mode only).
    fn secrets_key(&self) -> Result<&[u8; 32]> {
        match self.inner.as_ref() {
            DatastoreInner::Local {
                secrets_key: Some(key),
                ..
            } => Ok(key),
            DatastoreInner::Local {
                secrets_key: None, ..
            } => {
                Err(anyhow::anyhow!(
                    "Secrets key not configured — open with open_with_secrets()"
                ))
            }
            DatastoreInner::Remote(_) => unreachable!("secrets_key() called on Remote datastore"),
        }
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
