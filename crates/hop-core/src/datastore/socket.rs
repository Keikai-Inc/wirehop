//! Unix socket transport for daemon datastore access.
//!
//! **Server** (`spawn_listener`): async, runs inside the daemon (tokio).
//! **Client** (`DaemonConnection`): sync, used by `hop mcp` and other out-of-process consumers.

use std::io::{Read, Write};
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use anyhow::{Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::task::JoinHandle;

use super::protocol::{DsRequest, DsResponse};
use super::Datastore;

const SOCKET_NAME: &str = "daemon.sock";
const MAX_FRAME: usize = 16 * 1024 * 1024;

fn socket_path(config_dir: &Path) -> PathBuf {
    config_dir.join(SOCKET_NAME)
}

// ── Sync framing helpers (client side) ──────────────────────────────

fn write_frame(stream: &mut UnixStream, payload: &[u8]) -> Result<()> {
    let len = (payload.len() as u32).to_be_bytes();
    stream.write_all(&len).context("write frame length")?;
    stream.write_all(payload).context("write frame payload")?;
    stream.flush()?;
    Ok(())
}

fn read_frame(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut len_buf = [0u8; 4];
    stream.read_exact(&mut len_buf).context("read frame length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME {
        anyhow::bail!("frame too large: {len} bytes");
    }
    let mut payload = vec![0u8; len];
    stream.read_exact(&mut payload).context("read frame payload")?;
    Ok(payload)
}

// ── Client ──────────────────────────────────────────────────────────

/// Sync connection to the daemon's Unix socket.
pub struct DaemonConnection {
    stream: Mutex<UnixStream>,
}

impl DaemonConnection {
    /// Connect to the daemon socket in `config_dir`.
    pub fn connect(config_dir: &Path) -> Result<Self> {
        let path = socket_path(config_dir);
        let stream = UnixStream::connect(&path)
            .with_context(|| format!("connect to daemon socket at {}", path.display()))?;
        Ok(Self {
            stream: Mutex::new(stream),
        })
    }

    /// Send a request and receive the response (blocking).
    pub fn request(&self, req: &DsRequest) -> Result<DsResponse> {
        let payload = bincode::serde::encode_to_vec(req, bincode::config::standard())?;
        let mut stream = self.stream.lock().map_err(|e| anyhow::anyhow!("lock poisoned: {e}"))?;
        write_frame(&mut stream, &payload)?;
        let resp_bytes = read_frame(&mut stream)?;
        let (resp, _): (DsResponse, _) =
            bincode::serde::decode_from_slice(&resp_bytes, bincode::config::standard())?;
        Ok(resp)
    }
}

// ── Server ──────────────────────────────────────────────────────────

/// Spawn a Unix socket listener that serves datastore requests.
///
/// Returns a `JoinHandle` that removes the socket file when dropped/cancelled.
pub async fn spawn_listener(config_dir: &Path, datastore: Datastore) -> Result<JoinHandle<()>> {
    let path = socket_path(config_dir);

    // Remove stale socket from a previous crash
    if path.exists() {
        std::fs::remove_file(&path)
            .with_context(|| format!("remove stale socket at {}", path.display()))?;
    }

    let listener = UnixListener::bind(&path)
        .with_context(|| format!("bind daemon socket at {}", path.display()))?;

    // Set socket permissions to 0o660 (owner + group only)
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660));
    }

    tracing::info!("Daemon socket listening at {}", path.display());

    let path_for_cleanup = path.clone();
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let ds = datastore.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, ds).await {
                            tracing::debug!("Socket client disconnected: {e:#}");
                        }
                    });
                }
                Err(e) => {
                    tracing::warn!("Socket accept error: {e}");
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    });

    // Spawn cleanup task that runs when the main handle is dropped
    let cleanup_handle = handle;
    let wrapper = tokio::spawn(async move {
        cleanup_handle.await.ok();
        let _ = std::fs::remove_file(&path_for_cleanup);
    });

    Ok(wrapper)
}

async fn handle_connection(mut stream: tokio::net::UnixStream, ds: Datastore) -> Result<()> {
    loop {
        // Read request frame
        let mut len_buf = [0u8; 4];
        if stream.read_exact(&mut len_buf).await.is_err() {
            return Ok(()); // clean disconnect
        }
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_FRAME {
            anyhow::bail!("frame too large: {len} bytes");
        }
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).await?;

        let (req, _): (DsRequest, _) =
            bincode::serde::decode_from_slice(&payload, bincode::config::standard())?;

        // Dispatch to datastore (blocking) on a thread pool
        let ds_clone = ds.clone();
        let resp = tokio::task::spawn_blocking(move || dispatch_request(&ds_clone, req)).await??;

        // Write response frame
        let resp_bytes = bincode::serde::encode_to_vec(&resp, bincode::config::standard())?;
        let resp_len = (resp_bytes.len() as u32).to_be_bytes();
        stream.write_all(&resp_len).await?;
        stream.write_all(&resp_bytes).await?;
        stream.flush().await?;
    }
}

fn dispatch_request(ds: &Datastore, req: DsRequest) -> Result<DsResponse> {
    Ok(match req {
        DsRequest::KvGet { ns, key } => {
            DsResponse::KvEntry(ds.kv_get(&ns, &key)?)
        }
        DsRequest::KvSet { ns, key, entry } => {
            ds.kv_set(&ns, &key, &entry)?;
            DsResponse::Ok
        }
        DsRequest::KvDelete { ns, key } => {
            DsResponse::Bool(ds.kv_delete(&ns, &key)?)
        }
        DsRequest::KvList { ns, prefix } => {
            DsResponse::KvEntries(ds.kv_list(&ns, &prefix)?)
        }
        DsRequest::TsInsert { metric, point } => {
            ds.ts_insert(&metric, &point)?;
            DsResponse::Ok
        }
        DsRequest::TsInsertAt { metric, ts, point } => {
            ds.ts_insert_at(&metric, ts, &point)?;
            DsResponse::Ok
        }
        DsRequest::TsQuery { query } => {
            DsResponse::TsPoints(ds.ts_query(&query)?)
        }
        DsRequest::TsLatest { metric } => {
            DsResponse::TsLatest(ds.ts_latest(&metric)?)
        }
        DsRequest::CronAdd { job } => {
            ds.cron_add(&job)?;
            DsResponse::Ok
        }
        DsRequest::CronRemove { id } => {
            DsResponse::Bool(ds.cron_remove(&id)?)
        }
        DsRequest::CronList => {
            DsResponse::CronJobs(ds.cron_list()?)
        }
        DsRequest::CronGet { id } => {
            DsResponse::CronJob(ds.cron_get(&id)?)
        }
        DsRequest::CronFindByCatalogId { catalog_id } => {
            DsResponse::CronJob(ds.cron_find_by_catalog_id(&catalog_id)?)
        }
        DsRequest::CronGetDue { now_ms } => {
            DsResponse::CronJobs(ds.cron_get_due(now_ms)?)
        }
        DsRequest::CronUpdateLastRun { id, ts, next_run } => {
            ds.cron_update_last_run(&id, ts, next_run)?;
            DsResponse::Ok
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::datastore::types::{KvEntry, MetricPoint, CronJob, TimeSeriesQuery};
    use std::collections::BTreeMap;

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn socket_roundtrip_kv() {
        let dir = tempfile::tempdir().unwrap();
        let ds_path = dir.path().join("test.redb");
        let ds = Datastore::open(&ds_path).unwrap();

        let _listener = spawn_listener(dir.path(), ds).await.unwrap();

        // Give listener a moment to bind
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let conn = DaemonConnection::connect(dir.path()).unwrap();

        // Set
        let entry = KvEntry {
            value: b"hello".to_vec(),
            content_type: "text/plain".to_string(),
            updated_at: 1000,
        };
        let resp = conn.request(&DsRequest::KvSet {
            ns: "ns".into(),
            key: "k1".into(),
            entry: entry.clone(),
        }).unwrap();
        assert!(matches!(resp, DsResponse::Ok));

        // Get
        let resp = conn.request(&DsRequest::KvGet {
            ns: "ns".into(),
            key: "k1".into(),
        }).unwrap();
        match resp {
            DsResponse::KvEntry(Some(e)) => assert_eq!(e.value, b"hello"),
            other => panic!("expected KvEntry, got {other:?}"),
        }

        // List
        let resp = conn.request(&DsRequest::KvList {
            ns: "ns".into(),
            prefix: "".into(),
        }).unwrap();
        match resp {
            DsResponse::KvEntries(entries) => assert_eq!(entries.len(), 1),
            other => panic!("expected KvEntries, got {other:?}"),
        }

        // Delete
        let resp = conn.request(&DsRequest::KvDelete {
            ns: "ns".into(),
            key: "k1".into(),
        }).unwrap();
        assert!(matches!(resp, DsResponse::Bool(true)));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn socket_roundtrip_ts() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        let _listener = spawn_listener(dir.path(), ds).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let conn = DaemonConnection::connect(dir.path()).unwrap();

        // Insert
        let point = MetricPoint { value: 42.0, tags: BTreeMap::new() };
        let resp = conn.request(&DsRequest::TsInsertAt {
            metric: "cpu".into(),
            ts: 1000,
            point,
        }).unwrap();
        assert!(matches!(resp, DsResponse::Ok));

        // Query
        let resp = conn.request(&DsRequest::TsQuery {
            query: TimeSeriesQuery {
                metric: "cpu".into(),
                start: 0,
                end: u64::MAX,
                tags_filter: None,
                limit: None,
            },
        }).unwrap();
        match resp {
            DsResponse::TsPoints(pts) => {
                assert_eq!(pts.len(), 1);
                assert_eq!(pts[0].1.value, 42.0);
            }
            other => panic!("expected TsPoints, got {other:?}"),
        }

        // Latest
        let resp = conn.request(&DsRequest::TsLatest { metric: "cpu".into() }).unwrap();
        match resp {
            DsResponse::TsLatest(Some((ts, pt))) => {
                assert_eq!(ts, 1000);
                assert_eq!(pt.value, 42.0);
            }
            other => panic!("expected TsLatest, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn socket_roundtrip_cron() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        let _listener = spawn_listener(dir.path(), ds).await.unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        let conn = DaemonConnection::connect(dir.path()).unwrap();

        let job = CronJob {
            id: "j1".into(),
            name: "Test Job".into(),
            schedule: "0 * * * * *".into(),
            script: "return 'ok'".into(),
            enabled: true,
            last_run: None,
            next_run: 5000,
            created_at: 1000,
            tags: vec![],
            targets: None,
            catalog_id: Some("test-cat".into()),
        };

        // Add
        let resp = conn.request(&DsRequest::CronAdd { job }).unwrap();
        assert!(matches!(resp, DsResponse::Ok));

        // Get
        let resp = conn.request(&DsRequest::CronGet { id: "j1".into() }).unwrap();
        match resp {
            DsResponse::CronJob(Some(j)) => assert_eq!(j.name, "Test Job"),
            other => panic!("expected CronJob, got {other:?}"),
        }

        // List
        let resp = conn.request(&DsRequest::CronList).unwrap();
        match resp {
            DsResponse::CronJobs(jobs) => assert_eq!(jobs.len(), 1),
            other => panic!("expected CronJobs, got {other:?}"),
        }

        // FindByCatalogId
        let resp = conn.request(&DsRequest::CronFindByCatalogId { catalog_id: "test-cat".into() }).unwrap();
        match resp {
            DsResponse::CronJob(Some(j)) => assert_eq!(j.id, "j1"),
            other => panic!("expected CronJob, got {other:?}"),
        }

        // GetDue
        let resp = conn.request(&DsRequest::CronGetDue { now_ms: 6000 }).unwrap();
        match resp {
            DsResponse::CronJobs(jobs) => assert_eq!(jobs.len(), 1),
            other => panic!("expected CronJobs, got {other:?}"),
        }

        // UpdateLastRun
        let resp = conn.request(&DsRequest::CronUpdateLastRun {
            id: "j1".into(),
            ts: 6000,
            next_run: 60000,
        }).unwrap();
        assert!(matches!(resp, DsResponse::Ok));

        // Remove
        let resp = conn.request(&DsRequest::CronRemove { id: "j1".into() }).unwrap();
        assert!(matches!(resp, DsResponse::Bool(true)));
    }
}
