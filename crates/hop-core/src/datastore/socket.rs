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

/// The shared operator group whose members may use the daemon socket without
/// root: `admin` on macOS (where humans-with-admin live), `hop` on Linux. The
/// privsep monitor adds `_hop` to it so the worker can group-own the socket.
#[cfg(unix)]
pub const OPERATOR_GROUP: &str = if cfg!(target_os = "macos") { "admin" } else { "hop" };

/// Resolve the operator group's gid, if it exists.
#[cfg(unix)]
pub fn operator_group_gid() -> Option<u32> {
    nix::unistd::Group::from_name(OPERATOR_GROUP)
        .ok()
        .flatten()
        .map(|g| g.gid.as_raw())
}

/// A lazily-populated handle to the daemon's netdoc, shared with the socket server
/// so the **local** admin path can propagate mutations (revoke/reconcile/snapshot)
/// exactly like the network admin path. Empty until the netdoc finishes coming up;
/// admin mutations before then simply skip propagation (best-effort).
pub type NetDocHandle =
    std::sync::Arc<tokio::sync::OnceCell<std::sync::Arc<crate::netdoc::NetDoc>>>;

/// Spawn a Unix socket listener that serves datastore + operator-admin requests.
///
/// `host_public_key` lets the daemon answer operator `AdminRequest`s (mint
/// invites, report identity) on behalf of the local CLI — so operators never
/// read `_hop`-owned config or need root (privsep §6). The socket is group-owned
/// by [`OPERATOR_GROUP`] (mode `0660`), so only that group + the daemon reach it.
///
/// Returns a `JoinHandle` that removes the socket file when dropped/cancelled.
pub async fn spawn_listener(
    config_dir: &Path,
    datastore: Datastore,
    host_public_key: iroh::PublicKey,
    netdoc: NetDocHandle,
) -> Result<JoinHandle<()>> {
    let path = socket_path(config_dir);

    // Remove stale socket from a previous crash (best-effort; bind will
    // fail with a clear error if removal didn't work).
    if path.exists() {
        let _ = std::fs::remove_file(&path);
    }

    let listener = UnixListener::bind(&path)
        .with_context(|| format!("bind daemon socket at {}", path.display()))?;

    // Mode 0o660 (owner + group). Under privsep the worker is unprivileged and
    // the monitor's setgid config dir already gives the socket the operator group
    // (so admin operators connect without root); we additionally best-effort set
    // the group. We must NOT touch the group when running as **root**
    // (non-privsep): the root daemon's socket is reached by setuid helper
    // subprocesses via their root group, and re-grouping it would lock them out.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if !crate::unix_user::is_running_as_root()
            && let Some(gid) = operator_group_gid()
        {
            let _ = nix::unistd::chown(&path, None, Some(nix::unistd::Gid::from_raw(gid)));
        }
        let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o660));
    }

    tracing::info!("Daemon socket listening at {}", path.display());

    let config_dir = config_dir.to_path_buf();
    let path_for_cleanup = path.clone();
    let handle = tokio::spawn(async move {
        loop {
            match listener.accept().await {
                Ok((stream, _addr)) => {
                    let ds = datastore.clone();
                    let cfg = config_dir.clone();
                    let nd = netdoc.clone();
                    tokio::spawn(async move {
                        if let Err(e) = handle_connection(stream, ds, cfg, host_public_key, nd).await {
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

async fn handle_connection(
    mut stream: tokio::net::UnixStream,
    ds: Datastore,
    config_dir: std::path::PathBuf,
    host_public_key: iroh::PublicKey,
    netdoc: NetDocHandle,
) -> Result<()> {
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

        // Local self-admin (G26): a mutating admin op via this socket must propagate
        // to the warren just like the network admin path. Capture the bits we need
        // BEFORE `req` is moved into the blocking dispatch.
        let is_admin = matches!(req, DsRequest::Admin(_));
        let (admin_revoke_id, admin_upsert_id) = match &req {
            DsRequest::Admin(a) => (
                crate::admin::removed_peer_full_id(&config_dir, a),
                crate::admin::upserted_peer_full_id(&config_dir, a),
            ),
            _ => (None, None),
        };

        // Dispatch (blocking) on a thread pool — both datastore ops and the
        // operator-admin handler are sync.
        let ds_clone = ds.clone();
        let cfg = config_dir.clone();
        let resp =
            tokio::task::spawn_blocking(move || dispatch_request(&ds_clone, &cfg, &host_public_key, req))
                .await??;

        // After a successful admin mutation, run the SAME post-mutation propagate the
        // network admin path runs (reconcile → refresh admins → re-export snapshot,
        // plus an explicit revoke for RemovePeer) so local admin reaches the warren —
        // the fix for "the sole admin node can't self-admin" (mux can't self-dial).
        if is_admin
            && !matches!(&resp, DsResponse::Admin(b) if matches!(b.as_ref(), crate::proto::AdminResponse::Error { .. }))
            && let Some(nd) = netdoc.get()
        {
            nd.propagate_admin_mutation(
                &config_dir,
                admin_revoke_id.as_deref(),
                admin_upsert_id.as_deref(),
            )
            .await;
        }

        // Write response frame
        let resp_bytes = bincode::serde::encode_to_vec(&resp, bincode::config::standard())?;
        let resp_len = (resp_bytes.len() as u32).to_be_bytes();
        stream.write_all(&resp_len).await?;
        stream.write_all(&resp_bytes).await?;
        stream.flush().await?;
    }
}

fn dispatch_request(
    ds: &Datastore,
    config_dir: &Path,
    host_public_key: &iroh::PublicKey,
    req: DsRequest,
) -> Result<DsResponse> {
    Ok(match req {
        DsRequest::Admin(admin_req) => {
            // The daemon owns identity + netdoc tickets, so it mints the invite /
            // reports identity on the operator's behalf — no `_hop`-file reads or
            // root in the CLI. (Non-mutating ops; peer/role mutations still go
            // over the authenticated network admin path which also reconciles.)
            let relay_url = std::fs::read_to_string(config_dir.join("relay_url")).ok();
            let resp = crate::admin::handle_admin_request(
                *admin_req,
                config_dir,
                relay_url.as_deref(),
                host_public_key,
                Some(ds),
            );
            DsResponse::Admin(Box::new(resp))
        }
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
            DsResponse::CronJob(Box::new(ds.cron_get(&id)?))
        }
        DsRequest::CronFindByCatalogId { catalog_id } => {
            DsResponse::CronJob(Box::new(ds.cron_find_by_catalog_id(&catalog_id)?))
        }
        DsRequest::CronGetDue { now_ms } => {
            DsResponse::CronJobs(ds.cron_get_due(now_ms)?)
        }
        DsRequest::CronUpdateLastRun { id, ts, next_run } => {
            ds.cron_update_last_run(&id, ts, next_run)?;
            DsResponse::Ok
        }
        DsRequest::CronPurgeCorrupt => {
            DsResponse::StringList(ds.cron_purge_corrupt()?)
        }
        DsRequest::SecretsGet { username, name } => {
            DsResponse::SecretValue(ds.secrets_get(&username, &name)?)
        }
        DsRequest::SecretsSet { username, name, value } => {
            ds.secrets_set(&username, &name, &value)?;
            DsResponse::Ok
        }
        DsRequest::SecretsDelete { username, name } => {
            DsResponse::Bool(ds.secrets_delete(&username, &name)?)
        }
        DsRequest::SecretsList { username } => {
            DsResponse::SecretNames(ds.secrets_list(&username)?)
        }
        DsRequest::NetStats => {
            DsResponse::NetStats(Box::new(crate::netstats::NET_STATS.snapshot()))
        }
        DsRequest::AuditAppend { event } => {
            ds.audit_append(&event)?;
            DsResponse::Ok
        }
        DsRequest::AuditQuery { query } => {
            DsResponse::AuditEvents(ds.audit_query(&query)?)
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

        let _listener = spawn_listener(dir.path(), ds, iroh::SecretKey::from_bytes(&[7u8; 32]).public(), std::sync::Arc::new(tokio::sync::OnceCell::new()))
            .await
            .unwrap();

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
    async fn socket_roundtrip_netstats() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        let _listener = spawn_listener(dir.path(), ds, iroh::SecretKey::from_bytes(&[7u8; 32]).public(), std::sync::Arc::new(tokio::sync::OnceCell::new()))
            .await
            .unwrap();
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;

        // Bump a couple of global counters so the snapshot is non-trivial.
        use std::sync::atomic::Ordering::Relaxed;
        crate::netstats::NET_STATS.eg_sent_ok.fetch_add(2, Relaxed);
        crate::netstats::NET_STATS.in_drop_spoof.fetch_add(1, Relaxed);

        let conn = DaemonConnection::connect(dir.path()).unwrap();
        let resp = conn.request(&DsRequest::NetStats).unwrap();
        match resp {
            DsResponse::NetStats(s) => {
                assert!(s.eg_sent_ok >= 2);
                assert!(s.in_drop_spoof >= 1);
                assert_eq!(s.eg_lat.len(), crate::netstats::LAT_BUCKETS);
                assert_eq!(s.in_lat.len(), crate::netstats::LAT_BUCKETS);
            }
            other => panic!("expected NetStats, got {other:?}"),
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn socket_roundtrip_ts() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();
        let _listener = spawn_listener(dir.path(), ds, iroh::SecretKey::from_bytes(&[7u8; 32]).public(), std::sync::Arc::new(tokio::sync::OnceCell::new()))
            .await
            .unwrap();
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
        let _listener = spawn_listener(dir.path(), ds, iroh::SecretKey::from_bytes(&[7u8; 32]).public(), std::sync::Arc::new(tokio::sync::OnceCell::new()))
            .await
            .unwrap();
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
            sandbox: None,
            run_as_user: None,
        };

        // Add
        let resp = conn.request(&DsRequest::CronAdd { job }).unwrap();
        assert!(matches!(resp, DsResponse::Ok));

        // Get
        let resp = conn.request(&DsRequest::CronGet { id: "j1".into() }).unwrap();
        match resp {
            DsResponse::CronJob(j) if j.is_some() => assert_eq!(j.unwrap().name, "Test Job"),
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
            DsResponse::CronJob(j) if j.is_some() => assert_eq!(j.unwrap().id, "j1"),
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
