//! Wire protocol types for daemon socket communication.

use serde::{Deserialize, Serialize};

use super::types::{CronJob, CronRun, KvEntry, MetricPoint, TimeSeriesQuery};

/// Request from a client to the daemon's datastore.
// Variants vary in size, but this is a short-lived IPC message serialized by
// value over a Unix socket — boxing would add indirection for no real benefit.
#[allow(clippy::large_enum_variant)]
#[derive(Serialize, Deserialize)]
pub enum DsRequest {
    KvGet { ns: String, key: String },
    KvSet { ns: String, key: String, entry: KvEntry },
    KvDelete { ns: String, key: String },
    KvList { ns: String, prefix: String },
    TsInsert { metric: String, point: MetricPoint },
    TsInsertAt { metric: String, ts: u64, point: MetricPoint },
    TsQuery { query: TimeSeriesQuery },
    TsLatest { metric: String },
    CronAdd { job: CronJob },
    CronRemove { id: String },
    CronList,
    CronGet { id: String },
    CronFindByCatalogId { catalog_id: String },
    CronGetDue { now_ms: u64 },
    CronUpdateLastRun { id: String, ts: u64, next_run: u64 },
    CronPurgeCorrupt,
    SecretsGet { username: String, name: String },
    SecretsSet { username: String, name: String, value: Vec<u8> },
    SecretsDelete { username: String, name: String },
    SecretsList { username: String },
    /// Operator admin op handled by the daemon itself (privsep §6): the daemon
    /// owns the identity/netdoc, so the local operator CLI asks it to mint
    /// invites / report identity instead of reading `_hop`-owned config + needing
    /// root. The socket is group-restricted to the operator group.
    Admin(Box<crate::proto::AdminRequest>),
    /// Read the data-plane (VPN forwarding) counters. Non-mutating; lets
    /// `hop debug net-stats` poll drop/queue/latency metrics from the worker.
    /// Appended last to keep existing variant discriminants stable.
    NetStats,
    /// Append a per-node audit/flow event. Appended last to keep existing
    /// variant discriminants stable.
    AuditAppend { event: Box<crate::audit::AuditEvent> },
    /// Query the per-node audit/flow log (most recent first).
    AuditQuery { query: crate::audit::AuditQuery },
    /// Recent runs of one cron job, newest first. Appended last.
    CronRuns { id: String, limit: u32 },
}

/// Response from the daemon's datastore to a client.
#[derive(Debug, Serialize, Deserialize)]
pub enum DsResponse {
    Ok,
    Bool(bool),
    Error(String),
    KvEntry(Option<KvEntry>),
    KvEntries(Vec<(String, KvEntry)>),
    TsPoints(Vec<(u64, MetricPoint)>),
    TsLatest(Option<(u64, MetricPoint)>),
    CronJob(Box<Option<CronJob>>),
    CronJobs(Vec<CronJob>),
    SecretValue(Option<Vec<u8>>),
    SecretNames(Vec<String>),
    StringList(Vec<String>),
    Admin(Box<crate::proto::AdminResponse>),
    NetStats(Box<crate::netstats::NetStatsSnapshot>),
    AuditEvents(Vec<crate::audit::AuditEvent>),
    CronRuns(Vec<CronRun>),
}
