//! Wire protocol types for daemon socket communication.

use serde::{Deserialize, Serialize};

use super::types::{CronJob, KvEntry, MetricPoint, TimeSeriesQuery};

/// Request from a client to the daemon's datastore.
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
    SecretsGet { name: String },
    SecretsSet { name: String, value: Vec<u8> },
    SecretsDelete { name: String },
    SecretsList,
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
}
