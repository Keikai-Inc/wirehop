//! Data types for the embedded datastore.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::sandbox::SandboxPolicy;

/// A single time-series data point.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    pub value: f64,
    /// Optional tags for filtering (e.g. {"host": "web-01", "cpu": "0"}).
    #[serde(default)]
    pub tags: BTreeMap<String, String>,
}

/// A key-value entry with metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KvEntry {
    pub value: Vec<u8>,
    /// MIME type hint: "application/json", "text/plain", etc.
    pub content_type: String,
    /// Unix timestamp in milliseconds.
    pub updated_at: u64,
}

/// A scheduled cron job definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CronJob {
    pub id: String,
    pub name: String,
    /// Cron expression: "*/5 * * * *"
    pub schedule: String,
    /// JavaScript source code to execute.
    pub script: String,
    pub enabled: bool,
    /// Unix timestamp ms of last successful run.
    pub last_run: Option<u64>,
    /// Unix timestamp ms of next scheduled run.
    pub next_run: u64,
    /// Unix timestamp ms when the job was created.
    pub created_at: u64,
    /// Tags for fleet targeting: ["fleet:web", "role:monitor"].
    #[serde(default)]
    pub tags: Vec<String>,
    /// Optional fleet target tag. When set, the scheduler resolves matching
    /// hosts and injects them as `hop.targets` before executing the script.
    #[serde(default)]
    pub targets: Option<String>,
    /// Optional catalog identifier for dedup. When set, `ensure` will skip
    /// creation if a job with the same catalog_id already exists.
    #[serde(default)]
    pub catalog_id: Option<String>,
    /// Optional sandbox policy for this job. When set, the JS runtime applies
    /// this policy to `hop.exec()`, `hop.fleet.exec()`, and `hop.local()` calls.
    #[serde(default)]
    pub sandbox: Option<SandboxPolicy>,
    /// Unix username this job runs as. Stamped automatically by the system
    /// at creation time — never user-settable. When the daemon runs as root
    /// and this is `Some`, `hop.local()` drops privileges to this user via
    /// `login -fp` (macOS) or `su -` (Linux).
    #[serde(default)]
    pub run_as_user: Option<String>,
}

/// An encrypted secret stored in the secrets table.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedSecret {
    /// ChaCha20-Poly1305 ciphertext (plaintext + 16-byte auth tag).
    pub ciphertext: Vec<u8>,
    /// 12-byte random nonce used for this encryption.
    pub nonce: [u8; 12],
    /// Unix timestamp in milliseconds when the secret was last updated.
    pub updated_at: u64,
}

/// Query parameters for time-series range queries.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeSeriesQuery {
    pub metric: String,
    /// Start of range (unix ms, inclusive).
    pub start: u64,
    /// End of range (unix ms, inclusive).
    pub end: u64,
    /// Optional tag filter — only return points matching all specified tags.
    pub tags_filter: Option<BTreeMap<String, String>>,
    /// Max number of results to return.
    pub limit: Option<usize>,
}
