//! Key-value operations on the embedded datastore.

use anyhow::Result;
#[allow(unused_imports)]
use redb::ReadableTable;

use super::protocol::{DsRequest, DsResponse};
use super::remote_dispatch;
use super::tables::KV_TABLE;
use super::types::KvEntry;
use super::Datastore;

impl Datastore {
    /// Get a KV entry by namespace and key.
    pub fn kv_get(&self, ns: &str, key: &str) -> Result<Option<KvEntry>> {
        remote_dispatch!(self,
            DsRequest::KvGet { ns: ns.into(), key: key.into() },
            DsResponse::KvEntry(e) => e
        );
        let txn = self.local_db().begin_read()?;
        let table = match txn.open_table(KV_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get((ns, key))? {
            Some(guard) => {
                let bytes = guard.value();
                let (entry, _): (KvEntry, _) =
                    bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
                Ok(Some(entry))
            }
            None => Ok(None),
        }
    }

    /// Set a KV entry.
    pub fn kv_set(&self, ns: &str, key: &str, entry: &KvEntry) -> Result<()> {
        remote_dispatch!(self,
            DsRequest::KvSet { ns: ns.into(), key: key.into(), entry: entry.clone() },
            DsResponse::Ok => ()
        );
        let bytes = bincode::serde::encode_to_vec(entry, bincode::config::standard())?;
        let txn = self.local_db().begin_write()?;
        {
            let mut table = txn.open_table(KV_TABLE)?;
            table.insert((ns, key), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Delete a KV entry. Returns true if the key existed.
    pub fn kv_delete(&self, ns: &str, key: &str) -> Result<bool> {
        remote_dispatch!(self,
            DsRequest::KvDelete { ns: ns.into(), key: key.into() },
            DsResponse::Bool(b) => b
        );
        let txn = self.local_db().begin_write()?;
        let existed = {
            let mut table = txn.open_table(KV_TABLE)?;
            table.remove((ns, key))?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    /// List KV entries in a namespace, optionally filtered by key prefix.
    pub fn kv_list(&self, ns: &str, prefix: &str) -> Result<Vec<(String, KvEntry)>> {
        remote_dispatch!(self,
            DsRequest::KvList { ns: ns.into(), prefix: prefix.into() },
            DsResponse::KvEntries(e) => e
        );
        let txn = self.local_db().begin_read()?;
        let table = match txn.open_table(KV_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };

        let mut results = Vec::new();
        // Range scan over all keys with this namespace
        let start = (ns, prefix);
        // Compute the end bound for the prefix scan
        let prefix_end = prefix_successor(prefix);
        let end_key;

        let iter = if let Some(ref end) = prefix_end {
            end_key = (ns, end.as_str());
            table.range(start..end_key)?
        } else {
            // No successor means prefix is empty or all 0xFF — scan to end of namespace
            // We need a namespace successor
            let ns_end = prefix_successor(ns);
            match ns_end {
                Some(ref ns_e) => {
                    end_key = (ns_e.as_str(), "");
                    table.range(start..end_key)?
                }
                None => {
                    // Scan everything from start
                    table.range(start..)?
                }
            }
        };

        for item in iter {
            let (key_guard, val_guard) = item?;
            let (item_ns, item_key) = key_guard.value();
            if item_ns != ns {
                break;
            }
            if !item_key.starts_with(prefix) {
                break;
            }
            let bytes = val_guard.value();
            let (entry, _): (KvEntry, _) =
                bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
            results.push((item_key.to_string(), entry));
        }

        Ok(results)
    }
}

/// Compute the lexicographic successor of a string prefix for range scans.
/// Returns None if no successor exists (empty string or all max bytes).
fn prefix_successor(prefix: &str) -> Option<String> {
    if prefix.is_empty() {
        return None;
    }
    let mut bytes = prefix.as_bytes().to_vec();
    // Increment the last byte, carrying over if needed
    while let Some(last) = bytes.last_mut() {
        if *last < 0xFF {
            *last += 1;
            return Some(String::from_utf8_lossy(&bytes).into_owned());
        }
        bytes.pop();
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_successor_works() {
        assert_eq!(prefix_successor("abc"), Some("abd".to_string()));
        assert_eq!(prefix_successor(""), None);
        assert_eq!(prefix_successor("a"), Some("b".to_string()));
    }

    #[test]
    fn kv_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        // Get non-existent key
        assert!(ds.kv_get("ns", "key1").unwrap().is_none());

        // Set and get
        let entry = KvEntry {
            value: b"hello".to_vec(),
            content_type: "text/plain".to_string(),
            updated_at: 1000,
        };
        ds.kv_set("ns", "key1", &entry).unwrap();
        let got = ds.kv_get("ns", "key1").unwrap().unwrap();
        assert_eq!(got.value, b"hello");
        assert_eq!(got.content_type, "text/plain");

        // Different namespace isolation
        assert!(ds.kv_get("other", "key1").unwrap().is_none());

        // Delete
        assert!(ds.kv_delete("ns", "key1").unwrap());
        assert!(!ds.kv_delete("ns", "key1").unwrap());
        assert!(ds.kv_get("ns", "key1").unwrap().is_none());
    }

    #[test]
    fn kv_list_with_prefix() {
        let dir = tempfile::tempdir().unwrap();
        let ds = Datastore::open(&dir.path().join("test.redb")).unwrap();

        let entry = |v: &str| KvEntry {
            value: v.as_bytes().to_vec(),
            content_type: "text/plain".to_string(),
            updated_at: 1000,
        };

        ds.kv_set("ns", "metric:cpu", &entry("1")).unwrap();
        ds.kv_set("ns", "metric:mem", &entry("2")).unwrap();
        ds.kv_set("ns", "config:ttl", &entry("3")).unwrap();
        ds.kv_set("other", "metric:disk", &entry("4")).unwrap();

        let results = ds.kv_list("ns", "metric:").unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].0, "metric:cpu");
        assert_eq!(results[1].0, "metric:mem");

        // Empty prefix lists all in namespace
        let all = ds.kv_list("ns", "").unwrap();
        assert_eq!(all.len(), 3);
    }
}
