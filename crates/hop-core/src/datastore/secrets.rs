//! Encrypted secrets operations on the embedded datastore.
//!
//! Secrets are scoped per-user: each user can only access their own secrets.
//! The key is `(username, secret_name)` in the redb table.

use anyhow::Result;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use redb::ReadableTable;

use super::protocol::{DsRequest, DsResponse};
use super::remote_dispatch;
use super::tables::{SECRETS_TABLE, SECRETS_V2_TABLE};
use super::types::SealedSecret;
use super::Datastore;

impl Datastore {
    /// Get a decrypted secret by name, scoped to a user.
    pub fn secrets_get(&self, username: &str, name: &str) -> Result<Option<Vec<u8>>> {
        remote_dispatch!(
            self,
            DsRequest::SecretsGet { username: username.into(), name: name.into() },
            DsResponse::SecretValue(v) => v
        );
        let Some(sealed) = self.secrets_get_sealed(username, name)? else {
            return Ok(None);
        };
        let key = self.secrets_key()?;
        let plaintext = decrypt(key, &sealed)?;
        Ok(Some(plaintext))
    }

    /// Set (encrypt and store) a secret, scoped to a user.
    pub fn secrets_set(&self, username: &str, name: &str, value: &[u8]) -> Result<()> {
        remote_dispatch!(
            self,
            DsRequest::SecretsSet {
                username: username.into(),
                name: name.into(),
                value: value.to_vec(),
            },
            DsResponse::Ok => ()
        );
        let key = self.secrets_key()?;
        let sealed = encrypt(key, value)?;
        let bytes = bincode::serde::encode_to_vec(&sealed, bincode::config::standard())?;
        let txn = self.local_db().begin_write()?;
        {
            let mut table = txn.open_table(SECRETS_V2_TABLE)?;
            table.insert((username, name), bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Delete a secret. Returns true if the name existed.
    pub fn secrets_delete(&self, username: &str, name: &str) -> Result<bool> {
        remote_dispatch!(
            self,
            DsRequest::SecretsDelete { username: username.into(), name: name.into() },
            DsResponse::Bool(b) => b
        );
        let txn = self.local_db().begin_write()?;
        let existed = {
            let mut table = txn.open_table(SECRETS_V2_TABLE)?;
            table.remove((username, name))?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    /// List secret names (not values) for a user.
    pub fn secrets_list(&self, username: &str) -> Result<Vec<String>> {
        remote_dispatch!(
            self,
            DsRequest::SecretsList { username: username.into() },
            DsResponse::SecretNames(names) => names
        );
        let txn = self.local_db().begin_read()?;
        let table = match txn.open_table(SECRETS_V2_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut names = Vec::new();
        // Scan for entries with matching username prefix
        for item in table.iter()? {
            let (key_guard, _) = item?;
            let (user, name) = key_guard.value();
            if user == username {
                names.push(name.to_string());
            }
        }
        Ok(names)
    }

    /// Migrate secrets from the old unscoped table to the new user-scoped table.
    /// Called once on startup. Assigns all existing secrets to `default_user`.
    pub fn migrate_secrets_if_needed(&self, default_user: &str) -> Result<()> {
        let txn = self.local_db().begin_read()?;
        let old_table = match txn.open_table(SECRETS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(()), // nothing to migrate
            Err(e) => return Err(e.into()),
        };

        // Check if old table has any entries
        let entries: Vec<(String, Vec<u8>)> = old_table
            .iter()?
            .filter_map(|item| {
                let (k, v) = item.ok()?;
                Some((k.value().to_string(), v.value().to_vec()))
            })
            .collect();
        drop(old_table);
        drop(txn);

        if entries.is_empty() {
            return Ok(());
        }

        tracing::info!(
            "Migrating {} secrets from legacy table to user-scoped table (user: {default_user})",
            entries.len()
        );

        let txn = self.local_db().begin_write()?;
        {
            let mut new_table = txn.open_table(SECRETS_V2_TABLE)?;
            for (name, encrypted_bytes) in &entries {
                // Copy the raw encrypted bytes — no need to decrypt/re-encrypt
                new_table.insert((default_user, name.as_str()), encrypted_bytes.as_slice())?;
            }
        }
        txn.commit()?;

        // Delete old table entries
        let txn = self.local_db().begin_write()?;
        {
            let mut old_table = txn.open_table(SECRETS_TABLE)?;
            for (name, _) in &entries {
                old_table.remove(name.as_str())?;
            }
        }
        txn.commit()?;

        tracing::info!("Secret migration complete");
        Ok(())
    }

    /// Internal: read the raw SealedSecret from redb (no decryption).
    fn secrets_get_sealed(&self, username: &str, name: &str) -> Result<Option<SealedSecret>> {
        let txn = self.local_db().begin_read()?;
        let table = match txn.open_table(SECRETS_V2_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get((username, name))? {
            Some(guard) => {
                let bytes = guard.value();
                let (sealed, _): (SealedSecret, _) =
                    bincode::serde::decode_from_slice(bytes, bincode::config::standard())?;
                Ok(Some(sealed))
            }
            None => Ok(None),
        }
    }
}

fn encrypt(key: &[u8; 32], plaintext: &[u8]) -> Result<SealedSecret> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let mut nonce_bytes = [0u8; 12];
    rand::fill(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| anyhow::anyhow!("encryption failed: {e}"))?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;
    Ok(SealedSecret {
        ciphertext,
        nonce: nonce_bytes,
        updated_at: now,
    })
}

fn decrypt(key: &[u8; 32], sealed: &SealedSecret) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    let nonce = Nonce::from_slice(&sealed.nonce);
    cipher
        .decrypt(nonce, sealed.ciphertext.as_ref())
        .map_err(|e| anyhow::anyhow!("decryption failed (wrong key or corrupted data): {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_key() -> [u8; 32] {
        super::super::derive_secrets_key(&[42u8; 32])
    }

    #[test]
    fn roundtrip_set_get() {
        let dir = tempfile::tempdir().unwrap();
        let ds =
            Datastore::open_with_secrets(&dir.path().join("test.redb"), test_key()).unwrap();

        ds.secrets_set("alice", "API_KEY", b"sk-test-123").unwrap();
        let val = ds.secrets_get("alice", "API_KEY").unwrap();
        assert_eq!(val, Some(b"sk-test-123".to_vec()));
    }

    #[test]
    fn user_isolation() {
        let dir = tempfile::tempdir().unwrap();
        let ds =
            Datastore::open_with_secrets(&dir.path().join("test.redb"), test_key()).unwrap();

        ds.secrets_set("alice", "KEY", b"alice-secret").unwrap();
        ds.secrets_set("bob", "KEY", b"bob-secret").unwrap();

        // Each user sees only their own
        assert_eq!(ds.secrets_get("alice", "KEY").unwrap(), Some(b"alice-secret".to_vec()));
        assert_eq!(ds.secrets_get("bob", "KEY").unwrap(), Some(b"bob-secret".to_vec()));

        // Alice can't see Bob's secrets
        let alice_list = ds.secrets_list("alice").unwrap();
        assert_eq!(alice_list, vec!["KEY".to_string()]);
        assert!(!alice_list.iter().any(|n| n.contains("bob")));
    }

    #[test]
    fn get_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let ds =
            Datastore::open_with_secrets(&dir.path().join("test.redb"), test_key()).unwrap();

        assert_eq!(ds.secrets_get("alice", "NOPE").unwrap(), None);
    }

    #[test]
    fn list_names_only() {
        let dir = tempfile::tempdir().unwrap();
        let ds =
            Datastore::open_with_secrets(&dir.path().join("test.redb"), test_key()).unwrap();

        ds.secrets_set("alice", "B_KEY", b"val-b").unwrap();
        ds.secrets_set("alice", "A_KEY", b"val-a").unwrap();

        let names = ds.secrets_list("alice").unwrap();
        assert_eq!(names, vec!["A_KEY".to_string(), "B_KEY".to_string()]);
    }

    #[test]
    fn delete_existing() {
        let dir = tempfile::tempdir().unwrap();
        let ds =
            Datastore::open_with_secrets(&dir.path().join("test.redb"), test_key()).unwrap();

        ds.secrets_set("alice", "KEY", b"val").unwrap();
        assert!(ds.secrets_delete("alice", "KEY").unwrap());
        assert!(!ds.secrets_delete("alice", "KEY").unwrap());
        assert_eq!(ds.secrets_get("alice", "KEY").unwrap(), None);
    }

    #[test]
    fn wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.redb");

        let ds1 = Datastore::open_with_secrets(&db_path, test_key()).unwrap();
        ds1.secrets_set("alice", "SECRET", b"hidden").unwrap();
        drop(ds1);

        let wrong_key = super::super::derive_secrets_key(&[99u8; 32]);
        let ds2 = Datastore::open_with_secrets(&db_path, wrong_key).unwrap();
        let result = ds2.secrets_get("alice", "SECRET");
        assert!(result.is_err());
    }

    #[test]
    fn overwrite_secret() {
        let dir = tempfile::tempdir().unwrap();
        let ds =
            Datastore::open_with_secrets(&dir.path().join("test.redb"), test_key()).unwrap();

        ds.secrets_set("alice", "KEY", b"old").unwrap();
        ds.secrets_set("alice", "KEY", b"new").unwrap();
        assert_eq!(ds.secrets_get("alice", "KEY").unwrap(), Some(b"new".to_vec()));
    }
}
