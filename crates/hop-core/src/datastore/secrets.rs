//! Encrypted secrets operations on the embedded datastore.

use anyhow::Result;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use redb::ReadableTable;

use super::protocol::{DsRequest, DsResponse};
use super::remote_dispatch;
use super::tables::SECRETS_TABLE;
use super::types::SealedSecret;
use super::Datastore;

impl Datastore {
    /// Get a decrypted secret by name. Returns the plaintext value.
    pub fn secrets_get(&self, name: &str) -> Result<Option<Vec<u8>>> {
        remote_dispatch!(
            self,
            DsRequest::SecretsGet { name: name.into() },
            DsResponse::SecretValue(v) => v
        );
        let Some(sealed) = self.secrets_get_sealed(name)? else {
            return Ok(None);
        };
        let key = self.secrets_key()?;
        let plaintext = decrypt(key, &sealed)?;
        Ok(Some(plaintext))
    }

    /// Set (encrypt and store) a secret.
    pub fn secrets_set(&self, name: &str, value: &[u8]) -> Result<()> {
        remote_dispatch!(
            self,
            DsRequest::SecretsSet {
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
            let mut table = txn.open_table(SECRETS_TABLE)?;
            table.insert(name, bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Delete a secret. Returns true if the name existed.
    pub fn secrets_delete(&self, name: &str) -> Result<bool> {
        remote_dispatch!(
            self,
            DsRequest::SecretsDelete { name: name.into() },
            DsResponse::Bool(b) => b
        );
        let txn = self.local_db().begin_write()?;
        let existed = {
            let mut table = txn.open_table(SECRETS_TABLE)?;
            table.remove(name)?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    /// List secret names (not values).
    pub fn secrets_list(&self) -> Result<Vec<String>> {
        remote_dispatch!(self, DsRequest::SecretsList, DsResponse::SecretNames(names) => names);
        let txn = self.local_db().begin_read()?;
        let table = match txn.open_table(SECRETS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(Vec::new()),
            Err(e) => return Err(e.into()),
        };
        let mut names = Vec::new();
        for item in table.iter()? {
            let (key_guard, _) = item?;
            names.push(key_guard.value().to_string());
        }
        Ok(names)
    }

    /// Internal: read the raw SealedSecret from redb (no decryption).
    fn secrets_get_sealed(&self, name: &str) -> Result<Option<SealedSecret>> {
        let txn = self.local_db().begin_read()?;
        let table = match txn.open_table(SECRETS_TABLE) {
            Ok(t) => t,
            Err(redb::TableError::TableDoesNotExist(_)) => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        match table.get(name)? {
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

        ds.secrets_set("API_KEY", b"sk-test-123").unwrap();
        let val = ds.secrets_get("API_KEY").unwrap();
        assert_eq!(val, Some(b"sk-test-123".to_vec()));
    }

    #[test]
    fn get_nonexistent() {
        let dir = tempfile::tempdir().unwrap();
        let ds =
            Datastore::open_with_secrets(&dir.path().join("test.redb"), test_key()).unwrap();

        assert_eq!(ds.secrets_get("NOPE").unwrap(), None);
    }

    #[test]
    fn list_names_only() {
        let dir = tempfile::tempdir().unwrap();
        let ds =
            Datastore::open_with_secrets(&dir.path().join("test.redb"), test_key()).unwrap();

        ds.secrets_set("B_KEY", b"val-b").unwrap();
        ds.secrets_set("A_KEY", b"val-a").unwrap();

        let names = ds.secrets_list().unwrap();
        assert_eq!(names, vec!["A_KEY".to_string(), "B_KEY".to_string()]);
    }

    #[test]
    fn delete_existing() {
        let dir = tempfile::tempdir().unwrap();
        let ds =
            Datastore::open_with_secrets(&dir.path().join("test.redb"), test_key()).unwrap();

        ds.secrets_set("KEY", b"val").unwrap();
        assert!(ds.secrets_delete("KEY").unwrap());
        assert!(!ds.secrets_delete("KEY").unwrap());
        assert_eq!(ds.secrets_get("KEY").unwrap(), None);
    }

    #[test]
    fn wrong_key_fails() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("test.redb");

        // Store with one key
        let ds1 = Datastore::open_with_secrets(&db_path, test_key()).unwrap();
        ds1.secrets_set("SECRET", b"hidden").unwrap();
        drop(ds1);

        // Try to read with a different key
        let wrong_key = super::super::derive_secrets_key(&[99u8; 32]);
        let ds2 = Datastore::open_with_secrets(&db_path, wrong_key).unwrap();
        let result = ds2.secrets_get("SECRET");
        assert!(result.is_err());
    }

    #[test]
    fn overwrite_secret() {
        let dir = tempfile::tempdir().unwrap();
        let ds =
            Datastore::open_with_secrets(&dir.path().join("test.redb"), test_key()).unwrap();

        ds.secrets_set("KEY", b"old").unwrap();
        ds.secrets_set("KEY", b"new").unwrap();
        assert_eq!(ds.secrets_get("KEY").unwrap(), Some(b"new".to_vec()));
    }
}
