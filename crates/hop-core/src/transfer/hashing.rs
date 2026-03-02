//! Content hashing for file comparison in sync mode.

use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};

const HASH_BUF_SIZE: usize = 64 * 1024; // 64 KiB

/// Compute an xxh3-64 hash of a file's contents.
/// Reads in 64 KiB chunks to avoid loading the entire file into memory.
pub fn hash_file_content(path: &Path) -> Result<u64> {
    let file = std::fs::File::open(path)
        .with_context(|| format!("cannot open for hashing: {}", path.display()))?;
    let mut reader = std::io::BufReader::new(file);
    let mut hasher = xxhash_rust::xxh3::Xxh3::new();
    let mut buf = vec![0u8; HASH_BUF_SIZE];

    loop {
        let n = reader
            .read(&mut buf)
            .with_context(|| format!("read error during hashing: {}", path.display()))?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }

    Ok(hasher.digest())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hash_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("test.txt");
        std::fs::write(&path, b"hello world").unwrap();

        let h1 = hash_file_content(&path).unwrap();
        let h2 = hash_file_content(&path).unwrap();
        assert_eq!(h1, h2);
    }

    #[test]
    fn same_content_same_hash() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = dir.path().join("a.txt");
        let p2 = dir.path().join("b.txt");
        std::fs::write(&p1, b"identical content").unwrap();
        std::fs::write(&p2, b"identical content").unwrap();

        assert_eq!(
            hash_file_content(&p1).unwrap(),
            hash_file_content(&p2).unwrap()
        );
    }

    #[test]
    fn different_content_different_hash() {
        let dir = tempfile::tempdir().unwrap();
        let p1 = dir.path().join("a.txt");
        let p2 = dir.path().join("b.txt");
        std::fs::write(&p1, b"content A").unwrap();
        std::fs::write(&p2, b"content B").unwrap();

        assert_ne!(
            hash_file_content(&p1).unwrap(),
            hash_file_content(&p2).unwrap()
        );
    }

    #[test]
    fn empty_file_hash() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("empty.txt");
        std::fs::write(&path, b"").unwrap();

        // Should not panic and should return a consistent value
        let h = hash_file_content(&path).unwrap();
        let h2 = hash_file_content(&path).unwrap();
        assert_eq!(h, h2);
    }

    #[test]
    fn large_file_multi_chunk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("large.bin");
        // Write 200 KiB — spans multiple 64 KiB read chunks
        let mut f = std::fs::File::create(&path).unwrap();
        let chunk = vec![0xABu8; 200 * 1024];
        f.write_all(&chunk).unwrap();
        drop(f);

        let h = hash_file_content(&path).unwrap();
        // Verify it matches xxh3 of the same data computed in one shot
        let expected = xxhash_rust::xxh3::xxh3_64(&chunk);
        assert_eq!(h, expected);
    }
}
