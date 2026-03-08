//! Block-level delta transfers (rsync-style algorithm).
//!
//! The algorithm works in 3 steps:
//! 1. Receiver computes rolling (Adler32-variant) + strong (xxh3-64) checksums
//!    per block of the existing file and sends them as `BlockSignatures`.
//! 2. Sender rolls through the new file byte-by-byte, matching blocks via
//!    the rolling hash → strong hash verification.
//! 3. Sender emits a stream of `DeltaOp` (CopyBlock or Literal) which the
//!    receiver uses to reconstruct the new file from the old file + literals.

use std::collections::HashMap;
use std::io::Read;
use std::path::Path;

use anyhow::{Context, Result};

use crate::proto::{BlockSignature, DeltaOperation};

/// Rolling checksum (Adler32-variant) used for fast block matching.
pub struct RollingChecksum {
    a: u32,
    b: u32,
    count: usize,
}

impl Default for RollingChecksum {
    fn default() -> Self {
        Self::new()
    }
}

impl RollingChecksum {
    pub fn new() -> Self {
        Self {
            a: 0,
            b: 0,
            count: 0,
        }
    }

    /// Update the checksum with a full block of data.
    pub fn update(&mut self, data: &[u8]) {
        self.a = 0;
        self.b = 0;
        self.count = data.len();
        for (i, &byte) in data.iter().enumerate() {
            self.a = self.a.wrapping_add(byte as u32);
            self.b = self.b.wrapping_add((data.len() - i) as u32 * byte as u32);
        }
    }

    /// Roll the checksum forward by removing `old_byte` and adding `new_byte`.
    pub fn roll(&mut self, old_byte: u8, new_byte: u8) {
        self.a = self.a.wrapping_sub(old_byte as u32).wrapping_add(new_byte as u32);
        self.b = self
            .b
            .wrapping_sub(self.count as u32 * old_byte as u32)
            .wrapping_add(self.a);
    }

    /// Get the current rolling checksum value.
    pub fn digest(&self) -> u32 {
        (self.b << 16) | (self.a & 0xffff)
    }
}

/// Compute block signatures for a file.
/// Returns a list of (index, rolling_checksum, strong_hash) per block.
pub fn compute_block_signatures(path: &Path, block_size: usize) -> Result<Vec<BlockSignature>> {
    let mut file = std::fs::File::open(path)
        .with_context(|| format!("cannot open for signatures: {}", path.display()))?;
    let mut signatures = Vec::new();
    let mut buf = vec![0u8; block_size];
    let mut index = 0u32;

    loop {
        let n = file
            .read(&mut buf)
            .with_context(|| format!("read error during signatures: {}", path.display()))?;
        if n == 0 {
            break;
        }

        let data = &buf[..n];
        let mut rolling = RollingChecksum::new();
        rolling.update(data);

        let strong = xxhash_rust::xxh3::xxh3_64(data);

        signatures.push(BlockSignature {
            index,
            rolling: rolling.digest(),
            strong,
        });
        index += 1;
    }

    Ok(signatures)
}

/// Build a lookup table from rolling checksum → vec of (strong_hash, block_index).
pub fn build_signature_lookup(
    signatures: &[BlockSignature],
) -> HashMap<u32, Vec<(u64, u32)>> {
    let mut map: HashMap<u32, Vec<(u64, u32)>> = HashMap::new();
    for sig in signatures {
        map.entry(sig.rolling)
            .or_default()
            .push((sig.strong, sig.index));
    }
    map
}

/// Compute delta operations by comparing new file data against block signatures.
///
/// Returns a list of DeltaOperations that, when applied to the old file's blocks,
/// produce the new file.
pub fn compute_delta(
    new_file_path: &Path,
    signatures: &[BlockSignature],
    block_size: usize,
) -> Result<Vec<DeltaOperation>> {
    if signatures.is_empty() {
        // No blocks in old file — everything is literal
        let data = std::fs::read(new_file_path)
            .with_context(|| format!("read new file: {}", new_file_path.display()))?;
        if data.is_empty() {
            return Ok(vec![]);
        }
        return Ok(vec![DeltaOperation::Literal(data)]);
    }

    let lookup = build_signature_lookup(signatures);
    let new_data = std::fs::read(new_file_path)
        .with_context(|| format!("read new file for delta: {}", new_file_path.display()))?;

    if new_data.is_empty() {
        return Ok(vec![]);
    }

    let mut ops = Vec::new();
    let mut literal_buf = Vec::new();
    let mut pos = 0usize;

    if new_data.len() < block_size {
        // File smaller than block size — all literal
        return Ok(vec![DeltaOperation::Literal(new_data)]);
    }

    let mut rolling = RollingChecksum::new();
    rolling.update(&new_data[0..block_size]);

    loop {
        if pos + block_size > new_data.len() {
            // Remaining bytes less than a block — all literal
            literal_buf.extend_from_slice(&new_data[pos..]);
            break;
        }

        let digest = rolling.digest();
        let mut matched = false;

        if let Some(candidates) = lookup.get(&digest) {
            // Rolling hash matches — verify with strong hash
            let window = &new_data[pos..pos + block_size];
            let strong = xxhash_rust::xxh3::xxh3_64(window);

            for &(sig_strong, sig_index) in candidates {
                if sig_strong == strong {
                    // Block match! Flush any pending literal data first
                    if !literal_buf.is_empty() {
                        ops.push(DeltaOperation::Literal(std::mem::take(&mut literal_buf)));
                    }
                    ops.push(DeltaOperation::CopyBlock { index: sig_index });
                    pos += block_size;
                    matched = true;

                    // Re-initialize rolling checksum for next window
                    if pos + block_size <= new_data.len() {
                        rolling.update(&new_data[pos..pos + block_size]);
                    }
                    break;
                }
            }
        }

        if !matched {
            // No match — add current byte to literal and roll forward
            literal_buf.push(new_data[pos]);
            pos += 1;

            if pos + block_size <= new_data.len() {
                rolling.roll(
                    new_data[pos - 1],
                    new_data[pos + block_size - 1],
                );
            }
        }
    }

    // Flush remaining literal data
    if !literal_buf.is_empty() {
        ops.push(DeltaOperation::Literal(literal_buf));
    }

    Ok(ops)
}

/// Reconstruct a file from delta operations applied to the old file.
///
/// Reads blocks from `old_path`, applies CopyBlock and Literal operations,
/// writes the result to `output_path`.
pub fn reconstruct_file(
    old_path: &Path,
    output_path: &Path,
    ops: &[DeltaOperation],
    block_size: usize,
) -> Result<u64> {
    use std::io::Write;

    // Read old file into memory for block access
    let old_data = std::fs::read(old_path)
        .with_context(|| format!("read old file for reconstruction: {}", old_path.display()))?;

    let mut output = std::fs::File::create(output_path)
        .with_context(|| format!("create output: {}", output_path.display()))?;
    let mut total_written = 0u64;

    for op in ops {
        match op {
            DeltaOperation::CopyBlock { index } => {
                let start = *index as usize * block_size;
                let end = (start + block_size).min(old_data.len());
                if start < old_data.len() {
                    let block = &old_data[start..end];
                    output.write_all(block)?;
                    total_written += block.len() as u64;
                }
            }
            DeltaOperation::Literal(data) => {
                output.write_all(data)?;
                total_written += data.len() as u64;
            }
        }
    }

    output.flush()?;
    Ok(total_written)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn write_test_file(dir: &std::path::Path, name: &str, content: &[u8]) -> std::path::PathBuf {
        let path = dir.join(name);
        let mut f = std::fs::File::create(&path).unwrap();
        f.write_all(content).unwrap();
        path
    }

    #[test]
    fn rolling_checksum_deterministic() {
        let data = b"hello world, this is a test block";
        let mut cs1 = RollingChecksum::new();
        cs1.update(data);
        let mut cs2 = RollingChecksum::new();
        cs2.update(data);
        assert_eq!(cs1.digest(), cs2.digest());
    }

    #[test]
    fn rolling_checksum_different_data() {
        let mut cs1 = RollingChecksum::new();
        cs1.update(b"aaaa");
        let mut cs2 = RollingChecksum::new();
        cs2.update(b"bbbb");
        assert_ne!(cs1.digest(), cs2.digest());
    }

    #[test]
    fn rolling_checksum_roll_matches_recompute() {
        // "abcd" -> roll off 'a', roll on 'e' -> should equal checksum of "bcde"
        let mut rolling = RollingChecksum::new();
        rolling.update(b"abcd");
        rolling.roll(b'a', b'e');

        let mut fresh = RollingChecksum::new();
        fresh.update(b"bcde");

        assert_eq!(rolling.digest(), fresh.digest());
    }

    #[test]
    fn identical_files_all_copy_blocks() {
        let dir = tempfile::tempdir().unwrap();
        let content = vec![0x42u8; 256 * 1024]; // 256 KiB = 4 blocks of 64 KiB
        let old = write_test_file(dir.path(), "old", &content);
        let new = write_test_file(dir.path(), "new", &content);

        let sigs = compute_block_signatures(&old, 64 * 1024).unwrap();
        assert_eq!(sigs.len(), 4);

        let ops = compute_delta(&new, &sigs, 64 * 1024).unwrap();
        // All ops should be CopyBlock
        for op in &ops {
            assert!(matches!(op, DeltaOperation::CopyBlock { .. }));
        }
    }

    #[test]
    fn completely_different_files_all_literal() {
        let dir = tempfile::tempdir().unwrap();
        let old_content = vec![0xAAu8; 128 * 1024];
        let new_content = vec![0xBBu8; 128 * 1024];
        let old = write_test_file(dir.path(), "old", &old_content);
        let new = write_test_file(dir.path(), "new", &new_content);

        let sigs = compute_block_signatures(&old, 64 * 1024).unwrap();
        let ops = compute_delta(&new, &sigs, 64 * 1024).unwrap();

        // All ops should be Literal (no matching blocks)
        for op in &ops {
            assert!(matches!(op, DeltaOperation::Literal(_)));
        }
    }

    #[test]
    fn delta_roundtrip_identical() {
        let dir = tempfile::tempdir().unwrap();
        let content = vec![0x42u8; 256 * 1024];
        let old = write_test_file(dir.path(), "old", &content);
        let new = write_test_file(dir.path(), "new", &content);
        let output = dir.path().join("output");

        let sigs = compute_block_signatures(&old, 64 * 1024).unwrap();
        let ops = compute_delta(&new, &sigs, 64 * 1024).unwrap();
        reconstruct_file(&old, &output, &ops, 64 * 1024).unwrap();

        assert_eq!(std::fs::read(&output).unwrap(), content);
    }

    #[test]
    fn delta_roundtrip_small_change() {
        let dir = tempfile::tempdir().unwrap();
        let mut content = vec![0x42u8; 256 * 1024];
        let old = write_test_file(dir.path(), "old", &content);

        // Change one byte in the middle of the second block
        content[64 * 1024 + 100] = 0xFF;
        let new = write_test_file(dir.path(), "new", &content);
        let output = dir.path().join("output");

        let sigs = compute_block_signatures(&old, 64 * 1024).unwrap();
        let ops = compute_delta(&new, &sigs, 64 * 1024).unwrap();
        reconstruct_file(&old, &output, &ops, 64 * 1024).unwrap();

        assert_eq!(std::fs::read(&output).unwrap(), content);
    }

    #[test]
    fn delta_roundtrip_appended_data() {
        let dir = tempfile::tempdir().unwrap();
        let old_content = vec![0x42u8; 128 * 1024];
        let old = write_test_file(dir.path(), "old", &old_content);

        // New file = old content + extra data
        let mut new_content = old_content.clone();
        new_content.extend_from_slice(&[0xBB; 32 * 1024]);
        let new = write_test_file(dir.path(), "new", &new_content);
        let output = dir.path().join("output");

        let sigs = compute_block_signatures(&old, 64 * 1024).unwrap();
        let ops = compute_delta(&new, &sigs, 64 * 1024).unwrap();
        reconstruct_file(&old, &output, &ops, 64 * 1024).unwrap();

        assert_eq!(std::fs::read(&output).unwrap(), new_content);
    }

    #[test]
    fn delta_empty_new_file() {
        let dir = tempfile::tempdir().unwrap();
        let old = write_test_file(dir.path(), "old", &[0x42; 128 * 1024]);
        let new = write_test_file(dir.path(), "new", &[]);
        let output = dir.path().join("output");

        let sigs = compute_block_signatures(&old, 64 * 1024).unwrap();
        let ops = compute_delta(&new, &sigs, 64 * 1024).unwrap();
        assert!(ops.is_empty());

        reconstruct_file(&old, &output, &ops, 64 * 1024).unwrap();
        assert_eq!(std::fs::read(&output).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn delta_small_file_below_block_size() {
        let dir = tempfile::tempdir().unwrap();
        let old = write_test_file(dir.path(), "old", b"old content here");
        let new_content = b"new content here!";
        let new = write_test_file(dir.path(), "new", new_content);
        let output = dir.path().join("output");

        let sigs = compute_block_signatures(&old, 64 * 1024).unwrap();
        let ops = compute_delta(&new, &sigs, 64 * 1024).unwrap();
        reconstruct_file(&old, &output, &ops, 64 * 1024).unwrap();

        assert_eq!(std::fs::read(&output).unwrap(), new_content);
    }

    #[test]
    fn block_signatures_count() {
        let dir = tempfile::tempdir().unwrap();
        // 3 full blocks + 1 partial
        let content = vec![0xAA; 64 * 1024 * 3 + 1000];
        let path = write_test_file(dir.path(), "file", &content);

        let sigs = compute_block_signatures(&path, 64 * 1024).unwrap();
        assert_eq!(sigs.len(), 4); // 3 full + 1 partial

        for (i, sig) in sigs.iter().enumerate() {
            assert_eq!(sig.index, i as u32);
        }
    }
}
