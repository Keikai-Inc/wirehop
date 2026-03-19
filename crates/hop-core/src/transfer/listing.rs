//! Directory walking and sync comparison logic.

use std::collections::HashMap;
use std::path::Path;
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};

use crate::proto::{FileEntry, DELTA_MIN_FILE_SIZE};
use super::hashing;

/// Recursively walk a directory and return a flat list of entries with paths
/// relative to `root`. Computes content hashes for regular files.
pub fn walk_directory(root: &Path) -> Result<Vec<FileEntry>> {
    let mut entries = Vec::new();
    let root = root
        .canonicalize()
        .with_context(|| format!("cannot resolve path: {}", root.display()))?;
    walk_recursive(&root, &root, &mut entries)?;
    entries.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(entries)
}

fn walk_recursive(base: &Path, current: &Path, entries: &mut Vec<FileEntry>) -> Result<()> {
    let read_dir = match std::fs::read_dir(current) {
        Ok(rd) => rd,
        Err(e) => {
            // Skip directories we can't read (macOS TCC restrictions, permission
            // denied, etc.) rather than aborting the entire walk.
            tracing::warn!("skipping unreadable directory {}: {e}", current.display());
            return Ok(());
        }
    };

    for entry in read_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(e) => {
                tracing::warn!("skipping entry in {}: {e}", current.display());
                continue;
            }
        };
        let metadata = match entry.metadata() {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("skipping {}: {e}", entry.path().display());
                continue;
            }
        };
        let full_path = entry.path();
        let rel_path = full_path
            .strip_prefix(base)
            .unwrap_or(&full_path)
            .to_string_lossy()
            .to_string();

        let symlink_meta = match std::fs::symlink_metadata(&full_path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("skipping {}: {e}", full_path.display());
                continue;
            }
        };
        let is_symlink = symlink_meta.file_type().is_symlink();

        let symlink_target = if is_symlink {
            std::fs::read_link(&full_path)
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        } else {
            None
        };

        let mtime = metadata
            .modified()
            .unwrap_or(UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let mode = file_mode(&metadata);

        // Compute content hash for regular files (not dirs/symlinks)
        let content_hash = if metadata.is_file() && !is_symlink {
            hashing::hash_file_content(&full_path).ok()
        } else {
            None
        };

        entries.push(FileEntry {
            path: rel_path,
            size: if metadata.is_file() {
                metadata.len()
            } else {
                0
            },
            mtime,
            mode,
            is_dir: metadata.is_dir(),
            is_symlink,
            symlink_target,
            content_hash,
        });

        if metadata.is_dir() && !is_symlink {
            walk_recursive(base, &full_path, entries)?;
        }
    }

    Ok(())
}

#[cfg(unix)]
fn file_mode(metadata: &std::fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode()
}

#[cfg(not(unix))]
fn file_mode(_metadata: &std::fs::Metadata) -> u32 {
    0o644
}

/// Public wrapper for getting file mode from metadata.
pub fn file_mode_from_metadata(metadata: &std::fs::Metadata) -> u32 {
    file_mode(metadata)
}

/// Result of comparing source and destination file lists for sync.
pub struct SyncPlan {
    /// Files that need to be transferred (new or changed).
    pub files_to_send: Vec<FileEntry>,
    /// Paths to delete on the destination (only populated when delete_extraneous is true).
    pub files_to_delete: Vec<String>,
    /// Files existing on both sides that are candidates for delta transfer
    /// (both sizes >= DELTA_MIN_FILE_SIZE and content differs).
    pub delta_candidates: Vec<String>,
}

/// Compare source and destination file listings to determine what needs to be
/// transferred.
///
/// Three-tier comparison for files existing on both sides:
/// 1. Size differs → transfer
/// 2. Both have content_hash → compare hash (skip if equal even with different mtime)
/// 3. Fallback → compare mtime
pub fn compute_sync_plan(
    source: &[FileEntry],
    dest: &[FileEntry],
    delete_extraneous: bool,
) -> SyncPlan {
    let dest_map: HashMap<&str, &FileEntry> = dest.iter().map(|e| (e.path.as_str(), e)).collect();
    let source_map: HashMap<&str, &FileEntry> =
        source.iter().map(|e| (e.path.as_str(), e)).collect();

    let mut files_to_send = Vec::new();
    let mut delta_candidates = Vec::new();

    for src_entry in source {
        if src_entry.is_dir {
            // Directories are always created (cheap to send as CreateDirectory)
            files_to_send.push(src_entry.clone());
            continue;
        }
        match dest_map.get(src_entry.path.as_str()) {
            Some(dst) => {
                // File exists on both sides — three-tier comparison
                if src_entry.size != dst.size {
                    // Size differs — definitely changed, check delta eligibility
                    files_to_send.push(src_entry.clone());
                    if src_entry.size >= DELTA_MIN_FILE_SIZE
                        && dst.size >= DELTA_MIN_FILE_SIZE
                    {
                        delta_candidates.push(src_entry.path.clone());
                    }
                } else if let (Some(src_hash), Some(dst_hash)) =
                    (src_entry.content_hash, dst.content_hash)
                {
                    // Both have content hash — compare directly
                    if src_hash != dst_hash {
                        files_to_send.push(src_entry.clone());
                        if src_entry.size >= DELTA_MIN_FILE_SIZE {
                            delta_candidates.push(src_entry.path.clone());
                        }
                    }
                    // If hashes match, skip (even if mtime differs)
                } else if src_entry.mtime != dst.mtime {
                    // Fallback: mtime comparison
                    files_to_send.push(src_entry.clone());
                    if src_entry.size >= DELTA_MIN_FILE_SIZE
                        && dst.size >= DELTA_MIN_FILE_SIZE
                    {
                        delta_candidates.push(src_entry.path.clone());
                    }
                }
            }
            None => {
                // File only on source — needs transfer
                files_to_send.push(src_entry.clone());
            }
        }
    }

    let mut files_to_delete = Vec::new();
    if delete_extraneous {
        for dst_entry in dest {
            if !source_map.contains_key(dst_entry.path.as_str()) {
                files_to_delete.push(dst_entry.path.clone());
            }
        }
        // Delete deepest paths first (children before parents)
        files_to_delete.sort_by(|a, b| b.len().cmp(&a.len()).then_with(|| b.cmp(a)));
    }

    SyncPlan {
        files_to_send,
        files_to_delete,
        delta_candidates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn file_entry(path: &str, size: u64, mtime: u64, hash: Option<u64>) -> FileEntry {
        FileEntry {
            path: path.to_string(),
            size,
            mtime,
            mode: 0o644,
            is_dir: false,
            is_symlink: false,
            symlink_target: None,
            content_hash: hash,
        }
    }

    fn dir_entry(path: &str) -> FileEntry {
        FileEntry {
            path: path.to_string(),
            size: 0,
            mtime: 1000,
            mode: 0o755,
            is_dir: true,
            is_symlink: false,
            symlink_target: None,
            content_hash: None,
        }
    }

    #[test]
    fn empty_source_and_dest() {
        let plan = compute_sync_plan(&[], &[], false);
        assert!(plan.files_to_send.is_empty());
        assert!(plan.files_to_delete.is_empty());
        assert!(plan.delta_candidates.is_empty());
    }

    #[test]
    fn new_file_on_source() {
        let source = vec![file_entry("a.txt", 100, 1000, Some(111))];
        let dest = vec![];
        let plan = compute_sync_plan(&source, &dest, false);
        assert_eq!(plan.files_to_send.len(), 1);
        assert_eq!(plan.files_to_send[0].path, "a.txt");
    }

    #[test]
    fn file_only_on_dest_with_delete() {
        let source = vec![];
        let dest = vec![file_entry("old.txt", 100, 1000, None)];
        let plan = compute_sync_plan(&source, &dest, true);
        assert!(plan.files_to_send.is_empty());
        assert_eq!(plan.files_to_delete, vec!["old.txt"]);
    }

    #[test]
    fn file_only_on_dest_without_delete() {
        let source = vec![];
        let dest = vec![file_entry("old.txt", 100, 1000, None)];
        let plan = compute_sync_plan(&source, &dest, false);
        assert!(plan.files_to_delete.is_empty());
    }

    #[test]
    fn identical_files_skipped() {
        let source = vec![file_entry("a.txt", 100, 1000, Some(111))];
        let dest = vec![file_entry("a.txt", 100, 1000, Some(111))];
        let plan = compute_sync_plan(&source, &dest, false);
        assert!(plan.files_to_send.is_empty());
    }

    #[test]
    fn size_differs_triggers_transfer() {
        let source = vec![file_entry("a.txt", 200, 1000, Some(111))];
        let dest = vec![file_entry("a.txt", 100, 1000, Some(222))];
        let plan = compute_sync_plan(&source, &dest, false);
        assert_eq!(plan.files_to_send.len(), 1);
    }

    #[test]
    fn hash_match_skips_even_with_different_mtime() {
        let source = vec![file_entry("a.txt", 100, 2000, Some(111))];
        let dest = vec![file_entry("a.txt", 100, 1000, Some(111))];
        let plan = compute_sync_plan(&source, &dest, false);
        // Same size, same hash → skip (even though mtime differs)
        assert!(plan.files_to_send.is_empty());
    }

    #[test]
    fn hash_differs_triggers_transfer() {
        let source = vec![file_entry("a.txt", 100, 1000, Some(111))];
        let dest = vec![file_entry("a.txt", 100, 1000, Some(222))];
        let plan = compute_sync_plan(&source, &dest, false);
        assert_eq!(plan.files_to_send.len(), 1);
    }

    #[test]
    fn no_hash_falls_back_to_mtime() {
        // Same size, no hashes, different mtime → transfer
        let source = vec![file_entry("a.txt", 100, 2000, None)];
        let dest = vec![file_entry("a.txt", 100, 1000, None)];
        let plan = compute_sync_plan(&source, &dest, false);
        assert_eq!(plan.files_to_send.len(), 1);
    }

    #[test]
    fn no_hash_same_mtime_skipped() {
        let source = vec![file_entry("a.txt", 100, 1000, None)];
        let dest = vec![file_entry("a.txt", 100, 1000, None)];
        let plan = compute_sync_plan(&source, &dest, false);
        assert!(plan.files_to_send.is_empty());
    }

    #[test]
    fn directories_always_sent() {
        let source = vec![dir_entry("subdir")];
        let dest = vec![dir_entry("subdir")];
        let plan = compute_sync_plan(&source, &dest, false);
        assert_eq!(plan.files_to_send.len(), 1);
        assert!(plan.files_to_send[0].is_dir);
    }

    #[test]
    fn delta_candidate_large_files_both_sides() {
        let big = 128 * 1024; // > DELTA_MIN_FILE_SIZE (64 KiB)
        let source = vec![file_entry("big.bin", big as u64, 2000, Some(111))];
        let dest = vec![file_entry("big.bin", big as u64, 1000, Some(222))];
        let plan = compute_sync_plan(&source, &dest, false);
        assert_eq!(plan.files_to_send.len(), 1);
        assert_eq!(plan.delta_candidates, vec!["big.bin"]);
    }

    #[test]
    fn delta_candidate_not_for_small_files() {
        let small = 1024u64; // < DELTA_MIN_FILE_SIZE
        let source = vec![file_entry("small.txt", small, 2000, None)];
        let dest = vec![file_entry("small.txt", small, 1000, None)];
        let plan = compute_sync_plan(&source, &dest, false);
        assert_eq!(plan.files_to_send.len(), 1);
        assert!(plan.delta_candidates.is_empty());
    }

    #[test]
    fn delete_order_deepest_first() {
        let source = vec![];
        let dest = vec![
            dir_entry("a"),
            file_entry("a/b/c.txt", 10, 1000, None),
            dir_entry("a/b"),
        ];
        let plan = compute_sync_plan(&source, &dest, true);
        // Deepest paths first
        assert_eq!(plan.files_to_delete[0], "a/b/c.txt");
        assert_eq!(plan.files_to_delete[1], "a/b");
        assert_eq!(plan.files_to_delete[2], "a");
    }
}
