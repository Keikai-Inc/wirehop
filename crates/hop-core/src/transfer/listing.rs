//! Directory walking and sync comparison logic.

use std::collections::HashMap;
use std::path::Path;
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};

use crate::proto::FileEntry;

/// Recursively walk a directory and return a flat list of entries with paths
/// relative to `root`.
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
    let read_dir = std::fs::read_dir(current)
        .with_context(|| format!("cannot read directory: {}", current.display()))?;

    for entry in read_dir {
        let entry = entry?;
        let metadata = entry.metadata()?;
        let full_path = entry.path();
        let rel_path = full_path
            .strip_prefix(base)
            .unwrap_or(&full_path)
            .to_string_lossy()
            .to_string();

        let symlink_meta = std::fs::symlink_metadata(&full_path)?;
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
}

/// Compare source and destination file listings to determine what needs to be
/// transferred. A file is "changed" if it exists only on source, or if its
/// size or mtime differs.
pub fn compute_sync_plan(
    source: &[FileEntry],
    dest: &[FileEntry],
    delete_extraneous: bool,
) -> SyncPlan {
    let dest_map: HashMap<&str, &FileEntry> = dest.iter().map(|e| (e.path.as_str(), e)).collect();
    let source_map: HashMap<&str, &FileEntry> =
        source.iter().map(|e| (e.path.as_str(), e)).collect();

    let mut files_to_send = Vec::new();
    for src_entry in source {
        if src_entry.is_dir {
            // Directories are always created (cheap to send as CreateDirectory)
            files_to_send.push(src_entry.clone());
            continue;
        }
        match dest_map.get(src_entry.path.as_str()) {
            Some(dst) => {
                // File exists on both sides — check if changed
                if src_entry.size != dst.size || src_entry.mtime != dst.mtime {
                    files_to_send.push(src_entry.clone());
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
    }
}
