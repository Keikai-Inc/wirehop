//! Compute rsync-style itemize-changes strings (YXcstpoguax).

use std::collections::HashMap;

use hop_core::proto::FileEntry;

/// Compute an itemize map from plan entries and destination entries.
///
/// Returns a map of path → "YXcstpoguax" string for each entry in
/// `plan_entries`. The `dest_entries` are the files currently on the
/// destination side, used to determine what changed.
///
/// `is_push` controls the direction character: `<` for push, `>` for pull.
pub fn compute_itemize_map(
    plan_entries: &[FileEntry],
    dest_entries: &[FileEntry],
    is_push: bool,
) -> HashMap<String, String> {
    let dest_map: HashMap<&str, &FileEntry> = dest_entries
        .iter()
        .map(|e| (e.path.as_str(), e))
        .collect();

    let mut result = HashMap::new();

    for entry in plan_entries {
        let itemize_str = match dest_map.get(entry.path.as_str()) {
            None => {
                // New file/dir — all plusses
                if entry.is_dir {
                    "cd+++++++++".to_string()
                } else if entry.is_symlink {
                    "cL+++++++++".to_string()
                } else {
                    let dir_char = if is_push { '<' } else { '>' };
                    format!("{}f+++++++++", dir_char)
                }
            }
            Some(dest) => {
                // Existing entry — compare fields
                if entry.is_dir {
                    // Dirs that exist already shouldn't be in the plan normally,
                    // but if they are, show minimal change
                    ".d..........".to_string()
                } else {
                    let dir_char = if is_push { '<' } else { '>' };
                    let type_char = if entry.is_symlink { 'L' } else { 'f' };

                    // pos 2: content (c) — hash differs or not available
                    let c = match (entry.content_hash, dest.content_hash) {
                        (Some(a), Some(b)) if a != b => 'c',
                        (Some(_), Some(_)) => '.',
                        _ => {
                            // No hash available — infer from size/mtime
                            if entry.size != dest.size {
                                'c'
                            } else {
                                '.'
                            }
                        }
                    };

                    // pos 3: size (s)
                    let s = if entry.size != dest.size { 's' } else { '.' };

                    // pos 4: mtime (t)
                    let t = if entry.mtime != dest.mtime { 't' } else { '.' };

                    // pos 5: permissions (p)
                    let p = if entry.mode != dest.mode { 'p' } else { '.' };

                    // pos 6-10: owner/group/unused/acl/xattr — always '.'
                    format!("{}{}{}{}{}{}.....", dir_char, type_char, c, s, t, p)
                }
            }
        };

        result.insert(entry.path.clone(), itemize_str);
    }

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(path: &str, size: u64, mtime: u64, is_dir: bool) -> FileEntry {
        FileEntry {
            path: path.to_string(),
            size,
            mtime,
            mode: 0o644,
            is_dir,
            is_symlink: false,
            symlink_target: None,
            content_hash: None,
        }
    }

    #[test]
    fn new_file_pull() {
        let plan = vec![make_entry("test.txt", 100, 1000, false)];
        let dest = vec![];
        let map = compute_itemize_map(&plan, &dest, false);
        assert_eq!(map.get("test.txt").unwrap(), ">f+++++++++");
    }

    #[test]
    fn new_file_push() {
        let plan = vec![make_entry("test.txt", 100, 1000, false)];
        let dest = vec![];
        let map = compute_itemize_map(&plan, &dest, true);
        assert_eq!(map.get("test.txt").unwrap(), "<f+++++++++");
    }

    #[test]
    fn new_dir() {
        let plan = vec![make_entry("subdir", 0, 0, true)];
        let dest = vec![];
        let map = compute_itemize_map(&plan, &dest, false);
        assert_eq!(map.get("subdir").unwrap(), "cd+++++++++");
    }

    #[test]
    fn changed_size_and_mtime() {
        let plan = vec![make_entry("test.txt", 200, 2000, false)];
        let dest = vec![make_entry("test.txt", 100, 1000, false)];
        let map = compute_itemize_map(&plan, &dest, false);
        // size differs → c='c', s='s', mtime differs → t='t', mode same → p='.'
        assert_eq!(map.get("test.txt").unwrap(), ">fcst......");
    }

    #[test]
    fn changed_mtime_only() {
        let plan = vec![make_entry("test.txt", 100, 2000, false)];
        let dest = vec![make_entry("test.txt", 100, 1000, false)];
        let map = compute_itemize_map(&plan, &dest, false);
        assert_eq!(map.get("test.txt").unwrap(), ">f..t......");
    }
}
