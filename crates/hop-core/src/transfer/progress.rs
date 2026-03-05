//! Progress reporting for file transfers.

use std::fmt;
use std::time::Duration;

/// Trait for reporting transfer progress to the UI.
pub trait ProgressReporter: Send + Sync {
    /// Called when starting to send/receive a file.
    fn file_started(&self, path: &str, size: u64);
    /// Called as data chunks are transferred.
    fn file_progress(&self, path: &str, bytes_transferred: u64, total: u64);
    /// Called when a file is fully transferred.
    fn file_done(&self, path: &str);
    /// Called when a file is skipped (unchanged in sync mode).
    fn file_skipped(&self, path: &str);
    /// Called when a file/directory is deleted (sync --delete).
    fn file_deleted(&self, path: &str);
    /// Called when a directory is created.
    fn dir_created(&self, path: &str);
    /// Called on error for a specific file.
    fn file_error(&self, path: &str, error: &str);
    /// Called when the remote host confirms receipt of a file (ack received).
    /// Default no-op — only meaningful for push transfers on the client side.
    fn file_confirmed(&self, _path: &str) {}
}

/// Summary of a completed transfer.
#[derive(Debug, Default)]
pub struct TransferSummary {
    pub files_transferred: u64,
    pub files_skipped: u64,
    pub files_deleted: u64,
    pub dirs_created: u64,
    pub bytes_transferred: u64,
    pub bytes_saved: u64,
    pub errors: Vec<String>,
    pub elapsed: Duration,
}

impl fmt::Display for TransferSummary {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let has_work = self.files_transferred > 0
            || self.dirs_created > 0
            || self.bytes_transferred > 0
            || self.files_deleted > 0;
        if has_work {
            // Build a compact summary: "transferred 2 file(s), 1 dir(s), 3.0 KB in 0.1s"
            write!(f, "transferred {} file(s)", self.files_transferred)?;
            if self.dirs_created > 0 {
                write!(f, ", {} dir(s)", self.dirs_created)?;
            }
            write!(
                f,
                ", {} in {:.1}s",
                format_bytes(self.bytes_transferred),
                self.elapsed.as_secs_f64(),
            )?;
        } else {
            write!(f, "nothing to transfer")?;
        }
        if self.files_skipped > 0 {
            write!(f, ", {} skipped", self.files_skipped)?;
        }
        if self.files_deleted > 0 && self.files_transferred == 0 && self.dirs_created == 0 {
            // Only show "deleted" standalone when nothing was transferred
            write!(f, "deleted {} file(s)", self.files_deleted)?;
        } else if self.files_deleted > 0 {
            write!(f, ", {} deleted", self.files_deleted)?;
        }
        if !self.errors.is_empty() {
            write!(f, ", {} error(s)", self.errors.len())?;
        }
        Ok(())
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = 1024 * KB;
    const GB: u64 = 1024 * MB;
    if bytes >= GB {
        format!("{:.1} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.1} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes as f64 / KB as f64)
    } else {
        format!("{bytes} B")
    }
}

/// A no-op progress reporter (for host-side use where we don't display progress).
pub struct SilentProgress;

impl ProgressReporter for SilentProgress {
    fn file_started(&self, _path: &str, _size: u64) {}
    fn file_progress(&self, _path: &str, _bytes_transferred: u64, _total: u64) {}
    fn file_done(&self, _path: &str) {}
    fn file_skipped(&self, _path: &str) {}
    fn file_deleted(&self, _path: &str) {}
    fn dir_created(&self, _path: &str) {}
    fn file_error(&self, _path: &str, _error: &str) {}
}
