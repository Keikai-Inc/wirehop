//! Ratatui-based inline progress UI for file transfers.
//!
//! Uses a 2-line inline viewport: line 1 shows the active file's progress bar,
//! line 2 shows an overall summary. Completed files are pushed into terminal
//! scrollback via `insert_before`. Falls back to simple `eprintln` for non-TTY.

use std::collections::HashMap;
use std::io::{self, IsTerminal};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use hop_core::transfer::progress::ProgressReporter;
use ratatui::prelude::*;
use ratatui::widgets::Paragraph;
use ratatui::{TerminalOptions, Viewport};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Clone)]
enum FileStatus {
    Sending { bytes_transferred: u64, total: u64 },
    Sent,
    Confirmed,
    Receiving { bytes_transferred: u64, total: u64 },
    Done,
    Skipped,
    Deleted,
    Error(String),
}

impl FileStatus {
    /// Whether this file has reached a final state and can be pushed to scrollback.
    fn is_complete(&self) -> bool {
        matches!(
            self,
            Self::Confirmed | Self::Done | Self::Skipped | Self::Deleted | Self::Error(_)
        )
    }
}

#[derive(Clone)]
struct FileState {
    path: String,
    size: u64,
    status: FileStatus,
}

struct TransferStateInner {
    files: Vec<FileState>,
    file_index: HashMap<String, usize>,
    is_push: bool,
    is_tty: bool,
    finished: bool,
    start_time: Instant,
    /// Number of consecutive files (from index 0) that have been pushed to scrollback.
    scrolled_count: usize,
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Shared transfer progress state. Implements `ProgressReporter` so it can be
/// passed directly to hop-core transfer functions.
pub struct TransferState {
    inner: Arc<Mutex<TransferStateInner>>,
}

impl Clone for TransferState {
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
        }
    }
}

impl TransferState {
    pub fn new(is_push: bool) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TransferStateInner {
                files: Vec::new(),
                file_index: HashMap::new(),
                is_push,
                is_tty: io::stderr().is_terminal(),
                finished: false,
                start_time: Instant::now(),
                scrolled_count: 0,
            })),
        }
    }

    /// Signal that the transfer is complete so the render loop can exit.
    pub fn mark_finished(&self) {
        self.inner.lock().unwrap().finished = true;
    }
}

// ---------------------------------------------------------------------------
// ProgressReporter impl
// ---------------------------------------------------------------------------

impl ProgressReporter for TransferState {
    fn file_started(&self, path: &str, size: u64) {
        let mut inner = self.inner.lock().unwrap();
        let status = if inner.is_push {
            FileStatus::Sending {
                bytes_transferred: 0,
                total: size,
            }
        } else {
            FileStatus::Receiving {
                bytes_transferred: 0,
                total: size,
            }
        };
        let idx = inner.files.len();
        inner.files.push(FileState {
            path: path.to_string(),
            size,
            status,
        });
        inner.file_index.insert(path.to_string(), idx);
        if !inner.is_tty {
            eprint!("  {} ({})...", path, format_size(size));
        }
    }

    fn file_progress(&self, path: &str, bytes_transferred: u64, total: u64) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(&idx) = inner.file_index.get(path) {
            inner.files[idx].status = if inner.is_push {
                FileStatus::Sending {
                    bytes_transferred,
                    total,
                }
            } else {
                FileStatus::Receiving {
                    bytes_transferred,
                    total,
                }
            };
        }
    }

    fn file_done(&self, path: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(&idx) = inner.file_index.get(path) {
            let status = if inner.is_push {
                FileStatus::Sent
            } else {
                FileStatus::Done
            };
            inner.files[idx].status = status;
            // For pull, "done" is the final state — print immediately in non-TTY mode.
            if !inner.is_tty && !inner.is_push {
                eprintln!(" done");
            }
        }
    }

    fn file_confirmed(&self, path: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(&idx) = inner.file_index.get(path) {
            // Only transition from Sent → Confirmed (ignore acks for dirs/deletes).
            if matches!(inner.files[idx].status, FileStatus::Sent) {
                inner.files[idx].status = FileStatus::Confirmed;
                if !inner.is_tty {
                    eprintln!(" done");
                }
            }
        }
    }

    fn file_skipped(&self, path: &str) {
        let mut inner = self.inner.lock().unwrap();
        let idx = inner.files.len();
        inner.files.push(FileState {
            path: path.to_string(),
            size: 0,
            status: FileStatus::Skipped,
        });
        inner.file_index.insert(path.to_string(), idx);
        if !inner.is_tty {
            eprintln!("  skip  {path}");
        }
    }

    fn file_deleted(&self, path: &str) {
        let mut inner = self.inner.lock().unwrap();
        let idx = inner.files.len();
        inner.files.push(FileState {
            path: path.to_string(),
            size: 0,
            status: FileStatus::Deleted,
        });
        inner.file_index.insert(path.to_string(), idx);
        if !inner.is_tty {
            eprintln!("  del   {path}");
        }
    }

    fn dir_created(&self, path: &str) {
        let mut inner = self.inner.lock().unwrap();
        let display_path = format!("{path}/");
        let idx = inner.files.len();
        inner.files.push(FileState {
            path: display_path.clone(),
            size: 0,
            status: FileStatus::Done,
        });
        inner.file_index.insert(display_path, idx);
        if !inner.is_tty {
            eprintln!("  {path}/");
        }
    }

    fn file_error(&self, path: &str, error: &str) {
        let mut inner = self.inner.lock().unwrap();
        if let Some(&idx) = inner.file_index.get(path) {
            inner.files[idx].status = FileStatus::Error(error.to_string());
        } else {
            let idx = inner.files.len();
            inner.files.push(FileState {
                path: path.to_string(),
                size: 0,
                status: FileStatus::Error(error.to_string()),
            });
            inner.file_index.insert(path.to_string(), idx);
        }
        if !inner.is_tty {
            eprintln!("  ERROR {path}: {error}");
        }
    }
}

// ---------------------------------------------------------------------------
// Render loop
// ---------------------------------------------------------------------------

/// Spawn a background render loop that updates the inline progress display.
///
/// For non-TTY output, returns a no-op handle (progress is reported via
/// `eprintln` directly in the `ProgressReporter` callbacks).
pub fn spawn_render_loop(state: TransferState) -> tokio::task::JoinHandle<()> {
    let is_tty = state.inner.lock().unwrap().is_tty;
    if !is_tty {
        return tokio::spawn(async {});
    }

    tokio::spawn(async move {
        let backend = CrosstermBackend::new(io::stderr());
        let options = TerminalOptions {
            viewport: Viewport::Inline(2),
        };
        let Ok(mut terminal) = Terminal::with_options(backend, options) else {
            return;
        };

        loop {
            render_tick(&state, &mut terminal);

            if state.inner.lock().unwrap().finished {
                flush_remaining(&state, &mut terminal);
                // Clear the viewport so the cursor ends up cleanly positioned.
                let _ = terminal.draw(|frame| {
                    frame.render_widget(Paragraph::new(""), frame.area());
                });
                break;
            }

            tokio::time::sleep(std::time::Duration::from_millis(80)).await;
        }
    })
}

fn render_tick(
    state: &TransferState,
    terminal: &mut Terminal<CrosstermBackend<io::Stderr>>,
) {
    let (files, scrolled, elapsed, finished) = {
        let inner = state.inner.lock().unwrap();
        (
            inner.files.clone(),
            inner.scrolled_count,
            inner.start_time.elapsed(),
            inner.finished,
        )
    };

    // Push consecutive completed files into scrollback.
    let mut new_scrolled = scrolled;
    for i in scrolled..files.len() {
        if files[i].status.is_complete() {
            let line_text = format_completed_line(&files[i]);
            let _ = terminal.insert_before(1, |buf| {
                Paragraph::new(Line::from(line_text)).render(buf.area, buf);
            });
            new_scrolled = i + 1;
        } else {
            break;
        }
    }

    if new_scrolled > scrolled {
        state.inner.lock().unwrap().scrolled_count = new_scrolled;
    }

    // Find the file currently being transferred.
    let active = files.iter().find(|f| {
        matches!(
            f.status,
            FileStatus::Sending { .. } | FileStatus::Receiving { .. }
        )
    });

    // Compute aggregate stats.
    let elapsed_secs = elapsed.as_secs_f64();
    let transferred = compute_transferred_bytes(&files);
    let speed = if elapsed_secs > 0.5 {
        transferred as f64 / elapsed_secs
    } else {
        0.0
    };
    let completed_count = files.iter().filter(|f| f.status.is_complete()).count();
    let total_count = files.len();

    // Draw the 2-line viewport.
    let _ = terminal.draw(|frame| {
        let area = frame.area();
        if area.height < 2 || area.width < 10 {
            return;
        }
        let w = area.width as usize;

        let line1 = if let Some(f) = active {
            format_active_line(f, speed, w)
        } else if finished {
            String::new()
        } else if !files.is_empty() {
            "  confirming...".to_string()
        } else {
            String::new()
        };

        let speed_str = if speed > 0.0 {
            format!("{}/s", format_size(speed as u64))
        } else {
            String::new()
        };
        let line2 = format!(
            "  {}/{} files | {}{}",
            completed_count,
            total_count,
            format_size(transferred),
            if speed_str.is_empty() {
                String::new()
            } else {
                format!(" | {speed_str}")
            },
        );

        let text = vec![Line::from(line1), Line::from(line2)];
        frame.render_widget(Paragraph::new(text), area);
    });
}

/// Insert any remaining completed files that haven't been scrolled yet.
fn flush_remaining(
    state: &TransferState,
    terminal: &mut Terminal<CrosstermBackend<io::Stderr>>,
) {
    let (files, scrolled) = {
        let inner = state.inner.lock().unwrap();
        (inner.files.clone(), inner.scrolled_count)
    };

    for i in scrolled..files.len() {
        if files[i].status.is_complete() {
            let line_text = format_completed_line(&files[i]);
            let _ = terminal.insert_before(1, |buf| {
                Paragraph::new(Line::from(line_text)).render(buf.area, buf);
            });
        }
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn format_completed_line(file: &FileState) -> String {
    let marker = match &file.status {
        FileStatus::Confirmed | FileStatus::Done => "\u{2713}",
        FileStatus::Skipped => "skip",
        FileStatus::Deleted => "del",
        FileStatus::Error(e) => return format!("  {}  ERROR: {e}", file.path),
        _ => "?",
    };

    if file.size > 0 {
        format!(
            "  {:<24} {:>8}  {marker}",
            file.path,
            format_size(file.size)
        )
    } else {
        format!("  {:<24} {marker}", file.path)
    }
}

fn format_active_line(file: &FileState, speed: f64, width: usize) -> String {
    let (bytes_transferred, total) = match &file.status {
        FileStatus::Sending {
            bytes_transferred,
            total,
        }
        | FileStatus::Receiving {
            bytes_transferred,
            total,
        } => (*bytes_transferred, *total),
        _ => return format!("  {}", file.path),
    };

    let progress_str = format!(
        "{} / {}",
        format_size(bytes_transferred),
        format_size(total)
    );

    // Build the progress bar: [========>           ]
    let bar_width: usize = 20;
    let fraction = if total > 0 {
        (bytes_transferred as f64 / total as f64).min(1.0)
    } else {
        0.0
    };
    let filled = (fraction * bar_width as f64) as usize;
    let bar = {
        let mut b = String::with_capacity(bar_width + 2);
        b.push('[');
        for i in 0..bar_width {
            if i < filled {
                b.push('=');
            } else if i == filled && filled < bar_width {
                b.push('>');
            } else {
                b.push(' ');
            }
        }
        b.push(']');
        b
    };

    let speed_str = if speed > 0.0 {
        format!("{}/s", format_size(speed as u64))
    } else {
        String::new()
    };

    let eta_str = if speed > 0.0 && total > bytes_transferred {
        let remaining = total - bytes_transferred;
        let eta_secs = remaining as f64 / speed;
        if eta_secs < 60.0 {
            format!("ETA {:.0}s", eta_secs)
        } else {
            format!("ETA {:.0}m", eta_secs / 60.0)
        }
    } else {
        String::new()
    };

    let suffix_parts: Vec<&str> = [speed_str.as_str(), eta_str.as_str()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    let suffix = suffix_parts.join("  ");

    let core = format!("  {}  {}  {}", file.path, progress_str, bar);
    if suffix.is_empty() {
        truncate_to_width(&core, width)
    } else {
        truncate_to_width(&format!("{core}  {suffix}"), width)
    }
}

fn truncate_to_width(s: &str, width: usize) -> String {
    if s.len() <= width {
        s.to_string()
    } else if width > 3 {
        format!("{}...", &s[..width - 3])
    } else {
        s[..width].to_string()
    }
}

fn compute_transferred_bytes(files: &[FileState]) -> u64 {
    files
        .iter()
        .map(|f| match &f.status {
            FileStatus::Sending {
                bytes_transferred, ..
            }
            | FileStatus::Receiving {
                bytes_transferred, ..
            } => *bytes_transferred,
            FileStatus::Sent | FileStatus::Confirmed | FileStatus::Done => f.size,
            _ => 0,
        })
        .sum()
}

pub fn format_size(bytes: u64) -> String {
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
