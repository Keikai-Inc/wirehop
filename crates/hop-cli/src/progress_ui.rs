//! Ratatui-based inline progress UI for file transfers.
//!
//! Uses a 2-line inline viewport: line 1 shows the active file's progress bar,
//! line 2 shows an overall summary. Completed files are pushed into terminal
//! scrollback via `insert_before`. Falls back to simple `eprintln` for non-TTY.

use std::collections::{HashMap, HashSet};
use std::io::{self, IsTerminal};
use std::sync::{Arc, Mutex};
use std::time::Instant;

use hop_core::transfer::progress::format_bytes_comma;

use hop_core::transfer::progress::ProgressReporter;
use ratatui::prelude::*;
use ratatui::widgets::Paragraph;
use ratatui::{TerminalOptions, Viewport};

// ---------------------------------------------------------------------------
// Data types
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum DisplayMode {
    Standard, // current format (used by cp)
    Rsync,    // rsync -avP style (used by sync)
}

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
    display_mode: DisplayMode,
    /// Total file count (non-dir, non-symlink) in the plan, for xfr#/to-chk counters.
    total_file_count: usize,
    /// Number of completed file transfers so far (for xfr# counter).
    xfr_count: usize,
    /// Directories already existing on dest (suppressed from rsync output).
    existing_dirs: HashSet<String>,
    /// Path → "YXcstpoguax" itemize string (empty map if -i not used).
    itemize_map: HashMap<String, String>,
    /// Suppress per-file progress stats (--no-progress).
    no_progress: bool,
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
        Self::with_mode(is_push, DisplayMode::Standard, 0, HashSet::new())
    }

    pub fn with_mode(
        is_push: bool,
        display_mode: DisplayMode,
        total_file_count: usize,
        existing_dirs: HashSet<String>,
    ) -> Self {
        Self {
            inner: Arc::new(Mutex::new(TransferStateInner {
                files: Vec::new(),
                file_index: HashMap::new(),
                is_push,
                is_tty: io::stderr().is_terminal(),
                finished: false,
                start_time: Instant::now(),
                scrolled_count: 0,
                display_mode,
                total_file_count,
                xfr_count: 0,
                existing_dirs,
                itemize_map: HashMap::new(),
                no_progress: false,
            })),
        }
    }

    /// Set the itemize map (path → "YXcstpoguax" string).
    pub fn set_itemize_map(&self, map: HashMap<String, String>) {
        self.inner.lock().unwrap().itemize_map = map;
    }

    /// Set whether per-file progress stats are suppressed.
    pub fn set_no_progress(&self, val: bool) {
        self.inner.lock().unwrap().no_progress = val;
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
            // Increment xfr_count for non-dir entries in Rsync mode
            if inner.display_mode == DisplayMode::Rsync
                && !inner.files[idx].path.ends_with('/')
            {
                inner.xfr_count += 1;
            }
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
                // Increment xfr_count for non-dir entries in Rsync mode
                if inner.display_mode == DisplayMode::Rsync
                    && !inner.files[idx].path.ends_with('/')
                {
                    inner.xfr_count += 1;
                }
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
            if inner.display_mode == DisplayMode::Rsync {
                eprintln!("deleting {path}");
            } else {
                eprintln!("  del   {path}");
            }
        }
    }

    fn dir_created(&self, path: &str) {
        let mut inner = self.inner.lock().unwrap();
        // In Rsync mode, suppress directories that already exist on dest
        if inner.display_mode == DisplayMode::Rsync && inner.existing_dirs.contains(path) {
            return;
        }
        let display_path = format!("{path}/");
        let idx = inner.files.len();
        inner.files.push(FileState {
            path: display_path.clone(),
            size: 0,
            status: FileStatus::Done,
        });
        inner.file_index.insert(display_path, idx);
        if !inner.is_tty {
            if inner.display_mode == DisplayMode::Rsync {
                eprintln!("{path}/");
            } else {
                eprintln!("  {path}/");
            }
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
    let (files, scrolled, elapsed, finished, display_mode, xfr_count, total_file_count, itemize_map, no_progress) = {
        let inner = state.inner.lock().unwrap();
        (
            inner.files.clone(),
            inner.scrolled_count,
            inner.start_time.elapsed(),
            inner.finished,
            inner.display_mode,
            inner.xfr_count,
            inner.total_file_count,
            inner.itemize_map.clone(),
            inner.no_progress,
        )
    };

    match display_mode {
        DisplayMode::Standard => {
            render_tick_standard(state, terminal, &files, scrolled, elapsed, finished);
        }
        DisplayMode::Rsync => {
            render_tick_rsync(
                state,
                terminal,
                &files,
                scrolled,
                elapsed,
                finished,
                xfr_count,
                total_file_count,
                &itemize_map,
                no_progress,
            );
        }
    }
}

fn render_tick_standard(
    state: &TransferState,
    terminal: &mut Terminal<CrosstermBackend<io::Stderr>>,
    files: &[FileState],
    scrolled: usize,
    elapsed: std::time::Duration,
    finished: bool,
) {
    // Push consecutive completed files into scrollback.
    let mut new_scrolled = scrolled;
    for (i, file) in files.iter().enumerate().skip(scrolled) {
        if file.status.is_complete() {
            let line_text = format_completed_line(file);
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
    let transferred = compute_transferred_bytes(files);
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

#[allow(clippy::too_many_arguments)]
fn render_tick_rsync(
    state: &TransferState,
    terminal: &mut Terminal<CrosstermBackend<io::Stderr>>,
    files: &[FileState],
    scrolled: usize,
    elapsed: std::time::Duration,
    finished: bool,
    xfr_count: usize,
    total_file_count: usize,
    itemize_map: &HashMap<String, String>,
    no_progress: bool,
) {
    // Push consecutive completed files into scrollback (multi-line for files).
    let mut new_scrolled = scrolled;
    for (i, file) in files.iter().enumerate().skip(scrolled) {
        if file.status.is_complete() {
            let lines = format_completed_lines_rsync(
                file, xfr_count, total_file_count, itemize_map, no_progress,
            );
            let line_count = lines.len();
            if line_count > 0 {
                let _ = terminal.insert_before(line_count as u16, |buf| {
                    let text: Vec<Line> = lines.into_iter().map(Line::from).collect();
                    Paragraph::new(text).render(buf.area, buf);
                });
            }
            new_scrolled = i + 1;
        } else {
            break;
        }
    }

    if new_scrolled > scrolled {
        state.inner.lock().unwrap().scrolled_count = new_scrolled;
    }

    // If --no-progress, draw empty viewport (no active file progress display).
    if no_progress {
        let _ = terminal.draw(|frame| {
            frame.render_widget(Paragraph::new(""), frame.area());
        });
        return;
    }

    // Find the file currently being transferred.
    let active = files.iter().find(|f| {
        matches!(
            f.status,
            FileStatus::Sending { .. } | FileStatus::Receiving { .. }
        )
    });

    let elapsed_secs = elapsed.as_secs_f64();
    let transferred = compute_transferred_bytes(files);
    let speed = if elapsed_secs > 0.5 {
        transferred as f64 / elapsed_secs
    } else {
        0.0
    };

    // Draw the 2-line viewport with rsync-P style active progress.
    let _ = terminal.draw(|frame| {
        let area = frame.area();
        if area.height < 2 || area.width < 10 {
            return;
        }

        let (line1, line2) = if let Some(f) = active {
            let (progress_line, name_line) = format_active_lines_rsync(f, speed);
            (name_line, progress_line)
        } else if finished {
            (String::new(), String::new())
        } else if !files.is_empty() {
            ("confirming...".to_string(), String::new())
        } else {
            (String::new(), String::new())
        };

        let text = vec![Line::from(line1), Line::from(line2)];
        frame.render_widget(Paragraph::new(text), area);
    });
}

/// Insert any remaining completed files that haven't been scrolled yet.
fn flush_remaining(
    state: &TransferState,
    terminal: &mut Terminal<CrosstermBackend<io::Stderr>>,
) {
    let (files, scrolled, display_mode, xfr_count, total_file_count, itemize_map, no_progress) = {
        let inner = state.inner.lock().unwrap();
        (
            inner.files.clone(),
            inner.scrolled_count,
            inner.display_mode,
            inner.xfr_count,
            inner.total_file_count,
            inner.itemize_map.clone(),
            inner.no_progress,
        )
    };

    for file in files.iter().skip(scrolled) {
        if file.status.is_complete() {
            match display_mode {
                DisplayMode::Standard => {
                    let line_text = format_completed_line(file);
                    let _ = terminal.insert_before(1, |buf| {
                        Paragraph::new(Line::from(line_text)).render(buf.area, buf);
                    });
                }
                DisplayMode::Rsync => {
                    let lines = format_completed_lines_rsync(
                        file, xfr_count, total_file_count, &itemize_map, no_progress,
                    );
                    let line_count = lines.len();
                    if line_count > 0 {
                        let _ = terminal.insert_before(line_count as u16, |buf| {
                            let text: Vec<Line> = lines.into_iter().map(Line::from).collect();
                            Paragraph::new(text).render(buf.area, buf);
                        });
                    }
                }
            }
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

/// Format a completed file entry in rsync style. Returns multiple lines:
/// - Dirs: 1 line (`path/`)
/// - Deletes: 1 line (`deleting path`) or with itemize `*deleting   path`
/// - Files: 2 lines (filename, then `{size:>15} 100% {speed} {time} (xfr#N, to-chk=M/T)`)
///   With --no-progress: 1 line (filename only)
/// - Errors: 1 line
fn format_completed_lines_rsync(
    file: &FileState,
    xfr_count: usize,
    total_file_count: usize,
    itemize_map: &HashMap<String, String>,
    no_progress: bool,
) -> Vec<String> {
    match &file.status {
        FileStatus::Confirmed | FileStatus::Done => {
            if file.path.ends_with('/') {
                // Directory — single line, optionally prefixed with itemize string
                let name = if let Some(change_str) = itemize_map.get(
                    file.path.trim_end_matches('/')
                ) {
                    format!("{} {}", change_str, file.path)
                } else {
                    file.path.clone()
                };
                vec![name]
            } else {
                // File — optionally prefixed with itemize string
                let name = if let Some(change_str) = itemize_map.get(&file.path) {
                    format!("{} {}", change_str, file.path)
                } else {
                    file.path.clone()
                };

                if no_progress {
                    // --no-progress: filename only, no stats line
                    vec![name]
                } else {
                    let to_chk = total_file_count.saturating_sub(xfr_count);
                    let stats = format!(
                        "{:>15} 100%    0.00kB/s    0:00:00 (xfr#{}, to-chk={}/{})",
                        format_bytes_comma(file.size),
                        xfr_count,
                        to_chk,
                        total_file_count,
                    );
                    vec![name, stats]
                }
            }
        }
        FileStatus::Deleted => {
            if !itemize_map.is_empty() {
                vec![format!("*deleting   {}", file.path)]
            } else {
                vec![format!("deleting {}", file.path)]
            }
        }
        FileStatus::Skipped => {
            // Skipped files are not shown in rsync mode
            vec![]
        }
        FileStatus::Error(e) => {
            vec![format!("ERROR: {} {e}", file.path)]
        }
        _ => vec![],
    }
}

/// Format an active (in-progress) file in rsync -P style.
/// Returns (progress_line, filename_line).
fn format_active_lines_rsync(file: &FileState, speed: f64) -> (String, String) {
    let (bytes_transferred, total) = match &file.status {
        FileStatus::Sending {
            bytes_transferred,
            total,
        }
        | FileStatus::Receiving {
            bytes_transferred,
            total,
        } => (*bytes_transferred, *total),
        _ => return (String::new(), file.path.clone()),
    };

    let pct = if total > 0 {
        (bytes_transferred as f64 / total as f64 * 100.0).min(100.0) as u8
    } else {
        0
    };

    let speed_str = if speed > 0.0 {
        format_speed_rsync(speed)
    } else {
        "0.00kB/s".to_string()
    };

    let eta = if speed > 0.0 && total > bytes_transferred {
        let remaining = total - bytes_transferred;
        let secs = (remaining as f64 / speed) as u64;
        format!("{}:{:02}:{:02}", secs / 3600, (secs % 3600) / 60, secs % 60)
    } else {
        "0:00:00".to_string()
    };

    let progress_line = format!(
        "{:>15} {:>3}%   {:>10}    {}",
        format_bytes_comma(bytes_transferred),
        pct,
        speed_str,
        eta,
    );

    (progress_line, file.path.clone())
}

/// Format speed in rsync style (e.g. `12.00MB/s`, `3.45kB/s`).
fn format_speed_rsync(bytes_per_sec: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * KB;
    const GB: f64 = 1024.0 * MB;
    if bytes_per_sec >= GB {
        format!("{:.2}GB/s", bytes_per_sec / GB)
    } else if bytes_per_sec >= MB {
        format!("{:.2}MB/s", bytes_per_sec / MB)
    } else if bytes_per_sec >= KB {
        format!("{:.2}kB/s", bytes_per_sec / KB)
    } else {
        format!("{:.2}B/s", bytes_per_sec)
    }
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
