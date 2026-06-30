//! Log-source discovery + search backend (G24 — federated log search UX).
//!
//! Runs on **each node** behind the hidden `hop __logsources` / `hop __logsearch`
//! commands, so a federated `hop fleet search` resolves the RIGHT source per-OS
//! (macOS unified log via `log show`, Linux journald/syslog, the hop audit log,
//! and well-known `/var/log` files) and does the matching **in-process** (fast,
//! smart-case, structured) instead of shelling out to `grep` on each node. The
//! client (one-shot or the interactive TUI) consumes the emitted NDJSON.
//!
//! Discoverability: `discover_sources()` lets `hop fleet sources` show users the
//! menu of what's actually searchable on each machine instead of a magic flag.

use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::process::{Command, Stdio};

use serde::{Deserialize, Serialize};

/// A searchable log source on this node — surfaced by `hop fleet sources`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogSource {
    /// Selector the user passes to `--source` (`system`, `audit`, or a name/path).
    pub id: String,
    /// Human label, e.g. "macOS unified log" or "nginx access".
    pub label: String,
    /// `system` | `audit` | `file`.
    pub kind: String,
    /// What it resolves to here: a command (`log show`) or a path.
    pub detail: String,
    /// Present + readable on this node right now.
    pub available: bool,
}

/// One matched log line, emitted as NDJSON by `hop __logsearch`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogLine {
    /// Best-effort timestamp text parsed from the line (display only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ts: Option<String>,
    /// The source id this came from.
    pub source: String,
    /// The raw log line (already matched).
    pub line: String,
}

/// How a source is read on this node.
enum Access {
    /// Spawn a command and read its stdout (log show / journalctl).
    Command(Vec<String>),
    /// Read a plain file.
    File(PathBuf),
    /// The hop audit log, via `hop audit --json` (daemon socket).
    Audit,
}

const MACOS_LOG: &str = "/usr/bin/log";

/// Well-known application log files to advertise when present (basename → path).
fn well_known_files() -> Vec<(&'static str, &'static str)> {
    vec![
        ("nginx", "/var/log/nginx/access.log"),
        ("nginx-error", "/var/log/nginx/error.log"),
        ("apache", "/var/log/apache2/access.log"),
        ("auth", "/var/log/auth.log"),
        ("kern", "/var/log/kern.log"),
        ("dpkg", "/var/log/dpkg.log"),
        ("install", "/var/log/install.log"),
    ]
}

fn readable(path: &str) -> bool {
    std::fs::File::open(path).is_ok()
}

fn cmd_exists(path: &str) -> bool {
    std::path::Path::new(path).exists()
}

fn linux_journalctl() -> bool {
    ["/usr/bin/journalctl", "/bin/journalctl"].iter().any(|p| cmd_exists(p))
}

/// The default OS system-log source for this node (`system`), resolved.
fn resolve_system(since: &str, line_cap: usize) -> (Access, String) {
    if cfg!(target_os = "macos") {
        // The macOS UNIFIED log — where modern macOS actually logs (the legacy
        // /var/log/system.log is nearly empty). `--last` accepts 1h/30m/2d.
        (
            Access::Command(vec![
                MACOS_LOG.into(),
                "show".into(),
                "--style".into(),
                "compact".into(),
                "--last".into(),
                since.to_string(),
            ]),
            "log show (unified log)".into(),
        )
    } else if linux_journalctl() {
        // journald — bound by line count (robust across distros vs date parsing).
        (
            Access::Command(vec![
                "journalctl".into(),
                "--no-pager".into(),
                "-n".into(),
                line_cap.to_string(),
            ]),
            "journalctl".into(),
        )
    } else if readable("/var/log/syslog") {
        (Access::File("/var/log/syslog".into()), "/var/log/syslog".into())
    } else if readable("/var/log/messages") {
        (Access::File("/var/log/messages".into()), "/var/log/messages".into())
    } else if readable("/var/log/system.log") {
        (Access::File("/var/log/system.log".into()), "/var/log/system.log".into())
    } else {
        // Nothing readable — an empty file read yields zero hits, not an error.
        (Access::File("/dev/null".into()), "(no system log)".into())
    }
}

/// Discover the log sources searchable on THIS node (for `hop fleet sources`).
pub fn discover_sources() -> Vec<LogSource> {
    let mut out = Vec::new();
    out.push(LogSource {
        id: "audit".into(),
        label: "hop audit log".into(),
        kind: "audit".into(),
        detail: "structured auth/connection/exec events".into(),
        available: true,
    });
    let (sys_access, sys_detail) = resolve_system("1h", 1);
    let sys_available = match &sys_access {
        Access::Command(argv) => cmd_exists(&argv[0]),
        Access::File(p) => p.to_str().map(readable).unwrap_or(false),
        Access::Audit => true,
    };
    out.push(LogSource {
        id: "system".into(),
        label: if cfg!(target_os = "macos") { "macOS unified log".into() } else { "system log".into() },
        kind: "system".into(),
        detail: sys_detail,
        available: sys_available,
    });
    for (name, path) in well_known_files() {
        if readable(path) {
            out.push(LogSource {
                id: name.into(),
                label: format!("{name} log"),
                kind: "file".into(),
                detail: path.into(),
                available: true,
            });
        }
    }
    out
}

/// Resolve a `--source` selector + window into an [`Access`] + display detail.
fn resolve(source: &str, since: &str, line_cap: usize) -> (Access, String) {
    if source == "audit" {
        return (Access::Audit, "hop audit log".into());
    }
    if source == "system" {
        return resolve_system(since, line_cap);
    }
    // A path (contains a slash) → that file.
    if source.contains('/') {
        return (Access::File(source.into()), source.to_string());
    }
    // A well-known name → its file, if present.
    if let Some((_, path)) = well_known_files().into_iter().find(|(n, _)| *n == source) {
        return (Access::File(path.into()), path.to_string());
    }
    // Unknown bare name → treat as a /var/log/<name>.log guess.
    let guess = format!("/var/log/{source}.log");
    (Access::File(PathBuf::from(&guess)), guess)
}

/// Smart-case substring match: case-insensitive unless `needle` has an uppercase
/// char (then case-sensitive) — the ripgrep/fzf convention.
fn smart_match(haystack: &str, needle: &str, needle_has_upper: bool) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle_has_upper {
        haystack.contains(needle)
    } else {
        haystack.to_ascii_lowercase().contains(needle)
    }
}

/// Pull a leading timestamp-ish token off a line for display (best-effort): the
/// `log show` compact + syslog formats both lead with a date/time field.
fn parse_ts(line: &str, source_kind_macos: bool) -> Option<String> {
    let trimmed = line.trim_start();
    if source_kind_macos {
        // "2026-06-29 22:30:49.193 ..." → keep the HH:MM:SS.
        let mut it = trimmed.split_whitespace();
        let _date = it.next()?;
        let time = it.next()?;
        return Some(time.split('.').next().unwrap_or(time).to_string());
    }
    // syslog: "Jun 29 22:26:40 host ..." → "Jun 29 22:26:40".
    let parts: Vec<&str> = trimmed.split_whitespace().take(3).collect();
    if parts.len() == 3 {
        Some(parts.join(" "))
    } else {
        None
    }
}

/// Run a search on this node, emitting each matching [`LogLine`] via `emit`.
/// `grep` is an optional smart-case substring pre-filter; `limit` caps emitted
/// matches. `line_cap` bounds how many source lines are scanned (back-pressure).
pub fn search(
    source: &str,
    since: &str,
    grep: Option<&str>,
    limit: usize,
    line_cap: usize,
    mut emit: impl FnMut(LogLine),
) -> anyhow::Result<()> {
    let (access, _detail) = resolve(source, since, line_cap);
    let needle_has_upper = grep.map(|g| g.chars().any(|c| c.is_ascii_uppercase())).unwrap_or(false);
    // Smart-case needle: keep the original when it has an uppercase char (matched
    // case-sensitively); lowercase it otherwise (matched against a lowercased line).
    let needle: Option<String> =
        grep.map(|g| if needle_has_upper { g.to_string() } else { g.to_ascii_lowercase() });
    let macos_sys = cfg!(target_os = "macos") && source == "system";
    let mut emitted = 0usize;

    // A line consumer shared across the access kinds.
    let mut consume = |raw: String| -> bool {
        if emitted >= limit {
            return false; // stop
        }
        let matched = match needle.as_deref() {
            Some(g) => smart_match(&raw, g, needle_has_upper),
            None => true,
        };
        if matched {
            let ts = parse_ts(&raw, macos_sys);
            emit(LogLine { ts, source: source.to_string(), line: raw });
            emitted += 1;
        }
        emitted < limit
    };

    match access {
        Access::Audit => {
            // Reuse the daemon's audit reader via the CLI (NDJSON per line). The
            // `hop` binary is on PATH on the node; runs over the daemon socket.
            let mut child = Command::new("hop")
                .args(["audit", "--json", "--since", since, "--limit", &line_cap.to_string()])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()?;
            if let Some(out) = child.stdout.take() {
                for line in BufReader::new(out).lines().map_while(Result::ok) {
                    // The audit JSON has its own structure; match the raw JSON text
                    // and re-wrap so provenance is uniform.
                    if !consume(line) {
                        break;
                    }
                }
            }
            let _ = child.wait();
        }
        Access::Command(argv) => {
            let mut child = Command::new(&argv[0])
                .args(&argv[1..])
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()?;
            if let Some(out) = child.stdout.take() {
                let mut scanned = 0usize;
                for line in BufReader::new(out).lines().map_while(Result::ok) {
                    scanned += 1;
                    if scanned > line_cap {
                        break;
                    }
                    if !consume(line) {
                        break;
                    }
                }
            }
            let _ = child.wait();
        }
        Access::File(path) => {
            let Ok(f) = std::fs::File::open(&path) else {
                return Ok(()); // unreadable/missing → zero hits, not an error
            };
            // Read the WHOLE file but keep only the last `line_cap` lines (the
            // recent window) before matching, so a huge log doesn't flood.
            let all: Vec<String> = BufReader::new(f).lines().map_while(Result::ok).collect();
            let start = all.len().saturating_sub(line_cap);
            for raw in all.into_iter().skip(start) {
                if !consume(raw) {
                    break;
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn smart_case_matching() {
        // lowercase needle → case-insensitive
        assert!(smart_match("Error: ASL failed", "asl", false));
        assert!(smart_match("error here", "error", false));
        // uppercase in needle → case-sensitive
        assert!(smart_match("ASL boom", "ASL", true));
        assert!(!smart_match("asl boom", "ASL", true));
        // empty needle matches anything
        assert!(smart_match("whatever", "", false));
    }

    #[test]
    fn parse_ts_formats() {
        // macOS log show compact leads with date + time.
        assert_eq!(
            parse_ts("2026-06-29 22:30:49.193 Df proc[1]: msg", true).as_deref(),
            Some("22:30:49")
        );
        // syslog leads with "Mon DD HH:MM:SS".
        assert_eq!(
            parse_ts("Jun 29 22:26:40 host login: msg", false).as_deref(),
            Some("Jun 29 22:26:40")
        );
    }

    #[test]
    fn discover_includes_audit_and_system() {
        let srcs = discover_sources();
        assert!(srcs.iter().any(|s| s.id == "audit"));
        assert!(srcs.iter().any(|s| s.id == "system"));
    }

    #[test]
    fn search_a_file_source_with_filter_and_limit() {
        let mut f = tempfile::NamedTempFile::new().unwrap();
        for i in 0..50 {
            writeln!(f, "line {i} ERROR widget").unwrap();
            writeln!(f, "line {i} ok").unwrap();
        }
        f.flush().unwrap();
        let path = f.path().to_str().unwrap().to_string();

        // smart-case substring filter + match limit (lowercase needle → case-insensitive).
        let mut hits = Vec::new();
        search(&path, "1h", Some("error"), 5, 10_000, |h| hits.push(h)).unwrap();
        assert_eq!(hits.len(), 5, "limit caps matches");
        assert!(hits.iter().all(|h| h.line.contains("ERROR")));
        assert!(hits.iter().all(|h| h.source == path));

        // Uppercase needle → case-sensitive, must still match the uppercase lines
        // (regression: a pre-lowercased needle would match NOTHING here).
        let mut upper = Vec::new();
        search(&path, "1h", Some("ERROR"), 100, 10_000, |h| upper.push(h)).unwrap();
        assert_eq!(upper.len(), 50, "uppercase needle matches the 50 ERROR lines");

        // No filter → returns lines up to the limit.
        let mut all = Vec::new();
        search(&path, "1h", None, 7, 10_000, |h| all.push(h)).unwrap();
        assert_eq!(all.len(), 7);
    }
}
