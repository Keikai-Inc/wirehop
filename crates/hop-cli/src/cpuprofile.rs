//! `hop debug cpu-profile` — sample the running host daemon's CPU to see where
//! the time goes (e.g. the per-packet VPN forwarding hot path).
//!
//! Unlike memory profiling, CPU sampling needs no special build and no restart —
//! it attaches to the **normal running daemon** and records its call stacks for a
//! few seconds, using each platform's native sampler:
//!   - **macOS**: `sample <pid> <secs>` → a call tree with sample counts.
//!   - **Linux**: `perf record -g` + `perf report` (falls back to a clear message
//!     if `perf` isn't installed or `perf_event_paranoid` blocks it).
//!
//! It auto-targets the busiest `hop host` process (the privsep worker), so during
//! a leak/CPU spike you just run it and read the top stacks.

use anyhow::{Context, Result, bail};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn run(secs: u64, pid: Option<u32>, out: Option<PathBuf>) -> Result<()> {
    if !hop_core::unix_user::is_running_as_root() {
        bail!("`hop debug cpu-profile` samples the system daemon — run it with sudo.");
    }
    let pid = match pid {
        Some(p) => p,
        None => find_host_worker()
            .context("could not find a running `hop host` daemon — pass --pid <PID>")?,
    };
    if !pid_alive(pid) {
        bail!("pid {pid} is not running");
    }
    let secs = secs.max(1);
    let out = out.unwrap_or_else(|| PathBuf::from(format!("/tmp/hop-cpu-{pid}-{}.txt", now_unix())));
    println!("Sampling pid {pid} for {secs}s with {} ...", platform::sampler_name());
    platform::sample(pid, secs, &out)
}

// ── pick the busiest `hop host` process (the privsep worker) ──────────────────

fn find_host_worker() -> Option<u32> {
    // `ps` over all processes: pid, %cpu, command. Choose the highest-%cpu line
    // whose command is a `hop host` daemon (the worker out-burns the monitor).
    let out = Command::new("ps")
        .args(["-axo", "pid=,pcpu=,command="])
        .output()
        .ok()?;
    let text = String::from_utf8_lossy(&out.stdout);
    let mut best: Option<(f64, u32)> = None;
    for line in text.lines() {
        // `ps` right-aligns the pid/%cpu columns with variable padding, so split
        // off the first two tokens with split_once (collapses runs of spaces) and
        // keep the remainder — which itself contains spaces — as the command.
        let line = line.trim_start();
        let Some((pid_s, rest)) = line.split_once(char::is_whitespace) else {
            continue;
        };
        let Some((cpu_s, cmd)) = rest.trim_start().split_once(char::is_whitespace) else {
            continue;
        };
        let cmd = cmd.trim_start();
        if !cmd.contains("hop host") || cmd.contains("debug cpu-profile") {
            continue;
        }
        let (Ok(pid), Ok(cpu)) = (pid_s.parse::<u32>(), cpu_s.parse::<f64>()) else {
            continue;
        };
        if best.map(|(c, _)| cpu > c).unwrap_or(true) {
            best = Some((cpu, pid));
        }
    }
    best.map(|(_, pid)| pid)
}

fn pid_alive(pid: u32) -> bool {
    unsafe { libc::kill(pid as libc::pid_t, 0) == 0 }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Render folded stacks (`func1;func2;func3 <count>` per line) to an interactive
/// SVG flame graph. Function-level: every box is a frame, width = sample count.
fn render_flamegraph(folded: &[u8], svg: &Path, title: &str) -> Result<()> {
    if folded.is_empty() {
        bail!("no stacks were collapsed — the sample produced no foldable frames");
    }
    let mut opts = inferno::flamegraph::Options::default();
    opts.title = title.to_string();
    let file = std::fs::File::create(svg).with_context(|| format!("creating {}", svg.display()))?;
    inferno::flamegraph::from_reader(&mut opts, folded, file)
        .with_context(|| format!("rendering flame graph {}", svg.display()))?;
    Ok(())
}

// ── macOS ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "macos")]
mod platform {
    use super::*;

    pub fn sampler_name() -> &'static str {
        "sample(1)"
    }

    pub fn sample(pid: u32, secs: u64, out: &Path) -> Result<()> {
        use inferno::collapse::{Collapse, sample::Folder};

        // `sample <pid> <secs> -file <out>` writes a call-tree report. -mayDie
        // tolerates the target exiting mid-sample.
        let status = Command::new("sample")
            .arg(pid.to_string())
            .arg(secs.to_string())
            .arg("-mayDie")
            .arg("-file")
            .arg(out)
            .status()
            .context("running sample(1) (ships with macOS / Xcode tools)")?;
        if !status.success() {
            bail!("sample(1) failed (need sudo to sample a daemon owned by another user)");
        }
        let report = std::fs::read_to_string(out).unwrap_or_default();
        print_hot(out, &report);

        // Fold the sample(1) report → flame graph SVG.
        let svg = out.with_extension("svg");
        let mut folded = Vec::new();
        Folder::default()
            .collapse(report.as_bytes(), &mut folded)
            .context("collapsing sample(1) output")?;
        super::render_flamegraph(&folded, &svg, &format!("hop host pid {pid} — {secs}s CPU"))?;
        println!("\n🔥 Flame graph: {}  (open in a browser)", svg.display());
        Ok(())
    }

    // Surface the "Sort by top of stack" section — the functions burning the most
    // self time, which is what you want for a hot loop.
    fn print_hot(out: &Path, report: &str) {
        println!("CPU profile written to {}", out.display());
        if let Some(idx) = report.find("Sort by top of stack") {
            println!("\nHottest functions (by self time):\n");
            for line in report[idx..].lines().take(30) {
                println!("{line}");
            }
        } else {
            println!("(open the file for the full call tree)");
        }
    }
}

// ── Linux ────────────────────────────────────────────────────────────────────

#[cfg(target_os = "linux")]
mod platform {
    use super::*;

    pub fn sampler_name() -> &'static str {
        "perf"
    }

    pub fn sample(pid: u32, secs: u64, out: &Path) -> Result<()> {
        if Command::new("perf").arg("--version").output().is_err() {
            bail!(
                "`perf` not found. Install it (e.g. `apt install linux-perf` / `linux-tools-$(uname -r)`), \
                 then retry. Also ensure /proc/sys/kernel/perf_event_paranoid <= 1."
            );
        }
        let data = format!("/tmp/hop-perf-{pid}-{}.data", now_unix());
        let rec = Command::new("perf")
            .args(["record", "-F", "99", "-g", "-o", &data, "-p", &pid.to_string(), "--", "sleep", &secs.to_string()])
            .status()
            .context("perf record")?;
        if !rec.success() {
            bail!("perf record failed (perf_event_paranoid too high, or pid not attachable)");
        }
        let report = Command::new("perf")
            .args(["report", "--stdio", "--no-children", "-i", &data])
            .output()
            .context("perf report")?;
        let text = String::from_utf8_lossy(&report.stdout);
        std::fs::write(out, text.as_bytes()).with_context(|| format!("writing {}", out.display()))?;
        println!("CPU profile written to {} (perf report)", out.display());
        for line in text.lines().filter(|l| !l.starts_with('#')).take(30) {
            println!("{line}");
        }

        // `perf script` → fold → flame graph SVG.
        use inferno::collapse::{Collapse, perf::Folder};
        let script = Command::new("perf")
            .args(["script", "-i", &data])
            .output()
            .context("perf script")?;
        let _ = std::fs::remove_file(&data);
        let svg = out.with_extension("svg");
        let mut folded = Vec::new();
        Folder::default()
            .collapse(&script.stdout[..], &mut folded)
            .context("collapsing perf script output")?;
        super::render_flamegraph(&folded, &svg, &format!("hop host pid {pid} — {secs}s CPU"))?;
        println!("\n🔥 Flame graph: {}  (open in a browser)", svg.display());
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_busiest_hop_host_from_ps_lines() {
        // Realistic `ps -axo pid=,pcpu=,command=` output: right-aligned columns
        // with VARIABLE padding (multiple spaces) — the case the old splitn parser
        // got wrong. Monitor (low cpu) + worker (busy) + the profiler itself.
        let text = "  100   0.0 /usr/local/bin/hop host --quiet --config /Library/x\n\
                    99101  88.5 /usr/local/bin/hop host --config /Library/x --quiet\n\
                     1023   3.1 /bin/zsh -c sudo hop debug cpu-profile --secs 15\n\
                      777  12.0 /usr/sbin/cupsd -l\n";
        let mut best: Option<(f64, u32)> = None;
        for line in text.lines() {
            let line = line.trim_start();
            let Some((pid_s, rest)) = line.split_once(char::is_whitespace) else {
                continue;
            };
            let Some((cpu_s, cmd)) = rest.trim_start().split_once(char::is_whitespace) else {
                continue;
            };
            let cmd = cmd.trim_start();
            if !cmd.contains("hop host") || cmd.contains("debug cpu-profile") {
                continue;
            }
            let (Ok(pid), Ok(cpu)) = (pid_s.parse::<u32>(), cpu_s.parse::<f64>()) else {
                continue;
            };
            if best.map(|(c, _)| cpu > c).unwrap_or(true) {
                best = Some((cpu, pid));
            }
        }
        // The busy worker (99101) — not the monitor, the profiler, or cupsd.
        assert_eq!(best.map(|(_, p)| p), Some(99101));
    }
}
