//! Microbenchmark for VtScreen::advance throughput.
//!
//! Run with: cargo run --release --example bench_advance -p hop-vt
//!
//! Compares VtScreen::advance against a naïve ring-buffer push (the
//! pattern hop's old ReplayBuffer used) over a few representative
//! workloads.

use std::collections::VecDeque;
use std::time::Instant;

use hop_vt::VtScreen;

fn bench<F: FnMut(&[u8])>(label: &str, payload: &[u8], iters: usize, mut f: F) {
    // Warm up so JIT-like effects (page faults, allocator) don't skew.
    for _ in 0..3 {
        f(payload);
    }
    let total_bytes = payload.len() * iters;
    let start = Instant::now();
    for _ in 0..iters {
        f(payload);
    }
    let elapsed = start.elapsed();
    let mbps = (total_bytes as f64 / 1_048_576.0) / elapsed.as_secs_f64();
    println!(
        "  {label:<32} {:.1} MB in {:.3}s  →  {:.1} MB/s",
        total_bytes as f64 / 1_048_576.0,
        elapsed.as_secs_f64(),
        mbps
    );
}

fn payload_yes() -> Vec<u8> {
    // What `yes` produces — pure printable with newlines, no escapes.
    let mut v = Vec::with_capacity(64 * 1024);
    for _ in 0..32_000 {
        v.extend_from_slice(b"y\n");
    }
    v
}

fn payload_color_runs() -> Vec<u8> {
    // Mixed text + SGR — closer to a typical `ls --color` or `htop` line.
    let mut v = Vec::with_capacity(64 * 1024);
    for _ in 0..1024 {
        v.extend_from_slice(b"\x1b[31mred\x1b[0m  \x1b[32mgreen\x1b[0m  \x1b[1;34mboldblue\x1b[0m\n");
    }
    v
}

fn payload_cursor_heavy() -> Vec<u8> {
    // What full-screen apps emit (vim, htop status repaints).
    let mut v = Vec::with_capacity(64 * 1024);
    for row in 1..=24 {
        for _ in 0..40 {
            v.extend_from_slice(format!("\x1b[{};1H", row).as_bytes());
            v.extend_from_slice(b"\x1b[0;37;40m");
            v.extend_from_slice(b"hello world this is a row of content                ");
        }
    }
    v
}

fn main() {
    println!("VtScreen::advance throughput");
    println!("============================");

    for (name, payload) in [
        ("yes (printable + LF)", payload_yes()),
        ("color SGR runs", payload_color_runs()),
        ("cursor-positioned repaints", payload_cursor_heavy()),
    ] {
        println!("\n{name} ({} KiB/iter):", payload.len() / 1024);

        let mut screen = VtScreen::new(24, 80);
        bench("VtScreen::advance", &payload, 100, |b| screen.advance(b));

        // Compare to the old ring-buffer push (memcpy-bounded).
        let mut ring: VecDeque<u8> = VecDeque::with_capacity(65_536);
        bench("ReplayBuffer-style push", &payload, 100, |b| {
            for &byte in b {
                if ring.len() == 65_536 {
                    ring.pop_front();
                }
                ring.push_back(byte);
            }
        });
    }
}
