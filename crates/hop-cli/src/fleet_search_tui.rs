//! Interactive, fzf-style federated log search (G24).
//!
//! `hop fleet search` in a TTY opens this: it fans `hop __logsearch` out to the
//! online nodes ONCE (streaming, into a shared buffer), then lets you filter that
//! buffer **locally and instantly** as you type — no network round-trip per
//! keystroke. Each row carries `node · source · time` provenance. The fan-out is
//! the "load"; filtering is local, which is what gives the ripgrep+fzf feel.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyModifiers};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::execute;
use hop_core::logsearch::LogLine;
use ratatui::prelude::*;
use ratatui::widgets::{List, ListItem, ListState, Paragraph};

use crate::fleet_search::{search_command, stream_node, Hit, SearchOpts};

/// Cap on buffered lines (a ring) so a chatty fleet can't grow memory unbounded.
const BUFFER_CAP: usize = 100_000;

struct Shared {
    hits: Mutex<Vec<Hit>>,
    finished: AtomicUsize,
    cancel: AtomicBool,
}

/// Smart-case substring filter (matches the per-node matcher).
fn matches(h: &Hit, query: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    if query.chars().any(|c| c.is_ascii_uppercase()) {
        h.line.contains(query)
    } else {
        h.line.to_ascii_lowercase().contains(query)
    }
}

pub async fn run(
    user_config_dir: &std::path::Path,
    targets: Vec<(String, String)>,
    opts: SearchOpts,
) -> Result<()> {
    let shared = Arc::new(Shared {
        hits: Mutex::new(Vec::new()),
        finished: AtomicUsize::new(0),
        cancel: AtomicBool::new(false),
    });
    let total_nodes = targets.len();

    // Coarse server-side pre-filter by the launch pattern to bound transfer; the
    // TUI refines locally on top. (Clearing the query in-TUI still filters the
    // buffer we pulled; widening beyond the pre-filter is a future re-fan.)
    let command = search_command(&opts.source, &opts.since, opts.pattern.as_deref(), opts.limit);

    for (target, name) in targets {
        let shared = shared.clone();
        let cfg = user_config_dir.to_path_buf();
        let command = command.clone();
        tokio::spawn(async move {
            let _ = tokio::time::timeout(Duration::from_secs(90), async {
                let _ = stream_node(&cfg, &target, command, |line| {
                    if shared.cancel.load(Ordering::Relaxed) {
                        return;
                    }
                    if let Ok(ll) = serde_json::from_str::<LogLine>(&line) {
                        let mut buf = shared.hits.lock().unwrap();
                        if buf.len() < BUFFER_CAP {
                            buf.push(Hit { node: name.clone(), source: ll.source, ts: ll.ts, line: ll.line });
                        }
                    }
                })
                .await;
            })
            .await;
            shared.finished.fetch_add(1, Ordering::Relaxed);
        });
    }

    // The render loop is blocking (crossterm event poll); run it off the async
    // runtime so the streaming tasks keep filling the buffer.
    let initial = opts.pattern.clone().unwrap_or_default();
    let shared_tui = shared.clone();
    let selected = tokio::task::spawn_blocking(move || tui_loop(shared_tui, total_nodes, initial))
        .await??;
    shared.cancel.store(true, Ordering::Relaxed);

    if let Some(line) = selected {
        // Pipe-friendly: the chosen line goes to stdout after the TUI restores.
        println!("{line}");
    }
    Ok(())
}

fn tui_loop(shared: Arc<Shared>, total_nodes: usize, initial_query: String) -> Result<Option<String>> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    let mut term = Terminal::new(backend)?;

    let mut query = initial_query;
    let mut selected: usize = 0;
    let mut follow = true; // stick to the newest matching line
    let mut list_state = ListState::default();

    let result = loop {
        // Build the visible slice under a short lock (clone only what's on screen).
        let size = term.size()?;
        let body_h = size.height.saturating_sub(2).max(1) as usize; // input + status rows
        let (total_hits, match_count, visible, view_start) = {
            let buf = shared.hits.lock().unwrap();
            let total_hits = buf.len();
            let idxs: Vec<usize> = buf
                .iter()
                .enumerate()
                .filter(|(_, h)| matches(h, &query))
                .map(|(i, _)| i)
                .collect();
            let match_count = idxs.len();
            if follow && match_count > 0 {
                selected = match_count - 1;
            }
            if selected >= match_count {
                selected = match_count.saturating_sub(1);
            }
            // Window the matches around `selected`.
            let start = selected.saturating_sub(body_h.saturating_sub(1));
            let end = (start + body_h).min(match_count);
            let start = end.saturating_sub(body_h);
            let visible: Vec<(Hit, bool)> = idxs[start..end]
                .iter()
                .enumerate()
                .map(|(off, &bi)| (buf[bi].clone(), start + off == selected))
                .collect();
            (total_hits, match_count, visible, start)
        };

        let finished = shared.finished.load(Ordering::Relaxed);
        list_state.select(if visible.is_empty() { None } else { Some(selected - view_start) });

        term.draw(|f| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Length(1), Constraint::Min(1), Constraint::Length(1)])
                .split(f.area());

            // Input line.
            let input = Line::from(vec![
                Span::styled("search ", Style::default().fg(Color::Cyan).add_modifier(Modifier::BOLD)),
                Span::raw(&query),
                Span::styled("▏", Style::default().fg(Color::Cyan)),
            ]);
            f.render_widget(Paragraph::new(input), chunks[0]);

            // Results.
            let items: Vec<ListItem> = visible
                .iter()
                .map(|(h, _sel)| {
                    let ts = h.ts.as_deref().unwrap_or("");
                    let prov = format!("{} · {} · {ts}  ", h.node, h.source);
                    ListItem::new(Line::from(vec![
                        Span::styled(prov, Style::default().fg(Color::DarkGray)),
                        Span::raw(h.line.clone()),
                    ]))
                })
                .collect();
            let list = List::new(items)
                .highlight_style(Style::default().add_modifier(Modifier::REVERSED));
            f.render_stateful_widget(list, chunks[1], &mut list_state);

            // Status bar.
            let scanning = finished < total_nodes;
            let status = format!(
                " {match_count}/{total_hits} matches · {}/{total_nodes} nodes{} · ↑↓ scroll · Enter pick · Esc quit ",
                finished,
                if scanning { " (scanning…)" } else { "" },
            );
            f.render_widget(
                Paragraph::new(Line::from(Span::styled(
                    status,
                    Style::default().bg(Color::Indexed(236)).fg(Color::Gray),
                ))),
                chunks[2],
            );
        })?;

        // Input (poll so the view refreshes as the stream fills, even when idle).
        if event::poll(Duration::from_millis(120))?
            && let Event::Key(k) = event::read()?
        {
            let ctrl = k.modifiers.contains(KeyModifiers::CONTROL);
            match k.code {
                    KeyCode::Esc => break None,
                    KeyCode::Char('c') if ctrl => break None,
                    KeyCode::Char('u') if ctrl => {
                        query.clear();
                        follow = true;
                    }
                    KeyCode::Enter => {
                        // Re-resolve the selected line under the lock.
                        let buf = shared.hits.lock().unwrap();
                        let idxs: Vec<usize> =
                            buf.iter().enumerate().filter(|(_, h)| matches(h, &query)).map(|(i, _)| i).collect();
                        break idxs.get(selected).map(|&i| buf[i].line.clone());
                    }
                    KeyCode::Backspace => {
                        query.pop();
                    }
                    KeyCode::Up => {
                        selected = selected.saturating_sub(1);
                        follow = false;
                    }
                    KeyCode::Down => {
                        selected += 1;
                        follow = false;
                    }
                    KeyCode::PageUp => {
                        selected = selected.saturating_sub(body_h);
                        follow = false;
                    }
                    KeyCode::PageDown => {
                        selected += body_h;
                        follow = false;
                    }
                    KeyCode::Home => {
                        selected = 0;
                        follow = false;
                    }
                    KeyCode::End => {
                        follow = true;
                    }
                    KeyCode::Char(c) if !ctrl => {
                        query.push(c);
                        follow = true;
                    }
                    _ => {}
            }
        }
    };

    disable_raw_mode()?;
    execute!(term.backend_mut(), LeaveAlternateScreen)?;
    term.show_cursor()?;
    Ok(result)
}
