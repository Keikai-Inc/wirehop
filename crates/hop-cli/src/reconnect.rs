use std::io::{self, Stdout};
use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyModifiers};
use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

use hop_core::proto::{self, ClientMessage};

use crate::mux::{self, ResolvedHost};

/// Result of the reconnection TUI flow.
pub enum ReconnectAction {
    /// Successfully reconnected via agent — contains IPC stream halves.
    ReconnectedViaAgent {
        send: OwnedWriteHalf,
        recv: OwnedReadHalf,
        new_session_id: Option<String>,
    },
    /// User chose to quit.
    Quit,
}

/// Show a reconnection TUI that reconnects through the agent process.
///
/// On success returns `ReconnectedViaAgent` with the IPC stream halves and
/// the new session_id from the host. On user quit returns `Quit`.
pub async fn show_reconnect_tui_via_agent(
    config_dir: &Path,
    resolved: &ResolvedHost,
    old_session_id: Option<&String>,
    stdin_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> ReconnectAction {
    let mut stdout = io::stdout();
    let _ = stdout.execute(EnterAlternateScreen);
    let _ = terminal::enable_raw_mode();

    let mut term = Terminal::new(CrosstermBackend::new(io::stdout())).unwrap();
    let _ = term.clear();

    let start = Instant::now();
    let mut attempt: u32 = 0;

    loop {
        attempt += 1;
        let backoff = backoff_secs(attempt);

        // Countdown phase
        let countdown_start = Instant::now();
        loop {
            let elapsed_in_countdown = countdown_start.elapsed().as_secs_f64();
            let remaining = (backoff as f64 - elapsed_in_countdown).max(0.0);
            let elapsed_total = start.elapsed().as_secs();

            render_frame(&mut term, attempt, elapsed_total, remaining.ceil() as u64, false);

            if remaining <= 0.0 {
                break;
            }

            if let Some(action) = poll_quit(stdin_rx) {
                cleanup(&mut stdout);
                return action;
            }
        }

        // Connecting phase
        let elapsed_total = start.elapsed().as_secs();
        render_frame(&mut term, attempt, elapsed_total, 0, true);

        let session_request = ClientMessage::RequestShellV2 {
            session_id: old_session_id.cloned(),
        };

        let connect_result = tokio::time::timeout(Duration::from_secs(10), async {
            let (mut send, mut recv) = mux::open_agent_stream_pub(
                config_dir,
                &resolved.host_id,
                resolved.relay_url.as_ref().map(|u| u.to_string()),
            )
            .await?;

            proto::write_message(&mut send, &session_request).await?;

            // Read the HostMessage to get the new session_id
            let response: hop_core::proto::HostMessage =
                proto::read_message(&mut recv).await?;
            let new_session_id = match response {
                hop_core::proto::HostMessage::SessionInfo { session_id, .. } => Some(session_id),
                _ => None,
            };

            Ok::<_, anyhow::Error>((send, recv, new_session_id))
        })
        .await;

        match connect_result {
            Ok(Ok((send, recv, new_session_id))) => {
                cleanup(&mut stdout);
                return ReconnectAction::ReconnectedViaAgent {
                    send,
                    recv,
                    new_session_id,
                };
            }
            _ => {
                // Connection failed or timed out — try again
            }
        }

        if let Some(action) = poll_quit(stdin_rx) {
            cleanup(&mut stdout);
            return action;
        }
    }
}

/// Compute backoff delay for a given attempt: 1, 2, 4, 8, 16, 30, 30, ...
fn backoff_secs(attempt: u32) -> u64 {
    let secs = 1u64.checked_shl(attempt.saturating_sub(1)).unwrap_or(30);
    secs.min(30)
}

/// Render one frame of the reconnection TUI.
fn render_frame(
    term: &mut Terminal<CrosstermBackend<Stdout>>,
    attempt: u32,
    elapsed_secs: u64,
    countdown_remaining: u64,
    connecting: bool,
) {
    let _ = term.draw(|frame| {
        let area = frame.area();

        // Center a box in the terminal
        let box_width = 44u16;
        let box_height = 7u16;
        let x = area.width.saturating_sub(box_width) / 2;
        let y = area.height.saturating_sub(box_height) / 2;
        let rect = Rect::new(x, y, box_width.min(area.width), box_height.min(area.height));

        let status_line = if connecting {
            String::from("Connecting...")
        } else {
            format!("Reconnecting in {}s...", countdown_remaining)
        };

        let spinner = if connecting {
            spinning_char(elapsed_secs)
        } else {
            ' '
        };

        let text = vec![
            Line::from(Span::styled(
                " Connection lost",
                Style::default()
                    .fg(Color::Red)
                    .add_modifier(Modifier::BOLD),
            )),
            Line::from(""),
            Line::from(format!(" {spinner} {status_line}")),
            Line::from(format!(
                " Attempt #{attempt} | Elapsed: {elapsed_secs}s"
            )),
            Line::from(Span::styled(
                " Press q or Ctrl+C to quit",
                Style::default().fg(Color::DarkGray),
            )),
        ];

        let block = Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Yellow));

        let paragraph = Paragraph::new(text).block(block).wrap(Wrap { trim: false });
        frame.render_widget(paragraph, rect);
    });
}

fn spinning_char(elapsed: u64) -> char {
    const FRAMES: &[char] = &['⠋', '⠙', '⠹', '⠸', '⠼', '⠴', '⠦', '⠧', '⠇', '⠏'];
    FRAMES[(elapsed as usize) % FRAMES.len()]
}

/// Non-blocking check for quit keys on stdin.
/// Returns `Some(Quit)` if the user pressed `q` or Ctrl+C, `None` otherwise.
fn poll_quit(stdin_rx: &mut mpsc::Receiver<Vec<u8>>) -> Option<ReconnectAction> {
    // Drain any pending input from the shared stdin channel
    while let Ok(data) = stdin_rx.try_recv() {
        for &byte in &data {
            if byte == b'q' || byte == 0x03 {
                return Some(ReconnectAction::Quit);
            }
        }
    }

    // Also check crossterm events (covers cases where raw mode is active
    // and crossterm event polling picks up keys)
    if event::poll(Duration::from_millis(250)).ok()? {
        if let Ok(Event::Key(KeyEvent { code, modifiers, .. })) = event::read() {
            match code {
                KeyCode::Char('q') => return Some(ReconnectAction::Quit),
                KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                    return Some(ReconnectAction::Quit);
                }
                _ => {}
            }
        }
    }

    None
}

fn cleanup(stdout: &mut Stdout) {
    let _ = terminal::disable_raw_mode();
    let _ = stdout.execute(LeaveAlternateScreen);
}
