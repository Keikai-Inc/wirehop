use std::collections::{BTreeSet, HashMap};
use std::io::{self, Stdout};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant};

use crossterm::terminal::{self, EnterAlternateScreen, LeaveAlternateScreen};
use crossterm::ExecutableCommand;
use ratatui::prelude::*;
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use tokio::net::unix::{OwnedReadHalf, OwnedWriteHalf};
use tokio::sync::mpsc;

use hop_core::net::netmon;
use hop_core::proto::{self, ClientMessage};

use crate::mux::{self, ResolvedHost};

/// Result of the reconnection TUI flow.
pub enum ReconnectAction {
    /// Successfully reconnected via agent — contains IPC stream halves.
    ReconnectedViaAgent {
        send: OwnedWriteHalf,
        recv: OwnedReadHalf,
        new_session_id: Option<String>,
        /// Stdin bytes pulled from the channel while the (visible) reconnect
        /// dialog was up. The caller decides what to replay — paste content is
        /// delivered, free typing is dropped. Always empty for the quick
        /// inline reconnect, which leaves the channel untouched.
        buffered_input: Vec<u8>,
    },
    /// User chose to quit.
    Quit,
}

/// What `poll_user_action` observed during a single poll cycle.
#[derive(Debug, PartialEq, Eq)]
enum PollAction {
    /// User pressed `q` or Ctrl+C.
    Quit,
    /// User pressed Enter/Return — caller should skip any current backoff
    /// and start a fresh attempt cycle.
    RetryNow,
    /// Nothing actionable observed.
    None,
}

/// Tracks the local interface IP set so the reconnect loop can notice when
/// the network situation changes (wifi rejoined, ethernet plugged in, VPN
/// flipped) and skip out of any pending exponential-backoff sleep. A fresh
/// network is the most likely moment for a reconnect to actually succeed,
/// so waiting out a 30-second backoff there is the exact wrong move.
struct NetWatcher {
    last_addrs: BTreeSet<IpAddr>,
    last_poll: Instant,
}

impl NetWatcher {
    fn new() -> Self {
        Self {
            last_addrs: netmon::current_interface_addrs(),
            last_poll: Instant::now(),
        }
    }

    /// True if the interface address set differs from the last observation.
    /// Throttles to once per second so we don't hammer `getifaddrs` from a
    /// tight render loop. Updates `last_addrs` on change so a single
    /// transition only fires once.
    fn changed(&mut self) -> bool {
        if self.last_poll.elapsed() < Duration::from_secs(1) {
            return false;
        }
        self.last_poll = Instant::now();
        let curr = netmon::current_interface_addrs();
        if curr != self.last_addrs {
            self.last_addrs = curr;
            true
        } else {
            false
        }
    }
}

/// Quick inline reconnection attempt (Tier 1).
///
/// Prints a single-line banner in the current terminal and attempts to
/// reconnect within `timeout`. On success returns `ReconnectedViaAgent`;
/// on failure returns `None` so the caller can escalate to the full TUI.
/// The banner is cleared on success or escalation.
pub async fn try_quick_reconnect(
    config_dir: &Path,
    resolved: &ResolvedHost,
    session_request: &ClientMessage,
    timeout: Duration,
) -> Option<ReconnectAction> {
    use std::io::Write;

    let mut stdout = io::stdout();

    // Print inline banner (no alternate screen)
    let _ = write!(stdout, "\r\x1b[K\x1b[33m[hop]\x1b[0m Connection lost. Reconnecting...");
    let _ = stdout.flush();

    let start = Instant::now();

    let session_request = session_request.clone();

    // Retry loop within the timeout window
    while start.elapsed() < timeout {
        let remaining = timeout.saturating_sub(start.elapsed());

        // Update countdown
        let secs_left = remaining.as_secs();
        let _ = write!(
            stdout,
            "\r\x1b[K\x1b[33m[hop]\x1b[0m Connection lost. Reconnecting... ({secs_left}s)"
        );
        let _ = stdout.flush();

        let connect_result = tokio::time::timeout(remaining.min(Duration::from_secs(15)), async {
            let (mut send, mut recv) = mux::open_agent_stream_pub(
                config_dir,
                &resolved.host_id,
                resolved.relay_url.as_ref().map(|u| u.to_string()),
                true, // reconnect: drop any half-open pooled connection, dial fresh
            )
            .await?;

            // Send session request + setup messages (WindowSize, SetEnv) before
            // reading SessionInfo.  The host reads setup messages with a 2-second
            // timeout per message; if we don't send them here the host falls
            // through to 80×24 defaults and may resize a resumed PTY incorrectly.
            proto::write_message(&mut send, &session_request).await?;
            send_setup_messages(&mut send).await?;

            let response: hop_core::proto::HostMessage =
                proto::read_message(&mut recv).await?;
            let new_session_id = match response {
                hop_core::proto::HostMessage::SessionInfo { session_id, .. } => Some(session_id),
                hop_core::proto::HostMessage::SessionError(msg) => {
                    anyhow::bail!("Host error: {msg}");
                }
                _ => None,
            };

            Ok::<_, anyhow::Error>((send, recv, new_session_id))
        })
        .await;

        match connect_result {
            Ok(Ok((send, recv, new_session_id))) => {
                // Clear banner
                let _ = write!(stdout, "\r\x1b[K");
                let _ = stdout.flush();
                return Some(ReconnectAction::ReconnectedViaAgent {
                    send,
                    recv,
                    new_session_id,
                    // Quick reconnect never drains the stdin channel; buffered
                    // input flows naturally into the resumed loop.
                    buffered_input: Vec::new(),
                });
            }
            _ => {
                // Brief pause before retrying (100ms catches quick cellular recoveries)
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
        }
    }

    // Clear banner before escalating to full TUI
    let _ = write!(stdout, "\r\x1b[K");
    let _ = stdout.flush();
    None
}

/// Show a reconnection TUI that reconnects through the agent process.
///
/// On success returns `ReconnectedViaAgent` with the IPC stream halves and
/// the new session_id from the host. On user quit returns `Quit`.
pub async fn show_reconnect_tui_via_agent(
    config_dir: &Path,
    resolved: &ResolvedHost,
    session_request: &ClientMessage,
    stdin_rx: &mut mpsc::Receiver<Vec<u8>>,
    initial_attempt_offset: u32,
) -> ReconnectAction {
    let mut stdout = io::stdout();
    let _ = stdout.execute(EnterAlternateScreen);
    let _ = terminal::enable_raw_mode();

    let mut term = Terminal::new(CrosstermBackend::new(io::stdout())).unwrap();
    let _ = term.clear();

    let start = Instant::now();
    let mut attempt: u32 = initial_attempt_offset;
    let mut net_watcher = NetWatcher::new();

    // Bytes pulled from stdin_rx while the reconnect dialog is up. Without
    // this buffer, paste bytes that landed in stdin_rx mid-disconnect would
    // be silently dropped by the quit-scanner. We replay these to the new
    // session before returning so the paste survives the reconnect.
    let mut pending_input: Vec<u8> = Vec::new();

    loop {
        attempt += 1;
        let backoff = backoff_secs(attempt);

        // Countdown phase (skip entirely when backoff is 0)
        if backoff > 0 {
            let countdown_start = Instant::now();
            loop {
                let elapsed_in_countdown = countdown_start.elapsed().as_secs_f64();
                let remaining = (backoff as f64 - elapsed_in_countdown).max(0.0);
                let elapsed_total = start.elapsed().as_secs();

                render_frame(&mut term, attempt, elapsed_total, remaining.ceil() as u64, false);

                if remaining <= 0.0 {
                    break;
                }

                match poll_user_action(stdin_rx, &mut pending_input).await {
                    PollAction::Quit => {
                        cleanup(&mut stdout);
                        return ReconnectAction::Quit;
                    }
                    PollAction::RetryNow => {
                        // User pressed Enter — they want a try right now and
                        // they want subsequent tries to be quick too. Reset
                        // the counter so this loop iteration ends, the next
                        // becomes attempt 1 (0s backoff), and the exponential
                        // ladder starts over from scratch.
                        attempt = 0;
                        break;
                    }
                    PollAction::None => {}
                }

                if net_watcher.changed() {
                    // Network just changed (wifi rejoined, VPN flipped,
                    // ethernet plugged in). This is the single best moment
                    // for a reconnect to actually succeed; bail out of the
                    // backoff and start fresh.
                    attempt = 0;
                    break;
                }
            }
        }

        // Connecting phase. The dial runs as a future we poll alongside stdin
        // and a 10s deadline, so `q`/Ctrl+C (quit) and the spinner stay live
        // WHILE connecting. The old code awaited a bare `timeout(10s, connect)`
        // with no input polling, so a slow/hung dial trapped the user in the
        // dialog with no way out (symptom: "stuck on the reconnecting window").
        let elapsed_total = start.elapsed().as_secs();
        render_frame(&mut term, attempt, elapsed_total, 0, true);

        let session_request = session_request.clone();

        let connect_fut = async {
            let (mut send, mut recv) = mux::open_agent_stream_pub(
                config_dir,
                &resolved.host_id,
                resolved.relay_url.as_ref().map(|u| u.to_string()),
                true, // reconnect: drop any half-open pooled connection, dial fresh
            )
            .await?;

            proto::write_message(&mut send, &session_request).await?;
            send_setup_messages(&mut send).await?;

            // Read the HostMessage to get the new session_id
            let response: hop_core::proto::HostMessage =
                proto::read_message(&mut recv).await?;
            let new_session_id = match response {
                hop_core::proto::HostMessage::SessionInfo { session_id, .. } => Some(session_id),
                hop_core::proto::HostMessage::SessionError(msg) => {
                    anyhow::bail!("Host error: {msg}");
                }
                _ => None,
            };

            Ok::<_, anyhow::Error>((send, recv, new_session_id))
        };
        tokio::pin!(connect_fut);
        let deadline = tokio::time::sleep(Duration::from_secs(10));
        tokio::pin!(deadline);
        let mut spinner = tokio::time::interval(Duration::from_millis(120));

        let connect_result = loop {
            tokio::select! {
                res = &mut connect_fut => break Some(res),
                _ = &mut deadline => break None, // timed out — fall through to retry
                _ = spinner.tick() => {
                    render_frame(&mut term, attempt, start.elapsed().as_secs(), 0, true);
                }
                chunk = stdin_rx.recv() => {
                    // Keep the dialog escapable mid-dial. Enter ("retry now") is a
                    // no-op while we're already dialing; q/Ctrl+C quits; any other
                    // bytes (paste) are buffered for replay on success. `None`
                    // (stdin closed) just means keep dialing.
                    if let Some(data) = chunk
                        && classify_chunk(&data, &mut pending_input) == PollAction::Quit
                    {
                        cleanup(&mut stdout);
                        return ReconnectAction::Quit;
                    }
                }
            }
        };

        match connect_result {
            Some(Ok((send, recv, new_session_id))) => {
                // Drain anything that arrived since the last poll and hand the
                // buffered bytes back to the caller. The caller applies the
                // paste-aware replay policy (deliver paste content, drop free
                // typing) — we don't blindly replay everything here.
                while let Ok(data) = stdin_rx.try_recv() {
                    pending_input.extend_from_slice(&data);
                }
                cleanup(&mut stdout);
                return ReconnectAction::ReconnectedViaAgent {
                    send,
                    recv,
                    new_session_id,
                    buffered_input: std::mem::take(&mut pending_input),
                };
            }
            _ => {
                // Connection failed or timed out — try again
            }
        }

        match poll_user_action(stdin_rx, &mut pending_input).await {
            PollAction::Quit => {
                cleanup(&mut stdout);
                return ReconnectAction::Quit;
            }
            PollAction::RetryNow => {
                attempt = 0;
            }
            PollAction::None => {}
        }
        if net_watcher.changed() {
            attempt = 0;
        }
    }
}

/// Compute backoff delay for a given attempt: 0, 1, 2, 4, 8, 16, 30, 30, ...
///
/// First attempt has zero backoff for instant reconnection after wake.
fn backoff_secs(attempt: u32) -> u64 {
    if attempt <= 1 {
        return 0;
    }
    let secs = 1u64.checked_shl(attempt.saturating_sub(2)).unwrap_or(30);
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
                " Enter: retry now · q / Ctrl+C: quit",
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

/// Drains pending stdin during the reconnect dialog, watching for the
/// quit / retry-now control keys while preserving every other byte in order.
///
/// A chunk consisting of exactly one byte — and only while no paste has been
/// buffered yet — is treated as a deliberate dialog keypress:
/// - `q`        / 0x03 (Ctrl+C) → `PollAction::Quit`
/// - 0x0d (CR)  / 0x0a (LF)     → `PollAction::RetryNow`
///
/// Once `pending_input` holds bytes we are mid-paste, so a solitary control
/// byte is far more likely the tail of that paste than a keypress; we keep it
/// rather than risk dropping part of the stream. Everything else (typed text,
/// paste, multi-byte escape sequences) is appended to `pending_input` so the
/// caller can replay it through the resumed session. Crucially this keeps the
/// closing `ESC[201~` bracketed-paste marker intact — drop it and the remote
/// app (vim/tmux) stays stuck treating every later keystroke as literal paste.
///
/// We deliberately do NOT read stdin via `crossterm::event` here. A background
/// blocking task owns the stdin fd and feeds `stdin_rx`; reading the fd again
/// would race that task and silently steal paste bytes. Instead we block up to
/// 250ms on the channel for the first chunk, which also paces the caller's
/// countdown loop without busy-spinning.
async fn poll_user_action(
    stdin_rx: &mut mpsc::Receiver<Vec<u8>>,
    pending_input: &mut Vec<u8>,
) -> PollAction {
    // Wait briefly for the first chunk to pace the caller's loop; a timeout or
    // closed channel means there is nothing to do this cycle.
    let first = match tokio::time::timeout(Duration::from_millis(250), stdin_rx.recv()).await {
        Ok(Some(data)) => data,
        _ => return PollAction::None,
    };

    let mut action = PollAction::None;
    let mut next = Some(first);
    while let Some(data) = next.take() {
        match classify_chunk(&data, pending_input) {
            PollAction::Quit => return PollAction::Quit,
            PollAction::RetryNow => action = PollAction::RetryNow,
            PollAction::None => {}
        }
        next = stdin_rx.try_recv().ok();
    }

    action
}

/// Classify a single stdin chunk during the reconnect dialog. A lone byte with
/// no paste buffered yet is a deliberate keypress (`q`/Ctrl+C → Quit, CR/LF →
/// RetryNow, neither is buffered); anything else is appended to `pending_input`
/// for replay. Shared by the countdown poll and the connect-phase select so
/// keys behave identically whether the dialog is waiting or actively dialing.
fn classify_chunk(data: &[u8], pending_input: &mut Vec<u8>) -> PollAction {
    if data.len() == 1 && pending_input.is_empty() {
        match data[0] {
            b'q' | 0x03 => return PollAction::Quit,
            0x0d | 0x0a => return PollAction::RetryNow,
            _ => {}
        }
    }
    pending_input.extend_from_slice(data);
    PollAction::None
}

/// Send WindowSize + SetEnv setup messages to the host.
///
/// Mirrors the setup phase of `client_shell_session_v2` so the host's
/// `read_setup_messages` (which has a 2-second timeout per message) receives
/// them before falling through to defaults.
async fn send_setup_messages(
    send: &mut (impl tokio::io::AsyncWrite + Unpin),
) -> anyhow::Result<()> {
    let (cols, rows, pixel_width, pixel_height) = match terminal::window_size() {
        Ok(size) => (size.columns, size.rows, size.width, size.height),
        Err(_) => (80, 24, 0, 0),
    };
    proto::write_message(
        send,
        &ClientMessage::WindowSize {
            cols,
            rows,
            pixel_width,
            pixel_height,
        },
    )
    .await?;

    let mut vars = HashMap::new();
    for key in &[
        "TERM", "LANG", "LC_ALL", "LC_CTYPE", "LC_COLLATE",
        "LC_MESSAGES", "LC_MONETARY", "LC_NUMERIC", "LC_TIME", "COLORTERM",
    ] {
        if let Ok(val) = std::env::var(key) {
            vars.insert(key.to_string(), val);
        }
    }
    vars.entry("TERM".to_string())
        .or_insert_with(|| "xterm-256color".to_string());
    proto::write_message(send, &ClientMessage::SetEnv { vars }).await?;

    Ok(())
}

fn cleanup(stdout: &mut Stdout) {
    let _ = terminal::disable_raw_mode();
    let _ = stdout.execute(LeaveAlternateScreen);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_progression() {
        // attempt 1: zero backoff for instant reconnect
        assert_eq!(backoff_secs(1), 0);
        // then exponential: 1, 2, 4, 8, 16, 30, 30...
        assert_eq!(backoff_secs(2), 1);
        assert_eq!(backoff_secs(3), 2);
        assert_eq!(backoff_secs(4), 4);
        assert_eq!(backoff_secs(5), 8);
        assert_eq!(backoff_secs(6), 16);
        assert_eq!(backoff_secs(7), 30);
        assert_eq!(backoff_secs(8), 30);
        // edge: attempt 0 also gets zero
        assert_eq!(backoff_secs(0), 0);
        // very large attempt stays capped at 30
        assert_eq!(backoff_secs(100), 30);
    }

    /// A paste arriving as one chunk must be preserved byte-for-byte,
    /// including the trailing `ESC[201~` bracketed-paste close marker. Losing
    /// it leaves the remote app stuck treating later keystrokes as literal.
    #[tokio::test]
    async fn preserves_bracketed_paste_close_marker() {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
        let mut paste = b"\x1b[200~hello world\x1b[201~".to_vec();
        tx.send(paste.clone()).await.unwrap();
        drop(tx);

        let mut pending = Vec::new();
        let action = poll_user_action(&mut rx, &mut pending).await;

        assert_eq!(action, PollAction::None);
        assert_eq!(pending, std::mem::take(&mut paste));
    }

    /// A lone control byte that arrives while a paste is already buffered is
    /// the paste's tail, not a dialog command — it must be kept in order.
    #[tokio::test]
    async fn keeps_lone_control_byte_mid_paste() {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
        tx.send(b"\x1b[200~line one\n".to_vec()).await.unwrap();
        tx.send(b"\r".to_vec()).await.unwrap(); // lone CR — would be RetryNow if empty
        tx.send(b"line two\x1b[201~".to_vec()).await.unwrap();
        drop(tx);

        let mut pending = Vec::new();
        let action = poll_user_action(&mut rx, &mut pending).await;

        assert_eq!(action, PollAction::None);
        assert_eq!(pending, b"\x1b[200~line one\n\rline two\x1b[201~".to_vec());
    }

    /// A solitary `q` / Ctrl-C with no buffered paste is a deliberate quit.
    #[tokio::test]
    async fn lone_quit_byte_with_empty_buffer_quits() {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
        tx.send(vec![b'q']).await.unwrap();
        drop(tx);

        let mut pending = Vec::new();
        let action = poll_user_action(&mut rx, &mut pending).await;

        assert_eq!(action, PollAction::Quit);
    }

    /// A solitary Enter with no buffered paste forces an immediate retry and
    /// is consumed (not replayed into the resumed session).
    #[tokio::test]
    async fn lone_enter_with_empty_buffer_retries() {
        let (tx, mut rx) = mpsc::channel::<Vec<u8>>(64);
        tx.send(vec![b'\r']).await.unwrap();
        drop(tx);

        let mut pending = Vec::new();
        let action = poll_user_action(&mut rx, &mut pending).await;

        assert_eq!(action, PollAction::RetryNow);
        assert!(pending.is_empty());
    }
}
