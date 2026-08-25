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
pub(crate) struct NetWatcher {
    last_addrs: BTreeSet<IpAddr>,
    last_poll: Instant,
}

impl NetWatcher {
    pub(crate) fn new() -> Self {
        Self {
            last_addrs: netmon::current_interface_addrs(),
            last_poll: Instant::now(),
        }
    }

    /// True if the interface address set differs from the last observation.
    /// Throttles to once per second so we don't hammer `getifaddrs` from a
    /// tight render loop. Updates `last_addrs` on change so a single
    /// transition only fires once.
    pub(crate) fn changed(&mut self) -> bool {
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
    stdin_rx: &mut mpsc::Receiver<Vec<u8>>,
    pending: &mut Vec<u8>,
) -> Option<ReconnectAction> {
    use std::io::Write;

    let mut stdout = io::stdout();

    // Print inline banner (no alternate screen)
    let _ = write!(stdout, "\r\x1b[K\x1b[33m[hop]\x1b[0m Connection lost. Reconnecting...");
    let _ = stdout.flush();

    let start = Instant::now();
    let base_request = session_request.clone();

    // Retry loop within the timeout window. The dial runs as a future polled
    // alongside stdin so q (quit) and Enter (escalate to the full dialog) stay
    // live the WHOLE time — Tier 1 used to ignore stdin entirely for up to its
    // 5s window, so keystrokes were buffered until it ended. `pending` is shared
    // with Tier 2 so any paste typed here survives an escalation.
    while start.elapsed() < timeout {
        let secs_left = timeout.saturating_sub(start.elapsed()).as_secs();
        let _ = write!(
            stdout,
            "\r\x1b[K\x1b[33m[hop]\x1b[0m Connection lost. Reconnecting... ({secs_left}s · Enter: options · q: quit)"
        );
        let _ = stdout.flush();

        let session_request = base_request.clone();
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
            let response: hop_core::proto::HostMessage = proto::read_message(&mut recv).await?;
            let new_session_id = match response {
                hop_core::proto::HostMessage::SessionInfo { session_id, .. } => Some(session_id),
                hop_core::proto::HostMessage::SessionError(msg) => anyhow::bail!("Host error: {msg}"),
                _ => None,
            };
            Ok::<_, anyhow::Error>((send, recv, new_session_id))
        };
        tokio::pin!(connect_fut);
        // ~2s per attempt; the next loop iteration is the retry pace.
        let deadline =
            tokio::time::sleep(Duration::from_secs(2).min(timeout.saturating_sub(start.elapsed())));
        tokio::pin!(deadline);

        let outcome = loop {
            tokio::select! {
                r = &mut connect_fut => break Some(r),
                _ = &mut deadline => break None,
                chunk = stdin_rx.recv() => {
                    if let Some(data) = chunk {
                        match classify_chunk(&data, pending) {
                            PollAction::Quit => {
                                let _ = write!(stdout, "\r\x1b[K");
                                let _ = stdout.flush();
                                return Some(ReconnectAction::Quit);
                            }
                            PollAction::RetryNow => {
                                // Enter: escalate to the full dialog now; `pending`
                                // carries forward to Tier 2.
                                let _ = write!(stdout, "\r\x1b[K");
                                let _ = stdout.flush();
                                return None;
                            }
                            PollAction::None => {}
                        }
                    }
                }
            }
        };
        if let Some(Ok((send, recv, new_session_id))) = outcome {
            let _ = write!(stdout, "\r\x1b[K");
            let _ = stdout.flush();
            return Some(ReconnectAction::ReconnectedViaAgent {
                send,
                recv,
                new_session_id,
                buffered_input: std::mem::take(pending),
            });
        }
    }

    let _ = write!(stdout, "\r\x1b[K");
    let _ = stdout.flush();
    None
}

/// Outcome of the responsive initial connect.
pub enum InitialConnectOutcome {
    Connected {
        send: OwnedWriteHalf,
        recv: OwnedReadHalf,
    },
    /// User pressed q / Ctrl+C while connecting.
    Quit,
}

/// Drive the INITIAL connect responsively — the same live spinner, instant
/// q/Ctrl+C, bounded per-attempt deadline, and backoff the reconnect path
/// already has. The old initial connect was a bare blocking await with raw mode
/// and the stdin reader set up only AFTER it returned, so during a slow/hung
/// dial nothing read the keyboard: `q`/Enter did nothing and the only way out
/// was to kill the process. Raw mode MUST already be enabled by the caller
/// (cmd_connect owns it for the whole interactive lifecycle).
///
/// After a few consecutive dial failures it restarts a wedged user-spawned agent
/// (Fix C self-heal — a no-op on a host that routes through the daemon mux), so
/// a stuck agent recovers automatically instead of needing a manual `killall`.
pub async fn run_initial_connect(
    config_dir: &Path,
    plan: &mux::ConnectPlan,
    session_request: &ClientMessage,
    stdin_rx: &mut mpsc::Receiver<Vec<u8>>,
) -> anyhow::Result<InitialConnectOutcome> {
    use std::io::Write;
    let mut stdout = io::stdout();
    let mut pending = Vec::new();
    let start = Instant::now();
    let mut net_watcher = NetWatcher::new();
    let mut attempt: u32 = 0;
    let mut consecutive_fail: u32 = 0;

    loop {
        attempt += 1;

        // Backoff between attempts, fully responsive (Enter = retry now, q = quit).
        let backoff = backoff_secs(attempt);
        if backoff > 0 {
            let cd_start = Instant::now();
            let cd = tokio::time::sleep(Duration::from_secs(backoff));
            tokio::pin!(cd);
            let mut tick = tokio::time::interval(Duration::from_millis(150));
            loop {
                let remaining =
                    (backoff as f64 - cd_start.elapsed().as_secs_f64()).max(0.0).ceil() as u64;
                let _ = write!(
                    stdout,
                    "\r\x1b[K\x1b[33m[hop]\x1b[0m Connection failed — retrying in {remaining}s  (Enter: now · q: quit)"
                );
                let _ = stdout.flush();
                tokio::select! {
                    _ = &mut cd => break,
                    _ = tick.tick() => { if net_watcher.changed() { attempt = 0; break; } }
                    chunk = stdin_rx.recv() => {
                        if let Some(data) = chunk {
                            match classify_chunk(&data, &mut pending) {
                                PollAction::Quit => {
                                    let _ = write!(stdout, "\r\x1b[K");
                                    let _ = stdout.flush();
                                    return Ok(InitialConnectOutcome::Quit);
                                }
                                PollAction::RetryNow => { attempt = 0; break; }
                                PollAction::None => {}
                            }
                        }
                    }
                }
            }
        }

        // Connecting phase: the dial runs as a future polled alongside the
        // spinner, a 12s deadline, and stdin — so q/Ctrl+C cancel instantly.
        let dial_fut = mux::dial_initial(config_dir, plan);
        tokio::pin!(dial_fut);
        let deadline = tokio::time::sleep(Duration::from_secs(12));
        tokio::pin!(deadline);
        let mut spinner = tokio::time::interval(Duration::from_millis(120));
        let mut spin: u64 = 0;
        let mut user_retry = false;

        let dial = loop {
            tokio::select! {
                r = &mut dial_fut => break Some(r),
                _ = &mut deadline => break None,
                _ = spinner.tick() => {
                    spin += 1;
                    let _ = write!(
                        stdout,
                        "\r\x1b[K\x1b[33m[hop]\x1b[0m {} Connecting… (attempt {attempt}, {}s)   q: cancel",
                        spinning_char(spin), start.elapsed().as_secs()
                    );
                    let _ = stdout.flush();
                }
                chunk = stdin_rx.recv() => {
                    if let Some(data) = chunk {
                        match classify_chunk(&data, &mut pending) {
                            PollAction::Quit => {
                                let _ = write!(stdout, "\r\x1b[K");
                                let _ = stdout.flush();
                                return Ok(InitialConnectOutcome::Quit);
                            }
                            PollAction::RetryNow => { attempt = 0; user_retry = true; break None; }
                            PollAction::None => {}
                        }
                    }
                }
            }
        };

        match dial {
            Some(Ok((mut send, mut recv))) => {
                let _ = write!(stdout, "\r\x1b[K");
                let _ = stdout.flush();
                // One-shot auth + session request. A failure here (e.g. an
                // invite already used) is terminal — don't loop on it.
                mux::finish_auth_and_request(config_dir, plan, session_request, &mut send, &mut recv)
                    .await?;
                return Ok(InitialConnectOutcome::Connected { send, recv });
            }
            _ => {
                // Dial failed or timed out (not a user-requested retry). After a
                // few in a row, restart a wedged user agent so it self-heals.
                if !user_retry {
                    consecutive_fail += 1;
                    if consecutive_fail >= 3 {
                        mux::restart_user_agent(config_dir);
                        consecutive_fail = 0;
                    }
                }
            }
        }
        if net_watcher.changed() {
            attempt = 0;
        }
    }
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
    pending_input: &mut Vec<u8>,
) -> ReconnectAction {
    let mut stdout = io::stdout();
    let _ = stdout.execute(EnterAlternateScreen);
    // Raw mode is held continuously by cmd_connect for the whole interactive
    // lifecycle, so we don't toggle it here — toggling created cooked-mode gaps
    // where the stdin reader line-buffered keystrokes (the "q didn't work" bug).

    let mut term = Terminal::new(CrosstermBackend::new(io::stdout())).unwrap();
    let _ = term.clear();

    let start = Instant::now();
    let mut attempt: u32 = initial_attempt_offset;
    let mut net_watcher = NetWatcher::new();

    // `pending_input` is owned by the caller and shared with Tier 1, so paste
    // typed during the quick reconnect survives an escalation into this dialog.

    loop {
        attempt += 1;
        let backoff = backoff_secs(attempt);

        // Countdown phase (skip entirely when backoff is 0). Poll stdin in a
        // select! — exactly like the connecting phase below — so Enter (retry now)
        // and q/Ctrl+C are instant during the wait. The old code blocked up to
        // 250ms per stdin poll between re-renders, so a keypress could sit
        // unhandled for a noticeable beat (the "Enter does nothing during the
        // countdown" feel). A 150ms render tick keeps the remaining-seconds
        // display moving and paces the network-change check.
        if backoff > 0 {
            let countdown_start = Instant::now();
            let countdown_deadline = tokio::time::sleep(Duration::from_secs(backoff));
            tokio::pin!(countdown_deadline);
            let mut tick = tokio::time::interval(Duration::from_millis(150));
            'countdown: loop {
                let remaining =
                    (backoff as f64 - countdown_start.elapsed().as_secs_f64()).max(0.0);
                render_frame(
                    &mut term,
                    attempt,
                    start.elapsed().as_secs(),
                    remaining.ceil() as u64,
                    false,
                );

                tokio::select! {
                    _ = &mut countdown_deadline => break 'countdown,
                    _ = tick.tick() => {
                        if net_watcher.changed() {
                            // Network just changed (wifi rejoined, VPN flipped,
                            // ethernet plugged in) — the single best moment for a
                            // reconnect to succeed. Bail out of the backoff and
                            // start fresh.
                            attempt = 0;
                            break 'countdown;
                        }
                    }
                    chunk = stdin_rx.recv() => {
                        // Instant response: Enter retries now (and resets the
                        // ladder so subsequent tries stay quick); q/Ctrl+C quits;
                        // paste is buffered for replay on success.
                        if let Some(data) = chunk {
                            match classify_chunk(&data, pending_input) {
                                PollAction::Quit => {
                                    cleanup(&mut stdout);
                                    return ReconnectAction::Quit;
                                }
                                PollAction::RetryNow => {
                                    attempt = 0;
                                    break 'countdown;
                                }
                                PollAction::None => {}
                            }
                        }
                    }
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
                    // Keep the dialog fully live mid-dial: q/Ctrl+C quits; Enter
                    // ABORTS the current dial and retries immediately (attempt = 0
                    // → next iteration has 0 backoff); other bytes (paste) are
                    // buffered for replay on success. `None` (stdin closed) just
                    // means keep dialing.
                    if let Some(data) = chunk {
                        match classify_chunk(&data, pending_input) {
                            PollAction::Quit => {
                                cleanup(&mut stdout);
                                return ReconnectAction::Quit;
                            }
                            PollAction::RetryNow => {
                                attempt = 0;
                                break None;
                            }
                            PollAction::None => {}
                        }
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
                    buffered_input: std::mem::take(pending_input),
                };
            }
            _ => {
                // Connection failed or timed out — try again
            }
        }

        match poll_user_action(stdin_rx, pending_input).await {
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

/// Compute backoff delay for a given attempt: 0, 0, 1, 2, 4, 5, 5, ...
///
/// Tuned for interactive sessions: the first two attempts are instant (the common
/// case is a brief blip), then a short exponential ramp capped at 5s. Reattach is
/// cheap and the server persists the PTY, so aggressive retry is the right default
/// — long 16/30s waits just feel like the session was abandoned.
fn backoff_secs(attempt: u32) -> u64 {
    if attempt <= 2 {
        return 0;
    }
    let secs = 1u64.checked_shl(attempt.saturating_sub(3)).unwrap_or(5);
    secs.min(5)
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

/// Classify a single stdin chunk during the reconnect dialog. A lone byte is a
/// deliberate keypress (`q`/Ctrl+C → Quit, CR/LF → RetryNow) unless we're
/// inside a bracketed paste; anything else is appended to `pending_input` for
/// replay. Shared by the countdown poll and the connect-phase select so keys
/// behave identically whether the dialog is waiting or actively dialing.
///
/// HISTORY — the "Enter/q do nothing" bug: this used to gate control keys on
/// `pending_input.is_empty()`, so the FIRST stray keypress (everyone mashes
/// keys at a frozen terminal — arrows, space, anything) poisoned the buffer
/// and permanently disabled q/Enter for the rest of the reconnect episode.
/// `pending` only drains on a successful reconnect, which is why keys
/// mysteriously "came back" for a moment after each brief success in a flap
/// storm. The correct discriminator for "was this typed or pasted?" is
/// bracketed-paste state, not buffer emptiness: real pastes arrive wrapped in
/// ESC[200~ … ESC[201~ (the session enables bracketed paste), and a LONE byte
/// outside those markers is always a human keypress no matter what junk was
/// typed earlier.
fn classify_chunk(data: &[u8], pending_input: &mut Vec<u8>) -> PollAction {
    if data.len() == 1 {
        let b = data[0];
        // Ctrl+C always quits — a lone 0x03 chunk is a real keypress even if
        // a paste is mid-flight (pastes deliver in large chunks), and a user
        // hammering Ctrl+C during a stuck paste wants OUT.
        if b == 0x03 {
            return PollAction::Quit;
        }
        if !inside_bracketed_paste(pending_input) {
            match b {
                b'q' => return PollAction::Quit,
                0x0d | 0x0a => return PollAction::RetryNow,
                _ => {}
            }
        }
    }
    pending_input.extend_from_slice(data);
    PollAction::None
}

/// True if `pending` ends inside an unterminated bracketed paste — i.e. the
/// last ESC[200~ (paste start) has no matching ESC[201~ (paste end) after it.
fn inside_bracketed_paste(pending: &[u8]) -> bool {
    const OPEN: &[u8] = b"\x1b[200~";
    const CLOSE: &[u8] = b"\x1b[201~";
    let find_last = |needle: &[u8]| -> Option<usize> {
        if pending.len() < needle.len() {
            return None;
        }
        (0..=pending.len() - needle.len()).rev().find(|&i| &pending[i..i + needle.len()] == needle)
    };
    match (find_last(OPEN), find_last(CLOSE)) {
        (Some(o), Some(c)) => o > c,
        (Some(_), None) => true,
        _ => false,
    }
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
    // Leave the alternate screen but keep raw mode on — cmd_connect owns it for
    // the whole lifecycle (and disables it once, before exit).
    let _ = stdout.execute(LeaveAlternateScreen);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backoff_progression() {
        // attempts 1 & 2: zero backoff for instant reconnect on a brief blip
        assert_eq!(backoff_secs(1), 0);
        assert_eq!(backoff_secs(2), 0);
        // then a short exponential ramp: 1, 2, 4, capped at 5
        assert_eq!(backoff_secs(3), 1);
        assert_eq!(backoff_secs(4), 2);
        assert_eq!(backoff_secs(5), 4);
        assert_eq!(backoff_secs(6), 5);
        assert_eq!(backoff_secs(7), 5);
        // edge: attempt 0 also gets zero
        assert_eq!(backoff_secs(0), 0);
        // very large attempt stays capped at 5
        assert_eq!(backoff_secs(100), 5);
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

    /// THE regression test for the "Enter/q do nothing 99% of the time" bug:
    /// after any stray keypress lands in pending (everyone mashes keys at a
    /// frozen terminal), control keys must STILL work. The old
    /// `pending_input.is_empty()` gate made the first stray byte permanently
    /// disable q/Enter for the whole reconnect episode.
    #[test]
    fn enter_and_q_work_after_stray_keypresses() {
        let mut pending = Vec::new();
        // Mash: arrow key (3-byte escape), a letter, a space.
        assert_eq!(classify_chunk(b"\x1b[A", &mut pending), PollAction::None);
        assert_eq!(classify_chunk(b"x", &mut pending), PollAction::None);
        assert_eq!(classify_chunk(b" ", &mut pending), PollAction::None);
        assert!(!pending.is_empty());
        // Enter must still retry, q must still quit.
        assert_eq!(classify_chunk(b"\r", &mut pending), PollAction::RetryNow);
        assert_eq!(classify_chunk(b"q", &mut pending), PollAction::Quit);
    }

    #[test]
    fn ctrl_c_always_quits_even_inside_paste() {
        let mut pending = Vec::new();
        assert_eq!(classify_chunk(b"\x1b[200~", &mut pending), PollAction::None);
        assert_eq!(classify_chunk(b"pasted text", &mut pending), PollAction::None);
        assert_eq!(classify_chunk(b"\x03", &mut pending), PollAction::Quit);
    }

    #[test]
    fn pasted_q_and_newlines_do_not_trigger_controls() {
        let mut pending = Vec::new();
        assert_eq!(classify_chunk(b"\x1b[200~", &mut pending), PollAction::None);
        // Inside the paste: lone q / CR chunks are CONTENT, not commands.
        assert_eq!(classify_chunk(b"q", &mut pending), PollAction::None);
        assert_eq!(classify_chunk(b"\r", &mut pending), PollAction::None);
        assert_eq!(classify_chunk(b"\x1b[201~", &mut pending), PollAction::None);
        // Paste closed: controls live again.
        assert_eq!(classify_chunk(b"q", &mut pending), PollAction::Quit);
    }

    #[test]
    fn multibyte_chunks_are_never_controls() {
        let mut pending = Vec::new();
        // Coalesced typing ("xq") buffers rather than quitting.
        assert_eq!(classify_chunk(b"xq", &mut pending), PollAction::None);
        assert_eq!(pending, b"xq");
    }

    #[test]
    fn bracketed_paste_state_tracking() {
        assert!(!inside_bracketed_paste(b""));
        assert!(!inside_bracketed_paste(b"hello"));
        assert!(inside_bracketed_paste(b"\x1b[200~partial"));
        assert!(!inside_bracketed_paste(b"\x1b[200~done\x1b[201~"));
        assert!(inside_bracketed_paste(b"\x1b[200~a\x1b[201~b\x1b[200~again"));
    }
}
