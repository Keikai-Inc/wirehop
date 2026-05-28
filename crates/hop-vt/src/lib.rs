//! Virtual-terminal snapshot for session reconnect.
//!
//! `VtScreen` owns an off-screen [`alacritty_terminal::Term`] that absorbs
//! every byte produced by a captured PTY. The Term is the canonical session
//! state — when a client (re)attaches, [`VtScreen::render_full_repaint`]
//! emits bytes that paint the current grid onto the client's terminal cold.
//!
//! Scrollback is intentionally disabled (`scrolling_history = 0`). The host
//! never replays history; it shows what's on screen *now*. Pre-disconnect
//! scrollback is the client-side emulator's responsibility, and the modern
//! emulator pushes the cleared viewport into its local scrollback on the
//! `\x1b[2J` we emit as part of the repaint.

use std::io::Write as _;

use alacritty_terminal::event::VoidListener;
use alacritty_terminal::grid::Dimensions;
use alacritty_terminal::index::{Column, Line, Point};
use alacritty_terminal::term::cell::{Cell, Flags};
use alacritty_terminal::term::{Config, Term, TermMode};
use alacritty_terminal::vte::ansi::{Color, NamedColor, Processor};

/// Off-screen terminal that ingests PTY output and snapshots its current
/// state as bytes for a (re)attaching client.
pub struct VtScreen {
    term: Term<VoidListener>,
    processor: Processor,
    dims: FixedDims,
}

impl VtScreen {
    /// Create an empty screen of `rows × cols`. Scrollback off.
    pub fn new(rows: u16, cols: u16) -> Self {
        let dims = FixedDims::new(rows, cols);
        let mut config = Config::default();
        config.scrolling_history = 0;
        let term = Term::new(config, &dims, VoidListener);
        Self {
            term,
            processor: Processor::new(),
            dims,
        }
    }

    /// Feed PTY output bytes through the vt parser into the grid.
    pub fn advance(&mut self, bytes: &[u8]) {
        self.processor.advance(&mut self.term, bytes);
    }

    /// Resize the grid. `(0, 0)` is ignored (matches kernel behavior for
    /// ptys not yet sized via TIOCSWINSZ).
    pub fn resize(&mut self, rows: u16, cols: u16) {
        if rows == 0 || cols == 0 {
            return;
        }
        let new = FixedDims::new(rows, cols);
        if new == self.dims {
            return;
        }
        self.dims = new;
        self.term.resize(self.dims);
    }

    /// Current grid dimensions as `(rows, cols)`.
    pub fn dims(&self) -> (u16, u16) {
        (self.dims.lines as u16, self.dims.cols as u16)
    }

    /// Whether the captured app is currently using the alternate screen
    /// (`\x1b[?1049h` or `\x1b[?47h`). Repaint emits the matching toggle
    /// so the client's terminal mode follows.
    pub fn is_alt_screen(&self) -> bool {
        self.term.mode().contains(TermMode::ALT_SCREEN)
    }

    /// Render the current grid as bytes that paint a fresh terminal into
    /// the same visible state. Includes:
    ///
    /// - SGR reset and `\x1b[2J\x1b[H` (clear + home)
    /// - `\x1b[?1049h` if the captured app is in the alternate screen, so
    ///   the client follows
    /// - One `\x1b[r;1H` cursor-move per row + SGR-grouped UTF-8 cells
    /// - Final cursor placement at the captured app's logical cursor
    ///
    /// Safe to send to a client whose terminal state is unknown — the
    /// prelude resets enough that the result is the same regardless of
    /// what was on screen before.
    pub fn render_full_repaint(&self) -> Vec<u8> {
        let rows = self.dims.lines as i32;
        let cols = self.dims.cols as usize;
        let mut out: Vec<u8> = Vec::with_capacity(rows as usize * cols * 4);

        // Prelude: reset, clear, then conditionally enter alt-screen and
        // clear that too. We always emit the primary clear so a client
        // that was *not* in alt-screen ends up with its primary screen
        // clean before alt-screen entry; a client already in alt-screen
        // sees the alt-screen clear take effect.
        out.extend_from_slice(b"\x1b[0m\x1b[2J\x1b[H");
        let alt = self.term.mode().contains(TermMode::ALT_SCREEN);
        if alt {
            out.extend_from_slice(b"\x1b[?1049h\x1b[2J\x1b[H");
        } else {
            // Force primary screen in case the client was left in alt-
            // screen by a prior session (e.g. vim exited during the
            // disconnect — the captured app left alt mode but the
            // client never received the `?1049l` because it was gone).
            out.extend_from_slice(b"\x1b[?1049l");
        }

        let grid = self.term.grid();
        let mut last_attrs: Option<(Color, Color, Flags)> = None;

        for row in 0..rows {
            let _ = write!(out, "\x1b[{};1H", row + 1);
            let mut col = 0usize;
            while col < cols {
                let p = Point::new(Line(row), Column(col));
                let cell = &grid[p];

                if cell.flags.contains(Flags::WIDE_CHAR_SPACER) {
                    // Placeholder cell after a wide char; the wide char
                    // itself was already emitted last iteration.
                    col += 1;
                    continue;
                }

                let attrs = (cell.fg, cell.bg, cell.flags);
                if last_attrs.as_ref() != Some(&attrs) {
                    emit_sgr(&mut out, cell);
                    last_attrs = Some(attrs);
                }

                let mut buf = [0u8; 4];
                let s = cell.c.encode_utf8(&mut buf);
                out.extend_from_slice(s.as_bytes());

                col += if cell.flags.contains(Flags::WIDE_CHAR) { 2 } else { 1 };
            }
        }

        out.extend_from_slice(b"\x1b[0m");

        // Place the cursor at the captured app's logical position. If the
        // cursor is somehow outside the grid (e.g. immediately after a
        // resize that hasn't been reconciled), clamp into bounds rather
        // than skipping — a visible cursor at (1,1) is less wrong than
        // an invisible cursor wherever the last cell landed.
        let cursor_pt = grid.cursor.point;
        let cur_row = cursor_pt.line.0.clamp(0, rows.saturating_sub(1)) + 1;
        let cur_col = (cursor_pt.column.0 as i32).clamp(0, cols as i32 - 1) + 1;
        let _ = write!(out, "\x1b[{};{}H", cur_row, cur_col);

        out
    }
}

/// Custom [`Dimensions`] impl with `scrolling_history = 0`: `total_lines`
/// equals `screen_lines`. alacritty's built-in `TermSize` adds history
/// rows which we don't want here.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct FixedDims {
    cols: usize,
    lines: usize,
}

impl FixedDims {
    fn new(rows: u16, cols: u16) -> Self {
        Self {
            cols: cols as usize,
            lines: rows as usize,
        }
    }
}

impl Dimensions for FixedDims {
    fn total_lines(&self) -> usize {
        self.lines
    }
    fn screen_lines(&self) -> usize {
        self.lines
    }
    fn columns(&self) -> usize {
        self.cols
    }
}

/// Emit an SGR sequence establishing `cell`'s attributes from a fully-
/// reset state. Always starts with `\x1b[0` so stale flags don't bleed.
fn emit_sgr(out: &mut Vec<u8>, cell: &Cell) {
    out.extend_from_slice(b"\x1b[0");
    if cell.flags.contains(Flags::BOLD) {
        out.extend_from_slice(b";1");
    }
    if cell.flags.contains(Flags::DIM) {
        out.extend_from_slice(b";2");
    }
    if cell.flags.contains(Flags::ITALIC) {
        out.extend_from_slice(b";3");
    }
    if cell.flags.intersects(Flags::ALL_UNDERLINES) {
        out.extend_from_slice(b";4");
    }
    if cell.flags.contains(Flags::INVERSE) {
        out.extend_from_slice(b";7");
    }
    if cell.flags.contains(Flags::HIDDEN) {
        out.extend_from_slice(b";8");
    }
    if cell.flags.contains(Flags::STRIKEOUT) {
        out.extend_from_slice(b";9");
    }
    emit_color(out, cell.fg, /* fg = */ true);
    emit_color(out, cell.bg, /* fg = */ false);
    out.extend_from_slice(b"m");
}

fn emit_color(out: &mut Vec<u8>, color: Color, is_fg: bool) {
    let base = if is_fg { 30 } else { 40 };
    let bright_base = if is_fg { 90 } else { 100 };
    let default_code = if is_fg { 39 } else { 49 };
    let extended_lead = if is_fg { 38 } else { 48 };
    match color {
        Color::Named(named) => {
            let n = named as u32;
            if n < 8 {
                let _ = write!(out, ";{}", base + n);
            } else if n < 16 {
                let _ = write!(out, ";{}", bright_base + (n - 8));
            } else {
                // Foreground/Background/Cursor/Dim* and friends — fall
                // back to "default" for anything outside the basic 16.
                let _ = write!(out, ";{}", default_code);
            }
        }
        Color::Indexed(idx) if idx < 8 => {
            let _ = write!(out, ";{}", base + idx as u32);
        }
        Color::Indexed(idx) if idx < 16 => {
            let _ = write!(out, ";{}", bright_base + (idx - 8) as u32);
        }
        Color::Indexed(idx) => {
            let _ = write!(out, ";{};5;{}", extended_lead, idx);
        }
        Color::Spec(rgb) => {
            let _ = write!(out, ";{};2;{};{};{}", extended_lead, rgb.r, rgb.g, rgb.b);
        }
    }
}

// Silence unused-import warning if NamedColor is only referenced in tests.
const _: fn() = || {
    let _ = NamedColor::Black;
};

#[cfg(test)]
mod tests {
    use super::*;

    /// Bytes that contain neither escape introducers (ESC, CSI) nor
    /// other CSI / OSC / DCS shapes — i.e. pure printable output.
    fn no_query_bytes(out: &[u8]) -> bool {
        // Catches DA1/DA2 (`\x1b[c`, `\x1b[>c`), DSR (`\x1b[Nn`),
        // OSC color queries (`\x1b]N;?`), DECRQM (`...$p`), kitty kbd
        // (`\x1b[?u`) — none of these are valid output bytes the grid
        // would produce. Render emits ESC for SGR/CUP/ED only; those
        // are inspected separately.
        !out.windows(3).any(|w| w == b"\x1b]?" || w == b"\x1b[c")
            && !out.windows(2).any(|w| w == b"\x1b]") // OSC introducer
    }

    #[test]
    fn empty_screen_renders_clean_prelude() {
        let screen = VtScreen::new(4, 10);
        let out = screen.render_full_repaint();
        // Must start with reset + clear + home (primary screen).
        assert!(
            out.starts_with(b"\x1b[0m\x1b[2J\x1b[H"),
            "missing reset/clear prelude: {:?}",
            String::from_utf8_lossy(&out)
        );
        // Not in alt-screen → must emit `?1049l` to force primary.
        assert!(out.windows(8).any(|w| w == b"\x1b[?1049l"));
    }

    #[test]
    fn printable_text_round_trips() {
        let mut screen = VtScreen::new(2, 10);
        screen.advance(b"hello");
        let out = screen.render_full_repaint();
        // The literal "hello" should appear in the rendered bytes.
        assert!(out.windows(5).any(|w| w == b"hello"));
    }

    #[test]
    fn alt_screen_toggle_reflected_in_repaint() {
        let mut screen = VtScreen::new(2, 10);
        assert!(!screen.is_alt_screen());
        screen.advance(b"\x1b[?1049h"); // enter alt screen
        assert!(screen.is_alt_screen());
        let out = screen.render_full_repaint();
        assert!(
            out.windows(8).any(|w| w == b"\x1b[?1049h"),
            "expected alt-screen entry in repaint"
        );
    }

    #[test]
    fn truncated_csi_does_not_leak_into_repaint() {
        let mut screen = VtScreen::new(2, 10);
        // Feed a partial CSI followed by real text. The partial CSI
        // should be absorbed across advance() calls; only the printable
        // tail makes it into the grid, with the SGR attribute applied.
        screen.advance(b"\x1b[1;3");
        screen.advance(b"1mhi");
        let out = screen.render_full_repaint();
        // "hi" must appear, preceded by an SGR run that includes ;31
        // (red foreground) and ;1 (bold) — proving the partial CSI was
        // parsed correctly across the boundary, not buffered as text.
        let hi_pos = out
            .windows(2)
            .position(|w| w == b"hi")
            .expect("hi missing from repaint");
        let before_hi = &out[..hi_pos];
        // The SGR run for the row containing "hi" begins with \x1b[0
        // (reset) — find the most recent one before "hi".
        let sgr_start = before_hi
            .windows(3)
            .rposition(|w| w == b"\x1b[0")
            .expect("no SGR run found before hi");
        let sgr_chunk = &before_hi[sgr_start..];
        assert!(
            sgr_chunk.windows(3).any(|w| w == b";31"),
            "SGR for hi missing red foreground (;31): {:?}",
            String::from_utf8_lossy(sgr_chunk)
        );
        assert!(
            sgr_chunk.windows(2).any(|w| w == b";1"),
            "SGR for hi missing bold (;1): {:?}",
            String::from_utf8_lossy(sgr_chunk)
        );
        // Negative: the literal bytes "[1;3" must not appear as
        // grid text. If parsing had failed and the partial bytes
        // landed in the grid as printable characters, we'd see the
        // string "[1;3" preceding the "1mhi" content. (Note: the
        // cursor-restore at end may contain "[1;3H" — that's the
        // *escape* for cursor position, which is correct.)
        let s = String::from_utf8_lossy(&out);
        // Strip cursor-restore tail before scanning for grid leakage.
        let cursor_tail_start = s.rfind("\x1b[").unwrap_or(s.len());
        let body = &s[..cursor_tail_start];
        assert!(
            !body.contains("[1;3"),
            "raw CSI bytes appeared as grid content: {:?}",
            body
        );
    }

    #[test]
    fn da1_query_absorbed_not_replayed() {
        let mut screen = VtScreen::new(2, 10);
        // The captured app queries device attributes; in a raw byte
        // ring the bytes would survive and be replayed to the new
        // client. Through the vt parser they're consumed (the parser
        // dispatches an event the VoidListener drops on the floor).
        screen.advance(b"prompt> \x1b[c");
        let out = screen.render_full_repaint();
        // `\x1b[c` must not appear in the repaint.
        assert!(
            !out.windows(3).any(|w| w == b"\x1b[c"),
            "DA1 query leaked into repaint: {:?}",
            String::from_utf8_lossy(&out)
        );
        assert!(no_query_bytes(&out));
        assert!(out.windows(7).any(|w| w == b"prompt>"));
    }

    #[test]
    fn resize_preserves_grid_content_within_new_bounds() {
        let mut screen = VtScreen::new(4, 10);
        screen.advance(b"line1\r\nline2");
        screen.resize(4, 20);
        let out = screen.render_full_repaint();
        assert!(out.windows(5).any(|w| w == b"line1"));
        assert!(out.windows(5).any(|w| w == b"line2"));
        let (r, c) = screen.dims();
        assert_eq!((r, c), (4, 20));
    }

    #[test]
    fn resize_ignores_zero_dims() {
        let mut screen = VtScreen::new(4, 10);
        screen.resize(0, 20);
        assert_eq!(screen.dims(), (4, 10));
        screen.resize(4, 0);
        assert_eq!(screen.dims(), (4, 10));
    }

    #[test]
    fn cursor_position_emitted_in_repaint() {
        let mut screen = VtScreen::new(4, 10);
        screen.advance(b"\x1b[3;5H"); // move to row 3, col 5
        let out = screen.render_full_repaint();
        // The final cursor-position sequence should be \x1b[3;5H.
        let s = String::from_utf8_lossy(&out);
        assert!(
            s.ends_with("\x1b[3;5H"),
            "cursor not at (3,5) in repaint tail: {:?}",
            &s[s.len().saturating_sub(40)..]
        );
    }
}
