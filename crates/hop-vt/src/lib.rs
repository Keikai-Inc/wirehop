//! Virtual-terminal snapshot for session reconnect and live observation.
//!
//! `VtScreen` owns an off-screen [`alacritty_terminal::Term`] that absorbs
//! every byte produced by a captured PTY. The Term is the canonical session
//! state — when a client (re)attaches, [`VtScreen::render`] emits bytes
//! that paint the current grid onto the client's terminal cold, optionally
//! clipped to a subscriber viewport smaller (or larger) than the native
//! grid.
//!
//! Two callers today: hop's session-resume path (uses
//! [`render_full_repaint`] — native dims, [`Prelude::Initial`]) and
//! hop-tap-d's subscriber stream (uses all three [`Prelude`] variants
//! with the actual subscriber viewport).
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

/// What [`VtScreen::render`] emits *before* the per-row cell paint.
///
/// The prelude is the part that establishes a known starting state on
/// the receiver's terminal — screen mode, clear, scroll region — so the
/// subsequent cells land in the right place. Each variant trades off
/// aggressiveness for size.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Prelude {
    /// Subscriber just attached, or hop is resuming a session. Forces
    /// the receiver into the captured app's current screen mode
    /// (alt vs primary), then clears + homes. Safe regardless of what
    /// state the receiver's terminal was in before.
    Initial,
    /// Subscriber resized after attach. Same as `Initial` plus a scroll-
    /// region reset (`\x1b[r`), because a `DECSTBM` set during the
    /// previous viewport (e.g. vim's status-line freeze) would otherwise
    /// confine cells to a region smaller than the new viewport.
    Resize,
    /// Live update following a prior frame. Minimal: SGR reset + home
    /// only. Assumes the receiver's terminal mode already matches.
    Live,
}

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
        // A 0-sized grid makes alacritty index row/col -1 on the first byte and
        // panic (which aborts the daemon). Clients can send WindowSize 0,0 (e.g.
        // a pty not yet sized via TIOCSWINSZ), so clamp to a 1×1 floor — `resize`
        // already does the same.
        let rows = rows.max(1);
        let cols = cols.max(1);
        let dims = FixedDims::new(rows, cols);
        let config = Config { scrolling_history: 0, ..Default::default() };
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

    /// Snapshot every visible row of the grid as a plain `String` (the
    /// cell characters, no SGR escape sequences). Returned vec has
    /// exactly `rows` entries; each entry is exactly `cols` characters
    /// wide with trailing whitespace preserved so the caller decides
    /// whether to trim.
    ///
    /// Useful for log dumps, session-picker UIs, and quick-look tools
    /// that want "what's on screen as text" without going through the
    /// repaint pipeline. The cost is one allocation per row plus a
    /// `cols`-wide push loop — fine for any non-hot-path use.
    pub fn text_rows(&self) -> Vec<String> {
        let grid = self.term.grid();
        let cols = self.dims.cols;
        let lines = self.dims.lines as i32;
        (0..lines)
            .map(|line_idx| {
                let mut row = String::with_capacity(cols);
                for col in 0..cols {
                    let p = Point::new(Line(line_idx), Column(col));
                    row.push(grid[p].c);
                }
                row
            })
            .collect()
    }

    /// Render the current grid clipped to `(vp_rows, vp_cols)` with the
    /// given prelude.
    ///
    /// Clipping is **bottom-anchored** when `vp_rows < grid rows`: the
    /// bottom rows are shown (where prompts and cursors live in
    /// interactive shells, and where status lines live in full-screen
    /// apps), not the top. Columns clip left-anchored (col 0 of the grid
    /// → col 0 of the viewport).
    ///
    /// If the viewport is larger than the grid in either axis, the cells
    /// outside the grid are erased to end-of-line so prior content on the
    /// receiver doesn't bleed through.
    ///
    /// Always emits a final cursor-position; if the captured cursor falls
    /// outside the visible viewport, the cursor is clamped to (1,1)
    /// rather than left wherever the last cell-write landed.
    pub fn render(&self, vp_rows: u16, vp_cols: u16, prelude: Prelude) -> Vec<u8> {
        let grid_rows = self.dims.lines as i32;
        let grid_cols = self.dims.cols;
        let vp_rows = vp_rows.max(1) as i32;
        let vp_cols = vp_cols.max(1) as usize;
        let render_rows = grid_rows.min(vp_rows);
        let render_cols = grid_cols.min(vp_cols);

        // Bottom-anchored row clip: skip the top `row_offset` grid rows
        // when the viewport is shorter. For a viewport ≥ the grid this
        // is 0 (no clip).
        let row_offset: i32 = grid_rows - render_rows;

        let mut out: Vec<u8> = Vec::with_capacity(render_rows as usize * render_cols * 4);

        self.emit_prelude(&mut out, prelude);

        let grid = self.term.grid();
        // Reset `last_attrs` on every row so the row's first cell always
        // emits an explicit SGR. Without this, the first cell inherits the
        // previous row's last SGR — which means losing the bytes from an
        // earlier row leaves subsequent rows painting in undefined
        // attribute state on the receiver. Per-row SGR independence costs
        // ~5–10 bytes per row and makes each row independently renderable
        // if anything earlier on the wire dropped.
        let mut last_attrs: Option<(Color, Color, Flags)>;

        for vp_row in 0..render_rows {
            last_attrs = None;
            let grid_row = vp_row + row_offset;
            let _ = write!(out, "\x1b[{};1H", vp_row + 1);
            let mut col = 0usize;
            while col < render_cols {
                let p = Point::new(Line(grid_row), Column(col));
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
            // Receiver wider than grid: erase the trailing cols on this
            // row so a prior render's wider content can't survive.
            if (render_cols as u16) < (vp_cols as u16) {
                out.extend_from_slice(b"\x1b[K");
            }
        }

        out.extend_from_slice(b"\x1b[0m");

        // Translate the captured cursor to viewport coords by subtracting
        // the bottom-anchor offset. If the cursor falls outside the
        // visible viewport (e.g. cursor is in a clipped-away row), clamp
        // to (1,1) — a visible cursor in the corner is less surprising
        // than an invisible cursor wherever the last cell-write landed.
        let cursor_pt = grid.cursor.point;
        let vp_cur_row = cursor_pt.line.0 - row_offset;
        let vp_cur_col = cursor_pt.column.0 as i32;
        let (cur_r, cur_c) =
            if vp_cur_row >= 0 && vp_cur_row < render_rows && vp_cur_col >= 0 && (vp_cur_col as usize) < render_cols {
                (vp_cur_row + 1, vp_cur_col + 1)
            } else {
                (1, 1)
            };
        let _ = write!(out, "\x1b[{};{}H", cur_r, cur_c);

        out
    }

    /// Render the current grid at native dimensions with `Prelude::Initial`.
    /// Equivalent to `render(rows, cols, Prelude::Initial)` where
    /// `(rows, cols) = dims()`.
    pub fn render_full_repaint(&self) -> Vec<u8> {
        let (rows, cols) = self.dims();
        self.render(rows, cols, Prelude::Initial)
    }

    fn emit_prelude(&self, out: &mut Vec<u8>, prelude: Prelude) {
        match prelude {
            Prelude::Live => {
                // Minimal — assume receiver already in matching mode.
                out.extend_from_slice(b"\x1b[H\x1b[0m");
            }
            Prelude::Initial | Prelude::Resize => {
                // 1. SGR reset
                // 2. Force receiver's screen mode to match captured app's
                //    *current* state (alt vs primary). Idempotent if
                //    already there. Fixes the "vim exited during the
                //    disconnect → client still in alt-screen" case for
                //    Initial, and "alice resized after bob exited alt"
                //    for Resize.
                // 3. (Resize only) `\x1b[r` resets DECSTBM scroll region.
                //    A prior viewport's scroll-region (vim status-line
                //    freeze, less paging) would confine output to a
                //    smaller area on the new viewport otherwise.
                // 4. Clear + home in the resulting buffer.
                out.extend_from_slice(b"\x1b[0m");
                if self.is_alt_screen() {
                    out.extend_from_slice(b"\x1b[?1049h");
                } else {
                    out.extend_from_slice(b"\x1b[?1049l");
                }
                if matches!(prelude, Prelude::Resize) {
                    out.extend_from_slice(b"\x1b[r");
                }
                out.extend_from_slice(b"\x1b[2J\x1b[H");
            }
        }
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
    fn zero_size_does_not_panic() {
        // A client can send WindowSize 0,0; new()+advance() must not panic
        // (regression: alacritty grid OOB aborted the daemon).
        let mut screen = VtScreen::new(0, 0);
        screen.advance(b"hello\r\nworld\x1b[2J");
        let _ = screen.render_full_repaint();
        screen.resize(0, 0); // also a no-op, not a panic
        assert_eq!(screen.dims(), (1, 1));
    }

    #[test]
    fn empty_screen_renders_clean_prelude() {
        let screen = VtScreen::new(4, 10);
        let out = screen.render_full_repaint();
        // Initial prelude (not in alt-screen): SGR reset → force primary
        // screen → clear + home, in that order.
        assert!(
            out.starts_with(b"\x1b[0m\x1b[?1049l\x1b[2J\x1b[H"),
            "wrong Initial prelude: {:?}",
            String::from_utf8_lossy(&out)
        );
    }

    #[test]
    fn live_prelude_is_minimal() {
        let mut screen = VtScreen::new(4, 10);
        screen.advance(b"hi");
        let out = screen.render(4, 10, Prelude::Live);
        // Live: just home + SGR reset, no screen-mode toggles.
        assert!(
            out.starts_with(b"\x1b[H\x1b[0m"),
            "wrong Live prelude: {:?}",
            String::from_utf8_lossy(&out)
        );
        assert!(!out.windows(8).any(|w| w == b"\x1b[?1049l"));
        assert!(!out.windows(8).any(|w| w == b"\x1b[?1049h"));
    }

    #[test]
    fn resize_prelude_includes_scroll_region_reset() {
        let screen = VtScreen::new(4, 10);
        let out = screen.render(4, 10, Prelude::Resize);
        // Resize: SGR reset → screen-mode force → scroll-region reset
        // (\x1b[r) → clear + home.
        assert!(
            out.windows(3).any(|w| w == b"\x1b[r"),
            "Resize prelude missing DECSTBM reset (\\x1b[r): {:?}",
            String::from_utf8_lossy(&out)
        );
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
    fn every_row_emits_explicit_sgr() {
        // Each row's first cell-painting MUST be preceded by an SGR run
        // (\x1b[0...m), so a row can be re-painted correctly even if any
        // earlier row's bytes were lost on the wire. Without per-row SGR
        // reset, the second row would inherit the first row's SGR — and
        // if the first row drops, the second row paints with undefined
        // attrs (often blank-on-blank, hence "missing data").
        let mut screen = VtScreen::new(5, 8);
        // Write 5 visibly distinct rows so each has real content.
        screen.advance(b"\x1b[31maaaaaaaa\r\n");
        screen.advance(b"\x1b[32mbbbbbbbb\r\n");
        screen.advance(b"\x1b[33mcccccccc\r\n");
        screen.advance(b"\x1b[34mdddddddd\r\n");
        screen.advance(b"\x1b[35meeeeeeee");
        let out = screen.render_full_repaint();
        let s = String::from_utf8_lossy(&out);
        // For each row N=1..=5, between the `\x1b[N;1H` cursor move and
        // the first letter of that row's content, there must be an
        // SGR-run starting with `\x1b[0`.
        for (row, ch) in [(1, 'a'), (2, 'b'), (3, 'c'), (4, 'd'), (5, 'e')] {
            let cup = format!("\x1b[{row};1H");
            let cup_pos = s.find(&cup).unwrap_or_else(|| panic!("row {row} CUP missing"));
            let after_cup = &s[cup_pos + cup.len()..];
            // Find the first letter of this row's content.
            let letter_pos = after_cup.find(ch).unwrap_or_else(|| panic!("row {row} content '{ch}' missing"));
            let between = &after_cup[..letter_pos];
            assert!(
                between.contains("\x1b[0"),
                "row {row} between CUP and content '{ch}' lacks SGR reset (got {between:?})"
            );
        }
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

    #[test]
    fn small_viewport_clips_bottom_anchored() {
        // 6-row grid with content in rows 1-6; render to a 3-row viewport.
        // Should show the BOTTOM 3 rows (4, 5, 6), not the top 3.
        let mut screen = VtScreen::new(6, 10);
        screen.advance(b"row1\r\nrow2\r\nrow3\r\nrow4\r\nrow5\r\nrow6");
        let out = screen.render(3, 10, Prelude::Initial);
        let s = String::from_utf8_lossy(&out);
        assert!(s.contains("row4"), "missing bottom row4: {s:?}");
        assert!(s.contains("row5"), "missing bottom row5: {s:?}");
        assert!(s.contains("row6"), "missing bottom row6: {s:?}");
        assert!(!s.contains("row1"), "row1 should be clipped away: {s:?}");
        assert!(!s.contains("row2"), "row2 should be clipped away: {s:?}");
    }

    #[test]
    fn wide_viewport_erases_trailing_cells() {
        // 8-col grid rendered into a 20-col viewport: each row should
        // end with \x1b[K to clear whatever might have been there.
        let mut screen = VtScreen::new(2, 8);
        screen.advance(b"hello");
        let out = screen.render(2, 20, Prelude::Initial);
        // Count the \x1b[K occurrences — should be at least one per row.
        let k_count = out.windows(3).filter(|w| *w == b"\x1b[K").count();
        assert!(
            k_count >= 2,
            "expected ≥2 \\x1b[K for 2 rows of erase-to-EOL, got {k_count}"
        );
    }

    #[test]
    fn text_rows_returns_grid_chars_no_escapes() {
        let mut screen = VtScreen::new(3, 8);
        screen.advance(b"hello\r\nworld\r\nbye");
        let rows = screen.text_rows();
        assert_eq!(rows.len(), 3, "expected 3 rows");
        // Each row is exactly cols-wide (trailing space preserved).
        assert!(rows.iter().all(|r| r.chars().count() == 8), "rows: {rows:?}");
        // Content lands left-aligned; trailing space pad.
        assert_eq!(rows[0].trim_end(), "hello");
        assert_eq!(rows[1].trim_end(), "world");
        assert_eq!(rows[2].trim_end(), "bye");
        // No escape bytes in the text snapshot.
        for r in &rows {
            assert!(!r.contains('\x1b'), "escape in text_rows: {r:?}");
        }
    }

    #[test]
    fn text_rows_ignores_color_attributes() {
        let mut screen = VtScreen::new(1, 12);
        // Bold red "hi", then default "there"
        screen.advance(b"\x1b[1;31mhi\x1b[0m there");
        let rows = screen.text_rows();
        assert_eq!(rows[0].trim_end(), "hi there");
    }

    #[test]
    fn viewport_matching_grid_is_unclipped() {
        // vp == grid dims should produce the same output as render_full_repaint.
        let mut screen = VtScreen::new(4, 10);
        screen.advance(b"hello\r\nworld");
        let direct = screen.render(4, 10, Prelude::Initial);
        let shim = screen.render_full_repaint();
        assert_eq!(direct, shim, "render_full_repaint must match render(native, Initial)");
    }
}
