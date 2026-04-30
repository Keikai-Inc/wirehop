# Terminal Session Audit (technical)

This document covers the implementation of `hop-tap`: the eBPF
program, the userspace daemon, the wire protocol, and how all of it
threads through hop's extension dispatcher to deliver live streams
to authorized peers.

For the user-facing description see [`docs/product/tap.md`](../product/tap.md).

## Repository layout

`hop-tap` lives in a separate workspace from hop core
(`/path/to/hop-tap` — see the project's own README).

```
hop-tap/
├── crates/
│   ├── hop-tap-ebpf-common/       # shared no_std event types
│   ├── hop-tap-ebpf/              # kernel-side; built with vlad's stage1 rustc
│   ├── hop-tap-protocol/          # wire types (TapRequest, TapResponse, ...)
│   │                              #   *also depended on by hop-cli*
│   └── hop-tap-d/                 # userspace daemon + bundled tap
├── manifests/
│   └── tap-terminal.toml.example
├── install.sh
└── hop-tap.service
```

`hop-tap-protocol` is intentionally minimal (just serde derives,
single dep on `serde`) so that `hop-cli`'s path dependency on it
costs nothing transitively.

## eBPF program

### Toolchain

The kernel-side crate (`hop-tap-ebpf`) is built with vlad's rustc
fork that supports `#[relocatable]` for native CO-RE in pure Rust:

```toml
# crates/hop-tap-ebpf/.cargo/config.toml
[build]
target = "bpfel-unknown-none"

[unstable]
build-std = ["core"]

[target.bpfel-unknown-none]
linker = "<path-to-bpf-linker>"
rustflags = ["-C", "debuginfo=2", "-C", "link-arg=--btf"]
```

Built with `cargo +stage1-vlad build --release`. The toolchain is
overridable via `HOP_TAP_BPF_TOOLCHAIN`; the default (`stage1-vlad`)
matches vlad's published rustup install.

### Hooks

Two kprobes:

| Symbol                | When it fires                                  | Emits          |
|-----------------------|------------------------------------------------|----------------|
| `pty_write`           | every PTY write (master→slave or slave→master) | `PtyWriteEvent`|
| `tty_release_struct`  | once per side as the kernel destroys the pty   | `PtyEndEvent`  |

We hook `pty_write` rather than `tty_write` because
`iterate_tty_write` flattens the `iov_iter` into `tty->write_buf`
*before* dispatching to `tty->ops->write`. By the time control
reaches `pty_write` the buffer is a contiguous kernel pointer; one
`bpf_probe_read_kernel` and we have the bytes. The trade-off is that
we don't capture console / serial TTYs (different `ops->write`),
which is intentional — the audit target is sshd / tmux / ssh-into-
container, all PTYs.

`tty_release_struct` is the canonical "this pty is gone" signal —
it's globally exported (`T` in `/proc/kallsyms`) and fires exactly
once per side of a pair when the final fd reference drops.

### CO-RE relocations

The eBPF program reads kernel struct fields via vlad's
`#[relocatable]` attribute. Each `(*ptr).field` access compiles to
a magic LLVM global that `bpf-linker` turns into a
`CORE_FIELD_BYTE_OFFSET` reloc in `.BTF.ext`; aya patches the offset
at load time against the running kernel's vmlinux BTF.

Relevant types in `crates/hop-tap-ebpf/src/vmlinux.rs`:

```rust
#[relocatable]
#[repr(C)]
pub struct task_struct {
    pub pid: i32,
}

#[relocatable]
#[repr(C)]
pub struct tty_struct {
    pub driver: *const tty_driver,
    pub index: i32,
    pub winsize: winsize,
}

#[relocatable]
#[repr(C)]
pub struct tty_driver {
    pub subtype: i16,
}

#[relocatable]
#[repr(C)]
pub struct winsize {
    pub ws_row: u16,
    pub ws_col: u16,
}
```

Each `pty_write` invocation produces six relocations: `task.pid`,
`tty.driver`, `(driver).subtype`, `tty.index`, `tty.winsize.ws_row`,
`tty.winsize.ws_col`. Compound nested access (`tty.winsize.ws_row`)
generates one reloc per leaf, not one per dereference — bpf-linker
emits a magic global per access path.

Validated cross-kernel earlier in the rustc fork's bring-up: the
same `.bpf.o` reads `task_struct.pid` correctly on Linux 5.4 (offset
1336) and 6.8 (offset 1592), with no recompile.

### Maps

```rust
#[map] pub static mut PTY_EVENTS:     PerfEventByteArray;     // pty_write events
#[map] pub static mut PTY_END_EVENTS: PerfEventByteArray;     // tty_release events
#[map] static mut EVENT_SCRATCH: PerCpuArray<PtyWriteEvent>;  // assembly buffer
```

`EVENT_SCRATCH` is a per-CPU scratch slot we fill with the event
header + data before sending. Keeps the kprobe's stack budget free
and avoids the "init a 152-byte struct on the stack" dance.

### Per-event capture

```rust
#[kprobe]
pub fn pty_write_handler(ctx: ProbeContext) -> u32 {
    // arg0: struct tty_struct *tty
    // arg1: const u8           *buf
    // arg2: size_t              count   (int on pre-6.6 kernels;
    //                                    reading as usize is safe both ways)
    let tty: *const tty_struct = ctx.arg(0)?;
    let buf: *const u8         = ctx.arg(1)?;
    let count: usize           = ctx.arg(2)?;

    // CO-RE chase: tty -> driver -> subtype
    let driver = bpf_probe_read_kernel(&raw const (*tty).driver)?;
    let subtype = bpf_probe_read_kernel(&raw const (*driver).subtype)?;

    let pty_index = bpf_probe_read_kernel(&raw const (*tty).index)?;
    let rows = bpf_probe_read_kernel(&raw const (*tty).winsize.ws_row)?;
    let cols = bpf_probe_read_kernel(&raw const (*tty).winsize.ws_col)?;

    // task_struct.pid via the existing relocation
    let task = bpf_get_current_task() as *const task_struct;
    let pid = bpf_probe_read_kernel(&raw const (*task).pid)?;

    // Helpers (no relocation needed)
    let comm = bpf_get_current_comm()?;
    let uid_gid = bpf_get_current_uid_gid();
    let uid = (uid_gid & 0xFFFF_FFFF) as u32;
    let gid = (uid_gid >> 32) as u32;

    // Bound the byte read with a static cap so the verifier accepts it.
    let read_len = if count >= MAX_CHUNK { MAX_CHUNK } else { count };
    bpf_probe_read_kernel_buf(buf, &mut scratch.data[..masked_read_len])?;

    PTY_EVENTS.output(&ctx, &scratch_bytes, 0);
    Ok(0)
}
```

(Simplified — actual code in `crates/hop-tap-ebpf/src/main.rs`.)

### Verifier-safe variable-length reads

`bpf_probe_read_kernel_buf` requires the destination slice's length
be statically bounded by the verifier. We use a power-of-two mask
combined with a static branch:

```rust
if read_len == MAX_CHUNK {
    bpf_probe_read_kernel_buf(buf, &mut data[..]);     // full
} else {
    let masked = read_len & (MAX_CHUNK - 1);           // 0..MAX_CHUNK-1
    if masked > 0 {
        bpf_probe_read_kernel_buf(buf, &mut data[..masked]);
    }
}
```

`MAX_CHUNK = 128` bytes per event. Larger writes are partially
captured; `total_len` records the original count so userspace can
flag truncation.

## Userspace daemon (`hop-tap-d`)

### Architecture

```
+-------------------------------------------------------------+
|  hop-tap-d                                                  |
|                                                             |
|  +---- tokio runtime ----+                                  |
|  |                       |                                  |
|  |  per-CPU AsyncPerf    |  ingest_event()                  |
|  |  readers (PTY_EVENTS, |  ingest_end_event()              |
|  |  PTY_END_EVENTS)      |                                  |
|  |                       |                                  |
|  |  tokio interval       |  log_summary()                   |
|  |  (every 5s)           |                                  |
|  +---|---------|---------+                                  |
|      |         | locks                                      |
|      v         v                                            |
|  +-----------------------+                                  |
|  | SessionTable:         |                                  |
|  | Arc<Mutex<HashMap<    |                                  |
|  |   pty_index,          |                                  |
|  |   SessionState>>>     |                                  |
|  +-----------------------+                                  |
|      ^                                                      |
|      | reads/writes                                         |
|  +-----------------------+                                  |
|  | extension thread      |  blocking ipc-channel I/O        |
|  | (std::thread, sync)   |                                  |
|  |  - bootstrap          |                                  |
|  |  - Hello/HelloAck     |                                  |
|  |  - Request -> Response|                                  |
|  |  - StreamOpen -> ...  |                                  |
|  +-----------|-----------+                                  |
|              | uses                                         |
|              v                                              |
|  +-----------------------+                                  |
|  | WriterSlot:           |  Arc<Mutex<Option<               |
|  | hop-bound IpcSender   |    IpcSender<ExtMessage>>>>      |
|  +-----------------------+                                  |
+-------------------------------------------------------------+
```

The split is necessary because:

- eBPF perf-array consumption is async (aya's `AsyncPerfEventArray`
  yields `Future`s).
- ipc-channel is sync. `IpcReceiver::recv()` blocks the calling
  thread.

So the extension half runs on a dedicated `std::thread`. It shares
the `SessionTable` and the `WriterSlot` with the tokio side via
`Arc<Mutex<...>>`. The slot is `None` until handshake completes,
then populated with the `IpcSender` so tokio readers can fan out
live `StreamFrame`s to subscribers.

### `SessionState`

Per-pty (`tty_struct.index`) state, keyed in the SessionTable:

```rust
struct SessionState {
    pty_index: i32,
    created_at: Instant,
    last_activity: Instant,

    // Sticky — captured the first time we saw this pty.
    opener_pid: u32,
    opener_comm: String,
    opener_uid: u32,
    opener_gid: u32,

    // Per-event — updates on every write.
    last_pid: u32,
    last_comm: String,
    last_uid: u32,
    last_gid: u32,

    output_bytes: u64,
    input_bytes:  u64,
    output_events: u64,
    input_events:  u64,

    // Off-screen emulator
    processor: vte::ansi::Processor,
    term:      Term<VoidListener>,    // alacritty
    dims:      FixedDims,             // current rows × cols

    subscribers: Vec<u64>,             // active stream_ids
}
```

### Lock ordering

Both `SessionTable` and `WriterSlot` are mutexes. The discipline:
**inside `ingest_event` / `ingest_end_event`, snapshot the fanout
data inside the SessionTable lock, drop it, then take the WriterSlot
lock briefly to send.** Never hold both at once — the extension
thread takes WriterSlot first then SessionTable, so overlapping
would deadlock.

```rust
let fanout: Option<FanOut> = {
    let mut table = sessions.lock();
    let state = table.entry(event.pty_index).or_insert_with(...);
    state.last_activity = now;
    state.last_uid = event.uid;
    // ... other updates
    if state.subscribers.is_empty() {
        None
    } else {
        Some(FanOut { /* snapshot */ })
    }
};                                  // table lock released here
if let Some(f) = fanout {
    fan_out(&writer_slot, f);       // takes writer lock briefly
}
```

### Off-screen emulator

Each session owns an `alacritty_terminal::Term<VoidListener>` that
parses every slave→master byte stream. Full CSI / OSC / SGR
semantics — same emulator that powers Alacritty itself.

The `vte::ansi::Processor` drives the `Term` directly:

```rust
fn ingest_output(&mut self, bytes: &[u8]) {
    self.processor.advance(&mut self.term, bytes);
}
```

When a subscriber attaches, we synthesize an "Initial" replay frame
by walking the grid and emitting SGR-aware escape sequences. This
beats the alternative (a rolling raw-byte buffer) because the byte
buffer can start mid-CSI sequence and confuse a fresh terminal,
while a grid render is always self-contained.

`render_grid_to_bytes` (in `crates/hop-tap-d/src/main.rs`):

1. `\x1b[2J\x1b[H\x1b[0m` — clear screen, home cursor, reset SGR
2. If `term.mode().contains(TermMode::ALT_SCREEN)`:
   `\x1b[?1049h\x1b[2J\x1b[H` — receiver enters alt screen too
3. For each row: `\x1b[<row>;1H` cursor placement, then per-cell
   SGR diff + UTF-8 char
4. `\x1b[0m` final reset
5. `\x1b[<cy>;<cx>H` final cursor placement at
   `term.grid().cursor.point`

Color encoding:
- `Color::Named(0..=7)`     → `30+n` (fg) / `40+n` (bg)
- `Color::Named(8..=15)`    → `90+(n-8)` / `100+(n-8)`
- `Color::Named(other)`     → `39` / `49` (default)
- `Color::Indexed(idx)`     → `38;5;idx` / `48;5;idx`
- `Color::Spec(rgb)`        → `38;2;r;g;b` / `48;2;r;g;b`

Flag bits: `BOLD`, `DIM`, `ITALIC`, `UNDERLINE`-family, `INVERSE`,
`HIDDEN`, `STRIKEOUT` all round-trip.

### `/proc` walk seed

At daemon startup (after kprobe attach, before reader spawn), we
walk `/proc/*/` and seed the SessionTable with pre-existing pty
sessions:

```rust
fn walk_proc_for_session_leaders() -> Vec<SeedRow> {
    for each /proc/<pid>/:
        let (sid, comm) = parse_proc_stat(pid)?;
        if sid != pid { continue; }                  // session leaders only
        let pty_index = pty_index_for_pid(pid)?;     // first /dev/pts/N fd
        let (uid, gid) = parse_proc_status_uid_gid(pid)?;
        out.push(SeedRow { pty_index, pid, comm, uid, gid });
}
```

Robust comm parsing: locate the parenthesised `comm` via the LAST
`)` in `/proc/<pid>/stat` (kernel uses raw `task->comm`, which can
contain parens or spaces). Fields after `") "` are space-separated;
sid is field index 3.

The walk is best-effort: vanished processes / unreadable fds / EACCES
are silently skipped per row. Live events for already-seeded ptys
hit `entry().or_insert_with` as no-ops and just update `last_*`.

## Wire protocol

### Layers

```
ExtMessage::Request   { request_id, peer_id, peer_username, peer_role,
                        payload: bincode(TapRequest) }
ExtMessage::Response  { request_id, ok,
                        payload: bincode(TapResponse) }

ExtMessage::StreamOpen   { request_id, ..., payload: bincode(TapStreamRequest) }
ExtMessage::StreamOpened { request_id, stream_id }
ExtMessage::StreamFrame  { stream_id, payload: bincode(TapStreamFrame) }
ExtMessage::StreamClosed { stream_id, reason }
```

`ExtMessage` is hop's per-extension envelope — opaque-payload bytes
the daemon relays between hop and the extension daemon over
ipc-channel. `Tap*` are hop-tap's subprotocol carried inside those
payloads, defined in `hop-tap-protocol`.

### Sub-protocol types (`hop-tap-protocol`)

```rust
pub enum TapRequest {
    List,
    Snapshot { pty_index: i32 },
}

pub enum TapResponse {
    SessionList(Vec<SessionInfo>),
    Snapshot { pty_index: i32, rows: u16, cols: u16,
               contents: Vec<String> },           // one entry per row
    Error(String),
}

pub struct SessionInfo {
    pub pty_index: i32,
    pub opener_pid: u32, pub opener_comm: String,
    pub opener_uid: u32, pub opener_gid: u32,
    pub opener_username: Option<String>,
    pub last_pid: u32,   pub last_comm: String,
    pub last_uid: u32,   pub last_gid: u32,
    pub last_username: Option<String>,
    pub output_bytes: u64, pub input_bytes: u64,
    pub output_events: u64, pub input_events: u64,
    pub age_ms: u64, pub idle_ms: u64,
}

pub enum TapStreamRequest {
    Subscribe { pty_index: i32 },
}

pub enum TapStreamFrame {
    Initial { rows: u16, cols: u16, replay_bytes: Vec<u8> },
    Output(Vec<u8>),
    Resize { rows: u16, cols: u16 },
}
```

Encoded with bincode 2 + serde, `bincode::config::standard()`.

## Streaming dispatcher (hop-core)

Implemented in `crates/hop-core/src/extensions/dispatcher.rs`.

### Flow

```
peer (CLI)          hop daemon                hop-core dispatcher       hop-tap-d
   |                   |                              |                     |
   | --- ExtensionStreamOpen --------------------> dispatch_stream_open      |
   |                   |                              | -- StreamOpen ------>|
   |                   |                              |     (request_id)     |
   |                   |                              |                      |
   |                   |                              | <----- StreamOpened -|
   |                   |                              |     (request_id,     |
   |                   |                              |      stream_id)      |
   |                   |                              |                      |
   |                   | <-- StreamHandle { stream_id, frames: mpsc::Recv }  |
   |                   |     drain frames from handle.frames                 |
   | <-- ExtensionStreamOpened (stream_id) -------|   |                      |
   |                   |                              | <----- StreamFrame --|
   | <-- ExtensionStreamFrame (...) ---------------- |     (stream_id,       |
   |                   |                              |      payload)        |
   |                   |                              | <----- StreamFrame --|
   | <-- ExtensionStreamFrame (...) ---------------- |                      |
   |                   |                              |                      |
   |                   |                              | <----- StreamClosed -|
   | <-- ExtensionStreamClosed --------------------- |                      |
```

### `ExtensionDispatcher` state

Two streaming-related maps alongside the existing `pending` map for
single-response calls:

```rust
pending: HashMap<u64, oneshot::Sender<(bool, Vec<u8>)>>,
                                    // request_id → response oneshot
pending_stream_open: HashMap<u64, PendingStreamOpen>,
                                    // request_id → (stream_id oneshot, frame mpsc tx)
streams: HashMap<u64, mpsc::UnboundedSender<StreamFrameKind>>,
                                    // stream_id → live frame fan-out
```

`StreamFrameKind` is the enum delivered to subscribers:

```rust
pub enum StreamFrameKind {
    Frame(Vec<u8>),
    Closed(Option<String>),
}
```

### `dispatch_stream_open`

Called by hop's daemon-side peer-op handler when the peer sends
`PeerRequest::ExtensionStreamOpen`. Returns a `StreamHandle`
containing the assigned `stream_id` and an mpsc receiver of
`StreamFrameKind`s.

```rust
pub async fn dispatch_stream_open(
    &self,
    peer: PeerContext,
    ext_id: String,
    payload: Vec<u8>,
) -> Result<StreamHandle, PeerResponse>
```

1. `ensure_connected` + `ensure_demux` for the extension.
2. Allocate `request_id`, create a `(stream_id_tx, frame_tx)` pair,
   register in `pending_stream_open`.
3. Send `ExtMessage::StreamOpen { request_id, peer_id, ..., payload }`.
4. Await `stream_id_rx`. The matching `StreamOpened` arrives on
   the demux task, which fires the oneshot and migrates `frame_tx`
   into `streams[stream_id]`.
5. Return the `StreamHandle`.

### `run_demux` arms (the per-extension demultiplexer)

```rust
ExtMessage::StreamOpened { request_id, stream_id } => {
    if let Some(p) = pending_stream_open.lock().await.remove(&request_id) {
        let _ = p.stream_id_tx.send(stream_id);
        streams.lock().await.insert(stream_id, p.frame_tx);
    }
}

ExtMessage::StreamFrame { stream_id, payload } => {
    if let Some(tx) = streams.lock().await.get(&stream_id) {
        let _ = tx.send(StreamFrameKind::Frame(payload));
    }
}

ExtMessage::StreamClosed { stream_id, reason } => {
    if let Some(tx) = streams.lock().await.remove(&stream_id) {
        let _ = tx.send(StreamFrameKind::Closed(reason));
    }
}
```

Channel-close clears all three maps so any in-flight requests /
streams resolve as "extension disconnected."

### Daemon-side fork in `hop-cli`

`crates/hop-cli/src/main.rs` (the binary that runs as `hop host`)
detects `PeerRequest::ExtensionStreamOpen` early in the peer-op
handler and forks:

```rust
if let PeerRequest::ExtensionStreamOpen { ext_id, payload } = request {
    match dispatcher.dispatch_stream_open(peer, ext_id, payload).await {
        Ok(mut handle) => {
            let stream_id = handle.stream_id;
            // 1. tell the peer the stream is open
            write(send, ExtensionStreamOpened { stream_id }).await?;
            // 2. pump frames
            while let Some(kind) = handle.frames.recv().await {
                let resp = match kind {
                    Frame(p)   => ExtensionStreamFrame { stream_id, payload: p },
                    Closed(r)  => ExtensionStreamClosed { stream_id, reason: r },
                };
                write(send, resp).await?;
                if matches!(kind, Closed(_)) { break; }
            }
        }
        Err(err_resp) => write(send, err_resp).await?,
    }
    return Ok(());
}
```

All other Extension* requests stay on the existing single-response
`dispatch()` path.

### CLI multi-message read loop

`cmd_remote_peer_op` detects streaming requests pre-send and
switches to a multi-message read loop on the response side:

```rust
let is_streaming = matches!(request, PeerRequest::ExtensionStreamOpen { .. });
// ... connect, send request ...
if is_streaming {
    loop {
        let resp = read_message(&mut recv).await?;
        let done = matches!(&resp,
            PeerResponse::ExtensionStreamClosed { .. } | PeerResponse::Error(_));
        display_peer_response(subcmd, sub_args, resp)?;
        if done { break; }
    }
} else {
    // single-message path (existing)
}
```

For `subcmd == "tap"`, `display_tap_stream_frame` decodes
`TapStreamFrame` from the payload and writes raw bytes to stdout —
no client-side emulator round-trip; the operator's terminal
interprets the captured escape sequences natively.

## Authorization (`PeerContext::scope_allows`)

In `hop-tap-d`, every operation that exposes session content goes
through:

```rust
fn scope_allows(&self, state: &SessionState) -> bool {
    if self.peer_role == "creator" {
        return true;
    }
    match (&self.peer_username, lookup_username(state.opener_uid)) {
        (Some(peer), Some(opener)) => peer == &opener,
        _ => false,
    }
}
```

Three call sites with **identical denial wording** so a peer can't
enumerate other users' ptys by probing:

- `TapRequest::List` — filters the table.
- `TapRequest::Snapshot` — returns the same `Error` text as a
  non-existent pty.
- `ExtMessage::StreamOpen` — refuses with `StreamClosed` carrying
  the same reason.

`peer_id`, `peer_username`, `peer_role` are forwarded from hop's
authenticated dispatcher (which pulls them from the peer table).
We trust hop's authentication; hop-tap doesn't re-verify.

## Testing

### Unit tests in `hop-core`

`crates/hop-core/src/extensions/dispatcher.rs` has four:

- `echo_round_trip_via_dispatcher` — single-response path
- `stream_round_trip_via_dispatcher` — full streaming path with a
  fake extension that emits StreamOpened → 2× StreamFrame →
  StreamClosed
- `list_returns_known_extensions` — manifest discovery
- `unknown_extension_in_call_returns_error`

### Daemon-side tests in `hop-tap-d`

The daemon's request handlers, scope check, and grid-render functions
are exercisable in unit tests without a running kernel. eBPF
integration is exercised in the project's CI by running the daemon
inside a privileged Linux container (colima/Docker) and triggering
synthetic pty traffic via `script(1)`.

End-to-end tests against a real hop daemon happen in the project's
integration-test scripts (`tap` stands in during local
development; the full path uses `hop <host> tap ...`).

## See also

- [`docs/product/tap.md`](../product/tap.md) — user-facing description.
- [`docs/technical/architecture.md`](architecture.md) — hop core's
  crate layout, extension framework's place in the picture.
- [`docs/technical/protocol.md`](protocol.md) — hop's wire protocol;
  Extension* peer-op variants are defined there.
- [hop-tap repository](https://github.com/keik-ai/hop-tap) — source.
