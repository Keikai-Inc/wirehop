# File Transfer

## Session Dispatch

The host-side handler `host_transfer_session()` in `crates/hop-core/src/transfer/mod.rs` dispatches based on a mode x direction matrix:

| Mode | Direction | Host Role | Helper Mode |
|---|---|---|---|
| `Copy` | `Push` (client->host) | Receive files | `"receive"` |
| `Copy` | `Pull` (host->client) | Send files | `"send"` or `"send-recursive"` |
| `Sync` | `Push` (client->host) | Receive sync | `"sync-receive"` |
| `Sync` | `Pull` (host->client) | Send sync | `"sync-send"` or `"sync-send-delete"` |

### Privilege Separation

When the daemon runs as root with a bound username, file I/O is delegated to a child process running as the target user via `helper::proxy_via_helper()`. This provides kernel-enforced file permissions (like sshd's scp/sftp model).

### Session Negotiation

For `hop/1+` connections, the host and client exchange capabilities:

```rust
TransferMsg::Capabilities {
    compression: Vec<String>,   // e.g., ["zstd"]
    max_chunk_size: u32,
    features_version: u32,
}

TransferMsg::Negotiated {
    compression: Option<String>, // e.g., Some("zstd")
    chunk_size: u32,
    zstd_level: Option<i32>,
}
```

For `hop/0`, `NegotiatedParams::legacy()` is used: no compression, 64 KiB chunks.

## TransferMsg Enum

See [Architecture & Protocol](architecture.md) for the full `TransferMsg` definition. Key message flows:

### Copy Push (client -> host)

```
Client                          Host
  |-- FileHeader(path,size) -->  |
  |-- FileData(chunk)       -->  |  (repeat)
  |-- FileEnd               -->  |
  |<-- FileAck(path,ok)     ---|
  |-- Done                  -->  |
```

### Sync Push

```
Client                          Host
  |-- FileList(entries)     -->  |  (client's listing)
  |<-- FileList(entries)    ---|  (host's listing)
  |  (compute_sync_plan)        |
  |-- TransferPlan(...)     -->  |
  |<-- PlanAck { proceed }  ---|
  |-- FileHeader/Data/End   -->  |  (send changed files)
  |<-- FileAck              ---|
  |-- Done                  -->  |
```

## Delta Algorithm

Implemented in `crates/hop-core/src/transfer/delta.rs`. An rsync-style block-matching algorithm that minimizes data transfer for files that have partially changed.

### Overview

1. **Receiver** computes per-block signatures of the existing file
2. **Sender** rolls through the new file, matching blocks against signatures
3. **Sender** emits `DeltaOp` stream: `CopyBlock` (reuse old block) or `Literal` (new data)
4. **Receiver** reconstructs the new file from old file blocks + literal data

### Rolling Checksum (Adler32-variant)

```rust
pub struct RollingChecksum {
    a: u32,   // Sum of bytes
    b: u32,   // Weighted sum
    count: usize,
}
```

- `update(data)`: compute checksum of a full block. `a = sum(bytes)`, `b = sum((len-i) * byte)`.
- `roll(old_byte, new_byte)`: O(1) update when sliding window by one byte.
- `digest()`: returns `(b << 16) | (a & 0xffff)`.

### Block Signature Computation

```rust
pub fn compute_block_signatures(path: &Path, block_size: usize) -> Result<Vec<BlockSignature>>
```

For each block of the existing file, computes:
- `rolling: u32` -- Adler32-variant rolling checksum
- `strong: u64` -- xxHash3-64 of the block data
- `index: u32` -- sequential block index

### Delta Computation

```rust
pub fn compute_delta(new_file_path, signatures, block_size) -> Result<Vec<DeltaOperation>>
```

Algorithm:

1. Build a `HashMap<u32, Vec<(u64, u32)>>` from rolling checksum to `(strong_hash, block_index)`.
2. Initialize rolling checksum on first `block_size` bytes of new file.
3. At each position:
   - If `rolling.digest()` matches a signature's rolling hash:
     - Compute strong hash (xxh3-64) of the window
     - If strong hash matches: emit `CopyBlock { index }`, advance by `block_size`, reinitialize rolling checksum
   - If no match: emit byte to literal buffer, advance by 1, roll the checksum forward
4. Flush remaining bytes as `Literal`.
5. Files smaller than `block_size`: all `Literal`.
6. Empty signatures (new file to old): all `Literal`.

### Reconstruction

```rust
pub fn reconstruct_file(old_path, output_path, ops, block_size) -> Result<u64>
```

Reads old file into memory, applies operations sequentially:
- `CopyBlock { index }`: write `old_data[index*block_size..(index+1)*block_size]`
- `Literal(data)`: write literal bytes

### Constants

```rust
const DELTA_BLOCK_SIZE: usize  = 64 * 1024;   // 64 KiB (same as TRANSFER_CHUNK_SIZE)
const DELTA_MIN_FILE_SIZE: u64 = 64 * 1024;   // Don't bother with delta for small files
```

## Negotiation

`crates/hop-core/src/transfer/negotiation.rs` defines session parameters.

### NegotiatedParams

```rust
pub struct NegotiatedParams {
    pub compression: Option<Compression>,  // Zstd { level: i32 }
    pub max_chunk_size: usize,
}
```

Factory methods:
- `legacy()`: no compression, 64 KiB chunks (hop/0)
- `v1_default()`: zstd level 3, 1 MiB max chunk (hop/1+)
- `from_negotiated(compression, chunk_size, zstd_level)`: from wire values, clamped to `[MIN_CHUNK_SIZE, MAX_CHUNK_SIZE]`

### Adaptive Chunk Sizing

```rust
pub struct ChunkSizer {
    current_size: usize,
    min_size: usize,       // MIN_CHUNK_SIZE (64 KiB)
    max_size: usize,       // up to MAX_CHUNK_SIZE (1 MiB)
    bytes_since_check: u64,
    last_check: Instant,
}
```

Re-evaluates every 2 MiB of data:
- Measures throughput in MB/s over the interval
- Scales chunk size: at 10 MB/s use 128 KiB, at 100 MB/s use 1 MiB
- **Dampened shrinks**: never drops below 50% of current size in one step to prevent oscillation from transient jitter

## Listing

`crates/hop-core/src/transfer/listing.rs` provides directory walking and sync comparison.

### walk_directory()

```rust
pub fn walk_directory(root: &Path) -> Result<Vec<FileEntry>>
```

- Recursively walks the directory tree
- Returns `FileEntry` structs with paths relative to `root`
- Computes `content_hash` (xxh3-64) for regular files, `None` for dirs/symlinks
- Sorts entries by path for deterministic ordering
- Gracefully skips unreadable directories (macOS TCC, permission denied) with a warning

### Sync Plan Computation

`compute_sync_plan()` compares source and destination file lists:
- Files with matching path + size + mtime + content_hash: skip
- Files present in source but not destination: send
- Files present in destination but not source: delete (if `delete_extraneous`)
- Changed files (different size, mtime, or content_hash): send
- Delta candidates: existing files >= `DELTA_MIN_FILE_SIZE` that are present on both sides

## Helper: Privilege Separation

`crates/hop-core/src/transfer/helper.rs` implements the privilege-separated transfer model.

### proxy_via_helper()

```rust
pub async fn proxy_via_helper(
    quic_send, quic_recv, dest, username, params, mode
) -> Result<()>
```

Spawns a child process running as the target user:

1. Build command: `hop __transfer-helper --mode <mode> --dest <path> [--compression zstd:level] --chunk-size <size>`
2. Spawn as the target user:
   - **macOS**: wrap in `/usr/bin/login -fpq <user> <hop-exe> <args>`. `login` sets up a full user session (fresh audit session id via `setaudit_addr`, `setlogin`, PAM) before exec'ing hop. A bare `setuid` from launchd's root audit session is not sufficient — macOS denies filesystem access to user-owned files without a proper user audit session, even when POSIX permissions would allow it. `-q` suppresses the "Last login" banner that would otherwise corrupt stdout IPC framing.
   - **Linux**: spawn directly with `.uid(uid).gid(gid)` and a `pre_exec` hook that calls `initgroups()` for supplementary groups. Linux has no audit-session axis, so this is sufficient.
3. Bidirectional proxy: `quic_recv -> child stdin`, `child stdout -> quic_send`. Uses `select!` so that the session tears down as soon as the helper's stdout closes, rather than waiting on `quic_recv` (which would stall for the full watchdog timeout when the helper exits early).
4. Wait for child exit; fail if non-zero

### Helper Modes

| Mode | Function |
|---|---|
| `receive` | Receive files from the stream, write to disk |
| `send` | Send a single file |
| `send-recursive` | Send a directory tree |
| `sync-receive` | Full sync protocol: send listing, read plan, receive files, handle deltas |
| `sync-send` | Send listing, compute plan, send changed files |
| `sync-send-delete` | Same as sync-send but with `delete_extraneous` |

### Entry Point

`run_transfer_helper()` runs in the child process. It reads from stdin (pipe from parent) and writes to stdout (pipe to parent), using the same transfer protocol as direct QUIC streams.

## Sender

`crates/hop-core/src/transfer/sender.rs` streams files over a QUIC stream.

```rust
pub async fn send_files(send, base_dir, files, progress, params) -> Result<u64>
```

For each `FileEntry`:
- **Symlinks**: `CreateSymlink { path, target }`
- **Directories**: `CreateDirectory(DirEntry { path, mode, mtime })`
- **Regular files**: `FileHeader` -> `FileData` chunks -> `FileEnd`

File data is read in chunks sized by `ChunkSizer`, optionally zstd-compressed. A reusable read buffer is allocated once at max chunk size.

## Receiver

`crates/hop-core/src/transfer/receiver.rs` writes received files to disk.

```rust
pub async fn receive_files(send, recv, dest_dir, progress, params) -> Result<u64>
```

- Writes each file to a temp file, then renames atomically for crash safety
- Sets file permissions (`mode`) and modification time (`mtime`) after write
- Path traversal protection via `safe_join()` -- rejects `..` components
- Sends `FileAck { path, success, error }` for each completed file/directory/delete
- Handles `CreateDirectory`, `CreateSymlink`, `DeletePath`, and delta reconstruction

## Hashing

`crates/hop-core/src/transfer/hashing.rs` provides content hashing for sync comparison.

```rust
pub fn hash_file_content(path: &Path) -> Result<u64>
```

Uses xxHash3-64 in streaming mode (64 KiB read buffer) to hash file contents without loading the entire file into memory. The hash is stored in `FileEntry.content_hash` for sync comparison.

*Last updated: v0.6.33*
