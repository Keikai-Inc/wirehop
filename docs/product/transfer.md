# File Transfer

hop provides two file transfer modes: `cp` for direct file copying and `sync` for rsync-style directory synchronization. Both operate over QUIC streams with automatic compression negotiation and privilege separation.

## hop cp

Copy files to/from a remote host. Uses `host:path` notation for remote paths.

### Syntax

```bash
hop cp [-r] <source>... <dest>
```

### Push and Pull

```bash
# Push: local -> remote
hop cp ./file.txt myhost:/tmp/file.txt
hop cp -r ./project/ myhost:/home/user/project/

# Pull: remote -> local
hop cp myhost:/var/log/app.log ./logs/
hop cp -r myhost:/etc/nginx/ ./backup/nginx/
```

### Flags

| Flag | Description |
|---|---|
| `-r`, `--recursive` | Copy directories recursively (required for directories) |

### Trailing-Slash Semantics

Trailing slashes on source paths follow rsync conventions:

```bash
# With trailing slash: copy CONTENTS of dir into dest
hop cp -r ./project/ myhost:/home/user/dest/
# Result: /home/user/dest/file1, /home/user/dest/file2, ...

# Without trailing slash: copy the dir itself into dest
hop cp -r ./project myhost:/home/user/dest/
# Result: /home/user/dest/project/file1, /home/user/dest/project/file2, ...
```

### Path Resolution

| Input | Interpretation |
|---|---|
| `/absolute/path` | Local absolute path |
| `./relative/path` | Local relative path |
| `host:path` | Remote -- `host` is an alias, NodeId, or invite token |
| `host:` | Remote home directory (`~`) |

Windows drive letters (e.g. `C:\`) are recognized as local paths.

---

## hop sync

rsync-style directory synchronization with delta transfer. Only transfers changed file content.

### Syntax

```bash
hop sync [flags] <source> <dest>
```

### Examples

```bash
# Sync local to remote
hop sync ./dist/ myhost:/var/www/html/

# Sync remote to local
hop sync myhost:/var/www/html/ ./backup/

# Dry run -- show what would change
hop sync -n ./dist/ myhost:/var/www/html/

# Delete files on dest that don't exist on source
hop sync --delete ./dist/ myhost:/var/www/html/

# Itemized changes (show per-file status)
hop sync -i ./dist/ myhost:/var/www/html/

# Full stats report
hop sync --stats ./dist/ myhost:/var/www/html/
```

### Flags

| Flag | Short | Description |
|---|---|---|
| `--delete` | | Delete extraneous files from destination not present in source |
| `--dry-run` | `-n` | Show what would be transferred without doing it |
| `--itemize-changes` | `-i` | Show itemized list of changes per file |
| `--stats` | | Show detailed transfer statistics |
| `--no-progress` | | Suppress per-file progress bars (show only filenames) |

The following flags are accepted for rsync compatibility but are no-ops (hidden from `--help`): `-a`/`--archive`, `-z`/`--compress`, `-P`, `--progress`, `-H`/`--human-readable`.

---

## Delta Transfer

Sync uses a block-level delta algorithm (rsync-style) to minimize data transfer for modified files:

1. **Receiver** computes rolling (Adler32-variant) + strong (xxh3-64) checksums per block of the existing file and sends them as block signatures
2. **Sender** rolls through the new file byte-by-byte, matching blocks via rolling hash then verifying with strong hash
3. **Sender** emits a stream of delta operations (`CopyBlock` or `Literal`) which the receiver applies to reconstruct the new file

This means only the changed portions of files are transferred, not entire files.

---

## Compression

Transfer sessions negotiate compression parameters at connection time.

| Protocol | Compression | Max Chunk Size |
|---|---|---|
| hop/0 (legacy) | None | 64 KiB |
| hop/1+ | zstd (default level 3) | 1 MiB |

Compression is negotiated automatically between sender and receiver. The zstd level and max chunk size are agreed upon during session setup.

---

## Progress Display

File transfers show real-time progress by default:

- Per-file progress bars with transfer speed and ETA
- `--no-progress` suppresses per-file bars and shows only filenames
- `--stats` prints a summary report after completion
- `--itemize-changes` shows a per-file change indicator (similar to rsync's `-i`)
- Dry-run mode (`-n`) lists changes without transferring data

---

## Privilege Separation

When the hop daemon runs as root and a session is bound to a Unix user, file transfers are executed via a privilege-separated helper process (`__transfer-helper`). The helper runs as the target user, ensuring all file I/O uses kernel-enforced user permissions. This applies to all transfer modes: copy push, copy pull, sync push, and sync pull.

*Last updated: v0.4.3*
