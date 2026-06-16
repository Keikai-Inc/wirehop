# Terminal Session Audit (hop-tap)

`hop-tap` is a hop extension that captures every TTY/PTY session on a
Linux host using eBPF. Authorized peers list active sessions, snapshot
current screens, and stream live byte updates — all through the
authenticated QUIC connection hop already uses.

It's installed and updated separately from hop core via its own curl
installer; once running, it registers with the local hop daemon and
shows up under `hop <host> ext list` and `hop <host> tap`.

## Architecture

```
+-------------------------------------------------------------------+
|  YOUR LAPTOP (client, any OS)                                     |
|                                                                   |
|  hop myserver tap list                                            |
|  hop myserver tap snapshot 0                                      |
|  hop myserver tap watch 0                                         |
+-------------------------------------------------------------------+
          | QUIC (P2P, encrypted, hop's existing transport)
          v
+-------------------------------------------------------------------+
|  LINUX HOST                                                       |
|                                                                   |
|  hop host (systemd, port-listener)                                |
|   |                                                               |
|   |  ipc-channel (manifest rendezvous)                            |
|   v                                                               |
|  hop-tap-d (systemd, root)                                        |
|  +-- eBPF kprobes: pty_write, tty_release_struct                  |
|  +-- Per-session alacritty Term (off-screen emulator)             |
|  +-- /proc walk seed for pre-existing sessions                    |
|  +-- Per-peer scope check (creator role / opener_username)        |
+-------------------------------------------------------------------+
```

## Install

One curl gets you both the daemon and the hop dependency. If hop is
already running, hop-tap registers itself as a plugin without touching
hop's binary or config.

```bash
curl -fsSL https://tap.keikai.ai/install.sh | bash
```

What it does:

- Linux-only; refuses macOS/Windows with a clear error.
- Detects x86_64 / arm64.
- If `hop` isn't installed, delegates to `https://hop.keikai.ai/install-daemon.sh`
  first. If `hop` is installed but its daemon isn't running, exits
  with a "start hop and re-run" message — never tries to start hop
  for you (avoids clobbering manual / user-local / non-systemd
  setups).
- Drops the manifest at `/etc/hop/extensions/tap-terminal.toml`
  (`expected_uid = 0` matches the systemd unit's `User=root`).
- Installs `hop-tap-d` and `tap` to `/usr/local/bin`.
- Installs `hop-tap.service`, enables and starts it.
- Restarts hop so the new manifest is picked up.

After install, verify:

```bash
sudo systemctl status hop-tap                     # daemon running
hop <host> ext list                               # tap.terminal listed
hop <host> tap list                               # active sessions
```

## CLI

All `tap` verbs live under the standard `hop <host>` prefix. The host
name is always first.

### `tap list`

Enumerate active sessions. Filtered to what your peer role and
identity are allowed to see.

```bash
$ hop myserver tap list
2 active session(s):
  pty=  3  user=alice(1000)    comm=bash      pid=  3214  out=12384b/421ev  in=83b/12ev   age=82s idle=0ms
  pty=  4  opener=alice(1000)  writer=root(0)  comm=sudo      out=2891b/14ev   in=4b/1ev    age=12s idle=0ms
```

The display has three forms depending on the session's identity state:

- `user=alice(1000) comm=bash` — opener and current writer are the
  same uid + pid (the most common case).
- `user=alice(1000) comm=vim (writer=PID)` — same uid, different pid;
  alice is running a sub-process (vim, ls, etc.) inside her shell.
- `opener=alice(1000) writer=root(0) comm=sudo` — different uids;
  privilege escalation in progress (sudo, setpriv, setuid binary).

### `tap snapshot <pty>`

Return the current screen state as a row × column grid, with full
SGR-aware reproduction (colors, attributes, cursor, alt-screen state).

```bash
$ hop myserver tap snapshot 3
snapshot pty=3 (24x80)
+--------------------------------------------------------------------------------+
|alice@myserver:~$ vim notes.md                                                  |
|  1 # Project plan                                                              |
|  2                                                                             |
|  3 ## Next sprint                                                              |
|  ...                                                                           |
+--------------------------------------------------------------------------------+
```

### `tap watch <pty>`

Subscribe to a live byte stream from the captured session. Initial
frame catches you up to the current screen state; subsequent frames
arrive as the session produces output. Your terminal renders the
captured escape sequences natively — no client-side emulator
round-trip, full color and cursor fidelity.

```bash
$ hop myserver tap watch 3
(stream 1 opened)
(initial frame: 24x80, replay=1342 bytes)
# ... bytes flow live to your terminal ...
```

Exits when the captured session ends or you Ctrl-C.

### Local-only access (`tap`)

The `tap` CLI bundled with hop-tap-d works **standalone** — connects
directly to the daemon's local Unix socket
(`/run/hop-tap/local.sock`); no hop daemon required. Authentication
is `SO_PEERCRED`: root sees every session, non-root users see only
sessions whose opener matches their uid. See
[tap.keikai.ai](https://tap.keikai.ai) for the canonical landing page.

```bash
tap list
tap snapshot 0
tap watch 0
tap repl
```

The hop integration described above is purely additive — it gives
peers on the hop network the same operations remotely, gated by
hop's peer/role identity rather than `SO_PEERCRED`.

## Security model

### Identity attribution

Each session carries two identity groups:

- **`opener_*`** — sticky, captured the first time the daemon sees
  the pty. For sessions started after the daemon, this is the
  controlling shell — i.e., who logged in. **Use this for
  authorization decisions.**
- **`last_*`** — updates per event; reflects whoever's currently
  writing bytes. Diverges from `opener_*` whenever sudo, su, or
  setpriv runs. Useful for diagnostic display, not authorization.

Username resolution uses `getpwuid_r` against the host's `/etc/passwd`.
If the uid doesn't resolve (PID/user namespacing edge case), the CLI
displays `uid=NNN` instead of fabricating a name.

### Pre-existing sessions

When hop-tap-d starts, it walks `/proc/*/` for processes that are pty
session leaders (where `pid == sid` from `/proc/<pid>/stat`) and seeds
the session table with their identity. So sessions that started
before the daemon get accurate `opener_*` from the start, not "first
writer the daemon happened to observe."

### Per-peer scope check

The daemon gates every operation on the peer's role:

- **`creator`** — admin tier, sees every session.
- **`peer`** (default) — sees only sessions where
  `opener_username == peer_username`. Other sessions are filtered
  from `tap list`; `tap snapshot` and `tap watch` on them return
  the same error as a non-existent pty (so peers can't enumerate
  by probing).

The peer's role is forwarded by hop's authenticated dispatcher, which
in turn pulls it from the peer table. We trust hop's authentication;
hop-tap doesn't re-verify identity claims.

### What's captured indiscriminately

The eBPF layer captures **all** TTY traffic on the host, regardless
of user. Anyone running hop-tap-d as root has read access to every
pty in the kernel — including content normally invisible (passwords
echoed by `sudo` in failure modes, secrets cat'd to stdout, etc.).

Decisions about who's allowed to *see* that data are made by the
daemon's scope check, not at capture time. This is a deliberate
choice: auditing requires capture, and auditing tools always run with
elevated trust.

By default, captured data lives only in `hop-tap-d`'s process memory
— each session has an alacritty Term holding the current 24×80 screen
plus a small replay buffer. There is no on-disk capture log unless an
operator explicitly enables one (future feature).

## Common workflows

### Live operator audit

You're running ops for a small team. Everyone has a hop peer, the
team lead has the `creator` role, junior ops have `peer`. The lead
runs:

```bash
$ hop prod-web tap list
3 active session(s):
  pty=  0  user=alice(1000)    comm=bash      ...
  pty=  1  user=bob(1001)      comm=psql      ...
  pty=  2  opener=carol(1002)  writer=root(0)  comm=sudo  ...

$ hop prod-web tap watch 2     # carol's sudo session is interesting
```

Junior ops can only see their own sessions, not each other's:

```bash
$ hop prod-web tap list   # as alice (peer role)
1 active session(s):
  pty=  0  user=alice(1000)    comm=bash      ...
```

### Compliance / forensic replay

After an incident, you want to know exactly what was typed and shown
on a particular pty. The daemon's session log isn't a recording today
— but `tap watch` while the session is alive gives you byte-faithful
real-time visibility, and the snapshot RPC captures any moment.

For permanent audit trails, an operator can layer a recording
capability on top: subscribe via tap watch and pipe to a file. That's
explicit configuration, not default behavior.

### AI agent supervision

Expose tap to an MCP-driven AI orchestrator. Claude (or another
agent) lists active sessions periodically, summarizes activity per
user, and flags anomalies. The agent runs as a `creator`-role peer
so it sees everything; its reports are the audit surface.

Future direction: the agent opens its own session via hop's existing
shell-session machinery and *responds* to anomalies — terminating a
runaway process, alerting the on-call, or replacing a suspicious
session with a honeypot.

## Limits and known gaps

- **Linux-only.** eBPF dependency. Other OS hosts can't run hop-tap.
  The client (`hop <host> tap ...`) works from any OS.
- **PTYs only.** We hook `pty_write`, not generic `tty_write`, so
  console / serial sessions are not captured. This is intentional —
  the audit target is sshd / tmux / ssh-into-container, all of which
  are PTYs.
- **No input injection.** `hop <host> tap watch` is read-only. Future
  work could let an authorized peer write into the captured pty
  (`pidfd_getfd` + write into the master fd).
- **No persistent recording.** Captured state lives in process memory.
  No disk-backed scrollback or session log by default.
- **Bounded replay buffer.** Each session's recent state is kept as
  the alacritty Term's 24-row grid (no scrollback). For deeper
  history you'd need to capture-as-you-go on the client side via
  `tap watch`.

## See also

- [`docs/technical/tap.md`](../technical/tap.md) — implementation
  details: eBPF program structure, CO-RE relocations, the streaming
  dispatcher, lock ordering.
- [`docs/product/security.md`](security.md) — hop's broader security
  model, peer roles, and the trust boundary tap inherits.
- [`docs/product/sessions.md`](sessions.md) — hop's own shell-session
  machinery, complementary to tap (sessions are *driven*, tap
  *observes*).
