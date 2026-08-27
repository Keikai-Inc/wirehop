# hop Overview

hop is a single-binary CLI tool that provides secure shell access, file transfer, and remote command execution on any machine -- through NAT, firewalls, and carrier-grade NAT -- with zero port forwarding and zero VPN configuration. Built on iroh (QUIC-based P2P networking), it uses Ed25519 identities and TLS 1.3 encryption. Share a one-time invite token, and you're connected.

## Why hop Exists

| SSH pain point | hop solution |
|---|---|
| Requires port forwarding or a VPN appliance | Direct P2P via NAT traversal + relay fallback |
| Tailscale/ZeroTier route trust through a central coordination server | Fully peer-to-peer — no central control plane, no accounts, no third party to depend on |
| ngrok/Cloudflare Tunnel route traffic through third parties | End-to-end encrypted, peer-to-peer |
| Key management and `authorized_keys` | One-time invite tokens with automatic key exchange |
| No built-in session persistence | Sessions survive disconnects (24h default) |
| No native file sync | Built-in `cp` and `sync` with delta transfer |

> **hop's defining guarantee is decentralization, not minimalism.** The wedge is
> that hop runs **independent of any third party or central control plane** —
> not that it avoids a background process. As hop grows into a full private
> network (the **[warren](warren.md)** — shipped; VPN on by default for new hosts), members run a
> local daemon (like Tailscale's, but with no coordination server behind it).
> "Single binary, no central anything" is the promise; a per-member daemon is
> fully in keeping with it.

## Core User Flows

### 1. Host / Invite / Connect

```bash
# On the server
hop host                          # start listening
hop invite --user jason           # generate one-time invite token

# On the client
hop connect <invite-token>        # exchange keys, open shell
hop myhost                        # reconnect by saved alias
```

### 2. Remote Execution

```bash
hop exec myhost -- uname -a
hop exec myhost --read-only -- cat /etc/passwd
echo "data" | hop exec myhost -- wc -l
```

### 3. File Transfer and Sync

```bash
hop cp localfile.txt myhost:/tmp/
hop cp -r ./project myhost:~/backup/
hop sync ./src myhost:~/project/src
hop sync --delete myhost:~/data ./local-data
```

### 4. Session Persistence

```bash
hop myhost              # connect, do work
  [network drops]       # session detaches, PTY stays alive
  [reconnecting...]     # TUI shows reconnection status
  [reconnected]         # same shell, same state
```

### 5. Remote Administration

```bash
hop admin myhost invite --user alice
hop admin myhost create-user bob --sudo --invite
hop admin myhost peers
hop admin myhost status
```

### 6. Fleet Management

```bash
hop admin orch fleet-invite --tags web,staging
hop admin orch fleet-list --tag web
hop fleet exec developer -- apt update
```

### 7. AI Agent Integration (MCP)

```bash
hop mcp                 # start MCP server on stdio
# Exposes hop_exec (sandboxed JS) and hop_skills tools
```

### 8. Private Network (the warren)

```bash
hop invite --role developer       # role decides reach over the VPN
hop config set vpn off            # opt OUT of the warren VPN (on by default for new hosts)
hop admin myhost grant abc123 ops # change a member's reach later
```

A daemon can bring up a built-in P2P VPN: a virtual IP in `100.64.0.0/10`,
MagicDNS (`*.hop`), and role→tag reach (default-deny). The VPN is **on by
default for a new host** (since v0.9.16) — opt out with `--host --no-vpn` or
`hop config set vpn off`. A config file predating the `vpn_enabled` field stays
**off** on upgrade, so updating an existing host never silently brings up a VPN.
(It was off by default in v0.6.37–0.9.15, an interim mitigation for the warren
write-authorization gap; that gap is now closed by anchor-conditional
author-validation enforce — see [security.md](security.md) and the warren trust
note in [../technical/warren-internals.md](../technical/warren-internals.md).)
Bringup is fail-safe
— if a TUN can't be created or the CGNAT range conflicts (e.g. Tailscale), it's
skipped and shell/exec/transfer are unaffected. See [warren.md](warren.md).

## Supported platforms

macOS and Linux. Windows via WSL only.

### Linux kernel floor

The published Linux binaries are **static musl** (no libc dependency, no
`ld.so`), so distro age does not matter. The kernel does:

| Build | Minimum kernel | Set by |
|---|---|---|
| Default (UPX-packed) | **2.6.27** (Oct 2008) | tokio's `eventfd2` / `epoll_create1` |
| `-uncompressed` variant | **2.6.27** (Oct 2008) | same |

2.6.27 predates every distro still in service, including RHEL/CentOS 6 (2.6.32)
and 7 (3.10).

**Why the `-uncompressed` variant exists anyway.** UPX unpacking is a stub that
runs before `main()`, and *which syscalls it needs depends on the UPX build*.
Binaries packed by Alpine's UPX (releases through v0.9.33, produced by
`scripts/release.sh`) unpack via `memfd_create(2)` and therefore require **3.17**,
which excludes RHEL/CentOS 7. Binaries packed by Debian/Ubuntu's `upx-ucl` (CI,
v0.9.35 onward) decompress in-memory via `mmap` and need nothing newer than the
program itself.

That is a toolchain detail that can change under us, so the uncompressed build
is published as insurance rather than deleted. `install.sh` and the npm
postinstall read `uname -r` and fetch `hop-linux-<arch>-uncompressed` below 3.17;
the release gate asserts that variant still starts with `memfd_create` returning
`ENOSYS`, so the fallback cannot quietly stop being one.

Everything newer is used opportunistically with fallbacks and is **not**
required: `getrandom` (3.17), `membarrier` (4.3), `rseq` (4.18), `io_uring`
(5.1), `clone3` (5.3), `openat2`/`GRND_INSECURE` (5.6), `faccessat2` (5.8).
QUIC `UDP_SEGMENT`/`UDP_GRO` (4.18/5.0) degrade to plain sends when absent.

*Measured by returning `ENOSYS` for each syscall via seccomp, which is what an
old kernel does. Startup and `hop host` were exercised this way; the VPN data
plane needs `/dev/net/tun` and has not been tested below 6.x.*

## Architecture

```
+------------------------------------------------------------------+
|                          hop binary                               |
+---------------+-----------------------------------+---------------+
|   CLI Layer   |         Core Library              |   hop-mcp     |
|   (clap)      |         (hop-core)                |   crate       |
+---------------+-----------------------------------+---------------+
|               |  +----------+ +-----------+       | +-----------+ |
|  Commands:    |  |  Auth    | |  Invite   |       | |  MCP      | |
|  . host       |  |  Module  | |  Module   |       | |  Server   | |
|  . invite     |  +----------+ +-----------+       | +-----------+ |
|  . connect    |  |  Shell   | | Transfer  |       | |  JS       | |
|  . exec       |  |  Module  | |  Module   |       | |  Runtime  | |
|  . cp / sync  |  +----------+ +-----------+       | +-----------+ |
|  . config     |  | Sandbox  | |  Admin    |       | |  Skills   | |
|  . peers      |  |  Module  | |  Module   |       | |  Store    | |
|  . admin      |  +----------+ +-----------+       | +-----------+ |
|  . fleet      |  |  Fleet   | |  Config   |       |               |
|  . mcp        |  |  Module  | |  Module   |       |               |
|  . agent      |  +----------+-+-----------+----+  |               |
|               |  |       Proto Module         |   |               |
|               |  |  (wire protocol + admin)   |   |               |
|               |  +----------------------------+   |               |
|               |  |        Net Module          |   |               |
|               |  | (iroh endpoint, relay)     |   |               |
+---------------+--+----------------------------+---+---------------+
|                      iroh (QUIC + P2P)                            |
|              NAT traversal . Relay (relay.keik.ai)                |
|              Ed25519 identity . TLS 1.3                           |
+-------------------------------------------------------------------+
```

### Crate Layout

| Crate | Purpose |
|---|---|
| `hop-cli` | Binary crate -- thin CLI wrapper, binary name `hop` |
| `hop-core` | Library -- networking, PTY, auth, config, protocol, sandbox, fleet, warren (netdoc + VPN) |
| `hop-mcp` | MCP server, JS runtime (QuickJS), capabilities, skills store |

### Wire Protocol

All messages are length-prefixed bincode frames over QUIC bi-directional streams.

*Last updated: v0.6.33*
