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
> network (the **[warren](warren.md)**), members run a local daemon (like
> Tailscale's, but with no coordination server behind it). "Single binary, no
> central anything" is the promise; a per-member daemon is fully in keeping with
> it.

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
| `hop-core` | Library -- networking, PTY, auth, config, protocol, sandbox, fleet |
| `hop-mcp` | MCP server, JS runtime (QuickJS), capabilities, skills store |

### Wire Protocol

All messages are length-prefixed bincode frames over QUIC bi-directional streams.

*Last updated: v0.4.3*
