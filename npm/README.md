# WireHop

Secure peer-to-peer remote access and private networks: a single binary, no
accounts, no port forwarding, no central coordination server. Install it on two
machines and they find each other and talk over an encrypted P2P QUIC
connection, whatever networks they're on.

Built for humans and AI agents alike — every command speaks `--json`, errors
are structured, and an agent can bootstrap an entire private network without a
browser or a third-party account.

```bash
npx @wirehop/wirehop --version
# or
npm install -g @wirehop/wirehop
```

This package downloads the platform's signed binary and verifies **both** its
SHA-256 checksum and an **RSA signature** against an embedded release key. If
either check fails, installation aborts.

## Use as an MCP server

```json
{
  "mcpServers": {
    "wirehop": {
      "command": "npx",
      "args": ["-y", "@wirehop/wirehop", "mcp"]
    }
  }
}
```

Tools exposed:

| Tool | What it does |
|---|---|
| `hop_exec` | Run JavaScript in a sandbox with `hop.*` bindings — exec, fleet, admin, roles, file transfer. An agent writes one program instead of orchestrating twenty tool calls. |
| `hop_cron` | Schedule recurring work that keeps running after the agent leaves |
| `hop_data` | Key-value and time-series storage on the node |
| `hop_skills` | Teaches the agent the `hop.*` API on demand |

The MCP server runs **locally**, under your own identity — there is no hosted
service, and nothing needs custody of your credentials.

## Quick start

```bash
# On the machine you want to reach:
hop host          # or: curl -fsSL https://hop.keikai.ai/install.sh | bash -s -- --host
hop invite        # prints a one-time token

# On your laptop:
hop connect <token>
```

## Environment

| Variable | Purpose |
|---|---|
| `WIREHOP_SKIP_DOWNLOAD=1` | Skip the binary download (supply `hop` on PATH yourself) |
| `WIREHOP_CDN_URL` | Override the download origin |

Windows isn't supported directly — use WSL.

## Links

- **Repository:** https://github.com/Keikai-Inc/wirehop
- **Docs:** https://github.com/Keikai-Inc/wirehop/tree/main/docs
- **License:** MIT OR Apache-2.0 · Copyright Keikai Inc.
