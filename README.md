# WireHop

**Every machine you run, reachable by name and scriptable, from one binary.**

Install `hop` on your laptop, servers, cloud boxes and Pis. Reach any of them
from anywhere: open a shell, run one command across all of them, sync files,
and leave a script running on a schedule that keeps its own state. Your AI
tools get the same access, within limits you set: every command speaks
`--json`, errors are structured, and an agent can set up a whole network
end-to-end without a browser or a third-party account.

Underneath, it is a private network your machines build themselves (a
*warren*): they find each other directly through NAT over end-to-end
encrypted QUIC, with virtual IPs and name resolution, and no account or
coordination server. When NAT blocks a direct path, an encrypted relay
forwards packets it cannot read; the default relays are run by Keikai, and
`hop host --relay` runs your own. VPNs should be as simple as SSH, and this one
is. WireHop is a tool you run, not a service you buy, fully open source under a
**permissive** licence: read every line, fork it, or ship it inside a
closed-source product.

## Quick start

```bash
# On the machine you want to reach:
curl -fsSL https://wirehop.org/install.sh | bash -s -- --host
hop invite            # prints a one-time token

# On your laptop:
curl -fsSL https://wirehop.org/install.sh | bash
hop connect <token>   # you now have a shell — and a private network
```

From there:

```bash
hop <name>                        # shell on any of your machines, by name
hop exec <name> -- <command>      # run a command remotely
hop sync ./project <name>:~/dst   # rsync-style sync over the P2P link
hop fleet exec <role> -- <cmd>    # run across every machine with a role
hop cron create ...               # leave scheduled work running on a node
```

## How it works

- **Peer-to-peer QUIC** (built on [iroh](https://github.com/n0-computer/iroh)):
  connections are end-to-end encrypted and hole-punch directly between your
  machines; a relay carries traffic only when NAT defeats hole-punching.
- **No accounts, no coordination server**: identity is a keypair on your disk;
  membership is a replicated document your machines gossip among themselves.
- **Least-privilege by design**: invites are single-use and time-limited, with
  capability tiers and per-invite sandboxes (read-only, path-scoped,
  command-allowlisted). Every node keeps its own audit log.

## Where it comes from

WireHop started in March 2026 as **hop**, an internal tool at Keikai, Inc. We
needed SSH-style access to our own machines behind NAT with no port forwarding,
no VPN and no accounts, and nothing like it existed. It ran our fleet for six
months, gained file sync, a private network, a scripting runtime and terminal
audit along the way, and was open-sourced in August 2026. Development is
AI-assisted (Claude Code) and directed by one engineer with twenty years in
real-time networking; the design decisions are written down in `docs/`.

## Security

WireHop has not had a third-party security audit. The threat model, the
sandbox and privilege-separation design, and a standing self-audit with its
open items are in [docs/technical/security.md](docs/technical/security.md).
Report vulnerabilities as described in [SECURITY.md](SECURITY.md).

## Documentation

- [Product docs](docs/product/) — commands, JS API, capabilities
- [Technical docs](docs/technical/) — protocols, internals, security model
- [CLI reference](docs/product/cli-reference.md) — every command, including
  `--json` schemas, structured error codes, and exit codes

## Installing

The installer detects your OS/arch, verifies a SHA-256 checksum **and an RSA
signature** against the key embedded in `install.sh`, and installs a single
binary. Releases are published on the
[Releases page](https://github.com/Keikai-Inc/wirehop/releases) and served from
`https://wirehop.org` (Keikai's CDN — WireHop is a Keikai Inc. open-source
project).

macOS `.pkg` installers and per-arch binaries for macOS/Linux (x86_64, arm64,
armv7) are attached to each release.

**Platforms:** macOS (Apple Silicon and Intel) and Linux (x86_64, arm64,
armv7) as both client and host. Windows works as a client under WSL today; a
native Windows client is planned, a Windows host is not yet.

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option. Copyright Keikai Inc.
