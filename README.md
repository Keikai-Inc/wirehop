# WireHop

**Secure private networking and remote access for Agents and users alike.
VPNs should be as simple as SSH.**

WireHop is a tool you run, not a service you buy. There is no company between
you and your machines, and that includes us: no accounts, no coordination
server, nothing that can be shut off. It is fully open source under a
**permissive** licence, so you can read every line, fork it, or ship it inside
a closed-source product.

WireHop ships a single binary, `hop`. Install it on two machines and they can
find each other and talk — over an encrypted peer-to-peer QUIC connection —
no matter what networks they're on. Add more machines and you have a private
network (a *warren*) with its own virtual IPs, name resolution, remote shell,
file sync, cross-fleet command execution, and a scheduler.

Built for humans and AI agents alike: every command speaks `--json`, errors
are structured, and an agent can bootstrap an entire private network
end-to-end without a browser or a third-party account.

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

## License

Dual-licensed under [MIT](LICENSE-MIT) or [Apache-2.0](LICENSE-APACHE), at
your option. Copyright Keikai Inc.
