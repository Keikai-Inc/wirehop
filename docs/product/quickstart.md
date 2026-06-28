# Quickstart — the three core jobs

Each job below is a copy-pasteable recipe a first-timer can finish in about a
minute. These commands are the same ones `tests/e2e/first-run.sh` runs and gates
on every release, so the docs and the product can't drift.

Install (any machine, no account, ~5 MB):

```bash
curl -fsSL https://hop.keikai.ai/install.sh | bash          # client (reach hosts)
curl -fsSL https://hop.keikai.ai/install.sh | bash -s -- --host   # node (private network)
```

The plain install is a **client**: no daemon, no VPN, just reach hosts you're
invited to. `--host` makes the machine a **node** on your private network (a
"warren"), VPN on by default (opt out with `--host --no-vpn`).

---

## 1. Reach a machine (SSH without a server)

On the machine you want to reach:

```bash
hop host                       # start hosting (or it's already running after --host install)
hop invite --user alice        # mint an invite for Unix user "alice"; prints a token
```

On your laptop, with the token:

```bash
hop connect <token>            # saves the host under its name (e.g. "myserver")
hop myserver                   # open a shell
hop myserver -- uname -a       # or run one command
hop cp ./file myserver:/tmp/   # copy files
```

No SSH daemon, no port forwarding, no public IP. Works through NAT.

---

## 2. Set up a private network (reach your machines by name)

Put the first machine on the warren (it auto-creates one):

```bash
curl -fsSL https://hop.keikai.ai/install.sh | bash -s -- --host
hop invite --role member       # invite another machine; prints a token
```

On the second machine, join with the token (VPN comes up by default):

```bash
curl -fsSL https://hop.keikai.ai/install.sh | bash -s -- --host --invite <token>
```

Now every machine is reachable **by name** from any other, anywhere:

```bash
ping founder.hop               # <hostname>.hop resolves to its private IP
hop founder                    # shell in by name
```

Names and access are default-deny and role-gated; the network state replicates
peer-to-peer with no central server.

---

## 3. Expose a local device

**A local service / port** (a dev server, a database) — forward it like `ssh -L`:

```bash
hop tunnel myserver 3000           # reach myserver's :3000 at localhost:3000
hop tunnel myserver 8080:3000      # ...at localhost:8080 instead
```

**A device on a LAN that can't run hop** (a printer, a Tablo, a NAS) — make one
hop node a doorway to its subnet (a subnet router); peers then reach the device by
its LAN IP. See [warren.md](warren.md) for advertising routes.

---

## When something doesn't work

| Symptom | Fix |
|---|---|
| `hop invite` says the user doesn't exist | Use an existing non-root Unix account: `hop invite --user $(whoami)`. |
| Joined a warren but can't reach a peer | The VPN is on by default for new nodes; on an older node enable it: `hop config set vpn on`. Check `hop warren status`. |
| `<name>.hop` doesn't resolve | The peer must be a warren **node** (not a plain client) and online; give discovery a few seconds after a fresh join. |
| A peer is offline | hop retries automatically; `hop peers` shows last-seen. |
