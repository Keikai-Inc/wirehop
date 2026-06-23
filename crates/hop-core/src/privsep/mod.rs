//! Privilege-separation primitives (privsep-node.md).
//!
//! The warren node is moving to an OpenSSH-style split: a tiny root **monitor**
//! that performs a fixed set of privileged primitives (create the TUN, bind the
//! privileged `:53`, spawn sessions as the bound user) and hands the resulting
//! file descriptors to an unprivileged **worker** that runs the entire
//! network-facing daemon. This module holds the cross-process plumbing that
//! split needs — chiefly **file-descriptor passing over a unix socket**
//! (`SCM_RIGHTS`), which hop did not previously have.
//!
//! Phase 0 of the plan is a feasibility gate: prove that a TUN fd created by
//! root can be read/written by a non-root process (especially on macOS utun).
//! `run_tun_fd_probe` implements that gate; it is exercised via the hidden
//! `hop __privsep-probe` subcommand and must be run as root.

use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, OwnedFd, RawFd};

use anyhow::{Context, Result};
use nix::sys::socket::{
    recvmsg, sendmsg, socketpair, AddressFamily, ControlMessage, ControlMessageOwned, MsgFlags,
    SockFlag, SockType,
};

/// Create a connected `AF_UNIX` `SOCK_STREAM` pair for the monitor↔worker
/// control channel. (macOS `AF_UNIX` has no `SOCK_SEQPACKET`, so the control
/// protocol length-prefixes its messages over a stream.) The pair is anonymous
/// — no on-disk path, so no third party can connect; the worker inherits one
/// end across the privilege-dropping exec.
pub fn control_socketpair() -> Result<(OwnedFd, OwnedFd)> {
    socketpair(
        AddressFamily::Unix,
        SockType::Stream,
        None,
        SockFlag::empty(),
    )
    .context("creating control socketpair")
}

/// The fixed, closed set of privileged operations the unprivileged worker may
/// ask the root monitor to perform (privsep-node.md §4). Minimality here is the
/// security argument: the monitor never exposes a general "run as root", only
/// these typed, range/allowlist-validated primitives. Reused by both the full
/// monitor/worker split and the lighter B-lite fallback.
// `Eq` is intentionally omitted: SpawnExec carries a SandboxPolicy, which is
// only `PartialEq`. Tests compare with `assert_eq!`, which needs only PartialEq.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum MonitorRequest {
    /// Create + configure a TUN at `vip` (must be in 100.64.0.0/10) and return
    /// its fd. The monitor validates the range before touching the kernel.
    CreateTun { vip: [u8; 4] },
    /// Bind a UDP socket on `(addr, port)` and return its fd. The monitor
    /// allowlists this to the node's own vip and port 53 (MagicDNS) only.
    BindPrivPort { addr: [u8; 4], port: u16 },
    /// Point the OS resolver for the warren `domain` at the local MagicDNS server
    /// on `vip:53` (split-DNS). Privileged (root-owned `/etc/resolver`, or
    /// `resolvectl`), so the worker delegates it. The monitor remembers the
    /// domain and reverts it when it exits. Replies `Ok` (no fd).
    ConfigureResolver { domain: String, vip: [u8; 4] },
    /// Set up Tier 1 LAN-bridging gateway forwarding for `routes` (`(cidr, snat)`):
    /// enable `ip_forward` + apply the nftables NAT/forward ruleset. Privileged
    /// (writes `/proc/sys/net`, runs `nft`), so the dropped worker delegates it.
    /// The monitor reverts it on exit. Replies `Ok` (no fd).
    SetupGateway { routes: Vec<(String, bool)> },
    /// Add (`add=true`) or remove a kernel route `cidr → dev` through the warren
    /// TUN, so an accepted subnet route leaves via the VPN. Privileged (`ip route`),
    /// so the dropped worker delegates it. The monitor allowlists `dev` to a TUN
    /// interface (`tun*`/`utun*`). Replies `Ok` (no fd).
    ModifyClientRoute { cidr: String, dev: String, add: bool },
    /// Configure IPv6 on the warren TUN for 4via6 client routing (Tier 3a): assign
    /// the client's own source address `addr` and route the via6 destination prefix
    /// into the TUN. Privileged (`ip -6`/`ifconfig`/`route`), so the dropped worker
    /// delegates it. The monitor validates `addr` is in the via6 client prefix and
    /// routes onto the TUN it created. Replies `Ok` (no fd).
    ConfigureTunV6 { addr: [u8; 16] },
    /// Pin a `/32` host route `dst → via <gateway>` (not the TUN). Used by an exit
    /// node to keep the warren relay reachable past the split-default, so the
    /// tunnel doesn't loop through the exit. Privileged. Reverted on worker exit.
    PinHostRoute { dst: [u8; 4], via: [u8; 4], add: bool },
    /// Spawn a session command on a fresh PTY and return the PTY **master** fd.
    /// The worker has already resolved `argv` (including the `login`/`su` and
    /// sandbox wrapper), so the monitor only performs the privileged act —
    /// `openpty` + spawn as root, which lets the embedded `login`/`su` switch to
    /// `username`. `username` is carried for the receiver-side ACL check (§9):
    /// the monitor confirms the worker is allowed to become that user before
    /// spawning. The monitor owns the child and reaps it; the worker drives I/O
    /// over the returned master fd and sees session end as master EOF.
    SpawnSession {
        argv: Vec<String>,
        env: Vec<(String, String)>,
        rows: u16,
        cols: u16,
        pixel_width: u16,
        pixel_height: u16,
        username: Option<String>,
    },
    /// Spawn a non-PTY exec command as `username` under the sandbox `policy`, and
    /// return four fds (stdin-write, stdout-read, stderr-read, status-read). The
    /// monitor builds the privileged command itself (it must apply the Linux
    /// sandbox `pre_exec`, which can't cross the wire), reaps the child, and
    /// writes the 4-byte exit code to the status pipe on exit — so the worker
    /// gets the exit code out-of-band without a second control reply.
    SpawnExec {
        cmd: String,
        policy: crate::sandbox::SandboxPolicy,
        username: String,
    },
    /// Spawn the trusted file-transfer helper (`hop __transfer-helper …`, the
    /// worker-built `argv`) as `username`, with stdin/stdout piped and stderr
    /// inherited. Returns three fds (stdin-write, stdout-read, status-read). No
    /// sandbox policy — the helper is hop's own code; the monitor applies only
    /// the user switch (login on macOS, uid/gid+initgroups on Linux). `argv[0]`
    /// must be the hop executable running `__transfer-helper`.
    SpawnHelper {
        argv: Vec<String>,
        username: String,
    },
}

/// The monitor's reply. On `OkFd` a file descriptor follows as ancillary data
/// (received with [`recv_fd`]); `Error` carries a human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MonitorReply {
    OkFd,
    /// Success for a side-effect primitive that returns no fd (e.g.
    /// `ConfigureResolver`).
    Ok,
    Error { message: String },
}

/// Cap on a single control message (defensive — these are tiny structs).
const MAX_CTRL_MSG: usize = 64 * 1024;

/// Write all of `buf` to a raw socket fd, looping over short writes.
fn write_all(sock: RawFd, buf: &[u8]) -> Result<()> {
    let mut off = 0;
    while off < buf.len() {
        let n = unsafe {
            libc::write(sock, buf[off..].as_ptr() as *const libc::c_void, buf.len() - off)
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e).context("write to control socket");
        }
        if n == 0 {
            anyhow::bail!("control socket closed mid-write");
        }
        off += n as usize;
    }
    Ok(())
}

/// Read exactly `buf.len()` bytes from a raw socket fd.
fn read_exact(sock: RawFd, buf: &mut [u8]) -> Result<()> {
    let mut off = 0;
    while off < buf.len() {
        let n = unsafe {
            libc::read(sock, buf[off..].as_mut_ptr() as *mut libc::c_void, buf.len() - off)
        };
        if n < 0 {
            let e = std::io::Error::last_os_error();
            if e.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            return Err(e).context("read from control socket");
        }
        if n == 0 {
            anyhow::bail!("control socket closed mid-read");
        }
        off += n as usize;
    }
    Ok(())
}

/// Send a length-prefixed, bincode-encoded control message.
pub fn send_msg<T: serde::Serialize>(sock: RawFd, msg: &T) -> Result<()> {
    let bytes = bincode::serde::encode_to_vec(msg, bincode::config::standard())
        .context("encoding control message")?;
    anyhow::ensure!(bytes.len() <= MAX_CTRL_MSG, "control message too large");
    write_all(sock, &(bytes.len() as u32).to_be_bytes())?;
    write_all(sock, &bytes)
}

/// Receive a length-prefixed, bincode-encoded control message.
pub fn recv_msg<T: serde::de::DeserializeOwned>(sock: RawFd) -> Result<T> {
    let mut len_buf = [0u8; 4];
    read_exact(sock, &mut len_buf)?;
    let len = u32::from_be_bytes(len_buf) as usize;
    anyhow::ensure!(len <= MAX_CTRL_MSG, "control message length {len} exceeds cap");
    let mut buf = vec![0u8; len];
    read_exact(sock, &mut buf)?;
    let (msg, _) = bincode::serde::decode_from_slice(&buf, bincode::config::standard())
        .context("decoding control message")?;
    Ok(msg)
}

/// Send a single file descriptor over `sock` via `SCM_RIGHTS`, with one byte of
/// in-band data (some platforms require ≥1 real byte alongside the ancillary
/// data). The kernel duplicates `fd` into the receiver; the sender keeps its own
/// copy (so it can remain the canonical owner that keeps the device alive).
pub fn send_fd(sock: RawFd, fd: RawFd) -> Result<()> {
    let fds = [fd];
    let cmsgs = [ControlMessage::ScmRights(&fds)];
    let iov = [IoSlice::new(&[0u8])];
    sendmsg::<()>(sock, &iov, &cmsgs, MsgFlags::empty(), None).context("sendmsg SCM_RIGHTS")?;
    Ok(())
}

/// Receive a single file descriptor sent via [`send_fd`]. Returns an [`OwnedFd`]
/// so the caller's drop closes it deterministically.
pub fn recv_fd(sock: RawFd) -> Result<OwnedFd> {
    use std::os::fd::FromRawFd;

    let mut data = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut data)];
    let mut cmsg_space = nix::cmsg_space!(RawFd);
    let msg = recvmsg::<()>(sock, &mut iov, Some(&mut cmsg_space), MsgFlags::empty())
        .context("recvmsg SCM_RIGHTS")?;
    for cmsg in msg.cmsgs().context("decoding control messages")? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg
            && let Some(&fd) = fds.first()
        {
            // SAFETY: the kernel just installed this fd into our table.
            return Ok(unsafe { OwnedFd::from_raw_fd(fd) });
        }
    }
    anyhow::bail!("no file descriptor in control message");
}

/// Send several file descriptors in one `SCM_RIGHTS` message (kept as a single
/// ancillary block so the receiver gets them atomically, in order). Used by
/// `SpawnExec`, which hands back stdin/stdout/stderr + a status pipe at once.
pub fn send_fds(sock: RawFd, fds: &[RawFd]) -> Result<()> {
    let cmsgs = [ControlMessage::ScmRights(fds)];
    let count = [fds.len() as u8];
    let iov = [IoSlice::new(&count)];
    sendmsg::<()>(sock, &iov, &cmsgs, MsgFlags::empty(), None).context("sendmsg SCM_RIGHTS (n)")?;
    Ok(())
}

/// Receive exactly `n` file descriptors sent via [`send_fds`], in order.
pub fn recv_fds(sock: RawFd, n: usize) -> Result<Vec<OwnedFd>> {
    use std::os::fd::FromRawFd;

    let mut data = [0u8; 1];
    let mut iov = [IoSliceMut::new(&mut data)];
    // Space for up to `n` fds in the ancillary buffer.
    let mut cmsg_space = vec![0u8; unsafe { libc::CMSG_SPACE((n * std::mem::size_of::<RawFd>()) as u32) } as usize];
    let msg = recvmsg::<()>(sock, &mut iov, Some(&mut cmsg_space), MsgFlags::empty())
        .context("recvmsg SCM_RIGHTS (n)")?;
    let mut out = Vec::with_capacity(n);
    for cmsg in msg.cmsgs().context("decoding control messages")? {
        if let ControlMessageOwned::ScmRights(fds) = cmsg {
            for fd in fds {
                // SAFETY: the kernel just installed these fds into our table.
                out.push(unsafe { OwnedFd::from_raw_fd(fd) });
            }
        }
    }
    anyhow::ensure!(
        out.len() == n,
        "expected {n} file descriptors, received {}",
        out.len()
    );
    Ok(out)
}

/// Phase-0 feasibility gate (privsep-node.md §8.1) — parent half.
///
/// The whole privsep design assumes a TUN fd created + configured by root can be
/// read/written by an unprivileged process. This probe creates a TUN as root,
/// spawns `hop __privsep-probe-child` dropped to `uid`/`gid`, passes it the TUN
/// fd, and the child attempts non-blocking I/O. The decisive question is whether
/// the kernel gates per-I/O on the caller's privilege (→ `EPERM`/`EACCES`, gate
/// FAILS) or only at device creation/configuration (→ `EAGAIN`/success, PASSES).
///
/// We `exec` the child rather than `fork()` because the probe runs inside hop's
/// tokio runtime, where a forked child could deadlock on an allocator lock held
/// by another thread; `exec` also mirrors the real monitor→worker handoff.
///
/// Returns `Ok(true)` if non-root I/O is permitted, `Ok(false)` if denied by
/// privilege, `Err` for setup failures. Must be called as root.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn run_tun_fd_probe(uid: u32, gid: u32) -> Result<bool> {
    use std::os::unix::process::CommandExt;

    anyhow::ensure!(
        crate::unix_user::is_running_as_root(),
        "the privsep probe must run as root (it creates a TUN)"
    );

    let (parent_sock, child_sock) = control_socketpair()?;
    // The child inherits child_sock across exec → clear CLOEXEC on it.
    clear_cloexec(child_sock.as_raw_fd())?;

    // Root: create + configure the TUN (the monitor's job); keep `dev` alive in
    // this parent so the device — and the fd we pass — stays valid.
    let dev = create_probe_tun().context("creating probe TUN")?;
    let tun_fd = dev.as_raw_fd();

    let exe = std::env::current_exe().context("resolving current exe")?;
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("__privsep-probe-child")
        .arg("--sock-fd")
        .arg(child_sock.as_raw_fd().to_string())
        .uid(uid)
        .gid(gid);
    let mut child = cmd.spawn().context("spawning probe child")?;

    // Hand the TUN fd to the now-unprivileged child.
    send_fd(parent_sock.as_raw_fd(), tun_fd).context("passing TUN fd to child")?;

    let status = child.wait().context("waiting on probe child")?;
    match status.code() {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        other => anyhow::bail!("probe child exited unexpectedly: {other:?}"),
    }
}

/// Phase-0 feasibility gate — child half, run by the hidden
/// `hop __privsep-probe-child` subcommand. The parent already dropped us to a
/// non-root uid/gid via `Command::uid/gid`. Receive the TUN fd from `sock_fd`
/// and attempt non-blocking read + write. Returns the process exit code:
/// 0 = non-root I/O permitted, 1 = denied by privilege, 2 = setup error.
#[cfg(any(target_os = "macos", target_os = "linux"))]
pub fn run_tun_fd_probe_child(sock_fd: RawFd) -> i32 {
    if nix::unistd::geteuid().is_root() {
        eprintln!("probe child: still root — the parent failed to drop privilege");
        return 2;
    }
    let tun = match recv_fd(sock_fd) {
        Ok(fd) => fd,
        Err(e) => {
            eprintln!("probe child: recv_fd failed: {e:#}");
            return 2;
        }
    };
    let fd = tun.as_raw_fd();

    // Non-blocking so a read with no pending packet returns EAGAIN, not a hang.
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL);
        libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK);
    }

    // A minimal write: on macOS utun each frame is prefixed with a 4-byte
    // address family (AF_INET = 2, network order); Linux with IFF_NO_PI has no
    // prefix. We write a tiny well-formed-enough IPv4 header to a benign dest.
    let mut frame: Vec<u8> = Vec::new();
    #[cfg(target_os = "macos")]
    frame.extend_from_slice(&(libc::AF_INET as u32).to_be_bytes());
    // 20-byte IPv4 header: version/ihl, ..., src 100.64.0.123, dst 100.64.0.123.
    frame.extend_from_slice(&[
        0x45, 0x00, 0x00, 0x14, 0x00, 0x00, 0x40, 0x00, 0x40, 0x00, 0x00, 0x00, 100, 64, 0, 123,
        100, 64, 0, 123,
    ]);

    let denied = |errno: i32| errno == libc::EPERM || errno == libc::EACCES;

    let wrote = unsafe {
        libc::write(fd, frame.as_ptr() as *const libc::c_void, frame.len())
    };
    if wrote < 0 {
        let e = std::io::Error::last_os_error();
        let errno = e.raw_os_error().unwrap_or(0);
        if denied(errno) {
            eprintln!("probe child: write denied by privilege ({e})");
            return 1;
        }
        // EAGAIN / ENOBUFS / other non-privilege errors still mean I/O is allowed.
        eprintln!("probe child: write returned non-privilege error ({e}) — I/O permitted");
    }

    let mut buf = [0u8; 2048];
    let r = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) };
    if r < 0 {
        let e = std::io::Error::last_os_error();
        let errno = e.raw_os_error().unwrap_or(0);
        if denied(errno) {
            eprintln!("probe child: read denied by privilege ({e})");
            return 1;
        }
        // EAGAIN is the expected "no packet pending" result — I/O is permitted.
    }

    eprintln!("probe child: non-root I/O on the passed TUN fd is PERMITTED");
    0
}

// ── Monitor-side privileged primitives ──────────────────────────────────────
//
// These are the operations the root monitor performs on a worker request. The
// *validation* is factored into pure predicates so it is unit-testable without
// root; the act (create the device / bind the socket) needs root and is covered
// by the daemon-install e2e. Validation is the §T3 security boundary — the
// monitor accepts only a vIP in the warren range and only the :53 bind.

/// Accept a `CreateTun` only for an address in the warren range (100.64.0.0/10).
fn validate_create_tun(vip: [u8; 4]) -> Result<()> {
    let addr = std::net::Ipv4Addr::from(vip);
    anyhow::ensure!(
        crate::vpn::is_virtual_addr(addr),
        "refusing CreateTun for {addr}: not in the warren range 100.64.0.0/10"
    );
    Ok(())
}

/// Accept a `BindPrivPort` only for MagicDNS port 53 on either the node's own vIP
/// (Linux) or loopback (macOS serves MagicDNS on `127.0.0.1` — see
/// `vpn::magicdns_bind_addr`). Both are local-only DNS sockets, never a general
/// privileged bind.
fn validate_bind_priv_port(addr: [u8; 4], port: u16) -> Result<()> {
    anyhow::ensure!(
        port == 53,
        "refusing BindPrivPort: only :53 (MagicDNS) is permitted, not :{port}"
    );
    let a = std::net::Ipv4Addr::from(addr);
    anyhow::ensure!(
        crate::vpn::is_virtual_addr(a) || a == std::net::Ipv4Addr::LOCALHOST,
        "refusing BindPrivPort: {a} is neither a warren vIP nor loopback"
    );
    Ok(())
}

/// Monitor side of `CreateTun`: validate, then create + configure the device.
/// The monitor keeps the returned `Device` alive (so the interface + route
/// persist across worker restarts) and passes its fd to the worker.
pub fn monitor_create_tun(vip: [u8; 4]) -> Result<tun::Device> {
    use tun::AbstractDevice;
    validate_create_tun(vip)?;
    let addr = std::net::Ipv4Addr::from(vip);
    let mut config = tun::configure();
    config
        .address(addr)
        .netmask(std::net::Ipv4Addr::new(255, 192, 0, 0))
        .mtu(crate::vpn::VPN_MTU)
        .up();
    let dev = tun::create(&config).map_err(|e| anyhow::anyhow!("create TUN {addr}: {e}"))?;
    // macOS doesn't auto-install the /10 route on a p2p utun — the monitor (root)
    // pins it explicitly so warren traffic flows. No-op on Linux.
    if let Ok(name) = dev.tun_name()
        && let Err(e) = crate::vpn::ensure_warren_route(&name)
    {
        tracing::warn!("privsep: warren route setup on {name} failed: {e:#}");
    }
    Ok(dev)
}

/// Monitor side of `BindPrivPort`: validate (own vIP + :53), then bind. Returns
/// the bound UDP socket's fd to hand to the worker's MagicDNS loop.
pub fn monitor_bind_priv_port(addr: [u8; 4], port: u16) -> Result<OwnedFd> {
    validate_bind_priv_port(addr, port)?;
    let a = std::net::Ipv4Addr::from(addr);
    let sock = std::net::UdpSocket::bind((a, port)).with_context(|| format!("binding {a}:{port}"))?;
    Ok(OwnedFd::from(sock))
}

/// Validate a `SpawnSession` before the monitor performs it. `argv[0]` must be
/// an absolute path to an allowlisted privileged session launcher (`login`/`su`)
/// or a plain shell — never an arbitrary worker-chosen binary — and `username`,
/// if present, must be a well-formed account name. This is the receiver-side
/// boundary (§9): the worker is unprivileged, so the monitor, not the worker,
/// decides what may be spawned as root.
fn validate_spawn_session(argv: &[String], username: Option<&str>) -> Result<()> {
    let bin = argv.first().context("SpawnSession: empty argv")?;
    // Allowlist the launcher. The privileged forms are exactly the user-switch
    // helpers the worker builds in `sandbox`; everything else must be an
    // absolute-path shell (session-as-self needs no setuid but still routes here
    // under a dropped worker). Reject relative paths (PATH-search ambiguity).
    let base = std::path::Path::new(bin)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("");
    let is_switcher = matches!(base, "login" | "su");
    anyhow::ensure!(
        bin.starts_with('/') || is_switcher,
        "SpawnSession: refusing non-absolute launcher {bin:?}"
    );
    if let Some(user) = username {
        anyhow::ensure!(
            crate::unix_user::validate_username(user).is_ok(),
            "SpawnSession: invalid username {user:?}"
        );
        validate_spawn_user(user)?;
    }
    Ok(())
}

/// Lowest uid a peer-bound session may target. Below this are system/service
/// accounts (`root`, `daemon`, `_www`, the `_hop` service user itself, …) — the
/// highest-value escalation targets for a compromised worker. macOS regular
/// accounts start at 500, Linux at 1000.
const MIN_SPAWNABLE_UID: u32 = if cfg!(target_os = "macos") { 500 } else { 1000 };

/// The root-owned allowlist of spawnable users, set by [`run_monitor`]. When
/// present and valid, it is the authoritative bound-user list — see
/// [`load_allowlist`] for why it must be root-owned.
static ALLOWLIST_PATH: std::sync::OnceLock<std::path::PathBuf> = std::sync::OnceLock::new();

/// Receiver-side authorization for a spawn target (privsep-node.md §9, Phase 4).
/// The monitor — not the unprivileged worker — decides who may be spawned, in two
/// layers. **Baseline:** refuse system/service accounts (uid <
/// [`MIN_SPAWNABLE_UID`]), so a compromised worker can never reach
/// `root`/`daemon`/`_hop`. **Allowlist:** if the operator placed a root-owned
/// `privsep-users` file in the daemon config dir, the target must appear in it —
/// constraining spawns to exactly the accounts peers are bound to.
///
/// The allowlist must come from the operator, not the worker: the worker owns
/// `peers.json`, so a worker RCE could forge bindings — only root-owned config is
/// a trustworthy source (the inherent ceiling of the trust model).
fn validate_spawn_user(username: &str) -> Result<()> {
    let (uid, _gid) = crate::transfer::helper::lookup_uid_gid(username)?;
    validate_spawnable_uid(uid, username)?;
    if let Some(allowed) = load_allowlist() {
        anyhow::ensure!(
            allowed.contains(username),
            "refusing to spawn as {username:?}: not in the privsep allowlist"
        );
    }
    Ok(())
}

/// The pure uid check, factored out for unit testing.
fn validate_spawnable_uid(uid: u32, username: &str) -> Result<()> {
    anyhow::ensure!(
        uid >= MIN_SPAWNABLE_UID,
        "refusing to spawn as system/service account {username:?} (uid {uid} < {MIN_SPAWNABLE_UID}); \
         only regular user accounts may be session/exec/transfer targets"
    );
    Ok(())
}

/// Load the operator's spawn allowlist, or `None` if there is no *trustworthy*
/// one (no file, or — critically — a file the worker could tamper with). The
/// file must be owned by root and not writable by group/other; otherwise the
/// unprivileged worker could rewrite it to authorize an escalation, so we ignore
/// it (falling back to the uid baseline) and warn loudly.
fn load_allowlist() -> Option<std::collections::HashSet<String>> {
    use std::os::unix::fs::MetadataExt;
    let path = ALLOWLIST_PATH.get()?;
    let md = std::fs::symlink_metadata(path).ok()?;
    if !md.is_file() {
        return None;
    }
    if md.uid() != 0 {
        tracing::warn!(
            "privsep: ignoring spawn allowlist {} — not root-owned (uid {}), so the worker \
             could tamper with it",
            path.display(),
            md.uid()
        );
        return None;
    }
    if md.mode() & 0o022 != 0 {
        tracing::warn!(
            "privsep: ignoring spawn allowlist {} — group/other-writable (mode {:o})",
            path.display(),
            md.mode() & 0o777
        );
        return None;
    }
    Some(parse_allowlist(&std::fs::read_to_string(path).ok()?))
}

/// Parse a `privsep-users` allowlist: one username per line, `#` comments and
/// blank lines ignored. Pure, for unit testing.
fn parse_allowlist(content: &str) -> std::collections::HashSet<String> {
    content
        .lines()
        .map(|l| l.split('#').next().unwrap_or("").trim())
        .filter(|l| !l.is_empty())
        .map(String::from)
        .collect()
}

/// Monitor side of `SpawnSession`: validate, open a PTY, spawn the worker-built
/// `argv` (with its embedded `login`/`su`) as root so it can switch to the bound
/// user, and return the PTY **master** fd. The monitor keeps the child to reap
/// it; the worker drives the master fd and detects exit via EOF.
pub fn monitor_spawn_session(
    argv: &[String],
    env: &[(String, String)],
    rows: u16,
    cols: u16,
    pixel_width: u16,
    pixel_height: u16,
    username: Option<&str>,
) -> Result<(OwnedFd, Box<dyn portable_pty::Child + Send + Sync>)> {
    use std::os::fd::FromRawFd;
    validate_spawn_session(argv, username)?;

    let pty = portable_pty::native_pty_system();
    let pair = pty
        .openpty(portable_pty::PtySize {
            rows,
            cols,
            pixel_width,
            pixel_height,
        })
        .context("monitor openpty")?;

    let mut cmd = portable_pty::CommandBuilder::new(&argv[0]);
    cmd.args(argv.iter().skip(1));
    for (k, v) in env {
        cmd.env(k, v);
    }
    let child = pair
        .slave
        .spawn_command(cmd)
        .context("monitor spawn session command")?;
    drop(pair.slave); // the child holds the slave; the monitor needs only the master

    // Dup the master fd into an OwnedFd to pass to the worker, then let the
    // PtyPair's master close its own copy. The dup keeps the master open.
    let raw = pair
        .master
        .as_raw_fd()
        .context("PTY master exposes no fd")?;
    let dup = unsafe { libc::dup(raw) };
    anyhow::ensure!(dup >= 0, "dup PTY master: {}", std::io::Error::last_os_error());
    let owned = unsafe { OwnedFd::from_raw_fd(dup) };
    drop(pair.master);

    tracing::info!(
        user = username.unwrap_or("<self>"),
        "privsep monitor: spawned session on PTY, passing master fd to worker"
    );
    Ok((owned, child))
}

/// Monitor side of `SpawnExec`: validate, build + spawn the privileged exec
/// command (with the OS sandbox applied) as the bound user, and return the four
/// fds the worker bridges — `[stdin-write, stdout-read, stderr-read,
/// status-read]` — plus the child and the status-pipe write end. The caller
/// (the monitor loop) passes the fds, then spawns a reaper that `wait()`s the
/// child and writes the 4-byte exit code (LE) to the status pipe.
pub fn monitor_spawn_exec(
    cmd: &str,
    policy: &crate::sandbox::SandboxPolicy,
    username: &str,
) -> Result<(Vec<OwnedFd>, std::process::Child, OwnedFd)> {
    anyhow::ensure!(
        crate::unix_user::validate_username(username).is_ok(),
        "SpawnExec: invalid username {username:?}"
    );
    validate_spawn_user(username)?;
    // Mirror spawn_sandboxed_command's layer-1 validation before spawning.
    if policy.is_restricted() {
        crate::sandbox::validate_command(cmd, policy)
            .map_err(|e| anyhow::anyhow!("SpawnExec: command rejected by policy: {e}"))?;
    }

    let mut command = crate::sandbox::build_exec_command_std(cmd, policy, username);
    let mut child = command.spawn().context("monitor spawn exec command")?;

    let stdin = OwnedFd::from(child.stdin.take().context("exec child has no stdin")?);
    let stdout = OwnedFd::from(child.stdout.take().context("exec child has no stdout")?);
    let stderr = OwnedFd::from(child.stderr.take().context("exec child has no stderr")?);
    let (status_r, status_w) = nix::unistd::pipe().context("status pipe")?;

    tracing::info!(user = username, "privsep monitor: spawned exec, passing 4 fds to worker");
    Ok((vec![stdin, stdout, stderr, status_r], child, status_w))
}

/// Validate a `SpawnHelper`: `argv[0]` must be the running hop executable, the
/// next arg must be the `__transfer-helper` subcommand (so the worker can't make
/// the monitor run an arbitrary program as the user), and the username valid.
fn validate_spawn_helper(argv: &[String], username: &str) -> Result<()> {
    let exe = std::env::current_exe().context("resolving current exe")?;
    let bin = argv.first().context("SpawnHelper: empty argv")?;
    anyhow::ensure!(
        std::path::Path::new(bin) == exe,
        "SpawnHelper: argv[0] {bin:?} is not this hop executable"
    );
    anyhow::ensure!(
        argv.get(1).map(String::as_str) == Some("__transfer-helper"),
        "SpawnHelper: not a __transfer-helper invocation"
    );
    anyhow::ensure!(
        crate::unix_user::validate_username(username).is_ok(),
        "SpawnHelper: invalid username {username:?}"
    );
    validate_spawn_user(username)?;
    Ok(())
}

/// Monitor side of `SpawnHelper`: spawn the trusted transfer helper as the bound
/// user (login on macOS, uid/gid+initgroups on Linux), stdin/stdout piped and
/// stderr inherited, and return `[stdin-write, stdout-read, status-read]` plus
/// the child and status-pipe write end (the loop reaps + reports the exit code).
pub fn monitor_spawn_helper(
    argv: &[String],
    username: &str,
) -> Result<(Vec<OwnedFd>, std::process::Child, OwnedFd)> {
    use std::process::Stdio;
    validate_spawn_helper(argv, username)?;

    let mut command;
    #[cfg(target_os = "macos")]
    {
        // login -fpq <user> <exe> <helper args…> — a real user/audit session.
        command = std::process::Command::new("/usr/bin/login");
        command.arg("-fpq").arg(username).args(argv);
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        use std::os::unix::process::CommandExt;
        let (uid, gid) = crate::transfer::helper::lookup_uid_gid(username)?;
        command = std::process::Command::new(&argv[0]);
        command.args(&argv[1..]).uid(uid).gid(gid);
        let user_c = std::ffi::CString::new(username)
            .map_err(|e| anyhow::anyhow!("username NUL: {e}"))?;
        // SAFETY: initgroups is a single syscall, async-signal-safe.
        unsafe {
            command.pre_exec(move || {
                libc::initgroups(user_c.as_ptr(), gid as _);
                Ok(())
            });
        }
    }

    command
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let mut child = command.spawn().context("monitor spawn transfer helper")?;

    let stdin = OwnedFd::from(child.stdin.take().context("helper has no stdin")?);
    let stdout = OwnedFd::from(child.stdout.take().context("helper has no stdout")?);
    let (status_r, status_w) = nix::unistd::pipe().context("status pipe")?;

    tracing::info!(user = username, "privsep monitor: spawned transfer helper, passing 3 fds");
    Ok((vec![stdin, stdout, status_r], child, status_w))
}

// ── Worker side: acquire the TUN from the monitor ───────────────────────────

/// The control-socket fd the monitor passed us, if we are a privsep worker.
fn worker_control_fd() -> Option<RawFd> {
    std::env::var("HOP_PRIVSEP_CTRL_FD").ok()?.trim().parse().ok()
}

/// Serializes every worker→monitor control transaction. The control socket is a
/// single shared fd (`HOP_PRIVSEP_CTRL_FD`); without this lock a per-connection
/// `SpawnSession`/`SpawnExec`/`SpawnHelper` could interleave its framed message
/// and `SCM_RIGHTS` fd batch with the VPN loop's `CreateTun`/`BindPrivPort` on
/// that one socket — corrupting the wire protocol and misrouting passed fds.
/// Each request function holds this across its full send→reply→recv-fd(s)
/// transaction. The I/O is fast, local socketpair I/O and the critical section
/// contains no `.await`, so a blocking `std` mutex is appropriate even for the
/// async callers (`acquire_tun`/`acquire_priv_port`).
static CTRL_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// True when this process is the unprivileged worker half of a privsep node.
pub fn is_privsep_worker() -> bool {
    worker_control_fd().is_some()
}

/// Watch the monitor-liveness pipe (`HOP_PRIVSEP_ALIVE_FD`) and shut the worker
/// down if the monitor dies. Spawns a blocking thread that reads the pipe; the
/// monitor never writes, so the read blocks until EOF — which happens only when
/// the monitor closes its write end, i.e. the monitor process is gone. We then
/// `raise(SIGTERM)` to run the worker's graceful shutdown (releasing the
/// datastore lock + TUN), with a hard `_exit` backstop if that stalls. No-ops
/// when not a privsep worker. Call once at host startup.
pub fn spawn_monitor_liveness_watcher() {
    let Some(fd) = std::env::var("HOP_PRIVSEP_ALIVE_FD")
        .ok()
        .and_then(|s| s.trim().parse::<RawFd>().ok())
    else {
        return;
    };
    std::thread::spawn(move || {
        let mut buf = [0u8; 1];
        loop {
            let n = unsafe { libc::read(fd, buf.as_mut_ptr() as *mut libc::c_void, 1) };
            if n > 0 {
                continue; // monitor never writes; tolerate a stray byte
            }
            if n < 0 && std::io::Error::last_os_error().kind() == std::io::ErrorKind::Interrupted {
                continue; // EINTR — retry
            }
            // EOF (n == 0) or a hard error: the monitor is gone.
            tracing::error!(
                "privsep worker: monitor exited; shutting down to release the datastore lock + TUN"
            );
            // Process-directed (not `raise`, which is thread-directed) so the
            // kernel delivers it to whichever thread runs tokio's SIGTERM handler.
            let _ = nix::sys::signal::kill(
                nix::unistd::Pid::this(),
                nix::sys::signal::Signal::SIGTERM,
            );
            // Backstop: if graceful shutdown stalls, force-exit so the OS releases
            // the redb lock and the device — a wedged worker must not block the
            // monitor's restart. The orphaned worker can't serve privileged ops
            // anymore, so a prompt exit beats a clean QUIC drain here.
            std::thread::sleep(std::time::Duration::from_secs(3));
            std::process::exit(0);
        }
    });
}

/// Wrap a TUN fd passed by the monitor as an async device. `raw_fd` only wraps
/// (no `.address()`), so the worker never reconfigures the interface — the
/// monitor already did, with root. `close_fd_on_drop` (default true) means the
/// worker's copy closes on exit while the monitor's canonical fd keeps the
/// device alive.
pub fn worker_tun_from_fd(fd: OwnedFd) -> Result<tun::AsyncDevice> {
    use std::os::fd::IntoRawFd;
    let raw = fd.into_raw_fd();
    let mut config = tun::configure();
    config.raw_fd(raw);
    tun::create_as_async(&config).map_err(|e| anyhow::anyhow!("wrapping passed TUN fd: {e}"))
}

/// Acquire the VPN TUN for `addr`: in privsep-worker mode, ask the monitor to
/// create it and receive the fd; otherwise create it directly (current,
/// non-privsep behavior). This is the single integration point in `enable_vpn`.
pub async fn acquire_tun(addr: std::net::Ipv4Addr) -> Result<tun::AsyncDevice> {
    match worker_control_fd() {
        Some(ctrl) => {
            let _guard = CTRL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            send_msg(ctrl, &MonitorRequest::CreateTun { vip: addr.octets() })
                .context("requesting TUN from privsep monitor")?;
            match recv_msg::<MonitorReply>(ctrl)? {
                MonitorReply::OkFd => worker_tun_from_fd(recv_fd(ctrl)?),
                MonitorReply::Ok => anyhow::bail!("monitor returned Ok without a TUN fd"),
                MonitorReply::Error { message } => {
                    anyhow::bail!("privsep monitor refused CreateTun: {message}")
                }
            }
        }
        None => crate::vpn::create_tun(addr).await,
    }
}

/// Acquire a privileged UDP socket bound to `addr:port` (MagicDNS `:53`): in
/// privsep-worker mode the worker is unprivileged and cannot bind a port < 1024,
/// so it asks the monitor (root) to bind and passes back the socket fd via
/// `SCM_RIGHTS`; otherwise it binds directly (non-privsep behavior). This is the
/// integration point for `vpn_dns_loop` — mirrors [`acquire_tun`].
pub async fn acquire_priv_port(
    addr: std::net::Ipv4Addr,
    port: u16,
) -> Result<tokio::net::UdpSocket> {
    match worker_control_fd() {
        Some(ctrl) => {
            let std_sock = {
                let _guard = CTRL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
                send_msg(
                    ctrl,
                    &MonitorRequest::BindPrivPort {
                        addr: addr.octets(),
                        port,
                    },
                )
                .context("requesting privileged port from privsep monitor")?;
                match recv_msg::<MonitorReply>(ctrl)? {
                    MonitorReply::OkFd => std::net::UdpSocket::from(recv_fd(ctrl)?),
                    MonitorReply::Ok => anyhow::bail!("monitor returned Ok without a socket fd"),
                    MonitorReply::Error { message } => {
                        anyhow::bail!("privsep monitor refused BindPrivPort: {message}")
                    }
                }
            };
            std_sock
                .set_nonblocking(true)
                .context("setting passed UDP socket non-blocking")?;
            tokio::net::UdpSocket::from_std(std_sock)
                .context("wrapping passed UDP socket for tokio")
        }
        None => tokio::net::UdpSocket::bind((addr, port))
            .await
            .with_context(|| format!("binding {addr}:{port}")),
    }
}

/// Point the OS resolver for `domain` at the local MagicDNS server on `vip:53`
/// (split-DNS). Writing resolver config is privileged, so in privsep-worker mode
/// the worker delegates to the monitor (`ConfigureResolver`); otherwise it
/// applies the config directly (non-privsep, worker is root). Best-effort: a
/// failure here only costs `.hop` name resolution, never connectivity.
pub fn configure_resolver(domain: &str, vip: std::net::Ipv4Addr) -> Result<()> {
    match worker_control_fd() {
        Some(ctrl) => {
            let _guard = CTRL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            send_msg(
                ctrl,
                &MonitorRequest::ConfigureResolver {
                    domain: domain.to_string(),
                    vip: vip.octets(),
                },
            )
            .context("requesting resolver config from privsep monitor")?;
            match recv_msg::<MonitorReply>(ctrl)? {
                MonitorReply::Ok => Ok(()),
                MonitorReply::OkFd => anyhow::bail!("monitor returned an fd for ConfigureResolver"),
                MonitorReply::Error { message } => {
                    anyhow::bail!("privsep monitor refused ConfigureResolver: {message}")
                }
            }
        }
        None => crate::vpn::resolver::apply(domain, vip),
    }
}

/// Set up Tier 1 LAN-bridging gateway forwarding for `routes`, delegating to the
/// monitor when this is the dropped worker (`nft`/`ip_forward` are privileged).
/// Mirrors [`configure_resolver`]; a non-privsep host applies it directly.
pub fn setup_gateway(routes: &[crate::vpn::gateway::GatewayRoute]) -> Result<()> {
    match worker_control_fd() {
        Some(ctrl) => {
            let _guard = CTRL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            let wire: Vec<(String, bool)> =
                routes.iter().map(|r| (r.cidr.clone(), r.snat)).collect();
            send_msg(ctrl, &MonitorRequest::SetupGateway { routes: wire })
                .context("requesting gateway setup from privsep monitor")?;
            match recv_msg::<MonitorReply>(ctrl)? {
                MonitorReply::Ok => Ok(()),
                MonitorReply::OkFd => anyhow::bail!("monitor returned an fd for SetupGateway"),
                MonitorReply::Error { message } => {
                    anyhow::bail!("privsep monitor refused SetupGateway: {message}")
                }
            }
        }
        None => crate::vpn::gateway::setup_gateway("", routes),
    }
}

/// Add a route `cidr → dev` (the warren TUN), delegating the privileged
/// `ip route add` to the monitor under privsep. No collision check — callers that
/// need it (subnet routes) run `route_collides` first; exit-node split-default
/// routes deliberately skip it (they capture everything, with more-specific routes
/// for the vIP/LAN/relay as the exceptions).
pub fn add_tun_route(cidr: &str, dev: &str) -> Result<()> {
    match worker_control_fd() {
        Some(ctrl) => {
            let _guard = CTRL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            send_msg(
                ctrl,
                &MonitorRequest::ModifyClientRoute {
                    cidr: cidr.to_string(),
                    dev: dev.to_string(),
                    add: true,
                },
            )
            .context("requesting client route from privsep monitor")?;
            match recv_msg::<MonitorReply>(ctrl)? {
                MonitorReply::Ok => Ok(()),
                MonitorReply::OkFd => anyhow::bail!("monitor returned an fd for ModifyClientRoute"),
                MonitorReply::Error { message } => {
                    anyhow::bail!("privsep monitor refused ModifyClientRoute: {message}")
                }
            }
        }
        None => crate::vpn::gateway::add_route_raw(cidr, dev),
    }
}

/// Configure IPv6 on the warren TUN for 4via6 client routing (Tier 3a),
/// delegating the privileged address/route setup to the monitor under privsep.
/// `addr` is the client's own via6 source address; `dev` is the warren TUN.
pub fn configure_tun_v6(addr: std::net::Ipv6Addr, dev: &str) -> Result<()> {
    match worker_control_fd() {
        Some(ctrl) => {
            let _guard = CTRL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            send_msg(ctrl, &MonitorRequest::ConfigureTunV6 { addr: addr.octets() })
                .context("requesting via6 TUN config from privsep monitor")?;
            match recv_msg::<MonitorReply>(ctrl)? {
                MonitorReply::Ok => Ok(()),
                MonitorReply::OkFd => anyhow::bail!("monitor returned an fd for ConfigureTunV6"),
                MonitorReply::Error { message } => {
                    anyhow::bail!("privsep monitor refused ConfigureTunV6: {message}")
                }
            }
        }
        None => crate::vpn::gateway::configure_tun_v6(addr, dev),
    }
}

/// Install a subnet route `cidr → dev` with the collision guard (returns
/// `Ok(false)` without touching the kernel if `cidr` would hijack the local LAN).
pub fn install_client_route(cidr: &str, dev: &str) -> Result<bool> {
    if crate::vpn::gateway::route_collides(cidr) {
        tracing::warn!(
            "vpn route: NOT installing {cidr} — it covers a local address (would hijack the \
             local LAN). Use a narrower /32 device route to reach a specific host."
        );
        return Ok(false);
    }
    add_tun_route(cidr, dev).map(|()| true)
}

/// Install exit-node routing: a **split default** (`0.0.0.0/1` + `128.0.0.0/1`,
/// which together cover everything but are more specific than the real default, so
/// they override it without replacing it) onto the warren TUN. The node's own vIP
/// (`100.64/10`) and local LAN keep their more-specific routes, so warren + LAN
/// traffic doesn't loop through the exit.
///
/// LIMITATION (follow-up): the warren relay's public IP is not yet pinned via the
/// original gateway, so a node that reaches the exit **only over the relay** (no
/// direct path) would loop. Reaching the exit over a direct path (same LAN, or any
/// route more specific than `/1`) is fine. Relay-pinning needs a route-via-gateway
/// monitor primitive.
pub fn install_exit_route(dev: &str) -> Result<()> {
    // Pin the warren relay(s) via the ORIGINAL gateway first, so the connection
    // that reaches the exit survives the split-default (else it loops/dies — the
    // exact failure the exit-node e2e caught).
    match crate::vpn::gateway::default_gateway_v4() {
        Some(gw) => {
            let relays = crate::vpn::gateway::resolve_relay_ips();
            if relays.is_empty() {
                tracing::warn!(
                    "vpn exit: could not resolve the warren relay to pin — a relay-only path \
                     to the exit will loop"
                );
            }
            for relay in relays {
                if let Err(e) = pin_host_route(relay, gw, true) {
                    tracing::warn!("vpn exit: pinning relay {relay} via {gw} failed: {e:#}");
                }
            }
        }
        None => tracing::warn!("vpn exit: no default gateway found to pin the relay — exit may loop"),
    }
    add_tun_route("0.0.0.0/1", dev)?;
    add_tun_route("128.0.0.0/1", dev)?;
    tracing::info!(
        "vpn exit: routing default traffic via the warren exit node (split-default + relay pin)"
    );
    Ok(())
}

/// Tear down exit-node routing (best-effort): remove the split-default + relay pins.
pub fn uninstall_exit_route(dev: &str) {
    uninstall_client_route("0.0.0.0/1", dev);
    uninstall_client_route("128.0.0.0/1", dev);
    if let Some(gw) = crate::vpn::gateway::default_gateway_v4() {
        for relay in crate::vpn::gateway::resolve_relay_ips() {
            let _ = pin_host_route(relay, gw, false);
        }
    }
}

/// Pin (or unpin) a `/32` host route `dst → via <gateway>`, delegating to the
/// monitor under privsep.
fn pin_host_route(dst: std::net::Ipv4Addr, via: std::net::Ipv4Addr, add: bool) -> Result<()> {
    match worker_control_fd() {
        Some(ctrl) => {
            let _guard = CTRL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            send_msg(
                ctrl,
                &MonitorRequest::PinHostRoute { dst: dst.octets(), via: via.octets(), add },
            )
            .context("requesting relay pin from privsep monitor")?;
            match recv_msg::<MonitorReply>(ctrl)? {
                MonitorReply::Ok => Ok(()),
                MonitorReply::OkFd => anyhow::bail!("monitor returned an fd for PinHostRoute"),
                MonitorReply::Error { message } => {
                    anyhow::bail!("privsep monitor refused PinHostRoute: {message}")
                }
            }
        }
        None => {
            let cidr = format!("{dst}/32");
            #[cfg(target_os = "linux")]
            {
                let _ = std::process::Command::new("ip").args(["route", "del", &cidr]).status();
                if add {
                    let st = std::process::Command::new("ip")
                        .args(["route", "add", &cidr, "via", &via.to_string()])
                        .status()
                        .context("ip route add (pin)")?;
                    if !st.success() {
                        anyhow::bail!("pinning {cidr} via {via} failed");
                    }
                }
                Ok(())
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = (via, add, cidr);
                Ok(())
            }
        }
    }
}

/// Remove a client route `cidr → dev` (best-effort), delegating under privsep.
pub fn uninstall_client_route(cidr: &str, dev: &str) {
    match worker_control_fd() {
        Some(ctrl) => {
            let _guard = CTRL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            if send_msg(
                ctrl,
                &MonitorRequest::ModifyClientRoute {
                    cidr: cidr.to_string(),
                    dev: dev.to_string(),
                    add: false,
                },
            )
            .is_ok()
            {
                let _ = recv_msg::<MonitorReply>(ctrl);
            }
        }
        None => crate::vpn::gateway::remove_route_raw(cidr, dev),
    }
}

/// Worker side of `SpawnSession`: ask the monitor to spawn `argv` (the
/// worker-resolved `login`/`su`/shell command) on a PTY and return the master
/// fd. Only meaningful in privsep-worker mode; callers gate on
/// [`is_privsep_worker`]. The returned fd is the PTY master the worker bridges
/// to the client stream.
pub fn worker_spawn_session(
    argv: &[String],
    env: &[(String, String)],
    rows: u16,
    cols: u16,
    pixel_width: u16,
    pixel_height: u16,
    username: Option<&str>,
) -> Result<OwnedFd> {
    let ctrl = worker_control_fd().context("worker_spawn_session called outside privsep worker")?;
    let req = MonitorRequest::SpawnSession {
        argv: argv.to_vec(),
        env: env.to_vec(),
        rows,
        cols,
        pixel_width,
        pixel_height,
        username: username.map(String::from),
    };
    let _guard = CTRL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    send_msg(ctrl, &req).context("requesting SpawnSession from monitor")?;
    match recv_msg::<MonitorReply>(ctrl)? {
        MonitorReply::OkFd => recv_fd(ctrl),
        MonitorReply::Ok => anyhow::bail!("monitor returned Ok without a PTY fd"),
        MonitorReply::Error { message } => {
            anyhow::bail!("privsep monitor refused SpawnSession: {message}")
        }
    }
}

/// Worker side of `SpawnExec`: ask the monitor to run `cmd` as `username` under
/// `policy` and return the four fds `[stdin-write, stdout-read, stderr-read,
/// status-read]`. The status fd yields the 4-byte LE exit code when the child
/// exits. Only meaningful in privsep-worker mode.
pub fn worker_spawn_exec(
    cmd: &str,
    policy: &crate::sandbox::SandboxPolicy,
    username: &str,
) -> Result<Vec<OwnedFd>> {
    let ctrl = worker_control_fd().context("worker_spawn_exec called outside privsep worker")?;
    let req = MonitorRequest::SpawnExec {
        cmd: cmd.to_string(),
        policy: policy.clone(),
        username: username.to_string(),
    };
    let _guard = CTRL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    send_msg(ctrl, &req).context("requesting SpawnExec from monitor")?;
    match recv_msg::<MonitorReply>(ctrl)? {
        MonitorReply::OkFd => recv_fds(ctrl, 4),
        MonitorReply::Ok => anyhow::bail!("monitor returned Ok without exec fds"),
        MonitorReply::Error { message } => {
            anyhow::bail!("privsep monitor refused SpawnExec: {message}")
        }
    }
}

/// Worker side of `SpawnHelper`: ask the monitor to run the transfer helper
/// `argv` as `username` and return `[stdin-write, stdout-read, status-read]`.
pub fn worker_spawn_helper(argv: &[String], username: &str) -> Result<Vec<OwnedFd>> {
    let ctrl = worker_control_fd().context("worker_spawn_helper called outside privsep worker")?;
    let req = MonitorRequest::SpawnHelper {
        argv: argv.to_vec(),
        username: username.to_string(),
    };
    let _guard = CTRL_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    send_msg(ctrl, &req).context("requesting SpawnHelper from monitor")?;
    match recv_msg::<MonitorReply>(ctrl)? {
        MonitorReply::OkFd => recv_fds(ctrl, 3),
        MonitorReply::Ok => anyhow::bail!("monitor returned Ok without helper fds"),
        MonitorReply::Error { message } => {
            anyhow::bail!("privsep monitor refused SpawnHelper: {message}")
        }
    }
}

// ── Phase 2: service user (`_hop`) & privilege drop ─────────────────────────

/// The unprivileged service account the worker runs as: `_hop` on macOS
/// (Apple's `_`-prefixed daemon-user convention), `hop` on Linux.
pub const SERVICE_USER: &str = if cfg!(target_os = "macos") {
    "_hop"
} else {
    "hop"
};

/// Resolve the service user's `(uid, gid)`, if the account exists. Returns
/// `None` when it hasn't been created (install-time step) — the caller then
/// keeps the worker as root (Phase-1 behavior) rather than failing.
pub fn service_user_ids() -> Option<(u32, u32)> {
    match nix::unistd::User::from_name(SERVICE_USER) {
        Ok(Some(u)) => Some((u.uid.as_raw(), u.gid.as_raw())),
        _ => None,
    }
}

/// Re-own the daemon config dir to the service user (privsep §6) so the
/// unprivileged worker reads its own identity/tickets/datastore, AND so the
/// daemon socket the worker binds inside the dir is reachable by the operator
/// group. Runs as root in the monitor before the worker is spawned; idempotent.
///
/// The group is set to the **operator group** (`admin` on macOS, `hop` on Linux)
/// — on Linux that equals the worker's own group (no change vs `_hop:_hop`); on
/// macOS it lets admin operators reach `daemon.sock`. The top dir is made
/// `setgid` so the worker-bound socket inherits that group. File *modes* are
/// unchanged: secrets stay as the installer set them (still no world access), and
/// operators don't read them directly — they go through the socket.
fn migrate_config_ownership(dir: &std::path::Path, uid: u32, service_gid: u32) -> Result<()> {
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    // Operator group, falling back to the service group if it doesn't exist.
    let gid = crate::datastore::socket::operator_group_gid().unwrap_or(service_gid);
    let want_uid = nix::unistd::Uid::from_raw(uid);
    let want_gid = nix::unistd::Gid::from_raw(gid);
    let mut stack = vec![dir.to_path_buf()];
    let mut changed = 0usize;
    while let Some(path) = stack.pop() {
        // Use symlink_metadata so we chown the link itself, never follow it out
        // of the config tree.
        let md = match std::fs::symlink_metadata(&path) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("privsep: stat {} failed: {e}", path.display());
                continue;
            }
        };
        if md.uid() != uid || md.gid() != gid {
            if let Err(e) = nix::unistd::fchownat(
                None,
                &path,
                Some(want_uid),
                Some(want_gid),
                nix::fcntl::AtFlags::AT_SYMLINK_NOFOLLOW,
            ) {
                tracing::warn!("privsep: chown {} failed: {e}", path.display());
            } else {
                changed += 1;
            }
        }
        if md.file_type().is_dir() {
            match std::fs::read_dir(&path) {
                Ok(entries) => {
                    for ent in entries.flatten() {
                        stack.push(ent.path());
                    }
                }
                Err(e) => tracing::warn!("privsep: readdir {} failed: {e}", path.display()),
            }
        }
    }
    // setgid the top dir so the daemon socket (and other files the worker creates)
    // inherit the operator group, making the socket reachable without root.
    if let Ok(md) = std::fs::symlink_metadata(dir) {
        let mode = md.permissions().mode();
        if mode & 0o2000 == 0 {
            let _ = std::fs::set_permissions(dir, std::fs::Permissions::from_mode(mode | 0o2000));
        }
    }
    tracing::info!(
        "privsep: config ownership migrated to {SERVICE_USER} ({changed} path(s) re-owned)"
    );
    Ok(())
}

/// Install the privilege drop on the worker command: as root in the forked
/// child (before `exec`), set supplementary groups for the service user, then
/// `setgid`, then `setuid` — the canonical order (groups before uid, since
/// dropping uid first would forbid the later setgid). Errors abort the child so
/// a half-dropped worker never execs.
fn apply_privilege_drop(cmd: &mut std::process::Command, username: &str, uid: u32, gid: u32) {
    use std::os::unix::process::CommandExt;
    let user_c = match std::ffi::CString::new(username) {
        Ok(c) => c,
        Err(_) => return,
    };
    // initgroups' `basegroup` is `c_int` on Apple but `gid_t` on Linux.
    #[cfg(target_os = "macos")]
    let basegroup = gid as libc::c_int;
    #[cfg(not(target_os = "macos"))]
    let basegroup = gid as libc::gid_t;
    unsafe {
        cmd.pre_exec(move || {
            // initgroups(_hop, gid): supplementary groups for the service user.
            if libc::initgroups(user_c.as_ptr(), basegroup) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setgid(gid as libc::gid_t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setuid(uid as libc::uid_t) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}

// ── Monitor side: supervise the worker, serve privileged primitives ─────────

/// Run the privilege-separation **monitor** (privsep-node.md §3). Spawns the
/// unprivileged worker (`hop host …` with the control fd + `HOP_PRIVSEP_WORKER`
/// set) and serves its `CreateTun`/`BindPrivPort` requests, keeping the created
/// devices/sockets alive for the worker's lifetime. Never returns: when the
/// worker exits, the monitor exits too and launchd/systemd `KeepAlive` restarts
/// the pair. (Phase 1: the worker still runs as root; the `_hop` privilege drop
/// is Phase 2. Behind the `HOP_PRIVSEP` flag — off by default.)
pub fn run_monitor(config_dir: &std::path::Path, quiet: bool) -> Result<()> {
    anyhow::ensure!(
        crate::unix_user::is_running_as_root(),
        "the privsep monitor must run as root"
    );
    // The operator's spawn allowlist (Phase-4 ACL) lives in the daemon config
    // dir. The monitor reads it (root-owned only) on each spawn request.
    let _ = ALLOWLIST_PATH.set(config_dir.join("privsep-users"));

    // Crash-loop fallback (anti-lockout). privsep ships on-by-default on macOS;
    // if a platform-specific issue keeps the worker from staying up, we must NOT
    // leave the host unreachable. The monitor re-spawns the worker, and if it
    // keeps exiting almost immediately, gives up on privsep and re-execs the
    // daemon **directly as root** (non-privsep) so the node stays online.
    const HEALTHY_UPTIME: std::time::Duration = std::time::Duration::from_secs(30);
    const MAX_FAST_FAILURES: u32 = 3;
    let mut fast_failures: u32 = 0;

    // The monitor is root, so it owns route enforcement: keep the warren /10 route
    // pinned to the hop utun across worker restarts, sleep/wake, and network
    // changes (macOS flushes it; Linux's kernel keeps it). No-op on Linux.
    crate::vpn::spawn_route_enforcer();

    loop {
    let spawn_instant = std::time::Instant::now();
    let (mon, wrk) = control_socketpair()?;
    clear_cloexec(wrk.as_raw_fd())?;

    let exe = std::env::current_exe().context("resolving current exe")?;
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("host").arg("--config").arg(config_dir);
    if quiet {
        cmd.arg("--quiet");
    }
    cmd.env("HOP_PRIVSEP_WORKER", "1")
        .env("HOP_PRIVSEP_CTRL_FD", wrk.as_raw_fd().to_string());

    // Liveness pipe (anti-lockout, the OpenSSH invariant: the worker must never
    // outlive its monitor). The worker inherits the READ end and blocks on it in
    // a watcher thread; the monitor holds the WRITE end. If the monitor dies for
    // any reason — even SIGKILL — the kernel closes the write end, the worker
    // reads EOF, and it shuts itself down, releasing the datastore lock + TUN so
    // a restart (or the crash-loop fallback) can reacquire them. Without this a
    // monitor death wedges the node: a stranded worker keeps the redb lock and
    // every restart attempt crash-loops.
    // The WRITE end must stay confined to the monitor — it must NOT leak into
    // the worker (its own write end would stop its read from ever hitting EOF)
    // nor into any session/exec child the monitor later forks (a long-lived shell
    // would pin it open past the monitor's death, wedging the liveness signal).
    // nix's `pipe()` returns both ends WITHOUT close-on-exec, so set it on the
    // write end and clear it on the read end (which the worker inherits via exec).
    let (alive_r, alive_w) = nix::unistd::pipe().context("creating liveness pipe")?;
    set_cloexec(alive_w.as_raw_fd())?; // write end stays in the monitor only
    clear_cloexec(alive_r.as_raw_fd())?; // worker inherits the read end across exec
    cmd.env("HOP_PRIVSEP_ALIVE_FD", alive_r.as_raw_fd().to_string());

    // Phase 2: drop the worker to the `_hop` service user. Gated on
    // HOP_PRIVSEP_DROP (separate from HOP_PRIVSEP) because a dropped worker
    // cannot host other-user sessions until Phase 3's SpawnSession lands — so
    // until then the default (HOP_PRIVSEP alone) keeps the worker as root and
    // only moves *who creates the TUN*. When enabled and the service user
    // exists, re-own the config so the worker reads its own secrets, then drop.
    if std::env::var_os("HOP_PRIVSEP_DROP").is_some() {
        match service_user_ids() {
            Some((uid, gid)) => {
                migrate_config_ownership(config_dir, uid, gid)?;
                apply_privilege_drop(&mut cmd, SERVICE_USER, uid, gid);
                tracing::info!(
                    "privsep monitor: worker will drop to {SERVICE_USER} (uid={uid}, gid={gid})"
                );
            }
            None => {
                tracing::warn!(
                    "privsep monitor: HOP_PRIVSEP_DROP set but service user {SERVICE_USER} does not \
                     exist; worker stays root (create it at install time)"
                );
            }
        }
    }

    let mut child = cmd.spawn().context("spawning privsep worker")?;
    drop(wrk); // only the worker needs that end
    drop(alive_r); // worker inherited the read end; monitor keeps `alive_w` open
    // `alive_w` stays in scope for this iteration: it closes when the monitor
    // process dies (kernel-closed) or at end of loop body, signaling the worker.
    tracing::info!(
        worker_pid = child.id(),
        "privsep monitor: spawned unprivileged worker; serving privileged primitives"
    );

    let mon_fd = mon.as_raw_fd();
    // Hold every created device/socket so the kernel keeps the interface up and
    // the :53 bind alive for as long as the monitor (and thus the worker) runs.
    let mut kept_tuns: Vec<tun::Device> = Vec::new();
    let mut kept_socks: Vec<OwnedFd> = Vec::new();
    // Resolver domains we pointed at MagicDNS for this worker; reverted below when
    // the worker exits so a stale split-DNS entry never outlives the daemon.
    let mut kept_resolvers: Vec<String> = Vec::new();
    // Whether we've applied LAN-bridging gateway forwarding (nft + ip_forward),
    // so it's torn down when the worker exits rather than leaking nftables rules.
    let mut gateway_active = false;
    // Exit-node relay pins (`<ip>/32` host routes) to remove on worker exit.
    let mut kept_pins: Vec<String> = Vec::new();

    loop {
        let req: MonitorRequest = match recv_msg(mon_fd) {
            Ok(r) => r,
            // The worker closed the channel (exited) — leave the loop to reap it.
            Err(_) => break,
        };
        match req {
            MonitorRequest::CreateTun { vip } => match monitor_create_tun(vip) {
                Ok(dev) => {
                    if send_msg(mon_fd, &MonitorReply::OkFd).is_ok()
                        && send_fd(mon_fd, dev.as_raw_fd()).is_ok()
                    {
                        tracing::info!(
                            vip = ?std::net::Ipv4Addr::from(vip),
                            "privsep monitor: served CreateTun, passed TUN fd to worker"
                        );
                        kept_tuns.push(dev);
                    }
                }
                Err(e) => {
                    tracing::warn!("privsep monitor: CreateTun denied: {e:#}");
                    let _ = send_msg(mon_fd, &MonitorReply::Error { message: format!("{e:#}") });
                }
            },
            MonitorRequest::BindPrivPort { addr, port } => match monitor_bind_priv_port(addr, port) {
                Ok(sock) => {
                    if send_msg(mon_fd, &MonitorReply::OkFd).is_ok()
                        && send_fd(mon_fd, sock.as_raw_fd()).is_ok()
                    {
                        kept_socks.push(sock);
                    }
                }
                Err(e) => {
                    let _ = send_msg(mon_fd, &MonitorReply::Error { message: format!("{e:#}") });
                }
            },
            MonitorRequest::ConfigureResolver { domain, vip } => {
                let addr = std::net::Ipv4Addr::from(vip);
                match crate::vpn::resolver::apply(&domain, addr) {
                    Ok(()) => {
                        if !kept_resolvers.contains(&domain) {
                            kept_resolvers.push(domain);
                        }
                        let _ = send_msg(mon_fd, &MonitorReply::Ok);
                    }
                    Err(e) => {
                        tracing::warn!("privsep monitor: ConfigureResolver denied: {e:#}");
                        let _ = send_msg(mon_fd, &MonitorReply::Error { message: format!("{e:#}") });
                    }
                }
            }
            MonitorRequest::SetupGateway { routes } => {
                let gw: Vec<crate::vpn::gateway::GatewayRoute> = routes
                    .into_iter()
                    .map(|(cidr, snat)| crate::vpn::gateway::GatewayRoute { cidr, snat })
                    .collect();
                match crate::vpn::gateway::setup_gateway("monitor", &gw) {
                    Ok(()) => {
                        gateway_active = true;
                        let _ = send_msg(mon_fd, &MonitorReply::Ok);
                    }
                    Err(e) => {
                        tracing::warn!("privsep monitor: SetupGateway denied: {e:#}");
                        let _ = send_msg(mon_fd, &MonitorReply::Error { message: format!("{e:#}") });
                    }
                }
            }
            MonitorRequest::ModifyClientRoute { cidr, dev: _, add } => {
                use tun::AbstractDevice;
                // Route onto the warren TUN the monitor itself created — the worker
                // can't reliably read the device name from a passed fd, so we don't
                // trust its `dev`; we use ours (inherently the warren overlay, so
                // this can never point a route at an arbitrary interface).
                match kept_tuns.last().and_then(|t| t.tun_name().ok()) {
                    None => {
                        let _ = send_msg(
                            mon_fd,
                            &MonitorReply::Error { message: "no warren TUN to route onto".into() },
                        );
                    }
                    Some(tun) if add => match crate::vpn::gateway::add_route_raw(&cidr, &tun) {
                        Ok(()) => {
                            let _ = send_msg(mon_fd, &MonitorReply::Ok);
                        }
                        Err(e) => {
                            tracing::warn!("privsep monitor: ModifyClientRoute add failed: {e:#}");
                            let _ = send_msg(mon_fd, &MonitorReply::Error { message: format!("{e:#}") });
                        }
                    },
                    Some(tun) => {
                        crate::vpn::gateway::remove_route_raw(&cidr, &tun);
                        let _ = send_msg(mon_fd, &MonitorReply::Ok);
                    }
                }
            }
            MonitorRequest::ConfigureTunV6 { addr } => {
                use tun::AbstractDevice;
                let v6 = std::net::Ipv6Addr::from(addr);
                // Defensive: only ever assign a v6 address in our own client prefix.
                if !crate::vpn::is_client_v6(v6) {
                    let _ = send_msg(
                        mon_fd,
                        &MonitorReply::Error { message: format!("refusing ConfigureTunV6 for {v6}: not in the via6 client prefix") },
                    );
                } else {
                    match kept_tuns.last().and_then(|t| t.tun_name().ok()) {
                        None => {
                            let _ = send_msg(
                                mon_fd,
                                &MonitorReply::Error { message: "no warren TUN to configure v6 on".into() },
                            );
                        }
                        Some(tun) => match crate::vpn::gateway::configure_tun_v6(v6, &tun) {
                            Ok(()) => {
                                let _ = send_msg(mon_fd, &MonitorReply::Ok);
                            }
                            Err(e) => {
                                tracing::warn!("privsep monitor: ConfigureTunV6 failed: {e:#}");
                                let _ = send_msg(mon_fd, &MonitorReply::Error { message: format!("{e:#}") });
                            }
                        },
                    }
                }
            }
            MonitorRequest::PinHostRoute { dst, via, add } => {
                let cidr = format!("{}/32", std::net::Ipv4Addr::from(dst));
                let via = std::net::Ipv4Addr::from(via).to_string();
                let _ = std::process::Command::new("ip").args(["route", "del", &cidr]).status();
                if add {
                    match std::process::Command::new("ip")
                        .args(["route", "add", &cidr, "via", &via])
                        .status()
                    {
                        Ok(s) if s.success() => {
                            if !kept_pins.contains(&cidr) {
                                kept_pins.push(cidr);
                            }
                            let _ = send_msg(mon_fd, &MonitorReply::Ok);
                        }
                        _ => {
                            tracing::warn!("privsep monitor: PinHostRoute add failed for {cidr} via {via}");
                            let _ = send_msg(
                                mon_fd,
                                &MonitorReply::Error { message: "ip route add (pin) failed".into() },
                            );
                        }
                    }
                } else {
                    kept_pins.retain(|c| c != &cidr);
                    let _ = send_msg(mon_fd, &MonitorReply::Ok);
                }
            }
            MonitorRequest::SpawnSession {
                argv,
                env,
                rows,
                cols,
                pixel_width,
                pixel_height,
                username,
            } => match monitor_spawn_session(
                &argv,
                &env,
                rows,
                cols,
                pixel_width,
                pixel_height,
                username.as_deref(),
            ) {
                Ok((master, child)) => {
                    if send_msg(mon_fd, &MonitorReply::OkFd).is_ok()
                        && send_fd(mon_fd, master.as_raw_fd()).is_ok()
                    {
                        // The worker now owns its own dup of the master; the
                        // monitor reaps the child off-thread so zombies don't
                        // accumulate and the request loop never blocks on wait().
                        std::thread::spawn(move || {
                            let mut child = child;
                            let _ = child.wait();
                        });
                    }
                    // `master` (the monitor's dup) drops here, closing its copy;
                    // the fd we passed to the worker keeps the PTY master open.
                }
                Err(e) => {
                    tracing::warn!("privsep monitor: SpawnSession denied: {e:#}");
                    let _ = send_msg(mon_fd, &MonitorReply::Error { message: format!("{e:#}") });
                }
            },
            MonitorRequest::SpawnExec {
                cmd,
                policy,
                username,
            } => match monitor_spawn_exec(&cmd, &policy, &username) {
                Ok((fds, child, status_w)) => {
                    let raws: Vec<RawFd> = fds.iter().map(|f| f.as_raw_fd()).collect();
                    if send_msg(mon_fd, &MonitorReply::OkFd).is_ok()
                        && send_fds(mon_fd, &raws).is_ok()
                    {
                        // Reap the child off-thread and report the exit code on
                        // the status pipe; the worker (holding dups of the I/O
                        // fds) reads it after stdout/stderr EOF.
                        std::thread::spawn(move || {
                            use std::io::Write;
                            let mut child = child;
                            let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
                            let mut sw = std::fs::File::from(status_w);
                            let _ = sw.write_all(&code.to_le_bytes());
                            // sw drops → close → worker sees 4 bytes then EOF.
                        });
                    }
                    // The monitor's fd copies drop here; the worker has dups.
                }
                Err(e) => {
                    tracing::warn!("privsep monitor: SpawnExec denied: {e:#}");
                    let _ = send_msg(mon_fd, &MonitorReply::Error { message: format!("{e:#}") });
                }
            },
            MonitorRequest::SpawnHelper { argv, username } => {
                match monitor_spawn_helper(&argv, &username) {
                    Ok((fds, child, status_w)) => {
                        let raws: Vec<RawFd> = fds.iter().map(|f| f.as_raw_fd()).collect();
                        if send_msg(mon_fd, &MonitorReply::OkFd).is_ok()
                            && send_fds(mon_fd, &raws).is_ok()
                        {
                            std::thread::spawn(move || {
                                use std::io::Write;
                                let mut child = child;
                                let code = child.wait().ok().and_then(|s| s.code()).unwrap_or(-1);
                                let mut sw = std::fs::File::from(status_w);
                                let _ = sw.write_all(&code.to_le_bytes());
                            });
                        }
                    }
                    Err(e) => {
                        tracing::warn!("privsep monitor: SpawnHelper denied: {e:#}");
                        let _ = send_msg(mon_fd, &MonitorReply::Error { message: format!("{e:#}") });
                    }
                }
            }
        }
    }

    let status = child.wait().context("waiting on privsep worker")?;
    let uptime = spawn_instant.elapsed();
    // Drop this iteration's kept devices/sockets before respawning (a fresh
    // worker creates fresh ones); they're scoped to the loop body.
    drop(kept_tuns);
    drop(kept_socks);
    drop(mon);
    drop(alive_w); // release the liveness write end for this iteration
    // Revert split-DNS so a stale resolver entry doesn't point at a now-down
    // MagicDNS server. A respawning worker re-applies it on bring-up.
    for domain in kept_resolvers.drain(..) {
        if let Err(e) = crate::vpn::resolver::remove(&domain) {
            tracing::warn!("privsep: reverting resolver for {domain} failed: {e:#}");
        }
    }
    // Tear down LAN-bridging gateway forwarding so nftables rules don't outlive
    // the worker (a respawning worker re-applies on bring-up).
    if gateway_active {
        crate::vpn::gateway::teardown_gateway();
    }
    for pin in kept_pins.drain(..) {
        let _ = std::process::Command::new("ip").args(["route", "del", &pin]).status();
    }

    if uptime < HEALTHY_UPTIME {
        fast_failures += 1;
        tracing::warn!(
            "privsep worker exited ({status:?}) after {uptime:?} — fast failure \
             {fast_failures}/{MAX_FAST_FAILURES}"
        );
        if fast_failures >= MAX_FAST_FAILURES {
            tracing::error!(
                "privsep worker crash-looped {MAX_FAST_FAILURES}x; falling back to a \
                 non-privsep root daemon so the node stays reachable"
            );
            return run_non_privsep_fallback(config_dir, quiet);
        }
        std::thread::sleep(std::time::Duration::from_millis(500)); // backoff
    } else {
        tracing::info!("privsep worker exited ({status:?}) after {uptime:?}; respawning");
        fast_failures = 0;
    }
    } // end retry loop
}

/// Last-resort fallback: re-exec the daemon **without** privilege separation, as
/// the current (root) process, so a host whose privsep worker can't stay up
/// stays online instead of locking out. Clears the `HOP_PRIVSEP*` env so the
/// re-exec takes the ordinary root-daemon path. Only returns on `exec` failure.
fn run_non_privsep_fallback(config_dir: &std::path::Path, quiet: bool) -> Result<()> {
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().context("resolving current exe")?;
    let mut cmd = std::process::Command::new(&exe);
    cmd.arg("host").arg("--config").arg(config_dir);
    if quiet {
        cmd.arg("--quiet");
    }
    cmd.env_remove("HOP_PRIVSEP")
        .env_remove("HOP_PRIVSEP_DROP")
        .env_remove("HOP_PRIVSEP_WORKER")
        .env_remove("HOP_PRIVSEP_CTRL_FD")
        // Mark the fallback so the daemon logs why it's not privsep-separated.
        .env("HOP_PRIVSEP_FALLBACK", "1");
    let err = cmd.exec(); // replaces this process; only returns on failure
    Err(anyhow::anyhow!("non-privsep fallback exec failed: {err}"))
}

/// Clear the close-on-exec flag so an fd survives `exec` into a child process.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn clear_cloexec(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("F_GETFD");
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error()).context("F_SETFD");
    }
    Ok(())
}

/// Set the close-on-exec flag so an fd is closed at `exec` and never leaks into
/// a child. Used for the liveness write end, which must stay confined to the
/// monitor process.
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn set_cloexec(fd: RawFd) -> Result<()> {
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
    if flags < 0 {
        return Err(std::io::Error::last_os_error()).context("F_GETFD");
    }
    if unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) } < 0 {
        return Err(std::io::Error::last_os_error()).context("F_SETFD");
    }
    Ok(())
}

/// Create a TUN/utun for the probe at a fixed CGNAT test address, reusing the
/// production `tun` configuration (`vpn::create_tun` is async; the probe is
/// single-threaded, so build a blocking device here with the same parameters).
#[cfg(any(target_os = "macos", target_os = "linux"))]
fn create_probe_tun() -> Result<tun::Device> {
    let mut config = tun::configure();
    config
        .address(std::net::Ipv4Addr::new(100, 64, 0, 123))
        .netmask(std::net::Ipv4Addr::new(255, 192, 0, 0))
        .mtu(crate::vpn::VPN_MTU)
        .up();
    tun::create(&config).map_err(|e| anyhow::anyhow!("create probe TUN: {e}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::os::fd::AsRawFd;

    /// The liveness-pipe invariant: the read end (held by the worker) must hit
    /// EOF the instant the last write end (held only by the monitor) closes —
    /// that EOF is the "monitor died" signal. Regression guard for the CLOEXEC
    /// leak that let the worker pin its own write end open (read never EOF'd, so
    /// a dead monitor wedged the node). Also checks the cloexec flag flipping.
    #[test]
    fn liveness_pipe_eofs_when_write_end_closes() {
        use std::os::fd::AsRawFd;
        let (alive_r, alive_w) = nix::unistd::pipe().unwrap();
        set_cloexec(alive_w.as_raw_fd()).unwrap();
        clear_cloexec(alive_r.as_raw_fd()).unwrap();
        // The write end is confined to the monitor (close-on-exec); the read end
        // crosses into the worker (cloexec cleared).
        let getfd = |fd: RawFd| unsafe { libc::fcntl(fd, libc::F_GETFD) };
        assert_eq!(getfd(alive_w.as_raw_fd()) & libc::FD_CLOEXEC, libc::FD_CLOEXEC);
        assert_eq!(getfd(alive_r.as_raw_fd()) & libc::FD_CLOEXEC, 0);
        // Closing the only write end makes a blocking read return 0 (EOF).
        let r_raw = alive_r.as_raw_fd();
        drop(alive_w);
        let mut buf = [0u8; 1];
        let n = unsafe { libc::read(r_raw, buf.as_mut_ptr() as *mut libc::c_void, 1) };
        assert_eq!(n, 0, "read on the liveness pipe must EOF once the write end is gone");
    }

    /// SCM_RIGHTS round-trip (no root): pass the read end of a pipe through a
    /// socketpair and confirm the received fd reads the bytes written to the
    /// pipe — proving send_fd/recv_fd move a working fd between "processes".
    #[test]
    fn scm_rights_round_trips_a_pipe_fd() {
        let (a, b) = control_socketpair().unwrap();

        // A pipe whose read end we'll pass over the socket.
        let (mut pr, mut pw) = std::io::pipe().unwrap();
        pw.write_all(b"privsep-ok").unwrap();
        drop(pw);

        send_fd(a.as_raw_fd(), pr.as_raw_fd()).unwrap();
        let received = recv_fd(b.as_raw_fd()).unwrap();

        // Read through the *received* fd (a distinct fd number, same pipe).
        let mut f = std::fs::File::from(received);
        let mut s = String::new();
        f.read_to_string(&mut s).unwrap();
        assert_eq!(s, "privsep-ok");

        // The original fd is still independently valid.
        let mut s2 = String::new();
        let _ = pr.read_to_string(&mut s2); // already drained via the dup; fine either way
    }

    /// The monitor's primitive validation is the privilege boundary: it must
    /// accept only warren-range vIPs and only the :53 bind.
    #[test]
    fn monitor_primitive_validation() {
        // CreateTun: warren range accepted, anything else rejected.
        assert!(validate_create_tun([100, 64, 0, 1]).is_ok());
        assert!(validate_create_tun([100, 127, 255, 254]).is_ok()); // top of /10
        assert!(validate_create_tun([10, 0, 0, 1]).is_err()); // private, not warren
        assert!(validate_create_tun([8, 8, 8, 8]).is_err()); // public
        assert!(validate_create_tun([100, 63, 0, 1]).is_err()); // just below the /10

        // BindPrivPort: only (warren vIP, 53).
        assert!(validate_bind_priv_port([100, 64, 0, 1], 53).is_ok());
        assert!(validate_bind_priv_port([127, 0, 0, 1], 53).is_ok()); // macOS MagicDNS on loopback
        assert!(validate_bind_priv_port([127, 0, 0, 1], 80).is_err()); // loopback but wrong port
        assert!(validate_bind_priv_port([100, 64, 0, 1], 80).is_err()); // wrong port
        assert!(validate_bind_priv_port([100, 64, 0, 1], 22).is_err());
        assert!(validate_bind_priv_port([8, 8, 8, 8], 53).is_err()); // non-vIP, non-loopback
    }

    /// SpawnSession only accepts an absolute-path launcher or the `login`/`su`
    /// user-switch helpers, and a well-formed username — the worker can't make
    /// the monitor run an arbitrary binary as root.
    #[test]
    fn spawn_session_validation() {
        let ok = |argv: &[&str], user: Option<&str>| {
            validate_spawn_session(
                &argv.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
                user,
            )
            .is_ok()
        };
        // Launcher allowlist (username None skips the account-existence check, so
        // these isolate the argv[0] boundary). login/su by basename are allowed
        // (the privileged switch helpers); an absolute-path shell is allowed
        // (session-as-self under a dropped worker).
        assert!(ok(&["login", "-fpq", "x", "/bin/zsh"], None));
        assert!(ok(&["/usr/bin/su", "-", "x"], None));
        assert!(ok(&["/bin/bash", "-l"], None));
        // A relative, non-allowlisted launcher is refused (PATH-search ambiguity).
        assert!(!ok(&["bash"], None));
        assert!(!ok(&["evil", "--root"], None));
        // Empty argv is refused.
        assert!(!ok(&[], None));
        // A malformed username is refused (fails the format check) even with an
        // allowlisted launcher.
        assert!(!ok(&["login", "-fpq", "bad user!"], Some("bad user!")));
    }

    /// Control messages frame + round-trip over the stream socketpair.
    #[test]
    fn control_protocol_round_trips() {
        let (a, b) = control_socketpair().unwrap();
        let req = MonitorRequest::CreateTun { vip: [100, 64, 0, 5] };
        send_msg(a.as_raw_fd(), &req).unwrap();
        let got: MonitorRequest = recv_msg(b.as_raw_fd()).unwrap();
        assert_eq!(got, req);

        let reply = MonitorReply::Error { message: "out of range".into() };
        send_msg(b.as_raw_fd(), &reply).unwrap();
        let got: MonitorReply = recv_msg(a.as_raw_fd()).unwrap();
        assert_eq!(got, reply);
    }

    /// The receiver-side ACL refuses system/service accounts and admits regular
    /// users — a compromised worker can never reach root/daemon/_hop.
    #[test]
    fn spawn_user_acl_rejects_system_accounts() {
        assert!(validate_spawnable_uid(0, "root").is_err()); // root
        assert!(validate_spawnable_uid(1, "daemon").is_err());
        assert!(validate_spawnable_uid(MIN_SPAWNABLE_UID - 1, "_svc").is_err());
        assert!(validate_spawnable_uid(MIN_SPAWNABLE_UID, "alice").is_ok());
        assert!(validate_spawnable_uid(1001, "hop").is_ok()); // the e2e bound user
        assert!(validate_spawnable_uid(60123, "bob").is_ok());
    }

    /// The allowlist parser ignores comments + blanks and trims usernames.
    #[test]
    fn allowlist_parsing() {
        let set = parse_allowlist(
            "# bound users\nalice\n  bob  \n\ncarol # inline note\n#full-line comment\n",
        );
        assert!(set.contains("alice"));
        assert!(set.contains("bob"));
        assert!(set.contains("carol"));
        assert!(!set.contains("dave"));
        assert!(!set.iter().any(|u| u.starts_with('#')));
        assert_eq!(set.len(), 3);
    }

    /// Several fds round-trip in order through one SCM_RIGHTS message (the
    /// SpawnExec stdin/stdout/stderr + status handoff).
    #[test]
    fn scm_rights_round_trips_multiple_fds() {
        use std::io::{Read, Write};
        let (a, b) = control_socketpair().unwrap();
        // Three independent pipes; send their write ends, write a distinct byte
        // through each received fd, read it back from the local read end.
        let mut reads = Vec::new();
        let mut send_fds_raw = Vec::new();
        let mut keep = Vec::new();
        for _ in 0..3 {
            let (r, w) = nix::unistd::pipe().unwrap();
            send_fds_raw.push(w.as_raw_fd());
            reads.push(r);
            keep.push(w); // keep write ends alive until after send
        }
        send_fds(a.as_raw_fd(), &send_fds_raw).unwrap();
        let got = recv_fds(b.as_raw_fd(), 3).unwrap();
        assert_eq!(got.len(), 3);
        for (i, fd) in got.iter().enumerate() {
            let mut wf = std::fs::File::from(fd.try_clone().unwrap());
            wf.write_all(&[i as u8 + 1]).unwrap();
            drop(wf);
            let mut rf = std::fs::File::from(reads[i].try_clone().unwrap());
            let mut buf = [0u8; 1];
            rf.read_exact(&mut buf).unwrap();
            assert_eq!(buf[0], i as u8 + 1);
        }
    }

    /// Receiving with no pending message is an error, not a panic/UB.
    #[test]
    fn recv_fd_without_message_errors() {
        let (a, b) = control_socketpair().unwrap();
        // Send one byte with NO ancillary fd.
        let iov = [IoSlice::new(&[0u8])];
        sendmsg::<()>(a.as_raw_fd(), &iov, &[], MsgFlags::empty(), None).unwrap();
        assert!(recv_fd(b.as_raw_fd()).is_err());
    }
}
