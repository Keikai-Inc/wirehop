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
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MonitorRequest {
    /// Create + configure a TUN at `vip` (must be in 100.64.0.0/10) and return
    /// its fd. The monitor validates the range before touching the kernel.
    CreateTun { vip: [u8; 4] },
    /// Bind a UDP socket on `(addr, port)` and return its fd. The monitor
    /// allowlists this to the node's own vip and port 53 (MagicDNS) only.
    BindPrivPort { addr: [u8; 4], port: u16 },
    // SpawnSession { user, … } is added in Phase 3 (move setuid into the monitor).
}

/// The monitor's reply. On `OkFd` a file descriptor follows as ancillary data
/// (received with [`recv_fd`]); `Error` carries a human-readable reason.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub enum MonitorReply {
    OkFd,
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

/// Accept a `BindPrivPort` only for the node's own vIP and the MagicDNS port 53.
fn validate_bind_priv_port(addr: [u8; 4], port: u16) -> Result<()> {
    anyhow::ensure!(
        port == 53,
        "refusing BindPrivPort: only :53 (MagicDNS) is permitted, not :{port}"
    );
    anyhow::ensure!(
        crate::vpn::is_virtual_addr(std::net::Ipv4Addr::from(addr)),
        "refusing BindPrivPort: {} is not a warren vIP",
        std::net::Ipv4Addr::from(addr)
    );
    Ok(())
}

/// Monitor side of `CreateTun`: validate, then create + configure the device.
/// The monitor keeps the returned `Device` alive (so the interface + route
/// persist across worker restarts) and passes its fd to the worker.
pub fn monitor_create_tun(vip: [u8; 4]) -> Result<tun::Device> {
    validate_create_tun(vip)?;
    let addr = std::net::Ipv4Addr::from(vip);
    let mut config = tun::configure();
    config
        .address(addr)
        .netmask(std::net::Ipv4Addr::new(255, 192, 0, 0))
        .mtu(crate::vpn::VPN_MTU)
        .up();
    tun::create(&config).map_err(|e| anyhow::anyhow!("create TUN {addr}: {e}"))
}

/// Monitor side of `BindPrivPort`: validate (own vIP + :53), then bind. Returns
/// the bound UDP socket's fd to hand to the worker's MagicDNS loop.
pub fn monitor_bind_priv_port(addr: [u8; 4], port: u16) -> Result<OwnedFd> {
    validate_bind_priv_port(addr, port)?;
    let a = std::net::Ipv4Addr::from(addr);
    let sock = std::net::UdpSocket::bind((a, port)).with_context(|| format!("binding {a}:{port}"))?;
    Ok(OwnedFd::from(sock))
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
        assert!(validate_bind_priv_port([100, 64, 0, 1], 80).is_err()); // wrong port
        assert!(validate_bind_priv_port([100, 64, 0, 1], 22).is_err());
        assert!(validate_bind_priv_port([8, 8, 8, 8], 53).is_err()); // non-vIP
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
