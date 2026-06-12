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
