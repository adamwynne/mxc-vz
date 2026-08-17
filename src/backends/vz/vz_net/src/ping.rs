//! Host-side ping sockets for the ICMP echo relay.
//!
//! There is no std API for ICMP, and privileges vary by platform, so the
//! socket is acquired down a ladder:
//!
//! 1. `SOCK_DGRAM`/`IPPROTO_ICMP` — the unprivileged "ping socket".
//!    Available on macOS out of the box and on Linux when
//!    `net.ipv4.ping_group_range` covers the process's group. The Linux
//!    kernel rewrites the echo id to a socket-local one and strips the IP
//!    header on receive; macOS keeps the IP header. Both are normalized
//!    here.
//! 2. `SOCK_RAW`/`IPPROTO_ICMP` — root only; receive includes the IP
//!    header.
//! 3. Neither → [`PingSocket::open`] fails and the gate drops ICMP
//!    (fail closed), exactly the pre-relay behavior.
//!
//! Sockets are `connect()`ed to the destination so the kernel filters
//! replies by source address.

use std::io;
use std::net::IpAddr;
use std::os::fd::RawFd;

pub struct PingSocket {
    fd: RawFd,
}

impl PingSocket {
    /// Open a non-blocking ICMP/ICMPv6 socket connected to `dst`, trying
    /// the unprivileged ping socket first and raw second. For ICMPv6 the
    /// kernel computes outgoing checksums (they need the pseudo-header).
    pub fn open(dst: IpAddr) -> io::Result<Self> {
        let (family, proto) = match dst {
            IpAddr::V4(_) => (libc::AF_INET, libc::IPPROTO_ICMP),
            IpAddr::V6(_) => (libc::AF_INET6, libc::IPPROTO_ICMPV6),
        };
        // SAFETY: plain socket syscalls; the fd is owned by the returned
        // struct and closed on drop.
        unsafe {
            let mut fd = libc::socket(family, libc::SOCK_DGRAM, proto);
            if fd < 0 {
                fd = libc::socket(family, libc::SOCK_RAW, proto);
            }
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }

            let rc = match dst {
                IpAddr::V4(v4) => {
                    let mut addr: libc::sockaddr_in = std::mem::zeroed();
                    addr.sin_family = libc::AF_INET as libc::sa_family_t;
                    addr.sin_addr.s_addr = u32::from_ne_bytes(v4.octets());
                    libc::connect(
                        fd,
                        std::ptr::from_ref(&addr).cast(),
                        std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
                    )
                }
                IpAddr::V6(v6) => {
                    let mut addr: libc::sockaddr_in6 = std::mem::zeroed();
                    addr.sin6_family = libc::AF_INET6 as libc::sa_family_t;
                    addr.sin6_addr.s6_addr = v6.octets();
                    libc::connect(
                        fd,
                        std::ptr::from_ref(&addr).cast(),
                        std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
                    )
                }
            };
            if rc != 0 {
                let error = io::Error::last_os_error();
                libc::close(fd);
                return Err(error);
            }

            let flags = libc::fcntl(fd, libc::F_GETFL);
            if flags < 0 || libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) < 0 {
                let error = io::Error::last_os_error();
                libc::close(fd);
                return Err(error);
            }

            Ok(Self { fd })
        }
    }

    /// Send one ICMP packet (header + payload, checksum already set).
    pub fn send(&self, packet: &[u8]) -> io::Result<()> {
        // SAFETY: fd is owned and open; buffer is a valid slice.
        let rc = unsafe { libc::send(self.fd, packet.as_ptr().cast(), packet.len(), 0) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(()); // dropped like any full-queue datagram
            }
            return Err(error);
        }
        Ok(())
    }

    /// Receive one ICMP packet, normalized to bare ICMP bytes (any leading
    /// IPv4 header — raw sockets on Linux, everything on macOS — is
    /// stripped). `Ok(None)` when nothing is pending.
    pub fn recv(&self) -> io::Result<Option<Vec<u8>>> {
        let mut buf = vec![0u8; 2048];
        // SAFETY: fd is owned and open; buffer is a valid slice.
        let rc = unsafe { libc::recv(self.fd, buf.as_mut_ptr().cast(), buf.len(), 0) };
        if rc < 0 {
            let error = io::Error::last_os_error();
            if error.kind() == io::ErrorKind::WouldBlock {
                return Ok(None);
            }
            return Err(error);
        }
        buf.truncate(rc as usize);
        // An ICMP message never starts with a 0x4_ byte (echo reply is 0,
        // request 8, unreachable 3, time-exceeded 11); an IPv4 header does.
        if buf.first().map(|b| b >> 4) == Some(4) && buf.len() > 20 {
            let header_len = usize::from(buf[0] & 0x0f) * 4;
            if header_len < buf.len() {
                buf.drain(..header_len);
            }
        }
        Ok(Some(buf))
    }
}

impl Drop for PingSocket {
    fn drop(&mut self) {
        // SAFETY: fd is owned; closed exactly once.
        unsafe { libc::close(self.fd) };
    }
}

/// Whether this process can open ping sockets at all — used by tests to
/// skip gracefully on hosts where neither ladder rung is available.
pub fn ping_supported() -> bool {
    PingSocket::open(IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)).is_ok()
}

/// v6 sibling of [`ping_supported`].
pub fn ping6_supported() -> bool {
    PingSocket::open(IpAddr::V6(std::net::Ipv6Addr::LOCALHOST)).is_ok()
}
