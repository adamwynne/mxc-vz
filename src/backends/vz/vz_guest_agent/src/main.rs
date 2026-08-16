//! Guest agent entry point. In the VM this runs as PID 1's child (or PID 1
//! itself behind a 10-line init) listening on vsock; unix/tcp listeners exist
//! for development and tests.
//!
//! Usage: vz_guest_agent <listen-spec>
//!   vsock:<port>   AF_VSOCK, any CID (the real guest transport)
//!   unix:<path>    Unix socket (local development)
//!   tcp:<addr>     TCP, e.g. tcp:127.0.0.1:7777 (local development)

use std::net::TcpListener;
use std::os::unix::net::UnixListener;

use vz_guest_agent::serve_connection;

fn main() {
    let spec = std::env::args().nth(1).unwrap_or_else(|| usage());
    match spec.split_once(':') {
        Some(("unix", path)) => {
            let _ = std::fs::remove_file(path);
            let listener = UnixListener::bind(path).expect("bind unix socket");
            eprintln!("vz_guest_agent: listening on unix:{path}");
            for stream in listener.incoming().flatten() {
                let reader = stream.try_clone().expect("clone stream");
                serve_connection(reader, stream);
            }
        }
        Some(("tcp", addr)) => {
            let listener = TcpListener::bind(addr).expect("bind tcp socket");
            eprintln!("vz_guest_agent: listening on tcp:{addr}");
            for stream in listener.incoming().flatten() {
                let reader = stream.try_clone().expect("clone stream");
                serve_connection(reader, stream);
            }
        }
        Some(("vsock", port)) => {
            let port: u32 = port.parse().unwrap_or_else(|_| usage());
            serve_vsock(port);
        }
        _ => usage(),
    }
}

fn usage() -> ! {
    eprintln!("usage: vz_guest_agent <vsock:PORT | unix:PATH | tcp:ADDR>");
    std::process::exit(2);
}

/// AF_VSOCK listener (Linux guest only). Serves connections serially — the
/// v1 lifecycle is one-shot, one exec at a time.
#[cfg(target_os = "linux")]
fn serve_vsock(port: u32) {
    use std::os::fd::{FromRawFd, OwnedFd};

    // SAFETY: plain libc socket calls; fds are checked and wrapped in
    // OwnedFd so they close on drop.
    unsafe {
        let fd = libc::socket(libc::AF_VSOCK, libc::SOCK_STREAM, 0);
        assert!(fd >= 0, "vsock socket() failed: {}", std::io::Error::last_os_error());
        let _listener = OwnedFd::from_raw_fd(fd); // closes on drop; held for the loop

        let mut addr: libc::sockaddr_vm = std::mem::zeroed();
        addr.svm_family = libc::AF_VSOCK as libc::sa_family_t;
        addr.svm_cid = libc::VMADDR_CID_ANY;
        addr.svm_port = port;
        let rc = libc::bind(
            fd,
            &addr as *const libc::sockaddr_vm as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_vm>() as libc::socklen_t,
        );
        assert!(rc == 0, "vsock bind() failed: {}", std::io::Error::last_os_error());
        let rc = libc::listen(fd, 1);
        assert!(rc == 0, "vsock listen() failed: {}", std::io::Error::last_os_error());
        eprintln!("vz_guest_agent: listening on vsock:{port}");

        loop {
            let client = libc::accept(fd, std::ptr::null_mut(), std::ptr::null_mut());
            if client < 0 {
                eprintln!("vz_guest_agent: accept failed: {}", std::io::Error::last_os_error());
                continue;
            }
            // A vsock stream fd behaves like any socket fd; UnixStream gives
            // us Read/Write/try_clone over it.
            let stream = std::os::unix::net::UnixStream::from_raw_fd(client);
            match stream.try_clone() {
                Ok(reader) => serve_connection(reader, stream),
                Err(error) => eprintln!("vz_guest_agent: clone failed: {error}"),
            }
        }
    }
}

#[cfg(not(target_os = "linux"))]
fn serve_vsock(_port: u32) {
    eprintln!("vz_guest_agent: vsock listening is only available on Linux guests");
    std::process::exit(2);
}
