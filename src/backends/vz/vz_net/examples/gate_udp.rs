//! Run the egress gate over a UDP datagram-per-frame socket — the framing
//! QEMU's `-netdev dgram` speaks, and the same shape as the VZ file-handle
//! attachment's socketpair. CI boots the real Alpine guest with this gate
//! as its only path off the VM.
//!
//! Usage:
//!   gate_udp --bind 127.0.0.1:PORT --peer 127.0.0.1:PORT \
//!            [--allow ENTRY]... [--resolve NAME=IP]...
//!
//! `--allow` entries are allowedHosts syntax (IP / CIDR / hostname).
//! `--resolve` pins a hostname to an IP for the gate's resolver (so tests
//! never depend on real DNS); unpinned names fall back to the system
//! resolver. Runs until killed.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr, UdpSocket};

use vz_net::filter::EgressFilter;
use vz_net::gate::{FrameTransport, Gate, GateConfig, Resolver, SystemResolver};
use vz_net::pattern::HostPattern;

struct UdpTransport {
    socket: UdpSocket,
    peer: SocketAddr,
}

impl FrameTransport for UdpTransport {
    fn recv(&mut self, buf: &mut [u8]) -> std::io::Result<Option<usize>> {
        match self.socket.recv_from(buf) {
            // Frames must come from the QEMU end we were pointed at.
            Ok((len, from)) if from == self.peer => Ok(Some(len)),
            Ok(_) => Ok(None),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(None),
            Err(e) => Err(e),
        }
    }

    fn send(&mut self, frame: &[u8]) -> std::io::Result<()> {
        match self.socket.send_to(frame, self.peer) {
            Ok(_) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => Ok(()),
            Err(e) => Err(e),
        }
    }
}

struct PinnedResolver {
    pins: HashMap<String, Vec<IpAddr>>,
    fallback: SystemResolver,
}

impl Resolver for PinnedResolver {
    fn resolve(&self, name: &str) -> Vec<IpAddr> {
        match self.pins.get(&name.to_ascii_lowercase()) {
            Some(ips) => ips.clone(),
            None => self.fallback.resolve(name),
        }
    }
}

fn main() {
    let mut bind = None;
    let mut peer = None;
    let mut allow: Vec<String> = Vec::new();
    let mut pins: HashMap<String, Vec<IpAddr>> = HashMap::new();

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| {
            args.next().unwrap_or_else(|| {
                eprintln!("error: {flag} requires a value");
                std::process::exit(2);
            })
        };
        match arg.as_str() {
            "--bind" => bind = Some(value("--bind")),
            "--peer" => peer = Some(value("--peer")),
            "--allow" => allow.push(value("--allow")),
            "--resolve" => {
                let pin = value("--resolve");
                let Some((name, ip)) = pin.split_once('=') else {
                    eprintln!("error: --resolve wants NAME=IP, got {pin}");
                    std::process::exit(2);
                };
                let ip: IpAddr = ip.parse().unwrap_or_else(|e| {
                    eprintln!("error: bad --resolve IP {ip}: {e}");
                    std::process::exit(2);
                });
                pins.entry(name.to_ascii_lowercase()).or_default().push(ip);
            }
            other => {
                eprintln!("error: unknown argument {other}");
                std::process::exit(2);
            }
        }
    }

    let (Some(bind), Some(peer)) = (bind, peer) else {
        eprintln!("usage: gate_udp --bind ADDR:PORT --peer ADDR:PORT [--allow ENTRY]... [--resolve NAME=IP]...");
        std::process::exit(2);
    };

    let socket = UdpSocket::bind(&bind).unwrap_or_else(|e| {
        eprintln!("error: bind {bind}: {e}");
        std::process::exit(1);
    });
    socket.set_nonblocking(true).expect("set_nonblocking");
    let peer: SocketAddr = peer.parse().unwrap_or_else(|e| {
        eprintln!("error: bad --peer address: {e}");
        std::process::exit(2);
    });

    let patterns = allow.iter().filter_map(|entry| match HostPattern::parse(entry) {
        Ok(pattern) => Some(pattern),
        Err(error) => {
            eprintln!("warning: skipping allow entry {entry:?}: {error}");
            None
        }
    });
    let filter = EgressFilter::new(patterns);

    println!("gate_udp: bound {bind}, peer {peer}, {} allow entries", allow.len());
    let _gate = Gate::spawn(
        UdpTransport { socket, peer },
        filter,
        PinnedResolver { pins, fallback: SystemResolver },
        GateConfig::default(),
    );

    // The gate runs on its own thread; park forever (CI kills the process).
    loop {
        std::thread::park();
    }
}
