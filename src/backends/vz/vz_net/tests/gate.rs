//! Gate end-to-end tests: a REAL second smoltcp stack plays the guest,
//! connected to the gate over an in-memory frame pipe. Everything the wire
//! would carry in production — ARP, DNS over UDP, TCP handshakes, RSTs,
//! relayed payload bytes — actually crosses the pipe as ethernet frames.
//!
//! "The internet" on the far side of the NAT is a real `TcpListener` on
//! host loopback: the gate's upstream connect is a genuine OS socket.

use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, Ipv4Addr, TcpListener};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::time::{Duration, Instant};

use smoltcp::iface::{Config, Interface, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpEndpoint};

use vz_net::filter::EgressFilter;
use vz_net::gate::{FrameTransport, Gate, GateConfig, Resolver};
use vz_net::pattern::HostPattern;

// ───────────────────────── in-memory frame pipe ─────────────────────────

struct PipeTransport {
    rx: Receiver<Vec<u8>>,
    tx: Sender<Vec<u8>>,
}

fn pipe_pair() -> (PipeTransport, PipeTransport) {
    let (a_tx, a_rx) = mpsc::channel();
    let (b_tx, b_rx) = mpsc::channel();
    (
        PipeTransport { rx: a_rx, tx: b_tx },
        PipeTransport { rx: b_rx, tx: a_tx },
    )
}

impl FrameTransport for PipeTransport {
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>> {
        match self.rx.try_recv() {
            Ok(frame) => {
                let len = frame.len().min(buf.len());
                buf[..len].copy_from_slice(&frame[..len]);
                Ok(Some(len))
            }
            Err(TryRecvError::Empty) => Ok(None),
            Err(TryRecvError::Disconnected) => Err(io::ErrorKind::BrokenPipe.into()),
        }
    }

    fn send(&mut self, frame: &[u8]) -> io::Result<()> {
        self.tx
            .send(frame.to_vec())
            .map_err(|_| io::ErrorKind::BrokenPipe.into())
    }
}

// ───────────────────────── the guest-side stack ─────────────────────────

struct GuestDevice {
    transport: PipeTransport,
}

struct GuestRx(Vec<u8>);
impl RxToken for GuestRx {
    fn consume<R, F: FnOnce(&[u8]) -> R>(self, f: F) -> R {
        f(&self.0)
    }
}
struct GuestTx<'a>(&'a mut PipeTransport);
impl TxToken for GuestTx<'_> {
    fn consume<R, F: FnOnce(&mut [u8]) -> R>(self, len: usize, f: F) -> R {
        let mut frame = vec![0u8; len];
        let result = f(&mut frame);
        let _ = self.0.send(&frame);
        result
    }
}

impl Device for GuestDevice {
    type RxToken<'a>
        = GuestRx
    where
        Self: 'a;
    type TxToken<'a>
        = GuestTx<'a>
    where
        Self: 'a;

    fn receive(&mut self, _t: SmolInstant) -> Option<(GuestRx, GuestTx<'_>)> {
        let mut buf = vec![0u8; 2048];
        if let Ok(Some(len)) = self.transport.recv(&mut buf) {
            buf.truncate(len);
            return Some((GuestRx(buf), GuestTx(&mut self.transport)));
        }
        None
    }

    fn transmit(&mut self, _t: SmolInstant) -> Option<GuestTx<'_>> {
        Some(GuestTx(&mut self.transport))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps
    }
}

const GUEST_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 15);
const GATEWAY: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 2);
const DNS_IP: Ipv4Addr = Ipv4Addr::new(10, 0, 2, 3);

struct Guest {
    device: GuestDevice,
    iface: Interface,
    sockets: SocketSet<'static>,
}

impl Guest {
    fn new(transport: PipeTransport) -> Self {
        let mut device = GuestDevice { transport };
        let mut config = Config::new(HardwareAddress::Ethernet(EthernetAddress([
            0x02, 0, 0, 0, 0, 0x15,
        ])));
        config.random_seed = 0x67756573;
        let mut iface = Interface::new(config, &mut device, SmolInstant::now());
        iface.update_ip_addrs(|addrs| {
            let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(GUEST_IP), 24));
        });
        iface
            .routes_mut()
            .add_default_ipv4_route(GATEWAY)
            .expect("default route");
        Self { device, iface, sockets: SocketSet::new(vec![]) }
    }

    fn poll(&mut self) {
        self.iface
            .poll(SmolInstant::now(), &mut self.device, &mut self.sockets);
    }

    /// Drive both stacks until `done` or the deadline.
    fn run_until(&mut self, deadline: Duration, mut done: impl FnMut(&mut Self) -> bool) -> bool {
        let start = Instant::now();
        while start.elapsed() < deadline {
            self.poll();
            if done(self) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(2));
        }
        false
    }

    /// DNS query through the gate; returns (rcode, A-record IPs).
    fn dns_query(&mut self, name: &str) -> Option<(u8, Vec<Ipv4Addr>)> {
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]);
        let mut socket = udp::Socket::new(rx, tx);
        socket.bind(33333).expect("bind guest udp");
        let handle = self.sockets.add(socket);

        let mut query = vec![0x12, 0x34, 0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            query.push(label.len() as u8);
            query.extend_from_slice(label.as_bytes());
        }
        query.push(0);
        query.extend_from_slice(&1u16.to_be_bytes());
        query.extend_from_slice(&1u16.to_be_bytes());

        let server = IpEndpoint::new(IpAddress::Ipv4(DNS_IP), 53);
        let mut sent = false;
        let mut answer: Option<Vec<u8>> = None;
        self.run_until(Duration::from_secs(5), |guest| {
            let socket = guest.sockets.get_mut::<udp::Socket>(handle);
            if !sent && socket.can_send() {
                socket.send_slice(&query, server).expect("send query");
                sent = true;
            }
            if let Ok((payload, _)) = socket.recv() {
                answer = Some(payload.to_vec());
                return true;
            }
            false
        });
        self.sockets.remove(handle);

        let payload = answer?;
        let rcode = payload[3] & 0x0f;
        let ancount = u16::from_be_bytes([payload[6], payload[7]]);
        let mut ips = Vec::new();
        // Answers follow the echoed question; records are fixed 16 bytes
        // for A with a name pointer (2+2+2+4+2+4).
        let question_len = query.len() - 12;
        let mut at = 12 + question_len;
        for _ in 0..ancount {
            let rdlen = u16::from_be_bytes([payload[at + 10], payload[at + 11]]) as usize;
            if rdlen == 4 {
                ips.push(Ipv4Addr::new(
                    payload[at + 12],
                    payload[at + 13],
                    payload[at + 14],
                    payload[at + 15],
                ));
            }
            at += 12 + rdlen;
        }
        Some((rcode, ips))
    }

    /// TCP connect through the gate. Returns the socket handle once
    /// established, or None if the connection was refused (RST) / timed out.
    fn tcp_connect(&mut self, dst: Ipv4Addr, port: u16) -> Option<smoltcp::iface::SocketHandle> {
        let socket = tcp::Socket::new(
            tcp::SocketBuffer::new(vec![0; 16384]),
            tcp::SocketBuffer::new(vec![0; 16384]),
        );
        let handle = self.sockets.add(socket);
        let local_port = 49000 + (port % 1000);
        {
            let context = self.iface.context();
            let socket = self.sockets.get_mut::<tcp::Socket>(handle);
            socket
                .connect(context, (IpAddress::Ipv4(dst), port), local_port)
                .expect("start connect");
        }
        let established = self.run_until(Duration::from_secs(5), |guest| {
            let socket = guest.sockets.get_mut::<tcp::Socket>(handle);
            match socket.state() {
                tcp::State::Established => true,
                // RST lands the socket back in Closed while still "open".
                tcp::State::Closed => true,
                _ => false,
            }
        });
        let socket = self.sockets.get_mut::<tcp::Socket>(handle);
        if established && socket.state() == tcp::State::Established {
            Some(handle)
        } else {
            self.sockets.remove(handle);
            None
        }
    }

    /// Send `data`, then read until the connection closes; returns received bytes.
    fn tcp_send_and_collect(&mut self, handle: smoltcp::iface::SocketHandle, data: &[u8]) -> Vec<u8> {
        let mut sent = false;
        let mut received = Vec::new();
        self.run_until(Duration::from_secs(5), |guest| {
            let socket = guest.sockets.get_mut::<tcp::Socket>(handle);
            if !sent && socket.can_send() {
                socket.send_slice(data).expect("guest send");
                sent = true;
            }
            while socket.can_recv() {
                let _ = socket.recv(|buf| {
                    received.extend_from_slice(buf);
                    (buf.len(), ())
                });
            }
            // Done when the far side closed after echoing everything.
            !socket.is_active() || (sent && received.len() >= data.len())
        });
        received
    }
}

// ───────────────────────── helpers ─────────────────────────

struct FixedResolver(Vec<IpAddr>);
impl Resolver for FixedResolver {
    fn resolve(&self, _name: &str) -> Vec<IpAddr> {
        self.0.clone()
    }
}

fn filter(entries: &[&str]) -> EgressFilter {
    EgressFilter::new(entries.iter().map(|e| HostPattern::parse(e).unwrap()))
}

/// Echo server on loopback: accepts one connection, echoes what it reads,
/// then closes. Returns its port.
fn spawn_echo_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo server");
    let port = listener.local_addr().unwrap().port();
    std::thread::spawn(move || {
        if let Ok((mut stream, _)) = listener.accept() {
            let mut buf = [0u8; 4096];
            // One echo round is all the tests need.
            if let Ok(n) = stream.read(&mut buf) {
                if n > 0 {
                    let _ = stream.write_all(&buf[..n]);
                }
            }
        }
    });
    port
}

fn start(
    entries: &[&str],
    resolver_ips: Vec<IpAddr>,
) -> (Gate, Guest) {
    let (gate_end, guest_end) = pipe_pair();
    let gate = Gate::spawn(
        gate_end,
        filter(entries),
        FixedResolver(resolver_ips),
        GateConfig::default(),
    );
    (gate, Guest::new(guest_end))
}

// ───────────────────────── the tests ─────────────────────────

#[test]
fn denied_destination_is_refused_with_a_prompt_rst() {
    let (_gate, mut guest) = start(&[], vec![]);
    let started = Instant::now();
    let handle = guest.tcp_connect(Ipv4Addr::new(127, 0, 0, 1), 65_000);
    assert!(handle.is_none(), "empty filter must deny the connect");
    assert!(
        started.elapsed() < Duration::from_secs(3),
        "denial must be an RST, not a timeout"
    );
}

#[test]
fn statically_allowed_ip_relays_bytes_to_a_real_server() {
    let port = spawn_echo_server();
    let (_gate, mut guest) = start(&["127.0.0.1"], vec![]);
    let handle = guest
        .tcp_connect(Ipv4Addr::new(127, 0, 0, 1), port)
        .expect("allowed connect must establish");
    let echoed = guest.tcp_send_and_collect(handle, b"through the gate");
    assert_eq!(echoed, b"through the gate");
}

#[test]
fn dns_for_allowed_name_populates_the_filter_and_enables_connect() {
    let port = spawn_echo_server();
    let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let (_gate, mut guest) = start(&["echo.test"], vec![loopback]);

    let (rcode, ips) = guest.dns_query("echo.test").expect("answer must arrive");
    assert_eq!(rcode, 0, "allowed name must resolve");
    assert_eq!(ips, vec![Ipv4Addr::new(127, 0, 0, 1)]);

    let handle = guest
        .tcp_connect(Ipv4Addr::new(127, 0, 0, 1), port)
        .expect("DNS-populated IP must be connectable");
    let echoed = guest.tcp_send_and_collect(handle, b"resolved then connected");
    assert_eq!(echoed, b"resolved then connected");
}

#[test]
fn dns_for_non_allowed_name_is_refused_and_grants_nothing() {
    let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let (_gate, mut guest) = start(&["echo.test"], vec![loopback]);

    let (rcode, ips) = guest.dns_query("evil.test").expect("a REFUSED reply, not silence");
    assert_eq!(rcode, 5, "non-allowed name must be REFUSED");
    assert!(ips.is_empty());

    // And the refusal populated nothing: connects still get RST.
    assert!(guest.tcp_connect(Ipv4Addr::new(127, 0, 0, 1), 65_001).is_none());
}

/// UDP send/receive through the gate: sends `payload` to (dst, port),
/// returns the first reply payload if any arrives before the deadline.
fn udp_exchange(
    guest: &mut Guest,
    dst: Ipv4Addr,
    port: u16,
    payload: &[u8],
    deadline: Duration,
) -> Option<Vec<u8>> {
    let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]);
    let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 4], vec![0; 2048]);
    let mut socket = udp::Socket::new(rx, tx);
    socket.bind(44444).expect("bind guest udp");
    let handle = guest.sockets.add(socket);

    let remote = IpEndpoint::new(IpAddress::Ipv4(dst), port);
    let mut sent = false;
    let mut reply: Option<Vec<u8>> = None;
    guest.run_until(deadline, |guest| {
        let socket = guest.sockets.get_mut::<udp::Socket>(handle);
        if !sent && socket.can_send() {
            socket.send_slice(payload, remote).expect("guest udp send");
            sent = true;
        }
        if let Ok((data, _)) = socket.recv() {
            reply = Some(data.to_vec());
            return true;
        }
        false
    });
    guest.sockets.remove(handle);
    reply
}

/// UDP echo server on host loopback; echoes every datagram once. Returns port.
fn spawn_udp_echo_server() -> u16 {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").expect("bind udp echo");
    let port = socket.local_addr().unwrap().port();
    std::thread::spawn(move || {
        let mut buf = [0u8; 2048];
        while let Ok((n, from)) = socket.recv_from(&mut buf) {
            if socket.send_to(&buf[..n], from).is_err() {
                break;
            }
        }
    });
    port
}

#[test]
fn udp_to_allowed_ip_relays_datagrams_both_ways() {
    let port = spawn_udp_echo_server();
    let (_gate, mut guest) = start(&["127.0.0.1"], vec![]);
    let reply = udp_exchange(
        &mut guest,
        Ipv4Addr::new(127, 0, 0, 1),
        port,
        b"udp through the gate",
        Duration::from_secs(5),
    );
    assert_eq!(reply.as_deref(), Some(&b"udp through the gate"[..]));
}

#[test]
fn udp_to_denied_ip_is_dropped_silently() {
    let port = spawn_udp_echo_server();
    let (_gate, mut guest) = start(&[], vec![]);
    let reply = udp_exchange(
        &mut guest,
        Ipv4Addr::new(127, 0, 0, 1),
        port,
        b"should vanish",
        Duration::from_secs(2),
    );
    assert_eq!(reply, None, "denied UDP must be dropped, never relayed");
}

#[test]
fn dns_populated_ip_is_usable_for_udp_too() {
    // The allowed-IP set is protocol-agnostic: a DNS-observed IP admits
    // UDP flows the same as TCP (upstream lxc parity — host rules match
    // all ports and protocols).
    let port = spawn_udp_echo_server();
    let loopback = IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1));
    let (_gate, mut guest) = start(&["echo.test"], vec![loopback]);
    let (rcode, _) = guest.dns_query("echo.test").expect("answer");
    assert_eq!(rcode, 0);
    let reply = udp_exchange(
        &mut guest,
        Ipv4Addr::new(127, 0, 0, 1),
        port,
        b"resolved then datagrammed",
        Duration::from_secs(5),
    );
    assert_eq!(reply.as_deref(), Some(&b"resolved then datagrammed"[..]));
}

#[test]
fn udp_flow_survives_idle_expiry_by_renating() {
    // After the idle timeout removes the flow's NAT state, the next
    // datagram simply creates a fresh flow — expiry frees resources, it
    // never bricks the path.
    let port = spawn_udp_echo_server();
    let (gate_end, guest_end) = pipe_pair();
    let config = GateConfig { udp_idle: Duration::from_millis(150), ..GateConfig::default() };
    let gate = Gate::spawn(gate_end, filter(&["127.0.0.1"]), FixedResolver(vec![]), config);
    let mut guest = Guest::new(guest_end);

    let first = udp_exchange(&mut guest, Ipv4Addr::new(127, 0, 0, 1), port, b"one", Duration::from_secs(5));
    assert_eq!(first.as_deref(), Some(&b"one"[..]));
    std::thread::sleep(Duration::from_millis(400)); // let the flow expire
    let second = udp_exchange(&mut guest, Ipv4Addr::new(127, 0, 0, 1), port, b"two", Duration::from_secs(5));
    assert_eq!(second.as_deref(), Some(&b"two"[..]));
    drop(gate);
}

/// Hand-built ICMP echo-request frame (the smoltcp guest has no ping
/// socket; ICMP tests speak raw frames over the pipe).
fn echo_request_frame(dst: Ipv4Addr, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    fn checksum(bytes: &[u8]) -> u16 {
        let mut sum = 0u32;
        for chunk in bytes.chunks(2) {
            sum += (u32::from(chunk[0]) << 8) | u32::from(*chunk.get(1).unwrap_or(&0));
        }
        while sum >> 16 != 0 {
            sum = (sum & 0xffff) + (sum >> 16);
        }
        !(sum as u16)
    }
    let mut frame = Vec::new();
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x02]); // dst: gate MAC
    frame.extend_from_slice(&[0x02, 0, 0, 0, 0, 0x15]); // src: guest MAC
    frame.extend_from_slice(&[0x08, 0x00]);
    let icmp_len = 8 + payload.len() as u16;
    let total_len = 20 + icmp_len;
    let mut ip = vec![
        0x45, 0,
        (total_len >> 8) as u8, total_len as u8,
        0, 0, 0x40, 0,
        64, 1, 0, 0,
    ];
    ip.extend_from_slice(&GUEST_IP.octets());
    ip.extend_from_slice(&dst.octets());
    let c = checksum(&ip);
    ip[10] = (c >> 8) as u8;
    ip[11] = c as u8;
    frame.extend_from_slice(&ip);
    let mut icmp = vec![8, 0, 0, 0];
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let c = checksum(&icmp);
    icmp[2] = (c >> 8) as u8;
    icmp[3] = c as u8;
    frame.extend_from_slice(&icmp);
    frame
}

/// Wait for an ICMP echo-reply frame on the pipe; returns (id, seq, payload).
fn wait_for_echo_reply(pipe: &mut PipeTransport, deadline: Duration) -> Option<(u16, u16, Vec<u8>)> {
    let start = Instant::now();
    let mut buf = vec![0u8; 2048];
    while start.elapsed() < deadline {
        if let Ok(Some(len)) = pipe.recv(&mut buf) {
            let frame = &buf[..len];
            if frame.len() >= 42 && frame[12..14] == [0x08, 0x00] && frame[23] == 1 && frame[34] == 0 {
                let icmp = &frame[34..];
                return Some((
                    u16::from_be_bytes([icmp[4], icmp[5]]),
                    u16::from_be_bytes([icmp[6], icmp[7]]),
                    icmp[8..].to_vec(),
                ));
            }
        }
        std::thread::sleep(Duration::from_millis(2));
    }
    None
}

#[test]
fn ping_to_allowed_ip_relays_with_the_guest_id_restored() {
    if !vz_net::ping::ping_supported() {
        eprintln!("skipping: no ping socket available on this host");
        return;
    }
    let (gate_end, mut guest_end) = pipe_pair();
    let _gate = Gate::spawn(
        gate_end,
        filter(&["127.0.0.1"]),
        FixedResolver(vec![]),
        GateConfig::default(),
    );
    guest_end
        .send(&echo_request_frame(Ipv4Addr::new(127, 0, 0, 1), 0xBEEF, 9, b"gate ping"))
        .expect("send echo request");
    let (id, seq, payload) =
        wait_for_echo_reply(&mut guest_end, Duration::from_secs(5)).expect("echo reply");
    assert_eq!(id, 0xBEEF, "guest id must be restored even if the kernel rewrote it");
    assert_eq!(seq, 9);
    assert_eq!(payload, b"gate ping");
}

#[test]
fn ping_to_denied_ip_is_dropped() {
    // No ping socket needed: the filter check precedes socket creation.
    let (gate_end, mut guest_end) = pipe_pair();
    let _gate = Gate::spawn(gate_end, filter(&[]), FixedResolver(vec![]), GateConfig::default());
    guest_end
        .send(&echo_request_frame(Ipv4Addr::new(127, 0, 0, 1), 1, 1, b"nope"))
        .expect("send echo request");
    assert!(
        wait_for_echo_reply(&mut guest_end, Duration::from_secs(2)).is_none(),
        "denied ping must be dropped"
    );
}

#[test]
fn garbage_frames_do_not_kill_the_gate() {
    let port = spawn_echo_server();
    let (gate_end, guest_end) = pipe_pair();
    let gate = Gate::spawn(
        gate_end,
        filter(&["127.0.0.1"]),
        FixedResolver(vec![]),
        GateConfig::default(),
    );
    let mut guest = Guest::new(guest_end);

    // Straight onto the wire: truncated, garbage, and zero-length frames.
    for frame in [vec![], vec![0xff; 9], (0..=255u8).collect::<Vec<_>>()] {
        guest.device.transport.send(&frame).expect("send garbage");
    }

    let handle = guest
        .tcp_connect(Ipv4Addr::new(127, 0, 0, 1), port)
        .expect("gate must survive garbage and still relay");
    let echoed = guest.tcp_send_and_collect(handle, b"still alive");
    assert_eq!(echoed, b"still alive");
    drop(gate);
}

#[test]
fn guest_handshake_completes_while_the_upstream_connect_pends() {
    // The gate SYN-ACKs an allowed flow immediately; the host-side connect
    // runs in parallel (TEST-NET here, so it will eventually fail and RST —
    // but the guest must not wait a connect-timeout for its handshake).
    let (_gate, mut guest) = start(&["192.0.2.9"], vec![]);
    let started = Instant::now();
    let handle = guest.tcp_connect(Ipv4Addr::new(192, 0, 2, 9), 4444);
    assert!(handle.is_some(), "allowed flow must establish against the gate");
    assert!(started.elapsed() < Duration::from_secs(3));
}
