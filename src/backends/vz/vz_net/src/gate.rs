//! The egress gate: a userspace network stack on the host side of the
//! guest's frame stream, enforcing `allowedHosts` at L3/L4 (TM-01).
//!
//! Every guest frame passes through here — there is no other path off the
//! VM. The gate is the guest's gateway and DNS server:
//!
//! - **TCP NAT (tun2proxy pattern):** each frame is peeked for a SYN before
//!   smoltcp sees it. A SYN to an allowed destination dynamically creates a
//!   listener for exactly that flow (`any_ip` lets smoltcp accept traffic
//!   addressed to arbitrary IPs) and a host-side connection to the real
//!   destination; bytes relay between the two. A SYN to a denied
//!   destination is answered with a synthesized RST and never reaches the
//!   stack.
//! - **DNS proxy:** the gate owns `dns_ip:53`. Queries for allow-listed
//!   names resolve on the host and the answers populate the filter's
//!   dynamic set ([`EgressFilter::observe_dns`]) before the guest hears
//!   them; anything else is REFUSED. DNS never *grants* anything by itself
//!   — the connect-time IP check is the control.
//! - **UDP relay:** datagrams to allowed destinations get per-flow NAT
//!   state (guest endpoint ↔ a connected host socket) with idle expiry;
//!   the allowed-IP set is protocol-agnostic, so DNS-observed IPs admit
//!   UDP the same as TCP (upstream lxc parity: host rules match all ports
//!   and protocols). Datagrams to denied destinations are dropped
//!   silently — standard NAT behavior for filtered UDP.
//! - **ICMP echo relay:** pings to allowed destinations relay through a
//!   host ping socket (see [`crate::ping`] for the privilege ladder); the
//!   guest's echo id is restored on replies. Denied pings — and hosts
//!   where no ping socket is available — drop (fail closed). Any other IP
//!   protocol is dropped: the gate is a terminating NAT, not a packet
//!   filter, so each protocol is opt-in.

use std::collections::{HashMap, VecDeque};
use std::io::{self, Read as _, Write as _};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::Duration;

use smoltcp::iface::{Config, Interface, PollResult, SocketHandle, SocketSet};
use smoltcp::phy::{Device, DeviceCapabilities, Medium, RxToken, TxToken};
use smoltcp::socket::{tcp, udp};
use smoltcp::time::Instant as SmolInstant;
use smoltcp::wire::{EthernetAddress, HardwareAddress, IpAddress, IpCidr, IpListenEndpoint};

use crate::dns::{build_refused, build_response, parse_query};
use crate::filter::EgressFilter;
use crate::ping::PingSocket;
use crate::wire::{
    peek_icmp_echo_request, peek_tcp_syn, peek_udp, synthesize_echo_reply, synthesize_rst,
    IcmpEchoInfo,
};

/// One ethernet frame per call, non-blocking receive. Implementations wrap
/// a `SOCK_DGRAM` socketpair end (VZ file-handle attachment), a UDP socket
/// (QEMU dgram netdev), or an in-memory pipe (tests).
pub trait FrameTransport: Send + 'static {
    /// Receive one frame into `buf`; `Ok(None)` when nothing is pending.
    fn recv(&mut self, buf: &mut [u8]) -> io::Result<Option<usize>>;
    fn send(&mut self, frame: &[u8]) -> io::Result<()>;
}

/// Host-side name resolution, injected so tests never touch real DNS.
pub trait Resolver: Send + Sync + 'static {
    fn resolve(&self, name: &str) -> Vec<IpAddr>;
}

/// Resolves via the host's system resolver. `ToSocketAddrs` exposes no
/// record TTLs, so answers use [`DNS_ANSWER_TTL`]; the filter's own clamp
/// bounds the grant either way.
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, name: &str) -> Vec<IpAddr> {
        (name, 0u16)
            .to_socket_addrs()
            .map(|addrs| addrs.map(|a| a.ip()).collect())
            .unwrap_or_default()
    }
}

/// TTL stamped on gate DNS answers and fed to `observe_dns`.
pub const DNS_ANSWER_TTL: Duration = Duration::from_secs(60);

/// Gate network identity. Defaults mirror the guest's static config
/// (`scripts/guest-init.sh`): guest 10.0.2.15/24, gateway .2, DNS .3.
#[derive(Debug, Clone)]
pub struct GateConfig {
    pub gateway_ip: core::net::Ipv4Addr,
    pub dns_ip: core::net::Ipv4Addr,
    pub prefix_len: u8,
    /// Idle timeout for UDP NAT flows; an expired flow's next datagram
    /// simply re-NATs.
    pub udp_idle: Duration,
}

impl Default for GateConfig {
    fn default() -> Self {
        Self {
            gateway_ip: core::net::Ipv4Addr::new(10, 0, 2, 2),
            dns_ip: core::net::Ipv4Addr::new(10, 0, 2, 3),
            prefix_len: 24,
            udp_idle: Duration::from_secs(30),
        }
    }
}

const GATE_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];
const TCP_BUFFER: usize = 64 * 1024;
const IDLE_SLEEP: Duration = Duration::from_millis(5);

/// A running gate; dropping shuts the event loop down and joins it.
pub struct Gate {
    shutdown: Arc<AtomicBool>,
    thread: Option<JoinHandle<()>>,
}

impl Gate {
    pub fn spawn(
        transport: impl FrameTransport,
        filter: EgressFilter,
        resolver: impl Resolver,
        config: GateConfig,
    ) -> Self {
        let shutdown = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&shutdown);
        let thread = std::thread::spawn(move || {
            event_loop(transport, filter, Arc::new(resolver), config, &flag);
        });
        Self { shutdown, thread: Some(thread) }
    }
}

impl Drop for Gate {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::SeqCst);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// smoltcp device over the transport plus an injection queue: frames are
/// drained from the transport by the event loop (which peeks SYNs first)
/// and only then offered to the stack.
struct GateDevice<T: FrameTransport> {
    transport: T,
    rx: VecDeque<Vec<u8>>,
}

struct GateRxToken(Vec<u8>);

impl RxToken for GateRxToken {
    fn consume<R, F>(self, f: F) -> R
    where
        F: FnOnce(&[u8]) -> R,
    {
        f(&self.0)
    }
}

struct GateTxToken<'a, T: FrameTransport>(&'a mut T);

impl<T: FrameTransport> TxToken for GateTxToken<'_, T> {
    fn consume<R, F>(self, len: usize, f: F) -> R
    where
        F: FnOnce(&mut [u8]) -> R,
    {
        let mut frame = vec![0u8; len];
        let result = f(&mut frame);
        let _ = self.0.send(&frame);
        result
    }
}

impl<T: FrameTransport> Device for GateDevice<T> {
    type RxToken<'a>
        = GateRxToken
    where
        Self: 'a;
    type TxToken<'a>
        = GateTxToken<'a, T>
    where
        Self: 'a;

    fn receive(&mut self, _timestamp: SmolInstant) -> Option<(Self::RxToken<'_>, Self::TxToken<'_>)> {
        let frame = self.rx.pop_front()?;
        Some((GateRxToken(frame), GateTxToken(&mut self.transport)))
    }

    fn transmit(&mut self, _timestamp: SmolInstant) -> Option<Self::TxToken<'_>> {
        Some(GateTxToken(&mut self.transport))
    }

    fn capabilities(&self) -> DeviceCapabilities {
        let mut caps = DeviceCapabilities::default();
        caps.medium = Medium::Ethernet;
        caps.max_transmission_unit = 1514;
        caps
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct FlowKey {
    guest_port: u16,
    dst_ip: core::net::Ipv4Addr,
    dst_port: u16,
}

enum FlowState {
    /// Host-side connect running on its own thread (std connect is
    /// blocking); the guest-side handshake completes meanwhile.
    AwaitUpstream(Receiver<io::Result<TcpStream>>),
    Relaying {
        upstream: TcpStream,
        /// Bytes received from the guest not yet written upstream.
        pending_to_upstream: Vec<u8>,
    },
}

struct Flow {
    key: FlowKey,
    state: FlowState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct UdpKey {
    guest_port: u16,
    dst_ip: core::net::Ipv4Addr,
    dst_port: u16,
}

struct UdpFlow {
    handle: SocketHandle,
    host: std::net::UdpSocket,
    guest: smoltcp::wire::IpEndpoint,
    last_activity: std::time::Instant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
struct IcmpKey {
    dst_ip: core::net::Ipv4Addr,
    guest_id: u16,
}

struct IcmpFlow {
    socket: PingSocket,
    /// Template for reply synthesis: MACs and addressing from the request
    /// frame, guest id to restore. seq/payload come from each reply.
    template: IcmpEchoInfo,
    frame_head: Vec<u8>,
    last_activity: std::time::Instant,
}

#[allow(clippy::too_many_lines)]
fn event_loop(
    transport: impl FrameTransport,
    mut filter: EgressFilter,
    resolver: Arc<impl Resolver>,
    config: GateConfig,
    shutdown: &AtomicBool,
) {
    let mut device = GateDevice { transport, rx: VecDeque::new() };

    let mut iface_config = Config::new(HardwareAddress::Ethernet(EthernetAddress(GATE_MAC)));
    iface_config.random_seed = 0x76_7a_6e_65_74; // deterministic; no entropy needed
    let mut iface = Interface::new(iface_config, &mut device, SmolInstant::now());
    iface.update_ip_addrs(|addrs| {
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(config.gateway_ip), config.prefix_len));
        let _ = addrs.push(IpCidr::new(IpAddress::Ipv4(config.dns_ip), config.prefix_len));
    });
    // The NAT accepts flows addressed to arbitrary destination IPs. any_ip
    // alone is not enough: smoltcp also requires the destination to route
    // to one of the interface's own addresses, so the gate carries a
    // default route pointing at itself.
    iface.set_any_ip(true);
    iface
        .routes_mut()
        .add_default_ipv4_route(config.gateway_ip)
        .expect("add gate self-route");

    let mut sockets = SocketSet::new(vec![]);
    let dns_handle = {
        let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 8192]);
        let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 8192]);
        let mut socket = udp::Socket::new(rx, tx);
        socket
            .bind(IpListenEndpoint { addr: Some(IpAddress::Ipv4(config.dns_ip)), port: 53 })
            .expect("bind gate DNS socket");
        sockets.add(socket)
    };

    let mut flows: HashMap<SocketHandle, Flow> = HashMap::new();
    let mut flow_keys: HashMap<FlowKey, SocketHandle> = HashMap::new();
    let mut udp_flows: HashMap<UdpKey, UdpFlow> = HashMap::new();
    let mut icmp_flows: HashMap<IcmpKey, IcmpFlow> = HashMap::new();
    type DnsReply = (crate::dns::DnsQuery, Vec<IpAddr>, smoltcp::wire::IpEndpoint);
    let (dns_tx, dns_rx): (Sender<DnsReply>, Receiver<DnsReply>) = mpsc::channel();

    let mut frame_buf = vec![0u8; 2048];
    while !shutdown.load(Ordering::SeqCst) {
        let mut did_work = false;

        // ── Drain the transport, peeking SYNs before the stack sees them ──
        while let Ok(Some(len)) = device.transport.recv(&mut frame_buf) {
            did_work = true;
            let frame = &frame_buf[..len];
            if let Some(syn) = peek_tcp_syn(frame) {
                let key = FlowKey {
                    guest_port: syn.src_port,
                    dst_ip: syn.dst_ip,
                    dst_port: syn.dst_port,
                };
                if let std::collections::hash_map::Entry::Vacant(entry) = flow_keys.entry(key) {
                    if !filter.allows_ip(IpAddr::V4(syn.dst_ip), std::time::Instant::now()) {
                        // Denied: RST straight back; the stack never sees it.
                        if let Some(rst) = synthesize_rst(frame, &syn) {
                            let _ = device.transport.send(&rst);
                        }
                        continue;
                    }
                    // Allowed: listener for exactly this flow + host-side
                    // connect in parallel with the guest handshake.
                    let mut socket = tcp::Socket::new(
                        tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                        tcp::SocketBuffer::new(vec![0; TCP_BUFFER]),
                    );
                    let listen = IpListenEndpoint {
                        addr: Some(IpAddress::Ipv4(syn.dst_ip)),
                        port: syn.dst_port,
                    };
                    if socket.listen(listen).is_ok() {
                        let handle = sockets.add(socket);
                        let (tx, rx) = mpsc::channel();
                        let dst = SocketAddr::new(IpAddr::V4(syn.dst_ip), syn.dst_port);
                        std::thread::spawn(move || {
                            let _ = tx.send(TcpStream::connect_timeout(
                                &dst,
                                Duration::from_secs(10),
                            ));
                        });
                        entry.insert(handle);
                        flows.insert(handle, Flow { key, state: FlowState::AwaitUpstream(rx) });
                    }
                }
            }
            if let Some(udp_info) = peek_udp(frame) {
                let to_dns_proxy =
                    udp_info.dst_ip == config.dns_ip && udp_info.dst_port == 53;
                if !to_dns_proxy {
                    if udp_info.dst_ip == config.gateway_ip || udp_info.dst_ip == config.dns_ip {
                        // No other services on the gate's own addresses.
                        continue;
                    }
                    let key = UdpKey {
                        guest_port: udp_info.src_port,
                        dst_ip: udp_info.dst_ip,
                        dst_port: udp_info.dst_port,
                    };
                    match udp_flows.entry(key) {
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            let now = std::time::Instant::now();
                            if !filter.allows_ip(IpAddr::V4(udp_info.dst_ip), now) {
                                // Denied UDP is dropped silently — standard
                                // NAT behavior for filtered datagrams.
                                continue;
                            }
                            let Some(flow) = open_udp_flow(&mut sockets, &udp_info) else {
                                continue;
                            };
                            entry.insert(flow);
                        }
                        std::collections::hash_map::Entry::Occupied(mut entry) => {
                            entry.get_mut().last_activity = std::time::Instant::now();
                        }
                    }
                }
            }
            if let Some(echo) = peek_icmp_echo_request(frame) {
                // Fully handled here (smoltcp never sees pings): allowed →
                // relay via a host ping socket; denied or no socket → drop.
                if !filter.allows_ip(IpAddr::V4(echo.dst_ip), std::time::Instant::now()) {
                    continue;
                }
                let key = IcmpKey { dst_ip: echo.dst_ip, guest_id: echo.id };
                let flow = match icmp_flows.entry(key) {
                    std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        let Ok(socket) = PingSocket::open(echo.dst_ip) else {
                            continue;
                        };
                        entry.insert(IcmpFlow {
                            socket,
                            template: echo.clone(),
                            frame_head: frame[..14.min(frame.len())].to_vec(),
                            last_activity: std::time::Instant::now(),
                        })
                    }
                };
                let mut packet = vec![8u8, 0, 0, 0];
                packet.extend_from_slice(&echo.id.to_be_bytes());
                packet.extend_from_slice(&echo.seq.to_be_bytes());
                packet.extend_from_slice(&echo.payload);
                let checksum = crate::wire::internet_checksum(&packet);
                packet[2] = (checksum >> 8) as u8;
                packet[3] = checksum as u8;
                let _ = flow.socket.send(&packet);
                flow.last_activity = std::time::Instant::now();
                did_work = true;
                continue;
            }
            device.rx.push_back(frame.to_vec());
        }

        let poll = iface.poll(SmolInstant::now(), &mut device, &mut sockets);
        did_work |= poll != PollResult::None;

        // ── DNS: refuse non-allowed names inline, resolve allowed ones on
        // worker threads, and answer (populating the filter) as results land ──
        loop {
            let socket = sockets.get_mut::<udp::Socket>(dns_handle);
            let Ok((packet, meta)) = socket.recv().map(|(p, m)| (p.to_vec(), m)) else {
                break;
            };
            did_work = true;
            let Some(query) = parse_query(&packet) else { continue };
            if !filter.matches_hostname(&query.name) {
                let _ = socket.send_slice(&build_refused(&query), meta.endpoint);
                continue;
            }
            let resolver = Arc::clone(&resolver);
            let tx = dns_tx.clone();
            std::thread::spawn(move || {
                let ips = resolver.resolve(&query.name);
                let _ = tx.send((query, ips, meta.endpoint));
            });
        }
        while let Ok((query, ips, endpoint)) = dns_rx.try_recv() {
            did_work = true;
            let now = std::time::Instant::now();
            for ip in &ips {
                // Populate-before-answer: by the time the guest can act on
                // the response, the connect-time check will admit these IPs.
                filter.observe_dns(&query.name, *ip, DNS_ANSWER_TTL, now);
            }
            let response = build_response(&query, &ips, DNS_ANSWER_TTL.as_secs() as u32);
            let socket = sockets.get_mut::<udp::Socket>(dns_handle);
            let _ = socket.send_slice(&response, endpoint);
        }

        // ── Relay UDP flows and expire idle ones ──
        let udp_now = std::time::Instant::now();
        let mut expired: Vec<UdpKey> = Vec::new();
        for (key, flow) in udp_flows.iter_mut() {
            let socket = sockets.get_mut::<udp::Socket>(flow.handle);
            // Guest → host.
            while let Ok((payload, _)) = socket.recv() {
                let _ = flow.host.send(payload);
                flow.last_activity = udp_now;
                did_work = true;
            }
            // Host → guest, bounded by what the socket can queue.
            let mut buf = [0u8; 2048];
            loop {
                if !socket.can_send() {
                    break;
                }
                match flow.host.recv(&mut buf) {
                    Ok(n) => {
                        let _ = socket.send_slice(&buf[..n], flow.guest);
                        flow.last_activity = udp_now;
                        did_work = true;
                    }
                    Err(_) => break,
                }
            }
            if udp_now.duration_since(flow.last_activity) > config.udp_idle {
                expired.push(*key);
            }
        }
        for key in expired {
            if let Some(flow) = udp_flows.remove(&key) {
                sockets.remove(flow.handle);
            }
        }

        // ── Relay ICMP echo replies and expire idle ping flows ──
        let mut expired_pings: Vec<IcmpKey> = Vec::new();
        for (key, flow) in icmp_flows.iter_mut() {
            while let Ok(Some(packet)) = flow.socket.recv() {
                // Bare ICMP; only echo replies go back to the guest.
                if packet.len() < 8 || packet[0] != 0 {
                    continue;
                }
                let mut template = flow.template.clone();
                template.seq = u16::from_be_bytes([packet[6], packet[7]]);
                let reply = synthesize_echo_reply(&flow.frame_head, &template, &packet[8..]);
                let _ = device.transport.send(&reply);
                flow.last_activity = udp_now;
                did_work = true;
            }
            if udp_now.duration_since(flow.last_activity) > config.udp_idle {
                expired_pings.push(*key);
            }
        }
        for key in expired_pings {
            icmp_flows.remove(&key);
        }

        // ── Relay established flows ──
        let mut finished: Vec<SocketHandle> = Vec::new();
        for (&handle, flow) in flows.iter_mut() {
            let socket = sockets.get_mut::<tcp::Socket>(handle);
            match &mut flow.state {
                FlowState::AwaitUpstream(rx) => match rx.try_recv() {
                    Ok(Ok(upstream)) => {
                        let _ = upstream.set_nonblocking(true);
                        flow.state = FlowState::Relaying { upstream, pending_to_upstream: Vec::new() };
                        did_work = true;
                    }
                    Ok(Err(_)) => {
                        // Destination allowed but unreachable: RST the guest.
                        socket.abort();
                        finished.push(handle);
                        did_work = true;
                    }
                    Err(TryRecvError::Empty) => {}
                    Err(TryRecvError::Disconnected) => {
                        socket.abort();
                        finished.push(handle);
                    }
                },
                FlowState::Relaying { upstream, pending_to_upstream } => {
                    did_work |= relay_once(socket, upstream, pending_to_upstream);
                    let guest_done = !socket.is_active();
                    let drained = pending_to_upstream.is_empty() && !socket.can_recv();
                    if guest_done && drained {
                        finished.push(handle);
                    }
                }
            }
        }
        for handle in finished {
            if let Some(flow) = flows.remove(&handle) {
                flow_keys.remove(&flow.key);
            }
            sockets.remove(handle);
        }

        if !did_work {
            std::thread::sleep(IDLE_SLEEP);
        }
    }
}

/// One relay round for a flow; returns whether any bytes moved.
fn relay_once(
    socket: &mut tcp::Socket,
    upstream: &mut TcpStream,
    pending_to_upstream: &mut Vec<u8>,
) -> bool {
    let mut moved = false;

    // Guest → upstream. Retry pending bytes first, then pull more.
    loop {
        if pending_to_upstream.is_empty() {
            if !socket.can_recv() {
                break;
            }
            let taken = socket
                .recv(|buf| (buf.len(), buf.to_vec()))
                .unwrap_or_default();
            if taken.is_empty() {
                break;
            }
            *pending_to_upstream = taken;
        }
        match upstream.write(pending_to_upstream) {
            Ok(0) => {
                socket.close();
                break;
            }
            Ok(n) => {
                pending_to_upstream.drain(..n);
                moved = true;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => {
                socket.abort();
                break;
            }
        }
    }

    // Upstream → guest, bounded by the socket's free send capacity.
    let mut buf = [0u8; 4096];
    while socket.can_send() {
        let room = socket.send_capacity() - socket.send_queue();
        if room == 0 {
            break;
        }
        let take = room.min(buf.len());
        match upstream.read(&mut buf[..take]) {
            Ok(0) => {
                // Upstream EOF: half-close toward the guest.
                socket.close();
                break;
            }
            Ok(n) => {
                let _ = socket.send_slice(&buf[..n]);
                moved = true;
            }
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => break,
            Err(_) => {
                socket.abort();
                break;
            }
        }
    }

    moved
}

/// NAT state for one guest UDP flow: a smoltcp socket owning the
/// destination endpoint (`any_ip`) paired with a connected, non-blocking
/// host socket. Returns None if the host side cannot be set up (the frame
/// is then dropped; the guest retries and re-NATs).
fn open_udp_flow(
    sockets: &mut SocketSet<'_>,
    info: &crate::wire::UdpInfo,
) -> Option<UdpFlow> {
    let host = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    host.connect((info.dst_ip, info.dst_port)).ok()?;
    host.set_nonblocking(true).ok()?;

    let rx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 16384]);
    let tx = udp::PacketBuffer::new(vec![udp::PacketMetadata::EMPTY; 16], vec![0; 16384]);
    let mut socket = udp::Socket::new(rx, tx);
    socket
        .bind(IpListenEndpoint { addr: Some(IpAddress::Ipv4(info.dst_ip)), port: info.dst_port })
        .ok()?;
    let handle = sockets.add(socket);

    Some(UdpFlow {
        handle,
        host,
        guest: smoltcp::wire::IpEndpoint::new(IpAddress::Ipv4(info.src_ip), info.src_port),
        last_activity: std::time::Instant::now(),
    })
}
