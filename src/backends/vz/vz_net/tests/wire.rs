//! Frame-peek codec tests: the gate inspects raw ethernet frames for TCP
//! SYNs (the NAT decision point) before smoltcp processes them, and
//! synthesizes RST frames for denied destinations. Fixtures are hand-built
//! byte-exact frames.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use vz_net::wire::{
    peek_icmp_echo_request, peek_tcp_syn, peek_udp, synthesize_echo_reply, synthesize_rst,
    IcmpEchoInfo, TcpSynInfo, UdpInfo,
};

/// Build an ethernet+IPv4+TCP frame. `flags` is the TCP flags byte.
#[allow(clippy::too_many_arguments)]
fn tcp_frame(
    src_mac: [u8; 6],
    dst_mac: [u8; 6],
    src_ip: Ipv4Addr,
    dst_ip: Ipv4Addr,
    src_port: u16,
    dst_port: u16,
    seq: u32,
    flags: u8,
) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&[0x08, 0x00]); // IPv4

    let tcp_len = 20u16;
    let total_len = 20 + tcp_len;
    let mut ip = vec![
        0x45, 0, // version 4, IHL 5, DSCP
        (total_len >> 8) as u8,
        total_len as u8,
        0, 0, 0x40, 0, // id, flags: DF
        64, 6, // TTL, protocol TCP
        0, 0, // checksum (filled below)
    ];
    ip.extend_from_slice(&src_ip.octets());
    ip.extend_from_slice(&dst_ip.octets());
    let checksum = internet_checksum(&ip);
    ip[10] = (checksum >> 8) as u8;
    ip[11] = checksum as u8;
    frame.extend_from_slice(&ip);

    let mut tcp = vec![
        (src_port >> 8) as u8,
        src_port as u8,
        (dst_port >> 8) as u8,
        dst_port as u8,
    ];
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes()); // ack
    tcp.push(5 << 4); // data offset 5 words
    tcp.push(flags);
    tcp.extend_from_slice(&[0x20, 0x00, 0, 0, 0, 0]); // window, checksum, urgent
    let checksum = tcp_checksum(src_ip, dst_ip, &tcp);
    tcp[16] = (checksum >> 8) as u8;
    tcp[17] = checksum as u8;
    frame.extend_from_slice(&tcp);
    frame
}

fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum = 0u32;
    for chunk in bytes.chunks(2) {
        let word = (u32::from(chunk[0]) << 8) | u32::from(*chunk.get(1).unwrap_or(&0));
        sum += word;
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !(sum as u16)
}

fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(6);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp);
    internet_checksum(&pseudo)
}

const GUEST_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x15];
const GATE_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x02];

fn guest_ip() -> Ipv4Addr {
    Ipv4Addr::new(10, 0, 2, 15)
}

#[test]
fn syn_frame_is_detected_with_its_flow_details() {
    let dst = Ipv4Addr::new(140, 82, 112, 22);
    let frame = tcp_frame(GUEST_MAC, GATE_MAC, guest_ip(), dst, 49500, 443, 0x1000, 0x02);
    let syn = peek_tcp_syn(&frame).expect("SYN must be detected");
    assert_eq!(
        syn,
        TcpSynInfo {
            src_ip: IpAddr::V4(guest_ip()),
            dst_ip: IpAddr::V4(dst),
            src_port: 49500,
            dst_port: 443,
            seq: 0x1000,
        }
    );
}

#[test]
fn non_syn_tcp_frames_are_not_flagged() {
    let dst = Ipv4Addr::new(140, 82, 112, 22);
    for flags in [0x10u8, 0x18, 0x12, 0x04, 0x11] {
        // ACK, PSH|ACK, SYN|ACK (server-side, not a new guest flow), RST, FIN|ACK
        let frame = tcp_frame(GUEST_MAC, GATE_MAC, guest_ip(), dst, 49500, 443, 1, flags);
        assert_eq!(peek_tcp_syn(&frame), None, "flags {flags:#04x} must not match");
    }
}

#[test]
fn non_tcp_and_non_ipv4_frames_are_ignored() {
    // ARP frame
    let mut arp = Vec::new();
    arp.extend_from_slice(&GATE_MAC);
    arp.extend_from_slice(&GUEST_MAC);
    arp.extend_from_slice(&[0x08, 0x06]);
    arp.extend_from_slice(&[0u8; 28]);
    assert_eq!(peek_tcp_syn(&arp), None);

    // UDP frame: patch protocol byte and shorten
    let mut udp = tcp_frame(GUEST_MAC, GATE_MAC, guest_ip(), Ipv4Addr::new(10, 0, 2, 3), 5353, 53, 0, 0x02);
    udp[23] = 17; // protocol = UDP
    assert_eq!(peek_tcp_syn(&udp), None);
}

#[test]
fn truncated_and_garbage_frames_never_panic() {
    let good = tcp_frame(GUEST_MAC, GATE_MAC, guest_ip(), Ipv4Addr::new(1, 2, 3, 4), 1, 2, 3, 0x02);
    for len in 0..good.len() {
        let _ = peek_tcp_syn(&good[..len]);
    }
    let garbage: Vec<u8> = (0..=255).cycle().take(96).collect();
    let _ = peek_tcp_syn(&garbage);
}

#[test]
fn ip_options_shift_the_tcp_header() {
    // IHL 6 (one option word): the TCP header starts 4 bytes later.
    let base = tcp_frame(GUEST_MAC, GATE_MAC, guest_ip(), Ipv4Addr::new(9, 9, 9, 9), 7, 8, 9, 0x02);
    let mut frame = base[..14].to_vec();
    let mut ip = base[14..34].to_vec();
    ip[0] = 0x46; // IHL 6
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&[1, 1, 1, 1]); // option word (NOPs)
    frame.extend_from_slice(&base[34..]); // TCP header unchanged
    let syn = peek_tcp_syn(&frame).expect("SYN behind IP options must be detected");
    assert_eq!(syn.dst_port, 8);
}

/// Build an ethernet+IPv4+UDP frame (checksum left zero — valid for IPv4).
fn udp_frame(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, src_port: u16, dst_port: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&GATE_MAC);
    frame.extend_from_slice(&GUEST_MAC);
    frame.extend_from_slice(&[0x08, 0x00]);
    let udp_len = 8 + payload.len() as u16;
    let total_len = 20 + udp_len;
    let mut ip = vec![
        0x45, 0,
        (total_len >> 8) as u8, total_len as u8,
        0, 0, 0x40, 0,
        64, 17, 0, 0,
    ];
    ip.extend_from_slice(&src_ip.octets());
    ip.extend_from_slice(&dst_ip.octets());
    let checksum = internet_checksum(&ip);
    ip[10] = (checksum >> 8) as u8;
    ip[11] = checksum as u8;
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&src_port.to_be_bytes());
    frame.extend_from_slice(&dst_port.to_be_bytes());
    frame.extend_from_slice(&udp_len.to_be_bytes());
    frame.extend_from_slice(&[0, 0]);
    frame.extend_from_slice(payload);
    frame
}

#[test]
fn udp_frame_is_detected_with_its_flow_details() {
    let dst = Ipv4Addr::new(1, 1, 1, 1);
    let frame = udp_frame(guest_ip(), dst, 40000, 123, b"ntp-ish");
    assert_eq!(
        peek_udp(&frame),
        Some(UdpInfo {
            src_ip: IpAddr::V4(guest_ip()),
            dst_ip: IpAddr::V4(dst),
            src_port: 40000,
            dst_port: 123,
        })
    );
}

#[test]
fn peek_udp_ignores_tcp_and_garbage() {
    let tcp = tcp_frame(GUEST_MAC, GATE_MAC, guest_ip(), Ipv4Addr::new(1, 2, 3, 4), 1, 2, 3, 0x02);
    assert_eq!(peek_udp(&tcp), None);
    let good = udp_frame(guest_ip(), Ipv4Addr::new(1, 1, 1, 1), 1, 2, b"x");
    for len in 0..good.len() {
        let _ = peek_udp(&good[..len]);
    }
}

/// Build an ethernet+IPv4+ICMP echo-request frame with a valid checksum.
fn icmp_echo_frame(src_ip: Ipv4Addr, dst_ip: Ipv4Addr, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&GATE_MAC);
    frame.extend_from_slice(&GUEST_MAC);
    frame.extend_from_slice(&[0x08, 0x00]);
    let icmp_len = 8 + payload.len() as u16;
    let total_len = 20 + icmp_len;
    let mut ip = vec![
        0x45, 0,
        (total_len >> 8) as u8, total_len as u8,
        0, 0, 0x40, 0,
        64, 1, 0, 0, // TTL, protocol ICMP
    ];
    ip.extend_from_slice(&src_ip.octets());
    ip.extend_from_slice(&dst_ip.octets());
    let checksum = internet_checksum(&ip);
    ip[10] = (checksum >> 8) as u8;
    ip[11] = checksum as u8;
    frame.extend_from_slice(&ip);
    let mut icmp = vec![8, 0, 0, 0]; // echo request, checksum placeholder
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let checksum = internet_checksum(&icmp);
    icmp[2] = (checksum >> 8) as u8;
    icmp[3] = checksum as u8;
    frame.extend_from_slice(&icmp);
    frame
}

#[test]
fn icmp_echo_request_is_detected_with_id_seq_and_payload() {
    let dst = Ipv4Addr::new(1, 1, 1, 1);
    let frame = icmp_echo_frame(guest_ip(), dst, 0x1234, 7, b"ping payload");
    let echo = peek_icmp_echo_request(&frame).expect("echo request must be detected");
    assert_eq!(
        echo,
        IcmpEchoInfo {
            src_ip: IpAddr::V4(guest_ip()),
            dst_ip: IpAddr::V4(dst),
            id: 0x1234,
            seq: 7,
            payload: b"ping payload".to_vec(),
        }
    );
}

#[test]
fn icmp_non_echo_and_garbage_are_ignored() {
    // An echo REPLY (type 0) is not a request.
    let mut reply = icmp_echo_frame(guest_ip(), Ipv4Addr::new(1, 1, 1, 1), 1, 1, b"x");
    reply[34] = 0;
    assert_eq!(peek_icmp_echo_request(&reply), None);
    // TCP is not ICMP.
    let tcp = tcp_frame(GUEST_MAC, GATE_MAC, guest_ip(), Ipv4Addr::new(1, 2, 3, 4), 1, 2, 3, 0x02);
    assert_eq!(peek_icmp_echo_request(&tcp), None);
    let good = icmp_echo_frame(guest_ip(), Ipv4Addr::new(1, 1, 1, 1), 1, 1, b"abc");
    for len in 0..good.len() {
        let _ = peek_icmp_echo_request(&good[..len]);
    }
}

#[test]
fn echo_reply_frame_reverses_the_flow_with_valid_checksums() {
    let dst = Ipv4Addr::new(1, 1, 1, 1);
    let request = icmp_echo_frame(guest_ip(), dst, 0x4242, 3, b"round trip");
    let echo = peek_icmp_echo_request(&request).unwrap();
    let reply = synthesize_echo_reply(&request, &echo, b"round trip");

    assert_eq!(&reply[0..6], &GUEST_MAC, "back to the guest");
    assert_eq!(&reply[26..30], &dst.octets(), "source is the pinged host");
    assert_eq!(&reply[30..34], &guest_ip().octets());
    assert_eq!(internet_checksum(&reply[14..34]), 0, "IP checksum must verify");

    let icmp = &reply[34..];
    assert_eq!(icmp[0], 0, "type must be echo reply");
    assert_eq!(u16::from_be_bytes([icmp[4], icmp[5]]), 0x4242, "guest id restored");
    assert_eq!(u16::from_be_bytes([icmp[6], icmp[7]]), 3, "seq preserved");
    assert_eq!(&icmp[8..], b"round trip");
    assert_eq!(internet_checksum(icmp), 0, "ICMP checksum must verify");
}

#[test]
fn rst_answers_the_syn_with_swapped_flow_and_valid_checksums() {
    let dst = Ipv4Addr::new(140, 82, 112, 22);
    let syn_frame = tcp_frame(GUEST_MAC, GATE_MAC, guest_ip(), dst, 49500, 443, 0x2000, 0x02);
    let syn = peek_tcp_syn(&syn_frame).unwrap();
    let rst = synthesize_rst(&syn_frame, &syn).expect("RST synthesis");

    // Ethernet: back to the guest.
    assert_eq!(&rst[0..6], &GUEST_MAC);
    assert_eq!(&rst[6..12], &GATE_MAC);
    assert_eq!(&rst[12..14], &[0x08, 0x00]);

    // IP: swapped addresses, valid header checksum.
    assert_eq!(&rst[26..30], &dst.octets());
    assert_eq!(&rst[30..34], &guest_ip().octets());
    assert_eq!(internet_checksum(&rst[14..34]), 0, "IP checksum must verify");

    // TCP: swapped ports, RST|ACK, ack = seq+1, valid checksum.
    let tcp = &rst[34..];
    assert_eq!(u16::from_be_bytes([tcp[0], tcp[1]]), 443);
    assert_eq!(u16::from_be_bytes([tcp[2], tcp[3]]), 49500);
    assert_eq!(tcp[13] & 0x04, 0x04, "RST flag");
    assert_eq!(tcp[13] & 0x10, 0x10, "ACK flag");
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    assert_eq!(ack, 0x2001, "ack must be the SYN's seq + 1");
    assert_eq!(tcp_checksum(dst, guest_ip(), tcp), 0, "TCP checksum must verify");
}

/// Build an ethernet+IPv6+TCP frame with a valid checksum.
fn tcp6_frame(src: Ipv6Addr, dst: Ipv6Addr, src_port: u16, dst_port: u16, seq: u32, flags: u8) -> Vec<u8> {
    let mut frame = Vec::new();
    frame.extend_from_slice(&GATE_MAC);
    frame.extend_from_slice(&GUEST_MAC);
    frame.extend_from_slice(&[0x86, 0xDD]);
    let mut ip = vec![0x60, 0, 0, 0];
    ip.extend_from_slice(&20u16.to_be_bytes()); // payload length
    ip.push(6); // next header TCP
    ip.push(64);
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&ip);

    let mut tcp = Vec::new();
    tcp.extend_from_slice(&src_port.to_be_bytes());
    tcp.extend_from_slice(&dst_port.to_be_bytes());
    tcp.extend_from_slice(&seq.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes());
    tcp.push(5 << 4);
    tcp.push(flags);
    tcp.extend_from_slice(&[0x20, 0x00, 0, 0, 0, 0]);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 6]);
    pseudo.extend_from_slice(&tcp);
    let checksum = internet_checksum(&pseudo);
    tcp[16] = (checksum >> 8) as u8;
    tcp[17] = checksum as u8;
    frame.extend_from_slice(&tcp);
    frame
}

fn guest_ip6() -> Ipv6Addr {
    "fd00:6d78:63::15".parse().unwrap()
}

#[test]
fn v6_syn_is_detected() {
    let dst: Ipv6Addr = "2606:50c0:8000::153".parse().unwrap();
    let frame = tcp6_frame(guest_ip6(), dst, 50000, 443, 0x77, 0x02);
    let syn = peek_tcp_syn(&frame).expect("v6 SYN must be detected");
    assert_eq!(syn.src_ip, IpAddr::V6(guest_ip6()));
    assert_eq!(syn.dst_ip, IpAddr::V6(dst));
    assert_eq!(syn.dst_port, 443);
    for len in 0..frame.len() {
        let _ = peek_tcp_syn(&frame[..len]);
    }
}

#[test]
fn v6_rst_reverses_the_flow_with_a_valid_checksum() {
    let dst: Ipv6Addr = "2606:50c0:8000::153".parse().unwrap();
    let syn_frame = tcp6_frame(guest_ip6(), dst, 50000, 443, 0x3000, 0x02);
    let syn = peek_tcp_syn(&syn_frame).unwrap();
    let rst = synthesize_rst(&syn_frame, &syn).expect("v6 RST synthesis");

    assert_eq!(&rst[0..6], &GUEST_MAC);
    assert_eq!(&rst[12..14], &[0x86, 0xDD]);
    assert_eq!(&rst[22..38], &dst.octets(), "source is the denied destination");
    assert_eq!(&rst[38..54], &guest_ip6().octets());

    let tcp = &rst[54..];
    assert_eq!(u16::from_be_bytes([tcp[0], tcp[1]]), 443);
    assert_eq!(tcp[13] & 0x04, 0x04, "RST flag");
    let ack = u32::from_be_bytes([tcp[8], tcp[9], tcp[10], tcp[11]]);
    assert_eq!(ack, 0x3001);
    // Verify the v6 pseudo-header checksum.
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&rst[22..38]);
    pseudo.extend_from_slice(&rst[38..54]);
    pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 6]);
    pseudo.extend_from_slice(tcp);
    assert_eq!(internet_checksum(&pseudo), 0, "TCP checksum must verify");
}

#[test]
fn v6_frames_with_extension_headers_are_not_intercepted() {
    // next-header = hop-by-hop (0): the peek must not walk the chain; the
    // frame passes to smoltcp untouched.
    let dst: Ipv6Addr = "2606:50c0:8000::153".parse().unwrap();
    let mut frame = tcp6_frame(guest_ip6(), dst, 1, 2, 3, 0x02);
    frame[14 + 6] = 0; // hop-by-hop options
    assert_eq!(peek_tcp_syn(&frame), None);
    assert_eq!(peek_udp(&frame), None);
}

/// Build an ethernet+IPv6+ICMPv6 echo-request frame with a valid
/// pseudo-header checksum.
fn icmp6_echo_frame(src: Ipv6Addr, dst: Ipv6Addr, id: u16, seq: u16, payload: &[u8]) -> Vec<u8> {
    let mut icmp = vec![128u8, 0, 0, 0];
    icmp.extend_from_slice(&id.to_be_bytes());
    icmp.extend_from_slice(&seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(&icmp);
    let c = internet_checksum(&pseudo);
    icmp[2] = (c >> 8) as u8;
    icmp[3] = c as u8;

    let mut frame = Vec::new();
    frame.extend_from_slice(&GATE_MAC);
    frame.extend_from_slice(&GUEST_MAC);
    frame.extend_from_slice(&[0x86, 0xDD]);
    let mut ip = vec![0x60, 0, 0, 0];
    ip.extend_from_slice(&(icmp.len() as u16).to_be_bytes());
    ip.push(58);
    ip.push(64);
    ip.extend_from_slice(&src.octets());
    ip.extend_from_slice(&dst.octets());
    frame.extend_from_slice(&ip);
    frame.extend_from_slice(&icmp);
    frame
}

#[test]
fn v6_echo_request_is_detected() {
    let dst: Ipv6Addr = "fd00:beef::9".parse().unwrap();
    let frame = icmp6_echo_frame(guest_ip6(), dst, 0x7777, 3, b"ping6");
    let echo = peek_icmp_echo_request(&frame).expect("v6 echo request must be detected");
    assert_eq!(echo.src_ip, IpAddr::V6(guest_ip6()));
    assert_eq!(echo.dst_ip, IpAddr::V6(dst));
    assert_eq!(echo.id, 0x7777);
    assert_eq!(echo.payload, b"ping6");
    // NDP must never be intercepted: type 135 (neighbor solicitation).
    let mut ns = frame.clone();
    ns[54] = 135;
    assert_eq!(peek_icmp_echo_request(&ns), None);
    for len in 0..frame.len() {
        let _ = peek_icmp_echo_request(&frame[..len]);
    }
}

#[test]
fn v6_echo_reply_frame_has_a_valid_pseudo_header_checksum() {
    let dst: Ipv6Addr = "fd00:beef::9".parse().unwrap();
    let request = icmp6_echo_frame(guest_ip6(), dst, 0x4141, 5, b"v6 round trip");
    let echo = peek_icmp_echo_request(&request).unwrap();
    let reply = synthesize_echo_reply(&request, &echo, b"v6 round trip");

    assert_eq!(&reply[0..6], &GUEST_MAC);
    assert_eq!(&reply[12..14], &[0x86, 0xDD]);
    assert_eq!(&reply[22..38], &dst.octets(), "source is the pinged host");
    assert_eq!(&reply[38..54], &guest_ip6().octets());

    let icmp = &reply[54..];
    assert_eq!(icmp[0], 129, "ICMPv6 echo reply");
    assert_eq!(u16::from_be_bytes([icmp[4], icmp[5]]), 0x4141, "guest id restored");
    assert_eq!(&icmp[8..], b"v6 round trip");
    let mut pseudo = Vec::new();
    pseudo.extend_from_slice(&reply[22..38]);
    pseudo.extend_from_slice(&reply[38..54]);
    pseudo.extend_from_slice(&(icmp.len() as u32).to_be_bytes());
    pseudo.extend_from_slice(&[0, 0, 0, 58]);
    pseudo.extend_from_slice(icmp);
    assert_eq!(internet_checksum(&pseudo), 0, "ICMPv6 checksum must verify");
}
