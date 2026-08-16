//! Frame-peek codec tests: the gate inspects raw ethernet frames for TCP
//! SYNs (the NAT decision point) before smoltcp processes them, and
//! synthesizes RST frames for denied destinations. Fixtures are hand-built
//! byte-exact frames.

use std::net::Ipv4Addr;

use vz_net::wire::{peek_tcp_syn, peek_udp, synthesize_rst, TcpSynInfo, UdpInfo};

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
            src_ip: guest_ip(),
            dst_ip: dst,
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
            src_ip: guest_ip(),
            dst_ip: dst,
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
