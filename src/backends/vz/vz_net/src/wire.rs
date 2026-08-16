//! Minimal raw-frame inspection for the gate's NAT decision point.
//!
//! The gate peeks every guest frame for a TCP SYN *before* smoltcp
//! processes it: an allowed destination gets a dynamically-created listener
//! (the tun2proxy pattern), a denied one gets a synthesized RST. Only the
//! few header fields needed for that decision are parsed; everything else —
//! ARP, established flows, reassembly — belongs to smoltcp. Parsers must
//! tolerate arbitrary bytes (a hostile guest owns the frame contents).

use std::net::Ipv4Addr;

const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_RST: u8 = 0x04;

/// A new outbound TCP flow attempt observed on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSynInfo {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
}

/// If `frame` is an ethernet/IPv4/TCP segment with SYN set and ACK clear (a
/// connection-opening SYN, not a SYN|ACK), return its flow details.
pub fn peek_tcp_syn(frame: &[u8]) -> Option<TcpSynInfo> {
    let (ip, _) = ipv4_slices(frame)?;
    if ip[9] != IP_PROTO_TCP {
        return None;
    }
    let tcp = tcp_slice(frame)?;
    let flags = tcp[13];
    if flags & TCP_FLAG_SYN == 0 || flags & TCP_FLAG_ACK != 0 || flags & TCP_FLAG_RST != 0 {
        return None;
    }
    Some(TcpSynInfo {
        src_ip: Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        dst_ip: Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
    })
}

/// A UDP datagram observed on the wire (the UDP-relay decision point).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpInfo {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub src_port: u16,
    pub dst_port: u16,
}

/// If `frame` is an ethernet/IPv4/UDP datagram, return its flow details.
pub fn peek_udp(frame: &[u8]) -> Option<UdpInfo> {
    let (ip, payload_at) = ipv4_slices(frame)?;
    if ip[9] != IP_PROTO_UDP {
        return None;
    }
    let udp = frame.get(payload_at..)?;
    if udp.len() < 8 {
        return None;
    }
    Some(UdpInfo {
        src_ip: Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        dst_ip: Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        src_port: u16::from_be_bytes([udp[0], udp[1]]),
        dst_port: u16::from_be_bytes([udp[2], udp[3]]),
    })
}

/// Build the RST answering a denied SYN: flow reversed, `RST|ACK` with
/// `ack = seq + 1`, checksums valid. Returns a complete ethernet frame.
pub fn synthesize_rst(syn_frame: &[u8], syn: &TcpSynInfo) -> Option<Vec<u8>> {
    // 54 = 14 ethernet + 20 IP + 20 TCP; the SYN was already validated to
    // reach the TCP header, so this only fails on a truncated ethernet part.
    if syn_frame.len() < 14 {
        return None;
    }

    let mut frame = Vec::with_capacity(54);
    // Ethernet: send back to where the SYN came from.
    frame.extend_from_slice(&syn_frame[6..12]); // dst = guest MAC
    frame.extend_from_slice(&syn_frame[0..6]); // src = gate MAC
    frame.extend_from_slice(&ETHERTYPE_IPV4);

    let mut ip = vec![
        0x45, 0, 0, 40, // version/IHL, DSCP, total length (20+20)
        0, 0, 0x40, 0, // id, DF
        64, IP_PROTO_TCP, 0, 0, // TTL, proto, checksum placeholder
    ];
    ip.extend_from_slice(&syn.dst_ip.octets()); // src = the denied destination
    ip.extend_from_slice(&syn.src_ip.octets()); // dst = the guest
    let checksum = internet_checksum(&ip);
    ip[10] = (checksum >> 8) as u8;
    ip[11] = checksum as u8;
    frame.extend_from_slice(&ip);

    let mut tcp = Vec::with_capacity(20);
    tcp.extend_from_slice(&syn.dst_port.to_be_bytes());
    tcp.extend_from_slice(&syn.src_port.to_be_bytes());
    tcp.extend_from_slice(&0u32.to_be_bytes()); // seq
    tcp.extend_from_slice(&syn.seq.wrapping_add(1).to_be_bytes()); // ack
    tcp.push(5 << 4); // data offset
    tcp.push(TCP_FLAG_RST | TCP_FLAG_ACK);
    tcp.extend_from_slice(&[0, 0, 0, 0, 0, 0]); // window, checksum, urgent
    let checksum = tcp_checksum(syn.dst_ip, syn.src_ip, &tcp);
    tcp[16] = (checksum >> 8) as u8;
    tcp[17] = checksum as u8;
    frame.extend_from_slice(&tcp);

    Some(frame)
}

/// Ethernet + IPv4 header validation: returns (ip_header, payload_offset).
fn ipv4_slices(frame: &[u8]) -> Option<(&[u8], usize)> {
    if frame.len() < 14 + 20 || frame[12..14] != ETHERTYPE_IPV4 {
        return None;
    }
    let ip = &frame[14..];
    if ip[0] >> 4 != 4 {
        return None;
    }
    let header_len = usize::from(ip[0] & 0x0f) * 4;
    if header_len < 20 || ip.len() < header_len {
        return None;
    }
    Some((&frame[14..14 + header_len], 14 + header_len))
}

fn tcp_slice(frame: &[u8]) -> Option<&[u8]> {
    let (_, offset) = ipv4_slices(frame)?;
    let tcp = frame.get(offset..)?;
    if tcp.len() < 20 {
        return None;
    }
    Some(tcp)
}

pub(crate) fn internet_checksum(bytes: &[u8]) -> u16 {
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

pub(crate) fn tcp_checksum(src: Ipv4Addr, dst: Ipv4Addr, tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + tcp.len());
    pseudo.extend_from_slice(&src.octets());
    pseudo.extend_from_slice(&dst.octets());
    pseudo.push(0);
    pseudo.push(IP_PROTO_TCP);
    pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(tcp);
    internet_checksum(&pseudo)
}
