//! Minimal raw-frame inspection for the gate's NAT decision point.
//!
//! The gate peeks every guest frame for a TCP SYN *before* smoltcp
//! processes it: an allowed destination gets a dynamically-created listener
//! (the tun2proxy pattern), a denied one gets a synthesized RST. Only the
//! few header fields needed for that decision are parsed; everything else —
//! ARP, established flows, reassembly — belongs to smoltcp. Parsers must
//! tolerate arbitrary bytes (a hostile guest owns the frame contents).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

const ETHERTYPE_IPV4: [u8; 2] = [0x08, 0x00];
const ETHERTYPE_IPV6: [u8; 2] = [0x86, 0xDD];
const IP_PROTO_ICMP: u8 = 1;
const IP_PROTO_TCP: u8 = 6;
const IP_PROTO_UDP: u8 = 17;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;
const TCP_FLAG_RST: u8 = 0x04;

/// A new outbound TCP flow attempt observed on the wire (v4 or v6).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSynInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub seq: u32,
}

/// If `frame` is an ethernet IPv4-or-IPv6 TCP segment with SYN set and ACK
/// clear (a connection-opening SYN, not a SYN|ACK), return its flow
/// details. IPv6 extension headers are not walked: such frames are simply
/// not intercepted (they still reach the stack).
pub fn peek_tcp_syn(frame: &[u8]) -> Option<TcpSynInfo> {
    let (src_ip, dst_ip, proto, payload_at) = ip_slices(frame)?;
    if proto != IP_PROTO_TCP {
        return None;
    }
    let tcp = frame.get(payload_at..)?;
    if tcp.len() < 20 {
        return None;
    }
    let flags = tcp[13];
    if flags & TCP_FLAG_SYN == 0 || flags & TCP_FLAG_ACK != 0 || flags & TCP_FLAG_RST != 0 {
        return None;
    }
    Some(TcpSynInfo {
        src_ip,
        dst_ip,
        src_port: u16::from_be_bytes([tcp[0], tcp[1]]),
        dst_port: u16::from_be_bytes([tcp[2], tcp[3]]),
        seq: u32::from_be_bytes([tcp[4], tcp[5], tcp[6], tcp[7]]),
    })
}

/// Version-dispatching header parse: (src, dst, protocol, payload offset).
fn ip_slices(frame: &[u8]) -> Option<(IpAddr, IpAddr, u8, usize)> {
    if frame.len() < 14 {
        return None;
    }
    if frame[12..14] == ETHERTYPE_IPV4 {
        let (ip, payload_at) = ipv4_slices(frame)?;
        return Some((
            IpAddr::V4(Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15])),
            IpAddr::V4(Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19])),
            ip[9],
            payload_at,
        ));
    }
    if frame[12..14] == ETHERTYPE_IPV6 {
        let ip = frame.get(14..14 + 40)?;
        if ip[0] >> 4 != 6 {
            return None;
        }
        let mut src = [0u8; 16];
        src.copy_from_slice(&ip[8..24]);
        let mut dst = [0u8; 16];
        dst.copy_from_slice(&ip[24..40]);
        return Some((
            IpAddr::V6(Ipv6Addr::from(src)),
            IpAddr::V6(Ipv6Addr::from(dst)),
            ip[6], // next header; extension chains fail the proto match
            14 + 40,
        ));
    }
    None
}

/// A UDP datagram observed on the wire (the UDP-relay decision point).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UdpInfo {
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
}

/// If `frame` is an ethernet IPv4-or-IPv6 UDP datagram, return its flow
/// details.
pub fn peek_udp(frame: &[u8]) -> Option<UdpInfo> {
    let (src_ip, dst_ip, proto, payload_at) = ip_slices(frame)?;
    if proto != IP_PROTO_UDP {
        return None;
    }
    let udp = frame.get(payload_at..)?;
    if udp.len() < 8 {
        return None;
    }
    Some(UdpInfo {
        src_ip,
        dst_ip,
        src_port: u16::from_be_bytes([udp[0], udp[1]]),
        dst_port: u16::from_be_bytes([udp[2], udp[3]]),
    })
}

/// An ICMP echo request observed on the wire (the ping-relay decision
/// point). The payload is owned: the relay forwards it to the host ping
/// socket and must echo it back verbatim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IcmpEchoInfo {
    pub src_ip: Ipv4Addr,
    pub dst_ip: Ipv4Addr,
    pub id: u16,
    pub seq: u16,
    pub payload: Vec<u8>,
}

/// If `frame` is an ethernet/IPv4/ICMP **echo request** (type 8, code 0),
/// return its details. Other ICMP types are not relayed.
pub fn peek_icmp_echo_request(frame: &[u8]) -> Option<IcmpEchoInfo> {
    let (ip, payload_at) = ipv4_slices(frame)?;
    if ip[9] != IP_PROTO_ICMP {
        return None;
    }
    let icmp = frame.get(payload_at..)?;
    if icmp.len() < 8 || icmp[0] != 8 || icmp[1] != 0 {
        return None;
    }
    Some(IcmpEchoInfo {
        src_ip: Ipv4Addr::new(ip[12], ip[13], ip[14], ip[15]),
        dst_ip: Ipv4Addr::new(ip[16], ip[17], ip[18], ip[19]),
        id: u16::from_be_bytes([icmp[4], icmp[5]]),
        seq: u16::from_be_bytes([icmp[6], icmp[7]]),
        payload: icmp[8..].to_vec(),
    })
}

/// Build the echo-reply frame answering `echo`, carrying `payload` (the
/// bytes the real destination echoed) with the guest's original id/seq.
/// The request frame supplies the MACs to reverse.
pub fn synthesize_echo_reply(request_frame: &[u8], echo: &IcmpEchoInfo, payload: &[u8]) -> Vec<u8> {
    let icmp_len = 8 + payload.len();
    let total_len = 20 + icmp_len;

    let mut frame = Vec::with_capacity(14 + total_len);
    frame.extend_from_slice(&request_frame[6..12]); // dst = guest MAC
    frame.extend_from_slice(&request_frame[0..6]); // src = gate MAC
    frame.extend_from_slice(&ETHERTYPE_IPV4);

    let mut ip = vec![
        0x45, 0,
        (total_len >> 8) as u8, total_len as u8,
        0, 0, 0x40, 0,
        64, IP_PROTO_ICMP, 0, 0,
    ];
    ip.extend_from_slice(&echo.dst_ip.octets()); // src = the pinged host
    ip.extend_from_slice(&echo.src_ip.octets()); // dst = the guest
    let checksum = internet_checksum(&ip);
    ip[10] = (checksum >> 8) as u8;
    ip[11] = checksum as u8;
    frame.extend_from_slice(&ip);

    let mut icmp = vec![0, 0, 0, 0]; // echo reply, checksum placeholder
    icmp.extend_from_slice(&echo.id.to_be_bytes());
    icmp.extend_from_slice(&echo.seq.to_be_bytes());
    icmp.extend_from_slice(payload);
    let checksum = internet_checksum(&icmp);
    icmp[2] = (checksum >> 8) as u8;
    icmp[3] = checksum as u8;
    frame.extend_from_slice(&icmp);

    frame
}

/// Build the RST answering a denied SYN: flow reversed, `RST|ACK` with
/// `ack = seq + 1`, checksums valid. Returns a complete ethernet frame in
/// the SYN's address family.
pub fn synthesize_rst(syn_frame: &[u8], syn: &TcpSynInfo) -> Option<Vec<u8>> {
    if syn_frame.len() < 14 {
        return None;
    }

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

    let mut frame = Vec::with_capacity(14 + 40 + 20);
    // Ethernet: send back to where the SYN came from.
    frame.extend_from_slice(&syn_frame[6..12]); // dst = guest MAC
    frame.extend_from_slice(&syn_frame[0..6]); // src = gate MAC

    match (syn.dst_ip, syn.src_ip) {
        (IpAddr::V4(rst_src), IpAddr::V4(rst_dst)) => {
            frame.extend_from_slice(&ETHERTYPE_IPV4);
            let mut ip = vec![
                0x45, 0, 0, 40, // version/IHL, DSCP, total length (20+20)
                0, 0, 0x40, 0, // id, DF
                64, IP_PROTO_TCP, 0, 0, // TTL, proto, checksum placeholder
            ];
            ip.extend_from_slice(&rst_src.octets()); // src = the denied destination
            ip.extend_from_slice(&rst_dst.octets()); // dst = the guest
            let checksum = internet_checksum(&ip);
            ip[10] = (checksum >> 8) as u8;
            ip[11] = checksum as u8;
            frame.extend_from_slice(&ip);
        }
        (IpAddr::V6(rst_src), IpAddr::V6(rst_dst)) => {
            frame.extend_from_slice(&ETHERTYPE_IPV6);
            let mut ip = vec![0x60, 0, 0, 0]; // version, traffic class, flow label
            ip.extend_from_slice(&20u16.to_be_bytes()); // payload length
            ip.push(IP_PROTO_TCP);
            ip.push(64); // hop limit
            ip.extend_from_slice(&rst_src.octets());
            ip.extend_from_slice(&rst_dst.octets());
            frame.extend_from_slice(&ip);
        }
        _ => return None, // mixed families never happen for one segment
    }

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

pub(crate) fn tcp_checksum(src: IpAddr, dst: IpAddr, tcp: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(40 + tcp.len());
    match (src, dst) {
        (IpAddr::V4(src), IpAddr::V4(dst)) => {
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.push(0);
            pseudo.push(IP_PROTO_TCP);
            pseudo.extend_from_slice(&(tcp.len() as u16).to_be_bytes());
        }
        (IpAddr::V6(src), IpAddr::V6(dst)) => {
            pseudo.extend_from_slice(&src.octets());
            pseudo.extend_from_slice(&dst.octets());
            pseudo.extend_from_slice(&(tcp.len() as u32).to_be_bytes());
            pseudo.extend_from_slice(&[0, 0, 0, IP_PROTO_TCP]);
        }
        _ => return 0,
    }
    pseudo.extend_from_slice(tcp);
    internet_checksum(&pseudo)
}
