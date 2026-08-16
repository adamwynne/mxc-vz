//! Minimal DNS wire codec for the gate's DNS proxy.
//!
//! Scope: parse a single-question A/AAAA query from the guest, and build
//! either an answer (allow-listed name; resolver-provided IPs, gate-chosen
//! TTL) or a REFUSED response. Anything else — other qtypes, responses,
//! compressed question names, multi-question packets — is rejected by
//! returning `None`, and the caller drops the packet. The guest owns every
//! byte, so parsing must never panic.

use std::net::IpAddr;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QueryType {
    A,
    Aaaa,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DnsQuery {
    pub id: u16,
    /// Dotted name as sent (no trailing dot); match with
    /// [`crate::pattern::normalize_hostname`] semantics downstream.
    pub name: String,
    pub qtype: QueryType,
    /// The verbatim question section (QNAME + QTYPE + QCLASS), echoed into
    /// responses so name compression pointers stay valid.
    pub raw_question: Vec<u8>,
}

const FLAG_RESPONSE: u8 = 0x80;
const MAX_NAME_LEN: usize = 253;

/// Parse a standard single-question A/AAAA query.
pub fn parse_query(packet: &[u8]) -> Option<DnsQuery> {
    if packet.len() < 12 {
        return None;
    }
    let id = u16::from_be_bytes([packet[0], packet[1]]);
    if packet[2] & FLAG_RESPONSE != 0 {
        return None; // a response, not a query
    }
    if (packet[2] >> 3) & 0x0f != 0 {
        return None; // OPCODE != standard query
    }
    let qdcount = u16::from_be_bytes([packet[4], packet[5]]);
    if qdcount != 1 {
        return None;
    }

    // QNAME: uncompressed labels only. A pointer (top bits 11) in a
    // question is pointless and a parser-abuse vector.
    let mut name = String::new();
    let mut at = 12usize;
    loop {
        let len = usize::from(*packet.get(at)?);
        if len == 0 {
            at += 1;
            break;
        }
        if len & 0xc0 != 0 {
            return None; // compression pointer (or reserved bits)
        }
        let label = packet.get(at + 1..at + 1 + len)?;
        if !name.is_empty() {
            name.push('.');
        }
        name.push_str(std::str::from_utf8(label).ok()?);
        if name.len() > MAX_NAME_LEN {
            return None;
        }
        at += 1 + len;
    }

    let qtype = u16::from_be_bytes([*packet.get(at)?, *packet.get(at + 1)?]);
    let qclass = u16::from_be_bytes([*packet.get(at + 2)?, *packet.get(at + 3)?]);
    if qclass != 1 {
        return None; // class IN only
    }
    let qtype = match qtype {
        1 => QueryType::A,
        28 => QueryType::Aaaa,
        _ => return None,
    };

    Some(DnsQuery {
        id,
        name,
        qtype,
        raw_question: packet[12..at + 4].to_vec(),
    })
}

/// Build the answer for an allow-listed name: echoes the question, then one
/// record per IP of the question's family, each pointing back at the QNAME
/// (offset 12) with the gate's TTL.
pub fn build_response(query: &DnsQuery, ips: &[IpAddr], ttl_seconds: u32) -> Vec<u8> {
    let answers: Vec<&IpAddr> = ips
        .iter()
        .filter(|ip| matches!((query.qtype, ip), (QueryType::A, IpAddr::V4(_)) | (QueryType::Aaaa, IpAddr::V6(_))))
        .collect();

    let mut out = header(query, 0, answers.len() as u16);
    out.extend_from_slice(&query.raw_question);
    for ip in answers {
        out.extend_from_slice(&[0xC0, 0x0C]); // name: pointer to offset 12
        let (rtype, rdata): (u16, Vec<u8>) = match ip {
            IpAddr::V4(v4) => (1, v4.octets().to_vec()),
            IpAddr::V6(v6) => (28, v6.octets().to_vec()),
        };
        out.extend_from_slice(&rtype.to_be_bytes());
        out.extend_from_slice(&1u16.to_be_bytes()); // class IN
        out.extend_from_slice(&ttl_seconds.to_be_bytes());
        out.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        out.extend_from_slice(&rdata);
    }
    out
}

/// REFUSED (RCODE 5): the name is not allow-listed. Distinct from NXDOMAIN
/// on purpose — the name may well exist; this resolver refuses to say.
pub fn build_refused(query: &DnsQuery) -> Vec<u8> {
    let mut out = header(query, 5, 0);
    out.extend_from_slice(&query.raw_question);
    out
}

fn header(query: &DnsQuery, rcode: u8, ancount: u16) -> Vec<u8> {
    let mut out = Vec::with_capacity(12 + query.raw_question.len());
    out.extend_from_slice(&query.id.to_be_bytes());
    out.push(FLAG_RESPONSE | 0x04); // QR, AA
    out.push(rcode & 0x0f);
    out.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    out.extend_from_slice(&ancount.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    out.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    out
}
