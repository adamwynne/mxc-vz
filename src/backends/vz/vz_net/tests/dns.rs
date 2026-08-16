//! DNS wire codec tests. The gate's DNS proxy parses guest queries, and
//! builds either an answer (allow-listed name, resolver IPs) or a REFUSED
//! response. Adversarial bytes must never panic (the guest owns the query).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use vz_net::dns::{build_refused, build_response, parse_query, DnsQuery, QueryType};

/// Standard query for `name` with the given qtype (1=A, 28=AAAA).
fn query_bytes(id: u16, name: &str, qtype: u16) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&id.to_be_bytes());
    out.extend_from_slice(&[0x01, 0x00]); // RD=1, standard query
    out.extend_from_slice(&[0, 1, 0, 0, 0, 0, 0, 0]); // QDCOUNT=1
    for label in name.split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out.extend_from_slice(&qtype.to_be_bytes());
    out.extend_from_slice(&1u16.to_be_bytes()); // class IN
    out
}

#[test]
fn a_query_parses() {
    let bytes = query_bytes(0x1234, "api.github.com", 1);
    let query = parse_query(&bytes).expect("valid A query");
    assert_eq!(query.id, 0x1234);
    assert_eq!(query.name, "api.github.com");
    assert_eq!(query.qtype, QueryType::A);
}

#[test]
fn aaaa_query_parses() {
    let query = parse_query(&query_bytes(7, "example.com", 28)).expect("valid AAAA query");
    assert_eq!(query.qtype, QueryType::Aaaa);
}

#[test]
fn other_qtypes_are_rejected() {
    // MX
    assert!(parse_query(&query_bytes(7, "example.com", 15)).is_none());
    // TXT
    assert!(parse_query(&query_bytes(7, "example.com", 16)).is_none());
}

#[test]
fn responses_and_truncated_packets_are_rejected_without_panicking() {
    let mut response = query_bytes(1, "example.com", 1);
    response[2] |= 0x80; // QR=1: a response, not a query
    assert!(parse_query(&response).is_none());

    let good = query_bytes(1, "example.com", 1);
    for len in 0..good.len() {
        let _ = parse_query(&good[..len]);
    }
    let garbage: Vec<u8> = (0..=255).cycle().take(64).collect();
    let _ = parse_query(&garbage);
}

#[test]
fn compressed_names_in_queries_are_rejected() {
    // A query whose QNAME uses a compression pointer (0xC0) — pointless in
    // a question and a classic parser-abuse vector; refuse to parse.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&[0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0]);
    bytes.extend_from_slice(&[0xC0, 0x0C]); // pointer
    bytes.extend_from_slice(&1u16.to_be_bytes());
    bytes.extend_from_slice(&1u16.to_be_bytes());
    assert!(parse_query(&bytes).is_none());
}

#[test]
fn answer_carries_the_ips_with_the_ttl() {
    let query = DnsQuery {
        id: 0x4242,
        name: "api.github.com".to_string(),
        qtype: QueryType::A,
        raw_question: query_bytes(0x4242, "api.github.com", 1)[12..].to_vec(),
    };
    let ips = vec![
        IpAddr::V4(Ipv4Addr::new(140, 82, 112, 22)),
        IpAddr::V4(Ipv4Addr::new(140, 82, 113, 22)),
    ];
    let response = build_response(&query, &ips, 60);

    assert_eq!(&response[0..2], &0x4242u16.to_be_bytes());
    assert_eq!(response[2] & 0x80, 0x80, "QR must be set");
    assert_eq!(response[3] & 0x0f, 0, "RCODE NoError");
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    assert_eq!(ancount, 2);
    // First answer record: pointer to the question name, type A, class IN,
    // TTL, RDLENGTH 4, the address.
    let answers_at = 12 + query.raw_question.len();
    let answer = &response[answers_at..];
    assert_eq!(&answer[0..2], &[0xC0, 0x0C], "name pointer to offset 12");
    assert_eq!(u16::from_be_bytes([answer[2], answer[3]]), 1, "type A");
    assert_eq!(u32::from_be_bytes([answer[6], answer[7], answer[8], answer[9]]), 60, "TTL");
    assert_eq!(u16::from_be_bytes([answer[10], answer[11]]), 4);
    assert_eq!(&answer[12..16], &[140, 82, 112, 22]);
}

#[test]
fn answer_filters_ips_to_the_question_family() {
    let query = DnsQuery {
        id: 1,
        name: "example.com".to_string(),
        qtype: QueryType::A,
        raw_question: query_bytes(1, "example.com", 1)[12..].to_vec(),
    };
    let ips = vec![
        IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)),
        IpAddr::V6(Ipv6Addr::LOCALHOST),
    ];
    let response = build_response(&query, &ips, 60);
    let ancount = u16::from_be_bytes([response[6], response[7]]);
    assert_eq!(ancount, 1, "an A question must not receive AAAA records");
}

#[test]
fn refused_response_echoes_the_question_with_rcode_refused() {
    let query = DnsQuery {
        id: 0x9999,
        name: "evil.example.com".to_string(),
        qtype: QueryType::A,
        raw_question: query_bytes(0x9999, "evil.example.com", 1)[12..].to_vec(),
    };
    let response = build_refused(&query);
    assert_eq!(&response[0..2], &0x9999u16.to_be_bytes());
    assert_eq!(response[2] & 0x80, 0x80, "QR must be set");
    assert_eq!(response[3] & 0x0f, 5, "RCODE Refused");
    assert_eq!(u16::from_be_bytes([response[6], response[7]]), 0, "no answers");
    assert!(response.ends_with(&query.raw_question));
}
