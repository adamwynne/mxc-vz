//! allowedHosts entry parsing — upstream-lxc-compatible semantics
//! (docs/lxc-support/lxc-backend.md): bare IP literals, CIDR blocks, or
//! hostnames; IPv4-mapped IPv6 rewritten to IPv4; empty entries and invalid
//! CIDRs are skipped (skipping an allow entry only restricts).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use vz_net::pattern::{HostPattern, HostPatternError};

#[test]
fn ipv4_literal_parses_to_ip() {
    assert_eq!(
        HostPattern::parse("140.82.112.22"),
        Ok(HostPattern::Ip(IpAddr::V4(Ipv4Addr::new(140, 82, 112, 22))))
    );
}

#[test]
fn ipv6_literal_parses_to_ip() {
    assert_eq!(
        HostPattern::parse("2606:50c0:8000::153"),
        Ok(HostPattern::Ip("2606:50c0:8000::153".parse().unwrap()))
    );
}

#[test]
fn ipv4_mapped_ipv6_is_rewritten_to_ipv4() {
    // Upstream files ::ffff:a.b.c.d under IPv4 so it hits the v4 chain.
    assert_eq!(
        HostPattern::parse("::ffff:140.82.112.22"),
        Ok(HostPattern::Ip(IpAddr::V4(Ipv4Addr::new(140, 82, 112, 22))))
    );
}

#[test]
fn ipv4_cidr_parses() {
    let pattern = HostPattern::parse("10.1.0.0/16").expect("valid CIDR");
    let HostPattern::Cidr(cidr) = pattern else {
        panic!("expected Cidr, got {pattern:?}");
    };
    assert!(cidr.contains(IpAddr::V4(Ipv4Addr::new(10, 1, 200, 3))));
    assert!(!cidr.contains(IpAddr::V4(Ipv4Addr::new(10, 2, 0, 1))));
}

#[test]
fn ipv6_cidr_parses() {
    let pattern = HostPattern::parse("2001:db8::/32").expect("valid CIDR");
    let HostPattern::Cidr(cidr) = pattern else {
        panic!("expected Cidr, got {pattern:?}");
    };
    assert!(cidr.contains("2001:db8:1::1".parse().unwrap()));
    assert!(!cidr.contains("2001:db9::1".parse().unwrap()));
}

#[test]
fn cidr_with_nonzero_host_bits_matches_by_mask() {
    // Upstream passes these through because iptables applies the prefix mask
    // itself; our matcher must therefore mask too.
    let pattern = HostPattern::parse("10.0.0.5/8").expect("valid CIDR");
    let HostPattern::Cidr(cidr) = pattern else {
        panic!("expected Cidr, got {pattern:?}");
    };
    assert!(cidr.contains(IpAddr::V4(Ipv4Addr::new(10, 255, 0, 1))));
    assert!(!cidr.contains(IpAddr::V4(Ipv4Addr::new(11, 0, 0, 1))));
}

#[test]
fn out_of_range_prefix_is_invalid() {
    assert_eq!(
        HostPattern::parse("10.0.0.0/33"),
        Err(HostPatternError::InvalidCidr)
    );
    assert_eq!(
        HostPattern::parse("2001:db8::/129"),
        Err(HostPatternError::InvalidCidr)
    );
    assert_eq!(
        HostPattern::parse("not-an-ip/24"),
        Err(HostPatternError::InvalidCidr)
    );
}

#[test]
fn empty_and_whitespace_entries_are_invalid() {
    // Upstream guards these before resolution: Winsock resolves "" to every
    // local interface address, which would allow the host itself.
    assert_eq!(HostPattern::parse(""), Err(HostPatternError::Empty));
    assert_eq!(HostPattern::parse("   "), Err(HostPatternError::Empty));
}

#[test]
fn anything_else_is_a_hostname_normalized_for_matching() {
    assert_eq!(
        HostPattern::parse("API.GitHub.COM."),
        Ok(HostPattern::Hostname("api.github.com".to_string()))
    );
    assert_eq!(
        HostPattern::parse("api.github.com"),
        Ok(HostPattern::Hostname("api.github.com".to_string()))
    );
}

#[test]
fn v6_zero_prefix_matches_everything_v6_only() {
    let pattern = HostPattern::parse("::/0").expect("valid CIDR");
    let HostPattern::Cidr(cidr) = pattern else {
        panic!("expected Cidr, got {pattern:?}");
    };
    assert!(cidr.contains(IpAddr::V6(Ipv6Addr::LOCALHOST)));
    // Family-split like upstream: a v6 CIDR never matches a v4 destination.
    assert!(!cidr.contains(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))));
}
