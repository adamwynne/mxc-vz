//! EgressFilter — the TM-01 allowed-IP set. Decisions are keyed on
//! destination IP at L3/L4; DNS observations only *populate* the set
//! (bounded TTL, re-resolve), they are never themselves the control.

use std::net::IpAddr;
use std::time::{Duration, Instant};

use vz_net::filter::{EgressFilter, MAX_DNS_TTL, MIN_DNS_TTL};
use vz_net::pattern::HostPattern;

fn filter(entries: &[&str]) -> EgressFilter {
    EgressFilter::new(entries.iter().map(|e| HostPattern::parse(e).unwrap()))
}

fn ip(s: &str) -> IpAddr {
    s.parse().unwrap()
}

#[test]
fn static_ip_literal_is_allowed_everything_else_denied() {
    let f = filter(&["140.82.112.22"]);
    let now = Instant::now();
    assert!(f.allows_ip(ip("140.82.112.22"), now));
    assert!(!f.allows_ip(ip("140.82.112.23"), now));
    assert!(!f.allows_ip(ip("2606:50c0:8000::153"), now));
}

#[test]
fn cidr_membership_is_allowed() {
    let f = filter(&["10.1.0.0/16", "2001:db8::/32"]);
    let now = Instant::now();
    assert!(f.allows_ip(ip("10.1.255.254"), now));
    assert!(!f.allows_ip(ip("10.2.0.1"), now));
    assert!(f.allows_ip(ip("2001:db8:ffff::1"), now));
    assert!(!f.allows_ip(ip("2001:db9::1"), now));
}

#[test]
fn ipv4_mapped_destination_is_normalized_before_lookup() {
    // A guest connecting to ::ffff:140.82.112.22 is connecting to the v4
    // address; the filter must not treat the mapped form as a distinct IP.
    let f = filter(&["140.82.112.22"]);
    assert!(f.allows_ip(ip("::ffff:140.82.112.22"), Instant::now()));
}

#[test]
fn hostname_pattern_alone_allows_nothing_until_dns_observation() {
    let f = filter(&["api.github.com"]);
    assert!(!f.allows_ip(ip("140.82.112.22"), Instant::now()));
}

#[test]
fn dns_observation_for_matching_name_admits_ip_until_ttl_expiry() {
    let mut f = filter(&["api.github.com"]);
    let now = Instant::now();
    assert!(f.observe_dns("api.github.com", ip("140.82.112.22"), Duration::from_secs(60), now));
    assert!(f.allows_ip(ip("140.82.112.22"), now));
    assert!(f.allows_ip(ip("140.82.112.22"), now + Duration::from_secs(59)));
    assert!(!f.allows_ip(ip("140.82.112.22"), now + Duration::from_secs(61)));
}

#[test]
fn dns_observation_for_non_matching_name_is_refused_and_admits_nothing() {
    let mut f = filter(&["api.github.com"]);
    let now = Instant::now();
    assert!(!f.observe_dns("evil.example.com", ip("6.6.6.6"), Duration::from_secs(60), now));
    assert!(!f.allows_ip(ip("6.6.6.6"), now));
}

#[test]
fn hostname_matching_is_case_and_trailing_dot_insensitive() {
    let mut f = filter(&["api.github.com"]);
    assert!(f.matches_hostname("API.GITHUB.COM."));
    assert!(f.matches_hostname("api.github.com"));
    assert!(!f.matches_hostname("api.github.com.evil.example"));
    assert!(!f.matches_hostname("sub.api.github.com"));
    let now = Instant::now();
    assert!(f.observe_dns("API.GitHub.com.", ip("140.82.112.22"), Duration::from_secs(60), now));
    assert!(f.allows_ip(ip("140.82.112.22"), now));
}

#[test]
fn excessive_ttl_is_clamped_to_the_bound() {
    let mut f = filter(&["api.github.com"]);
    let now = Instant::now();
    f.observe_dns("api.github.com", ip("140.82.112.22"), Duration::from_secs(86_400), now);
    assert!(f.allows_ip(ip("140.82.112.22"), now + MAX_DNS_TTL - Duration::from_secs(1)));
    assert!(!f.allows_ip(ip("140.82.112.22"), now + MAX_DNS_TTL + Duration::from_secs(1)));
}

#[test]
fn zero_ttl_still_covers_the_immediate_connect() {
    // A 0-TTL record must not create an unusable allow window: the guest
    // resolves, then connects — the connect must land inside the window.
    let mut f = filter(&["api.github.com"]);
    let now = Instant::now();
    f.observe_dns("api.github.com", ip("140.82.112.22"), Duration::ZERO, now);
    assert!(f.allows_ip(ip("140.82.112.22"), now + MIN_DNS_TTL - Duration::from_millis(1)));
    assert!(!f.allows_ip(ip("140.82.112.22"), now + MIN_DNS_TTL + Duration::from_secs(1)));
}

#[test]
fn reobservation_refreshes_the_expiry() {
    let mut f = filter(&["api.github.com"]);
    let start = Instant::now();
    f.observe_dns("api.github.com", ip("140.82.112.22"), Duration::from_secs(60), start);
    let later = start + Duration::from_secs(50);
    f.observe_dns("api.github.com", ip("140.82.112.22"), Duration::from_secs(60), later);
    assert!(f.allows_ip(ip("140.82.112.22"), start + Duration::from_secs(100)));
    assert!(!f.allows_ip(ip("140.82.112.22"), start + Duration::from_secs(111)));
}

#[test]
fn static_and_dynamic_entries_compose() {
    let mut f = filter(&["10.0.0.0/8", "api.github.com"]);
    let now = Instant::now();
    f.observe_dns("api.github.com", ip("140.82.112.22"), Duration::from_secs(60), now);
    assert!(f.allows_ip(ip("10.9.9.9"), now));
    assert!(f.allows_ip(ip("140.82.112.22"), now));
    assert!(!f.allows_ip(ip("8.8.8.8"), now));
}

#[test]
fn empty_filter_denies_everything() {
    let f = EgressFilter::new(std::iter::empty());
    assert!(!f.allows_ip(ip("8.8.8.8"), Instant::now()));
    assert!(!f.matches_hostname("anything.example"));
}
