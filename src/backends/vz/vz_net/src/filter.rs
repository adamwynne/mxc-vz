//! The TM-01 allowed-IP set. `allows_ip` is the enforcement decision, made
//! at L3/L4 against the destination IP. DNS answers never decide anything —
//! [`EgressFilter::observe_dns`] only admits an IP into the dynamic set when
//! the *queried name* is allow-listed, and only for a bounded TTL, so the
//! set tracks re-resolution instead of growing monotonically.

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::{Duration, Instant};

use crate::pattern::{normalize_hostname, normalize_ip, HostPattern, IpCidr};

/// Upper TTL bound: a record claiming a day of validity still expires here,
/// forcing re-resolution (and re-filtering) of long-lived flows' targets.
pub const MAX_DNS_TTL: Duration = Duration::from_secs(300);

/// Lower TTL bound: a 0-TTL answer must still leave the guest a window to
/// act on the resolution it just received (resolve, then connect).
pub const MIN_DNS_TTL: Duration = Duration::from_secs(1);

#[derive(Debug, Clone)]
pub struct EgressFilter {
    static_ips: Vec<IpAddr>,
    cidrs: Vec<IpCidr>,
    /// Normalized allow-listed names (the DNS gate).
    hostnames: Vec<String>,
    /// DNS-populated IPs and their expiry instants.
    dynamic: HashMap<IpAddr, Instant>,
}

impl EgressFilter {
    pub fn new(patterns: impl IntoIterator<Item = HostPattern>) -> Self {
        let mut filter = Self {
            static_ips: Vec::new(),
            cidrs: Vec::new(),
            hostnames: Vec::new(),
            dynamic: HashMap::new(),
        };
        for pattern in patterns {
            match pattern {
                HostPattern::Ip(ip) => filter.static_ips.push(ip),
                HostPattern::Cidr(cidr) => filter.cidrs.push(cidr),
                HostPattern::Hostname(name) => filter.hostnames.push(name),
            }
        }
        filter
    }

    /// Is `name` allow-listed? Exact match only — allowing a domain does not
    /// allow its subdomains (upstream resolves entries as-is, same effect).
    pub fn matches_hostname(&self, name: &str) -> bool {
        let name = normalize_hostname(name);
        self.hostnames.contains(&name)
    }

    /// Record a DNS answer: admits `ip` until the (clamped) TTL expires and
    /// returns true iff `name` is allow-listed. A false return means the
    /// answer was ignored — the caller's DNS proxy should refuse the query
    /// rather than hand the guest an answer the filter will block anyway.
    pub fn observe_dns(&mut self, name: &str, ip: IpAddr, ttl: Duration, now: Instant) -> bool {
        if !self.matches_hostname(name) {
            return false;
        }
        let ttl = ttl.clamp(MIN_DNS_TTL, MAX_DNS_TTL);
        let expiry = now + ttl;
        // Re-observation refreshes; keep the later expiry so a short answer
        // cannot retract a longer one already granted.
        let entry = self.dynamic.entry(normalize_ip(ip)).or_insert(expiry);
        *entry = (*entry).max(expiry);
        // Opportunistic GC so a chatty guest cannot grow the map unboundedly
        // with expired one-shot entries.
        self.dynamic.retain(|_, expires| *expires > now);
        true
    }

    /// The enforcement decision: may the guest open a flow to `destination`?
    pub fn allows_ip(&self, destination: IpAddr, now: Instant) -> bool {
        let destination = normalize_ip(destination);
        if self.static_ips.contains(&destination) {
            return true;
        }
        if self.cidrs.iter().any(|cidr| cidr.contains(destination)) {
            return true;
        }
        matches!(self.dynamic.get(&destination), Some(expiry) if *expiry > now)
    }
}
