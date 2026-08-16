//! `allowedHosts` entry parsing, compatible with upstream's lxc backend
//! semantics: bare IP literals, CIDR blocks, or hostnames; IPv4-mapped IPv6
//! destinations are rewritten to their embedded IPv4 form; empty entries and
//! malformed CIDRs are errors the caller reports and skips (dropping an
//! allow entry only ever restricts).

use std::fmt;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostPattern {
    Ip(IpAddr),
    Cidr(IpCidr),
    /// Normalized (lowercase, no trailing dot) for DNS-name matching.
    Hostname(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HostPatternError {
    /// Empty entries are guarded before any resolution: Winsock resolves ""
    /// to every local interface address, which would allow the host itself.
    Empty,
    InvalidCidr,
}

impl fmt::Display for HostPatternError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "empty allowedHosts entry"),
            Self::InvalidCidr => write!(f, "malformed CIDR in allowedHosts entry"),
        }
    }
}

impl std::error::Error for HostPatternError {}

/// A CIDR block. Matching applies the prefix mask (upstream passes nonzero
/// host bits through because iptables masks; we must mask too) and is
/// family-split: a v6 block never matches a v4 destination and vice versa.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpCidr {
    network: IpAddr,
    prefix: u8,
}

impl IpCidr {
    pub fn contains(&self, destination: IpAddr) -> bool {
        match (self.network, normalize_ip(destination)) {
            (IpAddr::V4(network), IpAddr::V4(ip)) => {
                let mask = mask_v4(self.prefix);
                u32::from(network) & mask == u32::from(ip) & mask
            }
            (IpAddr::V6(network), IpAddr::V6(ip)) => {
                let mask = mask_v6(self.prefix);
                u128::from(network) & mask == u128::from(ip) & mask
            }
            _ => false,
        }
    }
}

fn mask_v4(prefix: u8) -> u32 {
    if prefix == 0 { 0 } else { u32::MAX << (32 - u32::from(prefix)) }
}

fn mask_v6(prefix: u8) -> u128 {
    if prefix == 0 { 0 } else { u128::MAX << (128 - u32::from(prefix)) }
}

/// Rewrite IPv4-mapped IPv6 (`::ffff:a.b.c.d`) to the embedded IPv4 address
/// so mapped and plain forms of the same destination compare equal.
pub fn normalize_ip(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => ip,
        },
        IpAddr::V4(_) => ip,
    }
}

/// Normalize a DNS name for matching: trim, lowercase, drop one trailing dot.
pub fn normalize_hostname(name: &str) -> String {
    let trimmed = name.trim();
    let trimmed = trimmed.strip_suffix('.').unwrap_or(trimmed);
    trimmed.to_ascii_lowercase()
}

impl HostPattern {
    pub fn parse(entry: &str) -> Result<Self, HostPatternError> {
        let entry = entry.trim();
        if entry.is_empty() {
            return Err(HostPatternError::Empty);
        }

        if let Some((address, prefix)) = entry.split_once('/') {
            let address: IpAddr = address.parse().map_err(|_| HostPatternError::InvalidCidr)?;
            let address = normalize_ip(address);
            let prefix: u8 = prefix.parse().map_err(|_| HostPatternError::InvalidCidr)?;
            let max = match address {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            if prefix > max {
                return Err(HostPatternError::InvalidCidr);
            }
            return Ok(Self::Cidr(IpCidr { network: address, prefix }));
        }

        if let Ok(address) = entry.parse::<IpAddr>() {
            return Ok(Self::Ip(normalize_ip(address)));
        }

        Ok(Self::Hostname(normalize_hostname(entry)))
    }
}
