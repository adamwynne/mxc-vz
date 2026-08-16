//! Egress filtering core for the vz backend's `network.allowedHosts`.
//!
//! Threat-model framing (TM-01): name resolution is advisory — a hostile
//! guest ignores `resolv.conf`, connects to hard-coded IPs, or runs its own
//! DoH. Enforcement therefore happens at L3/L4 on the host side of the
//! guest's network attachment, keyed on destination IP. The DNS proxy's only
//! filtering role is to *populate* the allowed-IP set from answers for
//! allow-listed names, with bounded TTLs so entries expire and re-resolve.
//!
//! This crate is the platform-neutral core: entry parsing ([`pattern`]) and
//! the allowed-IP set ([`filter`]). The datapath that feeds it (userspace
//! NAT over `VZFileHandleNetworkDeviceAttachment` frames) builds on top.

pub mod filter;
pub mod pattern;
