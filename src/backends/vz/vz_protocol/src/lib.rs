//! Host↔guest exec protocol for the MXC vz backend.
//!
//! Length-prefixed framed transport per threat model TM-06: guest→host bytes
//! are adversarial, so frames carry a hard payload cap, declared lengths are
//! validated before any allocation, and malformed input yields errors, never
//! panics. Shared by the host runner and the guest agent.

pub mod client;
pub mod frame;
pub mod message;
