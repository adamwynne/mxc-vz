//! Host runner for the MXC `vz` backend.
//!
//! `runner` is the platform-neutral VM lifecycle: a dedicated thread owns the
//! VM object (VZ requires runloop-thread affinity) and the rest of the host
//! talks to it over channels. `session` orchestrates the one-shot flow
//! (validate → boot → connect → exec → tear down) over any driver. `vz`
//! (macOS-only) implements the driver on top of Apple's
//! Virtualization.framework via objc2.

pub mod runner;
pub mod session;

#[cfg(target_os = "macos")]
pub mod vz;
