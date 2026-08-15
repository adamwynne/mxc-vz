//! Shared config structs, schema types, and policy validation for the MXC
//! `vz` (Apple Virtualization.framework) containment backend.
//!
//! See docs/macos-support/vz-backend.md for the design this crate implements.

pub mod policy;
pub mod validate;
pub mod vm_spec;
