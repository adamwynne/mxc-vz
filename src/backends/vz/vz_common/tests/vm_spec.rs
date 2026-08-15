//! Tests for policy → VM-spec translation (Phase 1/4 core, platform-neutral).
//!
//! Contract under test:
//! - `experimental.vz` options map to CPU count, memory bytes, and boot
//!   timeout; `guestImagePath` overrides the default guest image directory.
//! - `filesystem.readonlyPaths`/`readwritePaths` become virtio-fs shares with
//!   deterministic tags and per-share read-only flags; `deniedPaths` produce
//!   no share (denial-by-absence).
//! - Network: only `defaultPolicy: "allow"` attaches a NAT device; `"block"`
//!   or an absent network block mean NO device (kernel-level absence).
//! - Direct kernel boot: kernel + initramfs paths under the guest image dir,
//!   serial console on the kernel cmdline.

use std::path::{Path, PathBuf};
use std::time::Duration;

use vz_common::policy::Policy;
use vz_common::validate::validate_vz_policy;
use vz_common::vm_spec::{build_vm_spec, NetworkMode, VmSpec, INITRAMFS_FILE, KERNEL_FILE, VSOCK_AGENT_PORT};

fn spec_for(json: &str) -> VmSpec {
    let policy: Policy = serde_json::from_str(json).expect("test policy should parse");
    let validated = validate_vz_policy(&policy, true).expect("test policy should validate");
    build_vm_spec(&policy, &validated, Path::new("/opt/mxc/vz-guest"))
}

#[test]
fn minimal_policy_yields_default_spec() {
    let spec = spec_for(r#"{ "containment": "vz" }"#);
    assert_eq!(spec.cpu_count, 2);
    assert_eq!(spec.memory_bytes, 2048 * 1024 * 1024);
    assert_eq!(spec.boot_timeout, Duration::from_millis(30000));
    assert_eq!(spec.network, NetworkMode::None);
    assert!(spec.shares.is_empty());
    assert_eq!(spec.vsock_agent_port, VSOCK_AGENT_PORT);
}

#[test]
fn kernel_and_initramfs_live_under_default_guest_image_dir() {
    let spec = spec_for(r#"{ "containment": "vz" }"#);
    assert_eq!(
        spec.kernel_path,
        PathBuf::from("/opt/mxc/vz-guest").join(KERNEL_FILE)
    );
    assert_eq!(
        spec.initramfs_path,
        PathBuf::from("/opt/mxc/vz-guest").join(INITRAMFS_FILE)
    );
}

#[test]
fn guest_image_path_option_overrides_default_dir() {
    let spec = spec_for(
        r#"{
            "containment": "vz",
            "experimental": { "vz": { "guestImagePath": "/custom/guest" } }
        }"#,
    );
    assert_eq!(spec.kernel_path, PathBuf::from("/custom/guest").join(KERNEL_FILE));
    assert_eq!(
        spec.initramfs_path,
        PathBuf::from("/custom/guest").join(INITRAMFS_FILE)
    );
}

#[test]
fn resource_options_map_to_spec() {
    let spec = spec_for(
        r#"{
            "containment": "vz",
            "experimental": { "vz": { "cpuCount": 4, "memoryMB": 4096, "bootTimeoutMs": 5000 } }
        }"#,
    );
    assert_eq!(spec.cpu_count, 4);
    assert_eq!(spec.memory_bytes, 4096 * 1024 * 1024);
    assert_eq!(spec.boot_timeout, Duration::from_millis(5000));
}

#[test]
fn network_allow_attaches_nat() {
    let spec = spec_for(
        r#"{ "containment": "vz", "network": { "defaultPolicy": "allow" } }"#,
    );
    assert_eq!(spec.network, NetworkMode::Nat);
}

#[test]
fn network_block_means_no_device() {
    let spec = spec_for(
        r#"{ "containment": "vz", "network": { "defaultPolicy": "block" } }"#,
    );
    assert_eq!(spec.network, NetworkMode::None);
}

#[test]
fn network_block_absent_default_policy_means_no_device() {
    // A network block without defaultPolicy must fail closed.
    let spec = spec_for(
        r#"{ "containment": "vz", "network": { "allowedHosts": [] } }"#,
    );
    assert_eq!(spec.network, NetworkMode::None);
}

#[test]
fn filesystem_paths_become_tagged_shares() {
    let spec = spec_for(
        r#"{
            "containment": "vz",
            "filesystem": {
                "readonlyPaths": ["/usr/share/data"],
                "readwritePaths": ["/workspace", "/scratch"]
            }
        }"#,
    );
    // Readonly shares first, then readwrite; tags deterministic by index so
    // the guest agent can enumerate mounts without extra negotiation.
    assert_eq!(spec.shares.len(), 3);

    assert_eq!(spec.shares[0].tag, "mxcfs0");
    assert_eq!(spec.shares[0].host_path, PathBuf::from("/usr/share/data"));
    assert!(spec.shares[0].read_only);

    assert_eq!(spec.shares[1].tag, "mxcfs1");
    assert_eq!(spec.shares[1].host_path, PathBuf::from("/workspace"));
    assert!(!spec.shares[1].read_only);

    assert_eq!(spec.shares[2].tag, "mxcfs2");
    assert_eq!(spec.shares[2].host_path, PathBuf::from("/scratch"));
    assert!(!spec.shares[2].read_only);
}

#[test]
fn denied_paths_produce_no_share() {
    // Denial is by absence: deniedPaths never become devices.
    let spec = spec_for(
        r#"{
            "containment": "vz",
            "filesystem": {
                "readwritePaths": ["/workspace"],
                "deniedPaths": ["/etc/secrets"]
            }
        }"#,
    );
    assert_eq!(spec.shares.len(), 1);
    assert_eq!(spec.shares[0].host_path, PathBuf::from("/workspace"));
}

#[test]
fn kernel_cmdline_uses_serial_console() {
    let spec = spec_for(r#"{ "containment": "vz" }"#);
    assert!(
        spec.kernel_cmdline.contains("console=hvc0"),
        "cmdline {:?} must route the console to virtio (hvc0)",
        spec.kernel_cmdline
    );
}
