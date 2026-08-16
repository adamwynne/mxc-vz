//! Policy → VM-spec translation (platform-neutral core of the VM config).

use std::path::{Path, PathBuf};
use std::time::Duration;

use crate::policy::Policy;
use crate::validate::ValidatedVzPolicy;

/// Fixed guest vsock port the guest agent listens on from init.
pub const VSOCK_AGENT_PORT: u32 = 28024;

/// Kernel image file name inside the guest image directory.
pub const KERNEL_FILE: &str = "vmlinux";

/// Initramfs file name inside the guest image directory.
pub const INITRAMFS_FILE: &str = "initramfs.cpio.gz";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VirtioFsShare {
    pub tag: String,
    pub host_path: PathBuf,
    pub read_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetworkMode {
    None,
    Nat,
    /// Egress restricted to the parsed `allowedHosts` patterns, enforced
    /// host-side at L3/L4 (TM-01): the guest attaches through a file-handle
    /// device whose frames pass a host userspace gate built on
    /// `vz_net::filter::EgressFilter` — never through plain NAT.
    FilteredNat(Vec<vz_net::pattern::HostPattern>),
}

#[derive(Debug, Clone, PartialEq)]
pub struct VmSpec {
    pub cpu_count: u32,
    pub memory_bytes: u64,
    pub kernel_path: PathBuf,
    pub initramfs_path: PathBuf,
    pub kernel_cmdline: String,
    pub shares: Vec<VirtioFsShare>,
    pub network: NetworkMode,
    pub vsock_agent_port: u32,
    pub boot_timeout: Duration,
}

/// Serial console on virtio (hvc0); reboot-on-panic so a crashed guest exits
/// instead of hanging until the boot timeout.
const KERNEL_CMDLINE: &str = "console=hvc0 panic=1";

/// Build the platform-neutral VM spec from a validated vz policy.
///
/// Assumes `validate_vz_policy` has already passed: options are resolved,
/// paths are absolute, and deniedPaths do not overlap shares. deniedPaths are
/// enforced by absence — they never become devices.
pub fn build_vm_spec(
    policy: &Policy,
    validated: &ValidatedVzPolicy,
    default_guest_image_dir: &Path,
) -> VmSpec {
    let options = &validated.options;

    let guest_image_dir = options
        .guest_image_path
        .as_deref()
        .unwrap_or(default_guest_image_dir);

    let mut shares = Vec::new();
    if let Some(fs) = &policy.filesystem {
        let tagged = fs
            .readonly_paths
            .iter()
            .map(|path| (path, true))
            .chain(fs.readwrite_paths.iter().map(|path| (path, false)));
        for (index, (path, read_only)) in tagged.enumerate() {
            shares.push(VirtioFsShare {
                tag: format!("mxcfs{index}"),
                host_path: path.clone(),
                read_only,
            });
        }
    }

    // Only an explicit allow attaches a plain NAT device (allowedHosts are
    // no-ops under an allow default, matching upstream). Under block,
    // allowedHosts request filtered egress; invalid entries are skipped
    // (restricting only), and if nothing survives, device absence beats an
    // empty filter. Absent defaultPolicy fails closed.
    let network = match policy.network.as_ref() {
        Some(network) => match network.default_policy {
            Some(crate::policy::NetworkDefaultPolicy::Allow) => NetworkMode::Nat,
            Some(crate::policy::NetworkDefaultPolicy::Block)
                if !network.allowed_hosts.is_empty() =>
            {
                let patterns: Vec<_> = network
                    .allowed_hosts
                    .iter()
                    .filter_map(|entry| vz_net::pattern::HostPattern::parse(entry).ok())
                    .collect();
                if patterns.is_empty() {
                    NetworkMode::None
                } else {
                    NetworkMode::FilteredNat(patterns)
                }
            }
            _ => NetworkMode::None,
        },
        None => NetworkMode::None,
    };

    VmSpec {
        cpu_count: options.cpu_count,
        memory_bytes: options.memory_mb * 1024 * 1024,
        kernel_path: guest_image_dir.join(KERNEL_FILE),
        initramfs_path: guest_image_dir.join(INITRAMFS_FILE),
        kernel_cmdline: KERNEL_CMDLINE.to_string(),
        shares,
        network,
        vsock_agent_port: VSOCK_AGENT_PORT,
        boot_timeout: Duration::from_millis(options.boot_timeout_ms),
    }
}
