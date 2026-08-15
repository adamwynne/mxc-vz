//! Apple Virtualization.framework driver (macOS only).
//!
//! Threading model: `VZVirtualMachine` is affine to the dispatch queue passed
//! at init and must be driven from it. [`VzDriver`] creates a private serial
//! queue, initializes the VM against it, and submits every start/stop call to
//! that queue; completion handlers report back over an mpsc channel, which is
//! how the boot deadline is enforced (`recv_timeout`). The driver itself
//! lives on the runner's dedicated VM thread (see `runner`), which owns
//! creating and dropping it.
//!
//! Requirements at runtime: Apple Silicon, macOS 13+, and a binary signed
//! with the `com.apple.security.virtualization` entitlement — an unsigned
//! binary is killed on first VZ API use. See `scripts/vz.entitlements` and
//! `build-mac.sh`.

use std::path::Path;
use std::sync::mpsc;
use std::time::Duration;

use block2::RcBlock;
use dispatch2::{DispatchQueue, DispatchRetained};
use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_foundation::{NSArray, NSError, NSString, NSURL};
use objc2_virtualization::{
    VZDirectorySharingDeviceConfiguration, VZLinuxBootLoader, VZNATNetworkDeviceAttachment,
    VZNetworkDeviceConfiguration, VZSharedDirectory, VZSingleDirectoryShare,
    VZSocketDeviceConfiguration, VZVirtioFileSystemDeviceConfiguration,
    VZVirtioNetworkDeviceConfiguration, VZVirtioSocketDeviceConfiguration, VZVirtualMachine,
    VZVirtualMachineConfiguration,
};

use crate::runner::{VmDriver, VmError, VmHandle};
use vz_common::vm_spec::{NetworkMode, VmSpec};

/// Grace period for a force-stop to complete.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// A VZ completion handler: called with nil on success, an NSError on failure.
type CompletionBlock = block2::DynBlock<dyn Fn(*mut NSError)>;

/// Moves a queue-affine VZ object into a closure executed on exactly the
/// dispatch queue the VM was initialized with.
struct QueueBound<T>(T);

// SAFETY: only constructed around VZ objects that are used exclusively from
// the dispatch queue their VM was initialized with; the wrapper is how they
// travel to `exec_async` closures targeting that queue and nowhere else.
unsafe impl<T> Send for QueueBound<T> {}

pub struct VzDriver {
    vm: Retained<VZVirtualMachine>,
    queue: DispatchRetained<DispatchQueue>,
}

impl VzDriver {
    /// Build the VM configuration from the spec and create the VM bound to a
    /// fresh serial queue. Call on the thread that will own the driver (the
    /// runner's VM thread).
    pub fn new(spec: &VmSpec) -> Result<Self, VmError> {
        // SAFETY: class method with no arguments.
        if !unsafe { VZVirtualMachine::isSupported() } {
            return Err(VmError::Start(
                "Virtualization.framework is not available: requires Apple Silicon, macOS 13+, \
                 and the com.apple.security.virtualization entitlement (unsigned dev builds are \
                 killed on first VZ API use — see build-mac.sh)"
                    .to_string(),
            ));
        }

        let config = build_configuration(spec)?;
        // SAFETY: fully-built configuration; validate before constructing the VM.
        unsafe { config.validateWithError() }.map_err(|error| {
            VmError::Start(format!("invalid VM configuration: {}", error_message(&error)))
        })?;

        let queue = DispatchQueue::new("com.microsoft.mxc.vz-vm", None);
        // SAFETY: validated configuration and a fresh serial queue; the VM is
        // driven from this queue from here on.
        let vm = unsafe {
            VZVirtualMachine::initWithConfiguration_queue(VZVirtualMachine::alloc(), &config, &queue)
        };
        Ok(Self { vm, queue })
    }

    /// Submit `operation` (start/stop) on the VM's queue and wait for its
    /// completion handler, converting a missed `deadline` into `on_timeout`.
    fn run_on_queue(
        &self,
        deadline: Duration,
        on_timeout: VmError,
        operation: fn(&VZVirtualMachine, &CompletionBlock),
        on_error: fn(String) -> VmError,
    ) -> Result<(), VmError> {
        let (tx, rx) = mpsc::channel::<Result<(), String>>();
        let vm = QueueBound(self.vm.clone());
        self.queue.exec_async(move || {
            let vm = vm;
            let handler = RcBlock::new(move |error: *mut NSError| {
                let result = if error.is_null() {
                    Ok(())
                } else {
                    // SAFETY: non-null NSError from the completion handler,
                    // valid for the duration of the call.
                    Err(error_message(unsafe { &*error }))
                };
                let _ = tx.send(result);
            });
            operation(&vm.0, &handler);
        });
        match rx.recv_timeout(deadline) {
            Ok(Ok(())) => Ok(()),
            Ok(Err(reason)) => Err(on_error(reason)),
            Err(_) => Err(on_timeout),
        }
    }
}

impl VmDriver for VzDriver {
    fn start(&mut self, boot_timeout: Duration) -> Result<(), VmError> {
        self.run_on_queue(
            boot_timeout,
            VmError::BootTimeout,
            // SAFETY: invoked on the VM's queue; the handler outlives the
            // call (VZ copies escaping blocks).
            |vm, handler| unsafe { vm.startWithCompletionHandler(handler) },
            VmError::Start,
        )
    }

    fn stop(&mut self) -> Result<(), VmError> {
        self.run_on_queue(
            STOP_TIMEOUT,
            VmError::Stop("force-stop timed out".to_string()),
            // SAFETY: as above.
            |vm, handler| unsafe { vm.stopWithCompletionHandler(handler) },
            VmError::Stop,
        )
    }
}

/// Spawn a VM for `spec` on its own runner thread. This is the Phase 1
/// milestone entry point: boot with [`VmHandle::boot`], tear down by dropping
/// the handle. Exec over vsock is Phase 3.
pub fn spawn_vm(spec: VmSpec) -> Result<VmHandle, VmError> {
    VmHandle::spawn(move || VzDriver::new(&spec))
}

fn error_message(error: &NSError) -> String {
    error.localizedDescription().to_string()
}

fn file_url(path: &Path) -> Retained<NSURL> {
    NSURL::fileURLWithPath(&NSString::from_str(&path.to_string_lossy()))
}

/// Translate the platform-neutral [`VmSpec`] into a
/// `VZVirtualMachineConfiguration`: direct kernel boot (no bootloader
/// stage), one virtio-fs device per share, NAT or no network device, and a
/// vsock device for the (Phase 3) exec protocol. No console, GUI, or storage
/// devices — the guest runs from initramfs.
fn build_configuration(spec: &VmSpec) -> Result<Retained<VZVirtualMachineConfiguration>, VmError> {
    // SAFETY: object construction and property setters on freshly created
    // configuration objects, all on the current thread.
    unsafe {
        let boot_loader =
            VZLinuxBootLoader::initWithKernelURL(VZLinuxBootLoader::alloc(), &file_url(&spec.kernel_path));
        boot_loader.setInitialRamdiskURL(Some(&file_url(&spec.initramfs_path)));
        boot_loader.setCommandLine(&NSString::from_str(&spec.kernel_cmdline));

        let config = VZVirtualMachineConfiguration::new();
        config.setBootLoader(Some(&boot_loader));
        config.setCPUCount(spec.cpu_count as usize);
        config.setMemorySize(spec.memory_bytes);

        let mut sharing_devices: Vec<Retained<VZDirectorySharingDeviceConfiguration>> = Vec::new();
        for share in &spec.shares {
            let tag = NSString::from_str(&share.tag);
            VZVirtioFileSystemDeviceConfiguration::validateTag_error(&tag).map_err(|error| {
                VmError::Start(format!(
                    "invalid virtio-fs tag {:?}: {}",
                    share.tag,
                    error_message(&error)
                ))
            })?;
            let directory = VZSharedDirectory::initWithURL_readOnly(
                VZSharedDirectory::alloc(),
                &file_url(&share.host_path),
                share.read_only,
            );
            let single_share =
                VZSingleDirectoryShare::initWithDirectory(VZSingleDirectoryShare::alloc(), &directory);
            let device = VZVirtioFileSystemDeviceConfiguration::initWithTag(
                VZVirtioFileSystemDeviceConfiguration::alloc(),
                &tag,
            );
            device.setShare(Some(&single_share));
            sharing_devices.push(Retained::into_super(device));
        }
        config.setDirectorySharingDevices(&NSArray::from_retained_slice(&sharing_devices));

        // Only defaultPolicy "allow" gets a device; block/absent mean
        // kernel-level absence of networking (design doc, Phase 4 mapping).
        if spec.network == NetworkMode::Nat {
            let device = VZVirtioNetworkDeviceConfiguration::new();
            let nat = VZNATNetworkDeviceAttachment::new();
            device.setAttachment(Some(&nat));
            let devices: [Retained<VZNetworkDeviceConfiguration>; 1] = [Retained::into_super(device)];
            config.setNetworkDevices(&NSArray::from_retained_slice(&devices));
        }

        // vsock device for the guest agent; the host connects to
        // spec.vsock_agent_port after boot (Phase 3).
        let vsock: [Retained<VZSocketDeviceConfiguration>; 1] =
            [Retained::into_super(VZVirtioSocketDeviceConfiguration::new())];
        config.setSocketDevices(&NSArray::from_retained_slice(&vsock));

        Ok(config)
    }
}
