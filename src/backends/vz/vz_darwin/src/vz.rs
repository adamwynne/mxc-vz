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

use std::os::fd::{FromRawFd, RawFd};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use block2::RcBlock;
use dispatch2::{DispatchQueue, DispatchRetained};
use objc2::rc::Retained;
use objc2::AnyThread;
use objc2_foundation::{NSArray, NSError, NSString, NSURL};
use objc2_virtualization::{
    VZDirectorySharingDeviceConfiguration, VZLinuxBootLoader, VZNATNetworkDeviceAttachment,
    VZNetworkDeviceConfiguration, VZSharedDirectory, VZSingleDirectoryShare,
    VZSocketDeviceConfiguration, VZVirtioFileSystemDeviceConfiguration,
    VZVirtioNetworkDeviceConfiguration, VZVirtioSocketConnection, VZVirtioSocketDevice,
    VZVirtioSocketDeviceConfiguration, VZVirtualMachine, VZVirtualMachineConfiguration,
};

use crate::runner::{AgentStream, VmDriver, VmError, VmHandle};
use vz_common::vm_spec::{NetworkMode, VmSpec};

/// Grace period for a force-stop to complete.
const STOP_TIMEOUT: Duration = Duration::from_secs(10);

/// Poll interval between vsock connect attempts while the guest boots.
const CONNECT_RETRY_INTERVAL: Duration = Duration::from_millis(100);

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

    /// One vsock connect attempt, submitted on the VM's queue. `NotReady` is
    /// the pre-boot refusal (nothing listening on the port yet); `Fatal`
    /// failures no amount of waiting fixes.
    fn try_connect(&self, port: u32, wait_budget: Duration) -> ConnectAttempt {
        let (tx, rx) = mpsc::channel::<ConnectAttempt>();
        let vm = QueueBound(self.vm.clone());
        self.queue.exec_async(move || {
            let vm = vm;
            // SAFETY: property read on the VM's queue.
            let devices = unsafe { vm.0.socketDevices() };
            let Some(device) = devices.firstObject() else {
                let _ = tx.send(ConnectAttempt::Fatal(
                    "VM has no socket devices; the configuration must include a virtio socket device"
                        .to_string(),
                ));
                return;
            };
            let Ok(device) = device.downcast::<VZVirtioSocketDevice>() else {
                let _ = tx.send(ConnectAttempt::Fatal(
                    "socket device 0 is not a VZVirtioSocketDevice".to_string(),
                ));
                return;
            };
            let handler = RcBlock::new(
                move |connection: *mut VZVirtioSocketConnection, error: *mut NSError| {
                    let _ = tx.send(claim_connection(connection, error));
                },
            );
            // SAFETY: invoked on the VM's queue; the handler outlives the
            // call (VZ copies escaping blocks).
            unsafe { device.connectToPort_completionHandler(port, &handler) };
        });
        match rx.recv_timeout(wait_budget) {
            Ok(attempt) => attempt,
            Err(_) => ConnectAttempt::TimedOut,
        }
    }
}

/// Outcome of a single vsock connect attempt.
enum ConnectAttempt {
    /// A duped fd we exclusively own.
    Connected(RawFd),
    /// Refused — the guest agent is not listening yet; retry until deadline.
    NotReady,
    Fatal(String),
    /// The completion handler never fired within the attempt's budget.
    TimedOut,
}

/// Extract an owned fd from a connect completion. The fd inside a
/// `VZVirtioSocketConnection` is owned by that object and closed when it is
/// released (which can happen as soon as the handler returns), so the only
/// safe move is to `dup` it inside the handler.
fn claim_connection(
    connection: *mut VZVirtioSocketConnection,
    error: *mut NSError,
) -> ConnectAttempt {
    if connection.is_null() {
        return if error.is_null() {
            ConnectAttempt::Fatal(
                "connect completion delivered neither a connection nor an error".to_string(),
            )
        } else {
            // A refusal means nothing is listening on the port yet; the
            // NSError text adds nothing over "retry".
            ConnectAttempt::NotReady
        };
    }
    // SAFETY: non-null connection, valid for the duration of the call.
    let fd = unsafe { (*connection).fileDescriptor() };
    if fd < 0 {
        return ConnectAttempt::NotReady; // guest closed the connection immediately
    }
    // SAFETY: `fd` is open here (owned by the still-alive connection object).
    let duped = unsafe { libc::dup(fd) };
    if duped < 0 {
        ConnectAttempt::Fatal(format!(
            "dup of the vsock fd failed: {}",
            std::io::Error::last_os_error()
        ))
    } else {
        ConnectAttempt::Connected(duped)
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

    fn open_agent_stream(&mut self, port: u32, timeout: Duration) -> Result<AgentStream, VmError> {
        // Connect-with-retry is the boot-readiness signal (design doc,
        // Phase 3): the guest refuses until its agent listens on the port,
        // so refusals before the deadline mean "still booting", not broken.
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return Err(VmError::ConnectTimeout);
            }
            match self.try_connect(port, remaining) {
                // SAFETY: `fd` is a freshly duped descriptor this call owns
                // exclusively; UnixStream takes over closing it.
                ConnectAttempt::Connected(fd) => {
                    let stream = unsafe { UnixStream::from_raw_fd(fd) };
                    let reader = stream.try_clone().map_err(|e| {
                        VmError::Connect(format!("cloning the vsock stream failed: {e}"))
                    })?;
                    return Ok(AgentStream {
                        reader: Box::new(reader),
                        writer: Box::new(stream),
                    });
                }
                ConnectAttempt::NotReady => {
                    if Instant::now() + CONNECT_RETRY_INTERVAL >= deadline {
                        return Err(VmError::ConnectTimeout);
                    }
                    std::thread::sleep(CONNECT_RETRY_INTERVAL);
                }
                ConnectAttempt::Fatal(reason) => return Err(VmError::Connect(reason)),
                ConnectAttempt::TimedOut => return Err(VmError::ConnectTimeout),
            }
        }
    }
}

/// Spawn a VM for `spec` on its own runner thread: boot with
/// [`VmHandle::boot`], reach the guest agent with [`VmHandle::connect`],
/// tear down by dropping the handle. The full policy-to-outcome flow lives
/// in `session::run_one_shot`.
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
        // spec.vsock_agent_port after boot (`open_agent_stream`).
        let vsock: [Retained<VZSocketDeviceConfiguration>; 1] =
            [Retained::into_super(VZVirtioSocketDeviceConfiguration::new())];
        config.setSocketDevices(&NSArray::from_retained_slice(&vsock));

        Ok(config)
    }
}
