//! Lifecycle tests for the VM runner thread, using a fake driver.
//!
//! Contract under test (build plan, Phase 1 item 3 — "the fiddliest part"):
//! - The driver is created and dropped ON the VM thread (VZVirtualMachine is
//!   not Send; the factory closure runs on the thread the VM will live on).
//! - One-shot lifecycle: Created → boot → Running → stop → Stopped. Boot is
//!   only valid from Created; stop only from Running.
//! - A boot timeout force-stops the VM (best effort) and marks it Failed.
//! - Dropping the handle stops a running VM, drops the driver on the VM
//!   thread, and joins the thread — no leaks, no orphaned VMs.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use vz_darwin::runner::{AgentStream, VmDriver, VmError, VmHandle, VmState};

/// What the fake driver's `start` should do.
#[derive(Clone, Copy)]
enum StartBehavior {
    Succeed,
    Fail,
    TimeOut,
}

#[derive(Clone, Default)]
struct Probe {
    calls: Arc<Mutex<Vec<&'static str>>>,
    dropped: Arc<AtomicBool>,
}

impl Probe {
    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
    fn was_dropped(&self) -> bool {
        self.dropped.load(Ordering::SeqCst)
    }
}

struct FakeDriver {
    behavior: StartBehavior,
    probe: Probe,
}

impl VmDriver for FakeDriver {
    fn start(&mut self, _boot_timeout: Duration) -> Result<(), VmError> {
        self.probe.calls.lock().unwrap().push("start");
        match self.behavior {
            StartBehavior::Succeed => Ok(()),
            StartBehavior::Fail => Err(VmError::Start("kernel image not found".to_string())),
            StartBehavior::TimeOut => Err(VmError::BootTimeout),
        }
    }

    fn stop(&mut self) -> Result<(), VmError> {
        self.probe.calls.lock().unwrap().push("stop");
        Ok(())
    }

    // Agent streams are covered by tests/session.rs; the lifecycle fake has
    // no guest to connect to.
    fn open_agent_stream(&mut self, _port: u32, _timeout: Duration) -> Result<AgentStream, VmError> {
        self.probe.calls.lock().unwrap().push("connect");
        Err(VmError::Connect("lifecycle fake has no guest agent".to_string()))
    }
}

impl Drop for FakeDriver {
    fn drop(&mut self) {
        self.probe.dropped.store(true, Ordering::SeqCst);
    }
}

fn spawn(behavior: StartBehavior) -> (VmHandle, Probe) {
    let probe = Probe::default();
    let their_probe = probe.clone();
    let handle = VmHandle::spawn(move || {
        Ok(FakeDriver {
            behavior,
            probe: their_probe,
        })
    })
    .expect("spawn should succeed");
    (handle, probe)
}

const TIMEOUT: Duration = Duration::from_secs(5);

#[test]
fn boot_transitions_to_running() {
    let (handle, probe) = spawn(StartBehavior::Succeed);
    assert_eq!(handle.state().unwrap(), VmState::Created);
    handle.boot(TIMEOUT).expect("boot should succeed");
    assert_eq!(handle.state().unwrap(), VmState::Running);
    assert_eq!(probe.calls(), vec!["start"]);
}

#[test]
fn boot_failure_propagates_and_marks_failed() {
    let (handle, _probe) = spawn(StartBehavior::Fail);
    let error = handle.boot(TIMEOUT).expect_err("boot should fail");
    assert_eq!(error, VmError::Start("kernel image not found".to_string()));
    assert_eq!(handle.state().unwrap(), VmState::Failed);
}

#[test]
fn boot_timeout_force_stops_and_marks_failed() {
    let (handle, probe) = spawn(StartBehavior::TimeOut);
    let error = handle.boot(TIMEOUT).expect_err("boot should time out");
    assert_eq!(error, VmError::BootTimeout);
    assert_eq!(handle.state().unwrap(), VmState::Failed);
    assert_eq!(
        probe.calls(),
        vec!["start", "stop"],
        "a timed-out boot must be force-stopped, not left running"
    );
}

#[test]
fn double_boot_is_rejected() {
    let (handle, probe) = spawn(StartBehavior::Succeed);
    handle.boot(TIMEOUT).expect("first boot should succeed");
    let error = handle.boot(TIMEOUT).expect_err("second boot must fail");
    assert_eq!(error, VmError::AlreadyRunning);
    assert_eq!(probe.calls(), vec!["start"], "driver must not be started twice");
}

#[test]
fn stop_before_boot_is_rejected() {
    let (handle, probe) = spawn(StartBehavior::Succeed);
    let error = handle.stop().expect_err("stop before boot must fail");
    assert_eq!(error, VmError::NotRunning);
    assert!(probe.calls().is_empty());
}

#[test]
fn stop_after_boot_transitions_to_stopped() {
    let (handle, probe) = spawn(StartBehavior::Succeed);
    handle.boot(TIMEOUT).expect("boot should succeed");
    handle.stop().expect("stop should succeed");
    assert_eq!(handle.state().unwrap(), VmState::Stopped);
    assert_eq!(probe.calls(), vec!["start", "stop"]);
}

#[test]
fn boot_after_stop_is_rejected() {
    // One-shot lifecycle (Decision 3): a stopped VM is torn down, not reused.
    let (handle, _probe) = spawn(StartBehavior::Succeed);
    handle.boot(TIMEOUT).expect("boot should succeed");
    handle.stop().expect("stop should succeed");
    let error = handle.boot(TIMEOUT).expect_err("boot after stop must fail");
    assert_eq!(error, VmError::AlreadyRunning);
}

#[test]
fn connect_routes_to_the_driver_only_when_running() {
    let (handle, probe) = spawn(StartBehavior::Succeed);
    let error = handle
        .connect(28024, TIMEOUT)
        .expect_err("connect before boot must fail");
    assert_eq!(error, VmError::NotRunning);
    handle.boot(TIMEOUT).expect("boot should succeed");
    let error = handle
        .connect(28024, TIMEOUT)
        .expect_err("the lifecycle fake has no agent");
    assert_eq!(
        error,
        VmError::Connect("lifecycle fake has no guest agent".to_string())
    );
    assert_eq!(
        probe.calls(),
        vec!["start", "connect"],
        "connect must reach the driver only in the Running state"
    );
}

#[test]
fn drop_stops_running_vm_and_joins_thread() {
    let (handle, probe) = spawn(StartBehavior::Succeed);
    handle.boot(TIMEOUT).expect("boot should succeed");
    drop(handle);
    // Drop joins the VM thread, so by the time it returns the driver must
    // have been stopped and dropped on that thread.
    assert_eq!(probe.calls(), vec!["start", "stop"]);
    assert!(probe.was_dropped(), "driver must be dropped on shutdown");
}

#[test]
fn drop_without_boot_still_tears_down_cleanly() {
    let (handle, probe) = spawn(StartBehavior::Succeed);
    drop(handle);
    assert!(probe.calls().is_empty(), "nothing to stop");
    assert!(probe.was_dropped(), "driver must be dropped on shutdown");
}

#[test]
fn factory_failure_surfaces_from_spawn() {
    let result = VmHandle::spawn(|| -> Result<FakeDriver, VmError> {
        Err(VmError::Start("missing virtualization entitlement".to_string()))
    });
    let error = result.expect_err("factory failure must surface");
    assert_eq!(
        error,
        VmError::Start("missing virtualization entitlement".to_string())
    );
}

#[test]
fn errors_render_human_readable_messages() {
    for (error, needle) in [
        (VmError::BootTimeout, "boot"),
        (VmError::Start("x".to_string()), "start"),
        (VmError::Stop("x".to_string()), "stop"),
        (VmError::Connect("x".to_string()), "connect"),
        (VmError::ConnectTimeout, "agent"),
        (VmError::AlreadyRunning, "already"),
        (VmError::NotRunning, "not running"),
        (VmError::Terminated, "thread"),
    ] {
        let message = error.to_string().to_lowercase();
        assert!(
            message.contains(needle),
            "message {message:?} should mention {needle:?}"
        );
    }
}
