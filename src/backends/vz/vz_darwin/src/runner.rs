//! VM lifecycle state machine: a dedicated thread owns the driver, the
//! handle talks to it over channels.
//!
//! VZVirtualMachine has runloop-thread affinity and is not Send, so the
//! driver is created, driven, and dropped on one dedicated thread. The
//! factory closure passed to [`VmHandle::spawn`] runs on that thread.
//!
//! One-shot lifecycle (design doc, Decision 3): Created → Running →
//! Stopped/Failed. A stopped VM is torn down, never reused.

use std::fmt;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread::JoinHandle;
use std::time::Duration;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmState {
    Created,
    Running,
    Stopped,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VmError {
    BootTimeout,
    Start(String),
    Stop(String),
    AlreadyRunning,
    NotRunning,
    Terminated,
}

impl fmt::Display for VmError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BootTimeout => write!(f, "VM did not become ready before the boot timeout"),
            Self::Start(reason) => write!(f, "VM failed to start: {reason}"),
            Self::Stop(reason) => write!(f, "VM failed to stop: {reason}"),
            Self::AlreadyRunning => {
                write!(f, "VM was already booted; the vz lifecycle is one-shot")
            }
            Self::NotRunning => write!(f, "VM is not running"),
            Self::Terminated => write!(f, "VM thread terminated unexpectedly"),
        }
    }
}

impl std::error::Error for VmError {}

/// Driven by the VM thread; implementations own the platform VM object.
pub trait VmDriver: 'static {
    /// Boot the VM, returning once it is running or has definitively failed.
    /// The driver owns enforcing `boot_timeout` (a VZ driver pumps its
    /// runloop with this deadline).
    fn start(&mut self, boot_timeout: Duration) -> Result<(), VmError>;

    /// Force-stop the VM.
    fn stop(&mut self) -> Result<(), VmError>;
}

enum Command {
    Boot {
        timeout: Duration,
        reply: Sender<Result<(), VmError>>,
    },
    Stop {
        reply: Sender<Result<(), VmError>>,
    },
    State {
        reply: Sender<VmState>,
    },
    Shutdown,
}

/// Handle to a VM owned by its dedicated thread. Dropping the handle stops a
/// running VM (best effort), drops the driver on the VM thread, and joins
/// the thread.
pub struct VmHandle {
    commands: Sender<Command>,
    thread: Option<JoinHandle<()>>,
}

impl fmt::Debug for VmHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VmHandle").finish_non_exhaustive()
    }
}

impl VmHandle {
    /// Spawn the VM thread. `factory` runs ON that thread, so non-Send
    /// platform VM objects can be created there. A factory error tears the
    /// thread down and is returned here.
    pub fn spawn<D, F>(factory: F) -> Result<Self, VmError>
    where
        D: VmDriver,
        F: FnOnce() -> Result<D, VmError> + Send + 'static,
    {
        let (commands, command_rx) = mpsc::channel::<Command>();
        let (ready_tx, ready_rx) = mpsc::channel::<Result<(), VmError>>();

        let thread = std::thread::Builder::new()
            .name("mxc-vz-vm".to_string())
            .spawn(move || {
                let driver = match factory() {
                    Ok(driver) => {
                        let _ = ready_tx.send(Ok(()));
                        driver
                    }
                    Err(error) => {
                        let _ = ready_tx.send(Err(error));
                        return;
                    }
                };
                run_vm_thread(driver, command_rx);
            })
            .map_err(|e| VmError::Start(format!("failed to spawn VM thread: {e}")))?;

        let mut handle = VmHandle {
            commands,
            thread: Some(thread),
        };
        match ready_rx.recv() {
            Ok(Ok(())) => Ok(handle),
            Ok(Err(error)) => {
                handle.join();
                Err(error)
            }
            Err(_) => {
                handle.join();
                Err(VmError::Terminated)
            }
        }
    }

    pub fn boot(&self, boot_timeout: Duration) -> Result<(), VmError> {
        let (reply, rx) = mpsc::channel();
        self.commands
            .send(Command::Boot {
                timeout: boot_timeout,
                reply,
            })
            .map_err(|_| VmError::Terminated)?;
        rx.recv().map_err(|_| VmError::Terminated)?
    }

    pub fn stop(&self) -> Result<(), VmError> {
        let (reply, rx) = mpsc::channel();
        self.commands
            .send(Command::Stop { reply })
            .map_err(|_| VmError::Terminated)?;
        rx.recv().map_err(|_| VmError::Terminated)?
    }

    pub fn state(&self) -> Result<VmState, VmError> {
        let (reply, rx) = mpsc::channel();
        self.commands
            .send(Command::State { reply })
            .map_err(|_| VmError::Terminated)?;
        rx.recv().map_err(|_| VmError::Terminated)
    }

    fn join(&mut self) {
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

impl Drop for VmHandle {
    fn drop(&mut self) {
        // Shutdown stops a running VM and drops the driver on the VM thread;
        // if the thread is already gone the send just fails.
        let _ = self.commands.send(Command::Shutdown);
        self.join();
    }
}

fn run_vm_thread<D: VmDriver>(mut driver: D, commands: Receiver<Command>) {
    let mut state = VmState::Created;

    while let Ok(command) = commands.recv() {
        match command {
            Command::Boot { timeout, reply } => {
                let result = if state != VmState::Created {
                    Err(VmError::AlreadyRunning)
                } else {
                    match driver.start(timeout) {
                        Ok(()) => {
                            state = VmState::Running;
                            Ok(())
                        }
                        Err(error) => {
                            // A timed-out boot may still be mid-flight;
                            // force-stop so it cannot land later (best effort
                            // — the VM is torn down either way).
                            if error == VmError::BootTimeout {
                                let _ = driver.stop();
                            }
                            state = VmState::Failed;
                            Err(error)
                        }
                    }
                };
                let _ = reply.send(result);
            }
            Command::Stop { reply } => {
                let result = if state != VmState::Running {
                    Err(VmError::NotRunning)
                } else {
                    match driver.stop() {
                        Ok(()) => {
                            state = VmState::Stopped;
                            Ok(())
                        }
                        Err(error) => {
                            state = VmState::Failed;
                            Err(error)
                        }
                    }
                };
                let _ = reply.send(result);
            }
            Command::State { reply } => {
                let _ = reply.send(state);
            }
            Command::Shutdown => break,
        }
    }

    // Reached on Shutdown or when every handle sender is gone.
    if state == VmState::Running {
        let _ = driver.stop();
    }
    // `driver` drops here, on the VM thread.
}
