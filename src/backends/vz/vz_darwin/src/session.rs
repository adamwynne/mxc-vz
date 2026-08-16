//! One-shot session orchestrator: policy in, exec outcome out.
//!
//! Platform-neutral by driver-factory injection: the flow is exercised with
//! a fake driver serving the REAL guest agent (tests/session.rs) and wired
//! to `VzDriver` on macOS. Order of operations: everything policy-derived
//! (validation, exec request, VM spec) is computed before any VM resource
//! exists, so a bad policy never costs a boot.

use std::fmt;
use std::path::Path;
use std::time::Duration;

use vz_common::exec_plan::build_exec_request;
use vz_common::policy::Policy;
use vz_common::validate::{validate_vz_policy, VzPolicyError};
use vz_common::vm_spec::build_vm_spec;
use vz_protocol::client::{
    exec_collect_with_timeout, ExecCompletion, ExecError, ExecOutcome,
};

use crate::runner::{VmDriver, VmError, VmHandle};

#[derive(Debug, Clone, PartialEq)]
pub enum SessionOutcome {
    Completed(ExecOutcome),
    /// `process.timeout` elapsed; the VM was force-stopped. Partial output
    /// is discarded (see [`ExecCompletion::TimedOut`]).
    TimedOut,
}

#[derive(Debug)]
pub enum SessionError {
    Validation(Vec<VzPolicyError>),
    Vm(VmError),
    Exec(ExecError),
    /// The policy validated but cannot be translated into a session (e.g.
    /// no `process.commandLine` to run).
    Translation(String),
}

impl fmt::Display for SessionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Validation(errors) => {
                write!(f, "policy validation failed ({} error(s)):", errors.len())?;
                for error in errors {
                    write!(f, "\n  - {error}")?;
                }
                Ok(())
            }
            Self::Vm(error) => write!(f, "VM lifecycle failure: {error}"),
            Self::Exec(error) => write!(f, "exec failure: {error}"),
            Self::Translation(reason) => write!(f, "policy translation failed: {reason}"),
        }
    }
}

impl std::error::Error for SessionError {}

impl From<VmError> for SessionError {
    fn from(error: VmError) -> Self {
        Self::Vm(error)
    }
}

/// Run one policy end to end: validate → spawn VM → boot → connect to the
/// guest agent → exec `process.commandLine` → tear down.
///
/// The exec deadline is `process.timeout`, enforced host-side by
/// force-stopping the VM (never trusted to the guest); absent means no
/// deadline. Connect-with-retry against `spec.vsock_agent_port` doubles as
/// the boot-readiness signal, budgeted by the boot timeout. Teardown is by
/// drop: `VmHandle` stops a still-running VM and joins its thread on every
/// exit path.
pub fn run_one_shot<D, F>(
    policy: &Policy,
    experimental: bool,
    guest_image_dir: &Path,
    factory: F,
) -> Result<SessionOutcome, SessionError>
where
    D: VmDriver,
    F: FnOnce() -> Result<D, VmError> + Send + 'static,
{
    let validated = validate_vz_policy(policy, experimental).map_err(SessionError::Validation)?;
    let request =
        build_exec_request(policy).map_err(|error| SessionError::Translation(error.to_string()))?;
    let spec = build_vm_spec(policy, &validated, guest_image_dir);

    let handle = VmHandle::spawn(factory)?;
    handle.boot(spec.boot_timeout)?;
    let stream = handle.connect(spec.vsock_agent_port, spec.boot_timeout)?;

    let timeout = request.timeout_ms.map(Duration::from_millis);
    let completion = exec_collect_with_timeout(
        stream.reader,
        stream.writer,
        &request,
        None,
        timeout,
        // Timeout enforcement is VM teardown, not in-guest signalling: the
        // force-stop kills the process with the whole guest and severs the
        // vsock stream the exec client is blocked on.
        || {
            let _ = handle.stop();
        },
    )
    .map_err(SessionError::Exec)?;

    Ok(match completion {
        ExecCompletion::Completed(outcome) => SessionOutcome::Completed(outcome),
        ExecCompletion::TimedOut => SessionOutcome::TimedOut,
    })
}
