//! Policy → exec-request translation (Phase 4: process passthrough).

use crate::policy::Policy;
use vz_protocol::client::ExecRequest;

/// Build the exec protocol request from the policy's `process` block.
///
/// `cwd` passes through unchanged: virtio-fs shares mount at identical guest
/// paths, so the identity mapping IS the guest-mount-point mapping.
pub fn build_exec_request(policy: &Policy) -> Result<ExecRequest, String> {
    let process = policy
        .process
        .as_ref()
        .ok_or("policy has no process block; one-shot exec requires process.commandLine")?;
    let command_line = process
        .command_line
        .clone()
        .filter(|command| !command.is_empty())
        .ok_or("process.commandLine is required for one-shot exec")?;
    Ok(ExecRequest {
        command_line,
        env: process.env.clone().unwrap_or_default(),
        cwd: process.cwd.clone(),
        timeout_ms: process.timeout,
    })
}
