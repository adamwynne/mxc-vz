//! End-to-end exec protocol tests: the REAL guest agent serving the REAL
//! host client over a Unix socketpair — the same code that runs over vsock
//! in the VM, minus the transport. This is the Phase 3 milestone contract,
//! testable on any Linux host.

use std::os::unix::net::UnixStream;
use std::thread;

use vz_guest_agent::serve_connection;
use vz_protocol::client::{exec_collect, ExecError, ExecRequest};

/// Run one exec through a live agent on a socketpair.
fn run(request: ExecRequest, stdin: Option<&[u8]>) -> Result<vz_protocol::client::ExecOutcome, ExecError> {
    let (host_side, agent_side) = UnixStream::pair().expect("socketpair");
    let agent = thread::spawn(move || {
        let reader = agent_side.try_clone().expect("clone agent stream");
        serve_connection(reader, agent_side);
    });
    let reader = host_side.try_clone().expect("clone host stream");
    let outcome = exec_collect(reader, host_side, &request, stdin);
    agent.join().expect("agent thread should not panic");
    outcome
}

fn request(command_line: &str) -> ExecRequest {
    ExecRequest {
        command_line: command_line.to_string(),
        env: Vec::new(),
        cwd: None,
        timeout_ms: None,
    }
}

#[test]
fn echo_roundtrips_stdout_and_exit_code() {
    let outcome = run(request("echo hi"), None).expect("exec should succeed");
    assert_eq!(outcome.exit_code, 0);
    assert_eq!(outcome.stdout, b"hi\n");
    assert!(outcome.stderr.is_empty());
}

#[test]
fn exit_codes_propagate() {
    let outcome = run(request("exit 7"), None).expect("exec should succeed");
    assert_eq!(outcome.exit_code, 7);
}

#[test]
fn stdout_and_stderr_stay_separated() {
    let outcome = run(request("echo out; echo err 1>&2"), None).expect("exec should succeed");
    assert_eq!(outcome.stdout, b"out\n");
    assert_eq!(outcome.stderr, b"err\n");
}

#[test]
fn stdin_reaches_the_child() {
    let outcome = run(request("cat"), Some(b"fed through the frames"))
        .expect("exec should succeed");
    assert_eq!(outcome.exit_code, 0);
    assert_eq!(outcome.stdout, b"fed through the frames");
}

#[test]
fn env_entries_are_passed_through() {
    let mut req = request("echo \"$MXC_TEST_MARKER\"");
    req.env = vec!["MXC_TEST_MARKER=vz-agent-was-here".to_string()];
    let outcome = run(req, None).expect("exec should succeed");
    assert_eq!(outcome.stdout, b"vz-agent-was-here\n");
}

#[test]
fn cwd_is_honored() {
    let mut req = request("pwd");
    req.cwd = Some("/tmp".to_string());
    let outcome = run(req, None).expect("exec should succeed");
    // Symlinked temp dirs are fine as long as it is not the test's own cwd.
    assert!(
        outcome.stdout.starts_with(b"/tmp"),
        "got: {:?}",
        String::from_utf8_lossy(&outcome.stdout)
    );
}

#[test]
fn spawn_failure_surfaces_as_agent_error() {
    let mut req = request("true");
    req.cwd = Some("/nonexistent-mxc-vz-path".to_string());
    let error = run(req, None).expect_err("exec must fail");
    match error {
        ExecError::Agent(message) => {
            assert!(!message.is_empty(), "agent error should carry a reason")
        }
        other => panic!("expected ExecError::Agent, got {other:?}"),
    }
}

#[test]
fn large_output_crosses_multiple_frames() {
    // 3 MiB of output: must span at least 3 max-size frames and arrive intact.
    let outcome = run(
        request("head -c 3145728 /dev/zero | tr '\\0' 'a'"),
        None,
    )
    .expect("exec should succeed");
    assert_eq!(outcome.exit_code, 0);
    assert_eq!(outcome.stdout.len(), 3 * 1024 * 1024);
    assert!(outcome.stdout.iter().all(|&b| b == b'a'));
}

#[test]
fn signal_death_maps_to_128_plus_signal() {
    let outcome = run(request("kill -9 $$"), None).expect("exec should succeed");
    assert_eq!(outcome.exit_code, 137, "SIGKILL should surface as 128+9");
}
