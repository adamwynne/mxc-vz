//! Timeout semantics against the real agent (Phase 4: the plan's hard
//! guarantee — the host enforces `process.timeout` by force-stopping the VM,
//! which no in-guest cooperation can outrun).
//!
//! The force-stop hook here shuts down the socketpair, which is exactly what
//! a VZ force-stop does to the vsock connection from the exec client's
//! perspective.

use std::net::Shutdown;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use vz_guest_agent::serve_connection;
use vz_protocol::client::{exec_collect_with_timeout, ExecCompletion, ExecRequest};

fn request(command_line: &str, timeout_ms: Option<u64>) -> ExecRequest {
    ExecRequest {
        command_line: command_line.to_string(),
        env: Vec::new(),
        cwd: None,
        timeout_ms,
    }
}

fn run(
    request: &ExecRequest,
    timeout: Option<Duration>,
) -> (Result<ExecCompletion, vz_protocol::client::ExecError>, bool) {
    let (host_side, agent_side) = UnixStream::pair().expect("socketpair");
    let agent = thread::spawn(move || {
        let reader = agent_side.try_clone().expect("clone agent stream");
        serve_connection(reader, agent_side);
    });

    let stopped = Arc::new(AtomicBool::new(false));
    let force_stop = {
        let stopped = Arc::clone(&stopped);
        let stream = host_side.try_clone().expect("clone for force-stop");
        move || {
            stopped.store(true, Ordering::SeqCst);
            let _ = stream.shutdown(Shutdown::Both);
        }
    };

    let reader = host_side.try_clone().expect("clone host stream");
    let result = exec_collect_with_timeout(reader, host_side, request, None, timeout, force_stop);
    // The agent thread must terminate either way — completed exec or a dead
    // connection after force-stop.
    agent.join().expect("agent thread should not panic");
    (result, stopped.load(Ordering::SeqCst))
}

#[test]
fn fast_command_completes_within_timeout() {
    let (result, stopped) = run(&request("echo done", Some(30000)), Some(Duration::from_secs(30)));
    match result.expect("exec should succeed") {
        ExecCompletion::Completed(outcome) => {
            assert_eq!(outcome.exit_code, 0);
            assert_eq!(outcome.stdout, b"done\n");
        }
        ExecCompletion::TimedOut => panic!("fast command must not time out"),
    }
    assert!(!stopped, "force-stop must not fire on a completed exec");
}

#[test]
fn no_timeout_means_wait_for_completion() {
    let (result, stopped) = run(&request("sleep 0.2; echo late", None), None);
    match result.expect("exec should succeed") {
        ExecCompletion::Completed(outcome) => assert_eq!(outcome.stdout, b"late\n"),
        ExecCompletion::TimedOut => panic!("no timeout configured"),
    }
    assert!(!stopped);
}

#[test]
fn overrunning_command_is_force_stopped() {
    // Not via run(): a real VZ force-stop kills the VM and the child with
    // it, but our socketpair shutdown only kills the transport — the agent
    // thread would sit in child.wait() for the full sleep. So here the
    // agent thread is deliberately left detached (it dies with the test
    // process) and the promptness assertion wraps only the client call.
    let (host_side, agent_side) = UnixStream::pair().expect("socketpair");
    let _agent = thread::spawn(move || {
        let reader = agent_side.try_clone().expect("clone agent stream");
        serve_connection(reader, agent_side);
    });

    let stopped = Arc::new(AtomicBool::new(false));
    let force_stop = {
        let stopped = Arc::clone(&stopped);
        let stream = host_side.try_clone().expect("clone for force-stop");
        move || {
            stopped.store(true, Ordering::SeqCst);
            let _ = stream.shutdown(Shutdown::Both);
        }
    };

    let started = Instant::now();
    let reader = host_side.try_clone().expect("clone host stream");
    let result = exec_collect_with_timeout(
        reader,
        host_side,
        &request("sleep 30", Some(300)),
        None,
        Some(Duration::from_millis(300)),
        force_stop,
    );
    let elapsed = started.elapsed();

    match result.expect("timeout is an outcome, not an error") {
        ExecCompletion::TimedOut => {}
        ExecCompletion::Completed(outcome) => panic!("sleep 30 completed?! {outcome:?}"),
    }
    assert!(stopped.load(Ordering::SeqCst), "the force-stop hook must fire on timeout");
    assert!(
        elapsed < Duration::from_secs(10),
        "force-stop must unblock promptly, took {elapsed:?}"
    );
}
