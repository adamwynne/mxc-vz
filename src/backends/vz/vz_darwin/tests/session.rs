//! One-shot session tests: the platform-neutral orchestrator driving a fake
//! VM driver whose agent stream is served by the REAL guest agent over a
//! Unix socketpair — every layer except the hypervisor is the production
//! code path.
//!
//! Contract under test:
//! - Happy path: policy → boot → connect → exec through the real agent →
//!   outcome, with teardown on drop.
//! - `process.timeout` force-stops the VM and surfaces `TimedOut`.
//! - Validation failures short-circuit before any VM exists.
//! - Connecting is only valid in the Running state.
//! - Boot failures surface as `SessionError::Vm`.

use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use vz_common::policy::Policy;
use vz_common::validate::VzPolicyError;
use vz_darwin::runner::{AgentStream, VmDriver, VmError, VmHandle};
use vz_darwin::session::{run_one_shot, SessionError, SessionOutcome};
use vz_guest_agent::serve_connection;

fn policy(process: serde_json::Value) -> Policy {
    serde_json::from_value(serde_json::json!({
        "containment": "vz",
        "process": process,
    }))
    .expect("test policy should deserialize")
}

#[derive(Clone, Default)]
struct Probe {
    calls: Arc<Mutex<Vec<&'static str>>>,
}

impl Probe {
    fn calls(&self) -> Vec<&'static str> {
        self.calls.lock().unwrap().clone()
    }
    fn push(&self, call: &'static str) {
        self.calls.lock().unwrap().push(call);
    }
}

/// Fake driver whose `open_agent_stream` hands out one half of a socketpair
/// with the real guest agent serving the other half.
struct FakeAgentDriver {
    probe: Probe,
    fail_boot: bool,
    /// Clone of the host-side stream; `stop` shuts it down, mirroring a
    /// real VM force-stop severing the vsock connection.
    open_stream: Arc<Mutex<Option<UnixStream>>>,
}

impl FakeAgentDriver {
    fn new(probe: Probe, fail_boot: bool) -> Self {
        Self {
            probe,
            fail_boot,
            open_stream: Arc::new(Mutex::new(None)),
        }
    }
}

impl VmDriver for FakeAgentDriver {
    fn start(&mut self, _boot_timeout: Duration) -> Result<(), VmError> {
        self.probe.push("start");
        if self.fail_boot {
            Err(VmError::Start("kernel image not found".to_string()))
        } else {
            Ok(())
        }
    }

    fn stop(&mut self) -> Result<(), VmError> {
        self.probe.push("stop");
        if let Some(stream) = self.open_stream.lock().unwrap().take() {
            let _ = stream.shutdown(std::net::Shutdown::Both);
        }
        Ok(())
    }

    fn open_agent_stream(&mut self, _port: u32, _timeout: Duration) -> Result<AgentStream, VmError> {
        self.probe.push("connect");
        let (host, agent) = UnixStream::pair()
            .map_err(|e| VmError::Connect(format!("socketpair failed: {e}")))?;
        std::thread::spawn(move || {
            let reader = agent.try_clone().expect("clone agent stream");
            serve_connection(reader, agent);
        });
        let clone = |stream: &UnixStream| {
            stream
                .try_clone()
                .map_err(|e| VmError::Connect(format!("stream clone failed: {e}")))
        };
        *self.open_stream.lock().unwrap() = Some(clone(&host)?);
        Ok(AgentStream {
            reader: Box::new(clone(&host)?),
            writer: Box::new(host),
        })
    }
}

fn run(policy: &Policy, experimental: bool, probe: Probe, fail_boot: bool) -> Result<SessionOutcome, SessionError> {
    run_one_shot(policy, experimental, Path::new("/guest-images"), move || {
        Ok(FakeAgentDriver::new(probe, fail_boot))
    })
}

#[test]
fn one_shot_session_execs_through_the_real_agent() {
    let probe = Probe::default();
    let outcome = run(
        &policy(serde_json::json!({ "commandLine": "echo hi; echo err 1>&2; exit 3" })),
        true,
        probe.clone(),
        false,
    )
    .expect("session should complete");
    match outcome {
        SessionOutcome::Completed(outcome) => {
            assert_eq!(outcome.exit_code, 3);
            assert_eq!(outcome.stdout, b"hi\n");
            assert_eq!(outcome.stderr, b"err\n");
        }
        SessionOutcome::TimedOut => panic!("session must not time out"),
    }
    // The final stop is drop-driven teardown of the still-running VM;
    // run_one_shot joins the VM thread before returning.
    assert_eq!(probe.calls(), vec!["start", "connect", "stop"]);
}

#[test]
fn env_and_cwd_reach_the_guest_command() {
    let outcome = run(
        &policy(serde_json::json!({
            "commandLine": "echo \"$MXC_SESSION_MARKER\"; pwd",
            "env": ["MXC_SESSION_MARKER=through-the-session"],
            "cwd": "/tmp",
        })),
        true,
        Probe::default(),
        false,
    )
    .expect("session should complete");
    let SessionOutcome::Completed(outcome) = outcome else {
        panic!("session must not time out");
    };
    assert_eq!(outcome.exit_code, 0);
    assert!(
        outcome.stdout.starts_with(b"through-the-session\n/tmp"),
        "got: {:?}",
        String::from_utf8_lossy(&outcome.stdout)
    );
}

#[test]
fn exec_timeout_force_stops_the_vm_and_surfaces_timed_out() {
    let probe = Probe::default();
    let started = Instant::now();
    let outcome = run(
        &policy(serde_json::json!({ "commandLine": "sleep 30", "timeout": 300 })),
        true,
        probe.clone(),
        false,
    )
    .expect("a timed-out exec is an outcome, not an error");
    assert_eq!(outcome, SessionOutcome::TimedOut);
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "the session must not wait out the guest command"
    );
    // Exactly one stop: the timeout's force-stop. Drop-teardown sees a VM
    // already stopped and must not stop again.
    assert_eq!(probe.calls(), vec!["start", "connect", "stop"]);
}

#[test]
fn validation_failure_short_circuits_before_any_vm_exists() {
    let factory_ran = Arc::new(AtomicBool::new(false));
    let flag = Arc::clone(&factory_ran);
    // experimental=false: vz requires the experimental flag.
    let error = run_one_shot(
        &policy(serde_json::json!({ "commandLine": "true" })),
        false,
        Path::new("/guest-images"),
        move || {
            flag.store(true, Ordering::SeqCst);
            Ok(FakeAgentDriver::new(Probe::default(), false))
        },
    )
    .expect_err("validation must fail");
    match error {
        SessionError::Validation(errors) => {
            assert!(errors.contains(&VzPolicyError::ExperimentalRequired));
        }
        other => panic!("expected SessionError::Validation, got {other:?}"),
    }
    assert!(
        !factory_ran.load(Ordering::SeqCst),
        "no VM may be spawned for an invalid policy"
    );
}

#[test]
fn missing_command_line_is_a_translation_error() {
    let probe = Probe::default();
    let error = run(&policy(serde_json::json!({})), true, probe.clone(), false)
        .expect_err("a policy with nothing to run must fail");
    match error {
        SessionError::Translation(reason) => {
            assert!(reason.contains("commandLine"), "got: {reason}");
        }
        other => panic!("expected SessionError::Translation, got {other:?}"),
    }
    assert!(probe.calls().is_empty(), "translation happens before the VM spawns");
}

#[test]
fn connect_before_boot_is_rejected() {
    let probe = Probe::default();
    let their_probe = probe.clone();
    let handle = VmHandle::spawn(move || Ok(FakeAgentDriver::new(their_probe, false)))
        .expect("spawn should succeed");
    let error = handle
        .connect(28024, Duration::from_secs(1))
        .expect_err("connect before boot must fail");
    assert_eq!(error, VmError::NotRunning);
    assert!(probe.calls().is_empty(), "the driver must never be asked to connect");
}

#[test]
fn boot_failure_surfaces_as_vm_error() {
    let probe = Probe::default();
    let error = run(
        &policy(serde_json::json!({ "commandLine": "true" })),
        true,
        probe.clone(),
        true,
    )
    .expect_err("boot failure must surface");
    match error {
        SessionError::Vm(VmError::Start(reason)) => {
            assert_eq!(reason, "kernel image not found");
        }
        other => panic!("expected SessionError::Vm(Start), got {other:?}"),
    }
    assert_eq!(probe.calls(), vec!["start"], "no connect, no stop after a failed boot");
}
