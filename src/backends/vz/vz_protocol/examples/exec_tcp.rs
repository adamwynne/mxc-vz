//! Run one exec against a live guest agent over TCP, with connect-retry as
//! the readiness signal (the same pattern the macOS runner uses over vsock).
//!
//! Usage: exec_tcp <addr> <command> [retry-seconds]
//! Exits with the remote command's exit code; stdout/stderr pass through.

use std::io::Write;
use std::net::TcpStream;
use std::time::{Duration, Instant};

use vz_protocol::client::{exec_collect, ExecRequest};

fn main() {
    let mut args = std::env::args().skip(1);
    let (addr, command) = match (args.next(), args.next()) {
        (Some(addr), Some(command)) => (addr, command),
        _ => {
            eprintln!("usage: exec_tcp <addr> <command> [retry-seconds]");
            std::process::exit(2);
        }
    };
    let retry_secs: u64 = args.next().and_then(|s| s.parse().ok()).unwrap_or(0);

    // Behind a forwarder (QEMU slirp, SSH tunnels) the TCP connect succeeds
    // even before the guest is up, so a connect-retry is not a readiness
    // signal: retry the WHOLE exec on transport errors until the deadline.
    // (Fine for a smoke command; an interrupted exec may have partially run.)
    let deadline = Instant::now() + Duration::from_secs(retry_secs);
    let request = ExecRequest {
        command_line: command,
        env: Vec::new(),
        cwd: None,
        timeout_ms: None,
    };
    loop {
        let attempt = TcpStream::connect(&addr).map_err(ExecFailure::Connect).and_then(|stream| {
            let reader = stream.try_clone().expect("clone stream");
            exec_collect(reader, stream, &request, None).map_err(ExecFailure::Exec)
        });
        match attempt {
            Ok(outcome) => {
                std::io::stdout().write_all(&outcome.stdout).unwrap();
                std::io::stderr().write_all(&outcome.stderr).unwrap();
                std::process::exit(outcome.exit_code);
            }
            // A real agent-reported failure is a result, not unreadiness.
            Err(ExecFailure::Exec(vz_protocol::client::ExecError::Agent(message))) => {
                eprintln!("exec_tcp: guest agent error: {message}");
                std::process::exit(2);
            }
            Err(failure) if Instant::now() < deadline => {
                eprintln!("exec_tcp: {addr} not ready ({failure}); retrying...");
                std::thread::sleep(Duration::from_secs(2));
            }
            Err(failure) => {
                eprintln!("exec_tcp: giving up on {addr}: {failure}");
                std::process::exit(2);
            }
        }
    }
}

enum ExecFailure {
    Connect(std::io::Error),
    Exec(vz_protocol::client::ExecError),
}

impl std::fmt::Display for ExecFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Connect(error) => write!(f, "connect: {error}"),
            Self::Exec(error) => write!(f, "{error}"),
        }
    }
}
