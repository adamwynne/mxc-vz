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

    let deadline = Instant::now() + Duration::from_secs(retry_secs);
    let stream = loop {
        match TcpStream::connect(&addr) {
            Ok(stream) => break stream,
            Err(error) if Instant::now() < deadline => {
                eprintln!("exec_tcp: {addr} not ready ({error}); retrying...");
                std::thread::sleep(Duration::from_secs(2));
            }
            Err(error) => {
                eprintln!("exec_tcp: cannot connect to {addr}: {error}");
                std::process::exit(2);
            }
        }
    };

    let reader = stream.try_clone().expect("clone stream");
    let request = ExecRequest {
        command_line: command,
        env: Vec::new(),
        cwd: None,
        timeout_ms: None,
    };
    match exec_collect(reader, stream, &request, None) {
        Ok(outcome) => {
            std::io::stdout().write_all(&outcome.stdout).unwrap();
            std::io::stderr().write_all(&outcome.stderr).unwrap();
            std::process::exit(outcome.exit_code);
        }
        Err(error) => {
            eprintln!("exec_tcp: {error}");
            std::process::exit(2);
        }
    }
}
