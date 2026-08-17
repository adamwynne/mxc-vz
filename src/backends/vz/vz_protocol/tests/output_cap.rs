//! Captured-output cap tests (TM-06 / upstream-wslc parity): the guest owns
//! the stdout/stderr byte streams, so collection into host memory must be
//! bounded. wslc caps captured streams at 8 MiB with a one-time truncation
//! marker — same semantics here.

use std::io::Cursor;

use vz_protocol::client::{exec_collect, ExecRequest, MAX_CAPTURED_STREAM, STREAM_TRUNCATION_MARKER};
use vz_protocol::frame::{write_frame, Channel};
use vz_protocol::message::{encode_control, ControlMessage};

fn request() -> ExecRequest {
    ExecRequest {
        command_line: "irrelevant".to_string(),
        env: Vec::new(),
        cwd: None,
        timeout_ms: None,
    }
}

/// Build the byte stream a (hostile) agent would send: `stdout_total` bytes
/// of stdout in `chunk` sized frames, then a clean exit.
fn agent_stream(stdout_total: usize, chunk: usize, exit_code: i32) -> Vec<u8> {
    let mut stream = Vec::new();
    let mut sent = 0;
    while sent < stdout_total {
        let n = chunk.min(stdout_total - sent);
        write_frame(&mut stream, Channel::Stdout, &vec![b'x'; n]).unwrap();
        sent += n;
    }
    let exit = encode_control(&ControlMessage::Exit { code: exit_code }).unwrap();
    write_frame(&mut stream, Channel::Control, &exit).unwrap();
    stream
}

#[test]
fn output_below_the_cap_is_untouched() {
    let stream = agent_stream(1024 * 1024, 64 * 1024, 0);
    let outcome = exec_collect(Cursor::new(stream), Vec::new(), &request(), None)
        .expect("exec should complete");
    assert_eq!(outcome.exit_code, 0);
    assert_eq!(outcome.stdout.len(), 1024 * 1024);
    assert!(outcome.stderr.is_empty());
}

#[test]
fn oversized_stdout_is_truncated_with_a_marker_and_exit_still_arrives() {
    // 2 MiB past the cap: the head is kept, the marker appended exactly
    // once, the tail discarded — and the frames after the cap are still
    // DRAINED so the exit code arrives (unlike a hard stop, which would
    // lose the result of a successful command with chatty output).
    let stream = agent_stream(MAX_CAPTURED_STREAM + 2 * 1024 * 1024, 256 * 1024, 7);
    let outcome = exec_collect(Cursor::new(stream), Vec::new(), &request(), None)
        .expect("exec must still complete");
    assert_eq!(outcome.exit_code, 7, "exit code must survive truncation");
    assert_eq!(
        outcome.stdout.len(),
        MAX_CAPTURED_STREAM + STREAM_TRUNCATION_MARKER.len(),
        "head kept to the cap plus one marker"
    );
    assert!(outcome.stdout.ends_with(STREAM_TRUNCATION_MARKER));
    let marker_count = outcome
        .stdout
        .windows(STREAM_TRUNCATION_MARKER.len())
        .filter(|w| *w == STREAM_TRUNCATION_MARKER)
        .count();
    assert_eq!(marker_count, 1, "the marker is appended exactly once");
}

#[test]
fn stdout_and_stderr_caps_are_independent() {
    let mut stream = Vec::new();
    // stderr over the cap, stdout small: only stderr is truncated.
    write_frame(&mut stream, Channel::Stdout, b"small stdout").unwrap();
    let mut sent = 0;
    let total = MAX_CAPTURED_STREAM + 1024;
    while sent < total {
        let n = (1024 * 1024).min(total - sent);
        write_frame(&mut stream, Channel::Stderr, &vec![b'e'; n]).unwrap();
        sent += n;
    }
    let exit = encode_control(&ControlMessage::Exit { code: 0 }).unwrap();
    write_frame(&mut stream, Channel::Control, &exit).unwrap();

    let outcome = exec_collect(Cursor::new(stream), Vec::new(), &request(), None)
        .expect("exec should complete");
    assert_eq!(outcome.stdout, b"small stdout");
    assert_eq!(outcome.stderr.len(), MAX_CAPTURED_STREAM + STREAM_TRUNCATION_MARKER.len());
    assert!(outcome.stderr.ends_with(STREAM_TRUNCATION_MARKER));
}
