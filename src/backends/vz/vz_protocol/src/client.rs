//! Host-side exec client: drives one exec over any framed stream.

use std::io::{Read, Write};

use crate::frame::FrameError;

#[derive(Debug, Clone, PartialEq)]
pub struct ExecRequest {
    pub command_line: String,
    pub env: Vec<String>,
    pub cwd: Option<String>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct ExecOutcome {
    pub exit_code: i32,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

#[derive(Debug)]
pub enum ExecError {
    Frame(FrameError),
    /// The agent reported a failure (e.g. spawn error).
    Agent(String),
    /// The agent violated the protocol.
    Protocol(String),
}

impl std::fmt::Display for ExecError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Frame(error) => write!(f, "exec transport error: {error}"),
            Self::Agent(message) => write!(f, "guest agent error: {message}"),
            Self::Protocol(message) => write!(f, "protocol violation from guest: {message}"),
        }
    }
}

impl std::error::Error for ExecError {}

impl From<FrameError> for ExecError {
    fn from(error: FrameError) -> Self {
        Self::Frame(error)
    }
}

/// Outcome of a deadline-bounded exec: either the agent reported completion,
/// or the deadline passed and the force-stop hook was invoked.
#[derive(Debug)]
pub enum ExecCompletion {
    Completed(ExecOutcome),
    TimedOut,
}

/// Like [`exec_collect`], but enforce `timeout` by invoking `force_stop`
/// (host-side VM force-stop — the plan's hard guarantee) when the deadline
/// passes. `TimedOut` is an outcome, not an error.
pub fn exec_collect_with_timeout<R, W>(
    reader: R,
    writer: W,
    request: &ExecRequest,
    stdin: Option<Vec<u8>>,
    timeout: Option<std::time::Duration>,
    force_stop: impl FnOnce(),
) -> Result<ExecCompletion, ExecError>
where
    R: Read + Send + 'static,
    W: Write + Send + 'static,
{
    let Some(timeout) = timeout else {
        return exec_collect(reader, writer, request, stdin.as_deref())
            .map(ExecCompletion::Completed);
    };

    let (result_tx, result_rx) = std::sync::mpsc::channel();
    let request = request.clone();
    let worker = std::thread::spawn(move || {
        let _ = result_tx.send(exec_collect(reader, writer, &request, stdin.as_deref()));
    });

    match result_rx.recv_timeout(timeout) {
        Ok(result) => {
            let _ = worker.join();
            result.map(ExecCompletion::Completed)
        }
        Err(_) => {
            // Deadline passed: force-stop the VM. That tears down the
            // transport, which unblocks the worker; its transport error is
            // expected and discarded — TimedOut is the outcome.
            force_stop();
            let _ = worker.join();
            Ok(ExecCompletion::TimedOut)
        }
    }
}

/// Send `request` (plus optional stdin), then collect stdout/stderr until the
/// agent reports the exit code.
///
/// Stdin is sent up-front in capped chunks followed by the empty-frame EOF
/// signal — suitable for the one-shot collect API; interactive/PTY streaming
/// arrives with the mac-side runner integration.
/// Per-stream cap on collected stdout/stderr, matching upstream wslc's
/// captured-stream cap (`MAX_CAPTURED_STREAM_BYTES`): the guest owns these
/// byte streams, and without a ceiling one exec could grow host memory
/// without bound.
pub const MAX_CAPTURED_STREAM: usize = 8 * 1024 * 1024;

/// Appended exactly once to a stream that hits the cap, so a consumer can
/// tell the output was truncated rather than genuinely ending there
/// (verbatim upstream wslc marker).
pub const STREAM_TRUNCATION_MARKER: &[u8] =
    b"\n[output truncated: stream exceeded capture cap]\n";

/// Append `bytes` to a captured stream, enforcing [`MAX_CAPTURED_STREAM`].
/// Once the cap is reached the buffer stops growing; the marker is appended
/// exactly once, the first time data is actually dropped (including when an
/// earlier append landed exactly on the cap — an edge upstream misses).
fn append_capped(buf: &mut Vec<u8>, bytes: &[u8]) {
    if buf.len() > MAX_CAPTURED_STREAM {
        return; // already truncated and marked
    }
    if buf.len() == MAX_CAPTURED_STREAM {
        if !bytes.is_empty() {
            buf.extend_from_slice(STREAM_TRUNCATION_MARKER);
        }
        return;
    }
    let remaining = MAX_CAPTURED_STREAM - buf.len();
    if bytes.len() <= remaining {
        buf.extend_from_slice(bytes);
    } else {
        buf.extend_from_slice(&bytes[..remaining]);
        buf.extend_from_slice(STREAM_TRUNCATION_MARKER);
    }
}

pub fn exec_collect(
    mut reader: impl Read,
    mut writer: impl Write,
    request: &ExecRequest,
    stdin: Option<&[u8]>,
) -> Result<ExecOutcome, ExecError> {
    use crate::frame::{read_frame, write_frame, Channel, MAX_FRAME_PAYLOAD};
    use crate::message::{decode_control, encode_control, ControlMessage};

    let exec = ControlMessage::Exec {
        command_line: request.command_line.clone(),
        env: request.env.clone(),
        cwd: request.cwd.clone(),
        timeout_ms: request.timeout_ms,
    };
    let payload = encode_control(&exec)
        .map_err(|e| ExecError::Protocol(format!("encoding exec request: {e}")))?;
    write_frame(&mut writer, Channel::Control, &payload)?;

    for chunk in stdin.unwrap_or_default().chunks(MAX_FRAME_PAYLOAD) {
        write_frame(&mut writer, Channel::Stdin, chunk)?;
    }
    // Empty Stdin frame = EOF signal.
    write_frame(&mut writer, Channel::Stdin, &[])?;
    writer.flush().map_err(crate::frame::FrameError::from)?;

    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    loop {
        let frame = match read_frame(&mut reader) {
            Ok(frame) => frame,
            Err(crate::frame::FrameError::Closed) => {
                return Err(ExecError::Protocol(
                    "guest closed the stream before reporting an exit code".to_string(),
                ))
            }
            Err(error) => return Err(error.into()),
        };
        match frame.channel {
            // The guest owns these byte streams (TM-06): collection is
            // capped per stream (upstream wslc's MAX_CAPTURED_STREAM_BYTES
            // pattern — a hostile guest must not OOM the host), but frames
            // keep DRAINING past the cap so the exit code still arrives.
            Channel::Stdout => append_capped(&mut stdout, &frame.payload),
            Channel::Stderr => append_capped(&mut stderr, &frame.payload),
            Channel::Stdin => {
                return Err(ExecError::Protocol(
                    "guest sent a stdin frame to the host".to_string(),
                ))
            }
            Channel::Control => {
                let message = decode_control(&frame.payload)
                    .map_err(|e| ExecError::Protocol(format!("invalid control frame: {e}")))?;
                match message {
                    ControlMessage::Exit { code } => {
                        return Ok(ExecOutcome { exit_code: code, stdout, stderr })
                    }
                    ControlMessage::Error { message } => return Err(ExecError::Agent(message)),
                    ControlMessage::Exec { .. } => {
                        return Err(ExecError::Protocol(
                            "guest echoed an exec request".to_string(),
                        ))
                    }
                }
            }
        }
    }
}
