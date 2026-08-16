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
            Channel::Stdout => stdout.extend_from_slice(&frame.payload),
            Channel::Stderr => stderr.extend_from_slice(&frame.payload),
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
