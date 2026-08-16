//! Guest-side exec agent: accepts one framed connection, executes the
//! requested command, and bridges stdio over frames.
//!
//! Protocol per connection:
//! 1. First frame must be a Control/Exec message.
//! 2. The command line runs via `/bin/sh -c` with the request's env entries
//!    (`KEY=VALUE`) and cwd applied.
//! 3. Incoming Stdin frames feed the child; an EMPTY Stdin frame closes the
//!    child's stdin.
//! 4. Child stdout/stderr stream out as Stdout/Stderr frames.
//! 5. A Control/Exit frame with the exit code (128+signal for signal deaths)
//!    ends the exchange; failures before exec produce Control/Error.

use std::io::{Read, Write};
use std::process::{Command, Stdio};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;

use vz_protocol::frame::{read_frame, write_frame, Channel, FrameError, MAX_FRAME_PAYLOAD};
use vz_protocol::message::{decode_control, encode_control, ControlMessage};

type SharedWriter<W> = Arc<Mutex<W>>;

/// Serve a single connection. Errors are reported to the peer as
/// Control/Error frames (best effort); this function does not panic on
/// malformed input.
pub fn serve_connection(mut reader: impl Read, writer: impl Write + Send + 'static) {
    let writer: SharedWriter<_> = Arc::new(Mutex::new(writer));
    if let Err(message) = serve_inner(&mut reader, &writer) {
        let _ = send_control(&writer, &ControlMessage::Error { message });
    }
}

fn serve_inner<W: Write + Send + 'static>(
    reader: &mut impl Read,
    writer: &SharedWriter<W>,
) -> Result<(), String> {
    let first = read_frame(reader).map_err(|e| format!("reading exec request: {e}"))?;
    if first.channel != Channel::Control {
        return Err(format!("expected a control frame first, got {:?}", first.channel));
    }
    let message =
        decode_control(&first.payload).map_err(|e| format!("invalid exec request: {e}"))?;
    let ControlMessage::Exec { command_line, env, cwd, timeout_ms: _ } = message else {
        return Err("expected an exec request as the first control message".to_string());
    };

    let mut command = Command::new("/bin/sh");
    command
        .arg("-c")
        .arg(&command_line)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    for entry in &env {
        if let Some((key, value)) = entry.split_once('=') {
            command.env(key, value);
        }
    }
    if let Some(cwd) = &cwd {
        command.current_dir(cwd);
    }

    let mut child = command.spawn().map_err(|e| format!("spawn failed: {e}"))?;

    let stdout_pump = pump(child.stdout.take(), Channel::Stdout, Arc::clone(writer));
    let stderr_pump = pump(child.stderr.take(), Channel::Stderr, Arc::clone(writer));

    // Feed stdin until the EOF frame (empty payload) or the stream ends.
    let mut child_stdin = child.stdin.take();
    loop {
        match read_frame(reader) {
            Ok(frame) if frame.channel == Channel::Stdin => {
                if frame.payload.is_empty() {
                    child_stdin = None; // dropping the pipe closes it
                    break;
                }
                if let Some(stdin) = child_stdin.as_mut() {
                    if stdin.write_all(&frame.payload).is_err() {
                        child_stdin = None; // child stopped reading; keep draining frames
                    }
                }
            }
            Ok(_) => continue, // tolerate unexpected channels
            Err(FrameError::Closed) | Err(_) => {
                child_stdin = None;
                break;
            }
        }
    }
    drop(child_stdin);

    let status = child.wait().map_err(|e| format!("wait failed: {e}"))?;
    // Let the pipes drain fully before reporting the exit.
    if let Some(handle) = stdout_pump {
        let _ = handle.join();
    }
    if let Some(handle) = stderr_pump {
        let _ = handle.join();
    }

    let exit_code = exit_code_of(&status);
    send_control(writer, &ControlMessage::Exit { code: exit_code })
        .map_err(|e| format!("reporting exit: {e}"))?;
    Ok(())
}

fn exit_code_of(status: &std::process::ExitStatus) -> i32 {
    if let Some(code) = status.code() {
        return code;
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt;
        if let Some(signal) = status.signal() {
            return 128 + signal;
        }
    }
    -1
}

fn send_control<W: Write>(
    writer: &SharedWriter<W>,
    message: &ControlMessage,
) -> Result<(), FrameError> {
    let payload = encode_control(message).map_err(|e| {
        FrameError::Io(std::io::Error::other(format!("encoding control message: {e}")))
    })?;
    let mut writer = writer.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    write_frame(&mut *writer, Channel::Control, &payload)?;
    writer.flush().map_err(FrameError::from)
}

/// Stream a child pipe out as frames on `channel` until EOF.
fn pump<W: Write + Send + 'static>(
    pipe: Option<impl Read + Send + 'static>,
    channel: Channel,
    writer: SharedWriter<W>,
) -> Option<JoinHandle<()>> {
    let mut pipe = pipe?;
    Some(std::thread::spawn(move || {
        let mut buffer = vec![0u8; MAX_FRAME_PAYLOAD.min(64 * 1024)];
        loop {
            match pipe.read(&mut buffer) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    let mut writer =
                        writer.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
                    if write_frame(&mut *writer, channel, &buffer[..n]).is_err() {
                        break;
                    }
                    let _ = writer.flush();
                }
            }
        }
    }))
}
