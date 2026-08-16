//! Length-prefixed frame codec: [u32 LE payload_len][u8 channel][payload].
//!
//! TM-06 rules: the declared length is validated against the cap BEFORE any
//! allocation or payload read; unknown channel bytes are rejected; truncation
//! is distinguished from a clean close at a frame boundary.

use std::io::{ErrorKind, Read, Write};

/// Hard cap on a single frame's payload (TM-06: bounded reads). 16 MiB,
/// matching the caps used by the wslc (`MAX_FRAME_SIZE`) and windows_sandbox
/// (`MAX_IPC_FRAME`) backends upstream.
pub const MAX_FRAME_PAYLOAD: usize = 16 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Channel {
    Control,
    Stdin,
    Stdout,
    Stderr,
}

impl Channel {
    fn to_byte(self) -> u8 {
        match self {
            Self::Control => 0,
            Self::Stdin => 1,
            Self::Stdout => 2,
            Self::Stderr => 3,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            0 => Some(Self::Control),
            1 => Some(Self::Stdin),
            2 => Some(Self::Stdout),
            3 => Some(Self::Stderr),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Frame {
    pub channel: Channel,
    pub payload: Vec<u8>,
}

#[derive(Debug)]
pub enum FrameError {
    Io(std::io::Error),
    /// Declared payload length exceeds [`MAX_FRAME_PAYLOAD`].
    Oversized { declared: u32 },
    UnknownChannel(u8),
    /// The stream ended mid-frame.
    UnexpectedEof,
    /// The stream ended cleanly at a frame boundary.
    Closed,
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(error) => write!(f, "frame I/O error: {error}"),
            Self::Oversized { declared } => write!(
                f,
                "frame declares {declared} payload bytes, above the {MAX_FRAME_PAYLOAD}-byte cap"
            ),
            Self::UnknownChannel(byte) => write!(f, "unknown frame channel byte {byte}"),
            Self::UnexpectedEof => write!(f, "stream ended mid-frame"),
            Self::Closed => write!(f, "stream closed"),
        }
    }
}

impl std::error::Error for FrameError {}

impl From<std::io::Error> for FrameError {
    fn from(error: std::io::Error) -> Self {
        if error.kind() == ErrorKind::UnexpectedEof {
            Self::UnexpectedEof
        } else {
            Self::Io(error)
        }
    }
}

pub fn write_frame(w: &mut impl Write, channel: Channel, payload: &[u8]) -> Result<(), FrameError> {
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Err(FrameError::Oversized {
            declared: payload.len().min(u32::MAX as usize) as u32,
        });
    }
    w.write_all(&(payload.len() as u32).to_le_bytes())?;
    w.write_all(&[channel.to_byte()])?;
    w.write_all(payload)?;
    Ok(())
}

pub fn read_frame(r: &mut impl Read) -> Result<Frame, FrameError> {
    let mut length_bytes = [0u8; 4];
    // Distinguish clean close (no bytes at all) from mid-frame truncation.
    match r.read(&mut length_bytes[..1])? {
        0 => return Err(FrameError::Closed),
        _ => r.read_exact(&mut length_bytes[1..])?,
    }
    let declared = u32::from_le_bytes(length_bytes);
    if declared as usize > MAX_FRAME_PAYLOAD {
        return Err(FrameError::Oversized { declared });
    }

    let mut channel_byte = [0u8; 1];
    r.read_exact(&mut channel_byte)?;
    let channel =
        Channel::from_byte(channel_byte[0]).ok_or(FrameError::UnknownChannel(channel_byte[0]))?;

    let mut payload = vec![0u8; declared as usize];
    r.read_exact(&mut payload)?;
    Ok(Frame { channel, payload })
}
