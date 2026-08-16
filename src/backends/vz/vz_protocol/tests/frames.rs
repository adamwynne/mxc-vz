//! Frame codec tests.
//!
//! Contract under test (threat model TM-06 — all guest→host bytes are
//! hostile): length-prefixed frames, hard payload size cap, bounded reads
//! (an oversized declared length is rejected WITHOUT allocating or draining
//! it), unknown channels rejected, truncation detected, and no panic on any
//! byte stream.
//!
//! Wire format: [u32 LE payload_len][u8 channel][payload].

use std::io::{Cursor, Read};

use vz_protocol::frame::{
    read_frame, write_frame, Channel, Frame, FrameError, MAX_FRAME_PAYLOAD,
};

/// Reader that yields one byte at a time — exercises split reads across
/// header and payload boundaries.
struct TrickleReader<R: Read>(R);

impl<R: Read> Read for TrickleReader<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if buf.is_empty() {
            return Ok(0);
        }
        self.0.read(&mut buf[..1])
    }
}

fn encode(channel: Channel, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_frame(&mut out, channel, payload).expect("write should succeed");
    out
}

#[test]
fn roundtrip_every_channel() {
    for channel in [Channel::Control, Channel::Stdin, Channel::Stdout, Channel::Stderr] {
        let bytes = encode(channel, b"hello");
        let frame = read_frame(&mut Cursor::new(&bytes)).expect("read should succeed");
        assert_eq!(frame, Frame { channel, payload: b"hello".to_vec() });
    }
}

#[test]
fn sequential_frames_roundtrip() {
    let mut bytes = encode(Channel::Stdout, b"one");
    bytes.extend(encode(Channel::Stderr, b"two"));
    bytes.extend(encode(Channel::Control, b"{}"));

    let mut cursor = Cursor::new(&bytes);
    assert_eq!(read_frame(&mut cursor).unwrap().payload, b"one");
    assert_eq!(read_frame(&mut cursor).unwrap().payload, b"two");
    assert_eq!(read_frame(&mut cursor).unwrap().channel, Channel::Control);
    assert!(matches!(read_frame(&mut cursor), Err(FrameError::Closed)));
}

#[test]
fn empty_payload_roundtrips() {
    // An empty Stdin frame is the stdin-EOF signal, so this must work.
    let bytes = encode(Channel::Stdin, b"");
    let frame = read_frame(&mut Cursor::new(&bytes)).expect("read should succeed");
    assert!(frame.payload.is_empty());
}

#[test]
fn payload_at_exactly_the_cap_roundtrips() {
    let payload = vec![0xAB; MAX_FRAME_PAYLOAD];
    let bytes = encode(Channel::Stdout, &payload);
    let frame = read_frame(&mut Cursor::new(&bytes)).expect("read should succeed");
    assert_eq!(frame.payload.len(), MAX_FRAME_PAYLOAD);
}

#[test]
fn oversized_write_is_rejected() {
    let payload = vec![0u8; MAX_FRAME_PAYLOAD + 1];
    let mut out = Vec::new();
    assert!(write_frame(&mut out, Channel::Stdout, &payload).is_err());
    assert!(out.is_empty(), "nothing must be written for a rejected frame");
}

#[test]
fn oversized_declared_length_is_rejected_without_reading_payload() {
    // Header declares 4 GiB-ish payload; only the header is supplied. A
    // parser that tried to allocate or drain it would fail differently —
    // the cap check must happen on the declared length alone.
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&u32::MAX.to_le_bytes());
    bytes.push(2); // stdout
    let result = read_frame(&mut Cursor::new(&bytes));
    assert!(
        matches!(result, Err(FrameError::Oversized { declared }) if declared == u32::MAX),
        "got: {result:?}"
    );
}

#[test]
fn unknown_channel_byte_is_rejected() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&1u32.to_le_bytes());
    bytes.push(9); // no such channel
    bytes.push(b'x');
    assert!(matches!(
        read_frame(&mut Cursor::new(&bytes)),
        Err(FrameError::UnknownChannel(9))
    ));
}

#[test]
fn clean_eof_at_frame_boundary_is_closed() {
    assert!(matches!(
        read_frame(&mut Cursor::new(&[] as &[u8])),
        Err(FrameError::Closed)
    ));
}

#[test]
fn truncated_header_is_unexpected_eof() {
    let bytes = [1u8, 0]; // half a length prefix
    assert!(matches!(
        read_frame(&mut Cursor::new(&bytes)),
        Err(FrameError::UnexpectedEof)
    ));
}

#[test]
fn truncated_payload_is_unexpected_eof() {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(&5u32.to_le_bytes());
    bytes.push(2); // stdout
    bytes.extend_from_slice(b"ab"); // 2 of 5 declared bytes
    assert!(matches!(
        read_frame(&mut Cursor::new(&bytes)),
        Err(FrameError::UnexpectedEof)
    ));
}

#[test]
fn split_reads_reassemble_correctly() {
    let mut bytes = encode(Channel::Stdout, b"trickled payload");
    bytes.extend(encode(Channel::Control, b"{\"x\":1}"));
    let mut reader = TrickleReader(Cursor::new(bytes));
    assert_eq!(read_frame(&mut reader).unwrap().payload, b"trickled payload");
    assert_eq!(read_frame(&mut reader).unwrap().channel, Channel::Control);
    assert!(matches!(read_frame(&mut reader), Err(FrameError::Closed)));
}

#[test]
fn arbitrary_byte_streams_error_but_never_panic() {
    // Deterministic pseudo-random garbage: xorshift over a few seeds. The
    // parser must return SOME result (frame or error) without panicking and
    // without unbounded allocation.
    for seed in [1u64, 42, 0xDEAD_BEEF, u64::MAX] {
        let mut state = seed;
        let mut bytes = Vec::with_capacity(256);
        for _ in 0..256 {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            bytes.push(state as u8);
        }
        let mut cursor = Cursor::new(&bytes);
        for _ in 0..16 {
            match read_frame(&mut cursor) {
                Ok(_) => continue,
                Err(_) => break,
            }
        }
    }
}
