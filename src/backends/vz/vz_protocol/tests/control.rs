//! Control-message tests: JSON payloads on the Control channel.
//!
//! Guest→host control bytes are adversarial (TM-06): malformed JSON, unknown
//! message types, and trailing garbage must produce errors, never panics.

use vz_protocol::message::{decode_control, encode_control, ControlMessage};

#[test]
fn exec_request_roundtrips_with_all_fields() {
    let message = ControlMessage::Exec {
        command_line: "echo hi".to_string(),
        env: vec!["FOO=bar".to_string()],
        cwd: Some("/workspace".to_string()),
        timeout_ms: Some(60000),
    };
    let bytes = encode_control(&message).expect("encode should succeed");
    assert_eq!(decode_control(&bytes).expect("decode should succeed"), message);
}

#[test]
fn exec_request_minimal_defaults() {
    // Only type + commandLine on the wire; the rest defaults.
    let bytes = br#"{"type":"exec","commandLine":"true"}"#;
    let message = decode_control(bytes).expect("decode should succeed");
    assert_eq!(
        message,
        ControlMessage::Exec {
            command_line: "true".to_string(),
            env: Vec::new(),
            cwd: None,
            timeout_ms: None,
        }
    );
}

#[test]
fn exit_and_error_roundtrip() {
    for message in [
        ControlMessage::Exit { code: 0 },
        ControlMessage::Exit { code: 137 },
        ControlMessage::Error { message: "spawn failed: no such file".to_string() },
    ] {
        let bytes = encode_control(&message).expect("encode should succeed");
        assert_eq!(decode_control(&bytes).expect("decode should succeed"), message);
    }
}

#[test]
fn malformed_json_is_an_error_not_a_panic() {
    for bad in [
        &b"{"[..],
        b"",
        b"null",
        b"[1,2,3]",
        b"{\"type\":\"exec\"}",              // missing commandLine
        b"{\"type\":\"launchMissiles\"}",    // unknown type
        b"{\"type\":\"exit\",\"code\":\"x\"}", // wrong field type
        b"\xff\xfe\x00garbage",
    ] {
        assert!(decode_control(bad).is_err(), "should reject: {bad:?}");
    }
}

#[test]
fn wire_field_names_are_camel_case() {
    // The protocol mirrors the policy schema's camelCase convention.
    let message = ControlMessage::Exec {
        command_line: "ls".to_string(),
        env: Vec::new(),
        cwd: None,
        timeout_ms: Some(5),
    };
    let json = String::from_utf8(encode_control(&message).unwrap()).unwrap();
    assert!(json.contains("\"commandLine\""), "got: {json}");
    assert!(json.contains("\"timeoutMs\""), "got: {json}");
    assert!(json.contains("\"type\":\"exec\""), "got: {json}");
}
