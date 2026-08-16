//! Tests for policy → exec-request translation (Phase 4: process
//! passthrough).
//!
//! Contract: `process.commandLine` (required for one-shot exec), `env`
//! (KEY=VALUE list), `cwd` (identical guest paths — shares mount at the same
//! path, so passthrough IS the mapping), and `timeout` (ms) map onto the
//! exec protocol's request; everything else about the process block was
//! already validated.

use vz_common::exec_plan::build_exec_request;
use vz_common::policy::Policy;

fn policy(json: &str) -> Policy {
    serde_json::from_str(json).expect("test policy should parse")
}

#[test]
fn full_process_block_maps_through() {
    let request = build_exec_request(&policy(
        r#"{
            "containment": "vz",
            "process": {
                "commandLine": "python3 train.py --epochs 3",
                "env": ["PYTHONUNBUFFERED=1", "MODE=test"],
                "cwd": "/workspace",
                "timeout": 90000
            }
        }"#,
    ))
    .expect("translation should succeed");
    assert_eq!(request.command_line, "python3 train.py --epochs 3");
    assert_eq!(request.env, vec!["PYTHONUNBUFFERED=1", "MODE=test"]);
    assert_eq!(request.cwd.as_deref(), Some("/workspace"));
    assert_eq!(request.timeout_ms, Some(90000));
}

#[test]
fn minimal_process_block_uses_defaults() {
    let request = build_exec_request(&policy(
        r#"{ "containment": "vz", "process": { "commandLine": "true" } }"#,
    ))
    .expect("translation should succeed");
    assert_eq!(request.command_line, "true");
    assert!(request.env.is_empty());
    assert_eq!(request.cwd, None);
    assert_eq!(request.timeout_ms, None);
}

#[test]
fn missing_process_block_is_an_error() {
    let error = build_exec_request(&policy(r#"{ "containment": "vz" }"#))
        .expect_err("one-shot exec requires a process block");
    assert!(error.contains("process"), "got: {error}");
}

#[test]
fn missing_command_line_is_an_error() {
    let error = build_exec_request(&policy(
        r#"{ "containment": "vz", "process": { "timeout": 1000 } }"#,
    ))
    .expect_err("one-shot exec requires commandLine");
    assert!(error.contains("commandLine"), "got: {error}");
}
