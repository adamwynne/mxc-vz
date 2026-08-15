//! Schema (deserialization) tests for the 0.7.0-dev policy surface with the
//! `vz` containment value and the `experimental.vz` options object.
//!
//! Contract under test (docs/macos-support/vz-backend.md, Decision 1):
//! - `"vz"` is a valid `containment` value alongside the existing backends.
//! - Backend options live under `experimental.vz`; the object is optional and
//!   every field has a default (cpuCount 2, memoryMB 2048, bootTimeoutMs 30000).
//! - Unknown fields inside `experimental.vz` are rejected at parse time.
//! - JSON field names are camelCase.

use std::path::PathBuf;

use vz_common::policy::{Containment, NetworkDefaultPolicy, Policy, VzOptions};

fn parse(json: &str) -> Policy {
    serde_json::from_str(json).expect("policy JSON should parse")
}

#[test]
fn minimal_vz_policy_parses() {
    let policy = parse(r#"{ "containment": "vz" }"#);
    assert_eq!(policy.containment, Containment::Vz);
    assert!(policy.experimental.is_none());
    assert!(policy.filesystem.is_none());
    assert!(policy.network.is_none());
    assert!(policy.ui.is_none());
    assert!(policy.proxy.is_none());
}

#[test]
fn existing_containment_values_still_parse() {
    // Cross-backend portability: the same document with only `containment`
    // changed must remain parseable (Phase 5 contract, tested at parse level).
    for (name, expected) in [
        ("seatbelt", Containment::Seatbelt),
        ("microvm", Containment::Microvm),
        ("windowsSandbox", Containment::WindowsSandbox),
        ("vz", Containment::Vz),
    ] {
        let policy = parse(&format!(r#"{{ "containment": "{name}" }}"#));
        assert_eq!(policy.containment, expected, "containment {name}");
    }
}

#[test]
fn unknown_containment_value_is_rejected() {
    let result = serde_json::from_str::<Policy>(r#"{ "containment": "bhyve" }"#);
    assert!(result.is_err(), "unknown containment values must not parse");
}

#[test]
fn containment_is_required() {
    let result = serde_json::from_str::<Policy>(r#"{}"#);
    assert!(result.is_err(), "containment is a required field");
}

#[test]
fn full_vz_policy_parses_with_camel_case_fields() {
    let policy = parse(
        r#"{
            "containment": "vz",
            "filesystem": {
                "readonlyPaths": ["/usr/share/data"],
                "readwritePaths": ["/workspace"],
                "deniedPaths": ["/etc/secrets"]
            },
            "network": {
                "defaultPolicy": "allow",
                "allowedHosts": ["api.example.com"],
                "blockedHosts": []
            },
            "ui": { "guiAccess": false },
            "process": {
                "commandLine": ["echo", "hi"],
                "env": { "FOO": "bar" },
                "timeoutMs": 60000
            },
            "experimental": {
                "vz": {
                    "guestImagePath": "/opt/mxc/vz-guest",
                    "cpuCount": 4,
                    "memoryMB": 4096,
                    "bootTimeoutMs": 10000
                }
            }
        }"#,
    );

    let fs = policy.filesystem.as_ref().expect("filesystem");
    assert_eq!(fs.readonly_paths, vec![PathBuf::from("/usr/share/data")]);
    assert_eq!(fs.readwrite_paths, vec![PathBuf::from("/workspace")]);
    assert_eq!(fs.denied_paths, vec![PathBuf::from("/etc/secrets")]);

    let net = policy.network.as_ref().expect("network");
    assert_eq!(net.default_policy, NetworkDefaultPolicy::Allow);
    assert_eq!(net.allowed_hosts, vec!["api.example.com".to_string()]);
    assert!(net.blocked_hosts.is_empty());

    assert_eq!(policy.ui.as_ref().expect("ui").gui_access, Some(false));

    let process = policy.process.as_ref().expect("process");
    assert_eq!(
        process.command_line,
        Some(vec!["echo".to_string(), "hi".to_string()])
    );
    assert_eq!(process.timeout_ms, Some(60000));

    let vz = policy
        .experimental
        .as_ref()
        .and_then(|e| e.vz.as_ref())
        .expect("experimental.vz");
    assert_eq!(vz.guest_image_path, Some(PathBuf::from("/opt/mxc/vz-guest")));
    assert_eq!(vz.cpu_count, 4);
    assert_eq!(vz.memory_mb, 4096);
    assert_eq!(vz.boot_timeout_ms, 10000);
}

#[test]
fn vz_options_default_values() {
    // Decision 1: options optional with defaults — cpu 2, mem 2048, boot 30000.
    let options = VzOptions::default();
    assert_eq!(options.guest_image_path, None);
    assert_eq!(options.cpu_count, 2);
    assert_eq!(options.memory_mb, 2048);
    assert_eq!(options.boot_timeout_ms, 30000);
}

#[test]
fn partial_vz_options_fill_in_defaults() {
    let policy = parse(
        r#"{
            "containment": "vz",
            "experimental": { "vz": { "cpuCount": 8 } }
        }"#,
    );
    let vz = policy
        .experimental
        .as_ref()
        .and_then(|e| e.vz.as_ref())
        .expect("experimental.vz");
    assert_eq!(vz.cpu_count, 8);
    assert_eq!(vz.memory_mb, 2048, "unset memoryMB falls back to default");
    assert_eq!(vz.boot_timeout_ms, 30000, "unset bootTimeoutMs falls back to default");
}

#[test]
fn empty_vz_options_object_equals_defaults() {
    let policy = parse(
        r#"{ "containment": "vz", "experimental": { "vz": {} } }"#,
    );
    let vz = policy
        .experimental
        .as_ref()
        .and_then(|e| e.vz.as_ref())
        .expect("experimental.vz");
    assert_eq!(*vz, VzOptions::default());
}

#[test]
fn unknown_field_in_vz_options_is_rejected() {
    // Typos (memoryMb, cpus) must fail loudly, not silently use defaults.
    let result = serde_json::from_str::<Policy>(
        r#"{
            "containment": "vz",
            "experimental": { "vz": { "memoryMb": 1024 } }
        }"#,
    );
    assert!(result.is_err(), "unknown fields in experimental.vz must be rejected");
}

#[test]
fn extra_ui_fields_are_captured_for_warning() {
    // Decision 4: ui.* other than guiAccess is accepted (and later warned
    // about + ignored). The parser must retain the field names so validation
    // can report them.
    let policy = parse(
        r#"{
            "containment": "vz",
            "ui": { "guiAccess": false, "theme": "dark", "scaling": 2 }
        }"#,
    );
    let ui = policy.ui.as_ref().expect("ui");
    let mut extra: Vec<&str> = ui.extra.keys().map(String::as_str).collect();
    extra.sort_unstable();
    assert_eq!(extra, vec!["scaling", "theme"]);
}

#[test]
fn network_default_policy_block_parses() {
    let policy = parse(
        r#"{ "containment": "vz", "network": { "defaultPolicy": "block" } }"#,
    );
    let net = policy.network.as_ref().expect("network");
    assert_eq!(net.default_policy, NetworkDefaultPolicy::Block);
    assert!(net.allowed_hosts.is_empty());
    assert!(net.blocked_hosts.is_empty());
}

#[test]
fn policy_roundtrips_through_serialization() {
    let source = r#"{
        "containment": "vz",
        "filesystem": { "readwritePaths": ["/workspace"] },
        "experimental": { "vz": { "cpuCount": 4 } }
    }"#;
    let policy = parse(source);
    let json = serde_json::to_string(&policy).expect("policy should serialize");
    let reparsed: Policy = serde_json::from_str(&json).expect("roundtrip should parse");
    assert_eq!(policy, reparsed);
}
