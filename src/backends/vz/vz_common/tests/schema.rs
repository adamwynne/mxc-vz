//! Schema (deserialization) tests for the 0.8.0-dev policy surface with the
//! `vz` containment value and the `experimental.vz` options object.
//!
//! Contract under test (docs/macos-support/vz-backend.md, Decision 1, aligned
//! with upstream mxc-config.schema.0.8.0-dev.json):
//! - `"vz"` is a valid `containment` value alongside the existing backends;
//!   `containment` itself is nullable.
//! - The stable surface is closed (unknown fields rejected, matching
//!   `additionalProperties: false` upstream); the `experimental` block is
//!   intentionally permissive.
//! - Backend options live under `experimental.vz`; the object is optional and
//!   every field has a default (cpuCount 2, memoryMB 2048, bootTimeoutMs 30000).

use std::path::PathBuf;

use vz_common::policy::{
    ClipboardPolicy, Containment, NetworkDefaultPolicy, NetworkEnforcement, Policy, VzOptions,
};

fn parse(json: &str) -> Policy {
    serde_json::from_str(json).expect("policy JSON should parse")
}

#[test]
fn minimal_vz_policy_parses() {
    let policy = parse(r#"{ "containment": "vz" }"#);
    assert_eq!(policy.containment, Some(Containment::Vz));
    assert!(policy.experimental.is_none());
    assert!(policy.filesystem.is_none());
    assert!(policy.network.is_none());
    assert!(policy.ui.is_none());
}

#[test]
fn all_containment_wire_names_parse() {
    // Wire names from the upstream 0.8.0-dev schema (mixed naming styles are
    // upstream's, not ours), plus "vz".
    for (name, expected) in [
        ("process", Containment::Process),
        ("processcontainer", Containment::ProcessContainer),
        ("vm", Containment::Vm),
        ("windows_sandbox", Containment::WindowsSandbox),
        ("lxc", Containment::Lxc),
        ("microvm", Containment::Microvm),
        ("hyperlight", Containment::Hyperlight),
        ("wslc", Containment::Wslc),
        ("seatbelt", Containment::Seatbelt),
        ("isolation_session", Containment::IsolationSession),
        ("bubblewrap", Containment::Bubblewrap),
        ("vz", Containment::Vz),
    ] {
        let policy = parse(&format!(r#"{{ "containment": "{name}" }}"#));
        assert_eq!(policy.containment, Some(expected), "containment {name}");
    }
}

#[test]
fn containment_is_nullable() {
    // Upstream resolves the OS-native backend when containment is absent.
    assert_eq!(parse(r#"{}"#).containment, None);
    assert_eq!(parse(r#"{ "containment": null }"#).containment, None);
}

#[test]
fn unknown_containment_value_is_rejected() {
    let result = serde_json::from_str::<Policy>(r#"{ "containment": "bhyve" }"#);
    assert!(result.is_err(), "unknown containment values must not parse");
}

#[test]
fn full_vz_policy_parses_with_upstream_field_shapes() {
    let policy = parse(
        r#"{
            "version": "0.8.0-dev",
            "containerId": "vz-schema-test",
            "containment": "vz",
            "filesystem": {
                "readonlyPaths": ["/usr/share/data"],
                "readwritePaths": ["/workspace"],
                "deniedPaths": ["/etc/secrets"]
            },
            "network": {
                "defaultPolicy": "allow",
                "allowedHosts": ["api.example.com"],
                "blockedHosts": [],
                "allowLocalNetwork": false,
                "enforcementMode": "firewall"
            },
            "ui": { "clipboard": "none", "disable": true, "injection": false },
            "process": {
                "commandLine": "echo hi",
                "cwd": "/workspace",
                "env": ["FOO=bar"],
                "timeout": 60000
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

    assert_eq!(policy.version.as_deref(), Some("0.8.0-dev"));
    assert_eq!(policy.container_id.as_deref(), Some("vz-schema-test"));

    let fs = policy.filesystem.as_ref().expect("filesystem");
    assert_eq!(fs.readonly_paths, vec![PathBuf::from("/usr/share/data")]);
    assert_eq!(fs.readwrite_paths, vec![PathBuf::from("/workspace")]);
    assert_eq!(fs.denied_paths, vec![PathBuf::from("/etc/secrets")]);

    let net = policy.network.as_ref().expect("network");
    assert_eq!(net.default_policy, Some(NetworkDefaultPolicy::Allow));
    assert_eq!(net.allowed_hosts, vec!["api.example.com".to_string()]);
    assert!(net.blocked_hosts.is_empty());
    assert_eq!(net.allow_local_network, Some(false));
    assert_eq!(net.enforcement_mode, Some(NetworkEnforcement::Firewall));
    assert!(net.proxy.is_none());

    let ui = policy.ui.as_ref().expect("ui");
    assert_eq!(ui.clipboard, Some(ClipboardPolicy::None));
    assert_eq!(ui.disable, Some(true));
    assert_eq!(ui.injection, Some(false));

    let process = policy.process.as_ref().expect("process");
    assert_eq!(process.command_line.as_deref(), Some("echo hi"));
    assert_eq!(process.cwd.as_deref(), Some("/workspace"));
    assert_eq!(process.env, Some(vec!["FOO=bar".to_string()]));
    assert_eq!(process.timeout, Some(60000));

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
fn nested_network_proxy_parses() {
    let policy = parse(
        r#"{
            "containment": "vz",
            "network": { "defaultPolicy": "block", "proxy": { "url": "http://10.0.3.1:3128" } }
        }"#,
    );
    let proxy = policy
        .network
        .as_ref()
        .and_then(|n| n.proxy.as_ref())
        .expect("network.proxy");
    assert_eq!(proxy.url.as_deref(), Some("http://10.0.3.1:3128"));
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
fn experimental_block_is_permissive() {
    // Upstream convention: the experimental block tolerates unknown and
    // in-progress fields rather than rejecting them — both sibling backend
    // blocks and unknown fields inside experimental.vz itself.
    let policy = parse(
        r#"{
            "containment": "vz",
            "experimental": {
                "seatbelt": { "guiAccess": true },
                "telemetry": { "enabled": false },
                "vz": { "cpuCount": 4, "someFutureKnob": true }
            }
        }"#,
    );
    let vz = policy
        .experimental
        .as_ref()
        .and_then(|e| e.vz.as_ref())
        .expect("experimental.vz");
    assert_eq!(vz.cpu_count, 4);
}

#[test]
fn unknown_top_level_field_is_rejected() {
    // The stable surface is closed (additionalProperties: false upstream).
    let result = serde_json::from_str::<Policy>(
        r#"{ "containment": "vz", "filesystme": {} }"#,
    );
    assert!(result.is_err(), "typos on the stable surface must fail loudly");
}

#[test]
fn unknown_ui_field_is_rejected() {
    // Ui is closed upstream. This also catches stale pre-0.8 placements like
    // `ui.guiAccess` (guiAccess is a seatbelt options field, not a ui field).
    let result = serde_json::from_str::<Policy>(
        r#"{ "containment": "vz", "ui": { "guiAccess": true } }"#,
    );
    assert!(result.is_err(), "unknown ui fields must be rejected");
}

#[test]
fn network_default_policy_block_parses() {
    let policy = parse(
        r#"{ "containment": "vz", "network": { "defaultPolicy": "block" } }"#,
    );
    let net = policy.network.as_ref().expect("network");
    assert_eq!(net.default_policy, Some(NetworkDefaultPolicy::Block));
    assert!(net.allowed_hosts.is_empty());
    assert!(net.blocked_hosts.is_empty());
}

#[test]
fn policy_roundtrips_through_serialization() {
    let source = r#"{
        "containment": "vz",
        "filesystem": { "readwritePaths": ["/workspace"] },
        "process": { "commandLine": "echo hi" },
        "experimental": { "vz": { "cpuCount": 4 } }
    }"#;
    let policy = parse(source);
    let json = serde_json::to_string(&policy).expect("policy should serialize");
    let reparsed: Policy = serde_json::from_str(&json).expect("roundtrip should parse");
    assert_eq!(policy, reparsed);
}
