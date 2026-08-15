//! Validation tests for `containment: "vz"` policies.
//!
//! Contract under test (docs/macos-support/vz-backend.md, Decisions 1, 4, 5):
//! - The experimental flag is required to use vz.
//! - `ui.guiAccess: true`, `proxy`, and non-empty `network.blockedHosts` are
//!   rejected with distinct, clear errors; all errors are collected, not just
//!   the first.
//! - `filesystem.deniedPaths` entries are redundant (warning) unless they are
//!   equal to or inside a shared path, which is an error. Containment is
//!   lexical and component-wise.
//! - Extra ui.* fields are accepted and produce warnings.
//! - Resource option bounds: cpuCount >= 1, memoryMB >= 128, bootTimeoutMs >= 1.
//! - All policy paths must be absolute.

use std::path::PathBuf;

use vz_common::policy::Policy;
use vz_common::validate::{validate_vz_policy, Warning, VzPolicyError};

fn policy(json: &str) -> Policy {
    serde_json::from_str(json).expect("test policy JSON should parse")
}

fn errors_of(json: &str) -> Vec<VzPolicyError> {
    validate_vz_policy(&policy(json), true).expect_err("validation should fail")
}

const MINIMAL: &str = r#"{ "containment": "vz" }"#;

#[test]
fn minimal_policy_validates_with_defaults() {
    let validated = validate_vz_policy(&policy(MINIMAL), true).expect("should validate");
    assert_eq!(validated.options.cpu_count, 2);
    assert_eq!(validated.options.memory_mb, 2048);
    assert_eq!(validated.options.boot_timeout_ms, 30000);
    assert!(validated.warnings.is_empty());
}

#[test]
fn vz_requires_experimental_flag() {
    let errors = validate_vz_policy(&policy(MINIMAL), false)
        .expect_err("vz without the experimental flag must fail");
    assert!(errors.contains(&VzPolicyError::ExperimentalRequired));
}

#[test]
fn non_vz_containment_is_rejected_by_vz_validator() {
    let errors = errors_of(r#"{ "containment": "seatbelt" }"#);
    assert!(errors.contains(&VzPolicyError::NotVzContainment));
}

#[test]
fn explicit_options_are_resolved() {
    let validated = validate_vz_policy(
        &policy(
            r#"{
                "containment": "vz",
                "experimental": { "vz": { "cpuCount": 4, "memoryMB": 8192 } }
            }"#,
        ),
        true,
    )
    .expect("should validate");
    assert_eq!(validated.options.cpu_count, 4);
    assert_eq!(validated.options.memory_mb, 8192);
    assert_eq!(validated.options.boot_timeout_ms, 30000);
}

// ---- v1 scope exclusions (Decision 4) ----

#[test]
fn gui_access_true_is_rejected() {
    let errors = errors_of(r#"{ "containment": "vz", "ui": { "guiAccess": true } }"#);
    assert!(errors.contains(&VzPolicyError::GuiAccessUnsupported));
}

#[test]
fn gui_access_false_is_accepted() {
    let validated = validate_vz_policy(
        &policy(r#"{ "containment": "vz", "ui": { "guiAccess": false } }"#),
        true,
    )
    .expect("explicit guiAccess: false is fine");
    assert!(validated.warnings.is_empty());
}

#[test]
fn proxy_is_rejected() {
    let errors = errors_of(
        r#"{ "containment": "vz", "proxy": { "host": "127.0.0.1", "port": 8080 } }"#,
    );
    assert!(errors.contains(&VzPolicyError::ProxyUnsupported));
}

#[test]
fn blocked_hosts_are_rejected_in_v1() {
    let errors = errors_of(
        r#"{
            "containment": "vz",
            "network": { "defaultPolicy": "allow", "blockedHosts": ["evil.example.com"] }
        }"#,
    );
    assert!(errors.contains(&VzPolicyError::BlockedHostsUnsupported));
}

#[test]
fn empty_blocked_hosts_list_is_accepted() {
    validate_vz_policy(
        &policy(
            r#"{
                "containment": "vz",
                "network": { "defaultPolicy": "allow", "blockedHosts": [] }
            }"#,
        ),
        true,
    )
    .expect("an empty blockedHosts list blocks nothing and is harmless");
}

#[test]
fn allowed_hosts_are_accepted() {
    validate_vz_policy(
        &policy(
            r#"{
                "containment": "vz",
                "network": { "defaultPolicy": "allow", "allowedHosts": ["api.example.com"] }
            }"#,
        ),
        true,
    )
    .expect("allow-list ships in v1");
}

#[test]
fn extra_ui_fields_warn_and_are_ignored() {
    let validated = validate_vz_policy(
        &policy(r#"{ "containment": "vz", "ui": { "theme": "dark" } }"#),
        true,
    )
    .expect("extra ui fields are not errors");
    assert!(validated
        .warnings
        .contains(&Warning::IgnoredUiField("theme".to_string())));
}

#[test]
fn all_errors_are_collected_not_just_the_first() {
    let errors = errors_of(
        r#"{
            "containment": "vz",
            "ui": { "guiAccess": true },
            "proxy": { "host": "127.0.0.1", "port": 8080 },
            "network": { "defaultPolicy": "allow", "blockedHosts": ["evil.example.com"] }
        }"#,
    );
    assert!(errors.contains(&VzPolicyError::GuiAccessUnsupported));
    assert!(errors.contains(&VzPolicyError::ProxyUnsupported));
    assert!(errors.contains(&VzPolicyError::BlockedHostsUnsupported));
}

// ---- deniedPaths semantics (Decision 5) ----

#[test]
fn denied_path_outside_shares_is_a_warning_not_an_error() {
    let validated = validate_vz_policy(
        &policy(
            r#"{
                "containment": "vz",
                "filesystem": {
                    "readwritePaths": ["/workspace"],
                    "deniedPaths": ["/etc/secrets"]
                }
            }"#,
        ),
        true,
    )
    .expect("redundant deniedPaths are accepted for cross-backend portability");
    assert!(validated
        .warnings
        .contains(&Warning::RedundantDeniedPath(PathBuf::from("/etc/secrets"))));
}

#[test]
fn denied_path_inside_readwrite_share_is_rejected() {
    let errors = errors_of(
        r#"{
            "containment": "vz",
            "filesystem": {
                "readwritePaths": ["/workspace"],
                "deniedPaths": ["/workspace/secrets"]
            }
        }"#,
    );
    assert!(errors.contains(&VzPolicyError::DeniedPathInsideShare {
        denied: PathBuf::from("/workspace/secrets"),
        share: PathBuf::from("/workspace"),
    }));
}

#[test]
fn denied_path_inside_readonly_share_is_rejected() {
    let errors = errors_of(
        r#"{
            "containment": "vz",
            "filesystem": {
                "readonlyPaths": ["/usr/share/data"],
                "deniedPaths": ["/usr/share/data/private"]
            }
        }"#,
    );
    assert!(errors.contains(&VzPolicyError::DeniedPathInsideShare {
        denied: PathBuf::from("/usr/share/data/private"),
        share: PathBuf::from("/usr/share/data"),
    }));
}

#[test]
fn denied_path_equal_to_share_is_rejected() {
    let errors = errors_of(
        r#"{
            "containment": "vz",
            "filesystem": {
                "readwritePaths": ["/workspace"],
                "deniedPaths": ["/workspace"]
            }
        }"#,
    );
    assert!(errors.contains(&VzPolicyError::DeniedPathInsideShare {
        denied: PathBuf::from("/workspace"),
        share: PathBuf::from("/workspace"),
    }));
}

#[test]
fn sibling_path_with_shared_prefix_is_not_inside() {
    // Lexical containment is component-wise: /workspace-2 is NOT inside
    // /workspace, so this deniedPath is merely redundant.
    let validated = validate_vz_policy(
        &policy(
            r#"{
                "containment": "vz",
                "filesystem": {
                    "readwritePaths": ["/workspace"],
                    "deniedPaths": ["/workspace-2"]
                }
            }"#,
        ),
        true,
    )
    .expect("string-prefix sibling must not be treated as nested");
    assert!(validated
        .warnings
        .contains(&Warning::RedundantDeniedPath(PathBuf::from("/workspace-2"))));
}

#[test]
fn trailing_slash_does_not_defeat_containment_check() {
    let errors = errors_of(
        r#"{
            "containment": "vz",
            "filesystem": {
                "readwritePaths": ["/workspace/"],
                "deniedPaths": ["/workspace/secrets"]
            }
        }"#,
    );
    assert!(
        errors.iter().any(|e| matches!(
            e,
            VzPolicyError::DeniedPathInsideShare { denied, .. }
                if denied == &PathBuf::from("/workspace/secrets")
        )),
        "trailing slash on the share must not defeat the nesting check"
    );
}

#[test]
fn relative_policy_paths_are_rejected() {
    let errors = errors_of(
        r#"{
            "containment": "vz",
            "filesystem": { "readwritePaths": ["workspace"] }
        }"#,
    );
    assert!(errors.contains(&VzPolicyError::NonAbsolutePath(PathBuf::from("workspace"))));
}

// ---- resource option bounds (Decision 1) ----

#[test]
fn zero_cpu_count_is_rejected() {
    let errors = errors_of(
        r#"{ "containment": "vz", "experimental": { "vz": { "cpuCount": 0 } } }"#,
    );
    assert!(errors.contains(&VzPolicyError::InvalidCpuCount(0)));
}

#[test]
fn too_small_memory_is_rejected() {
    let errors = errors_of(
        r#"{ "containment": "vz", "experimental": { "vz": { "memoryMB": 64 } } }"#,
    );
    assert!(errors.contains(&VzPolicyError::InvalidMemoryMb(64)));
}

#[test]
fn zero_boot_timeout_is_rejected() {
    let errors = errors_of(
        r#"{ "containment": "vz", "experimental": { "vz": { "bootTimeoutMs": 0 } } }"#,
    );
    assert!(errors.contains(&VzPolicyError::InvalidBootTimeoutMs(0)));
}

#[test]
fn errors_render_human_readable_messages() {
    // Phase 5 requires "clear errors, mirroring existing seatbelt validation
    // style" — every error must have a non-empty Display message that names
    // the offending field.
    let cases: Vec<(VzPolicyError, &str)> = vec![
        (VzPolicyError::ExperimentalRequired, "experimental"),
        (VzPolicyError::GuiAccessUnsupported, "guiAccess"),
        (VzPolicyError::ProxyUnsupported, "proxy"),
        (VzPolicyError::BlockedHostsUnsupported, "blockedHosts"),
        (
            VzPolicyError::DeniedPathInsideShare {
                denied: PathBuf::from("/a/b"),
                share: PathBuf::from("/a"),
            },
            "deniedPaths",
        ),
        (VzPolicyError::InvalidCpuCount(0), "cpuCount"),
        (VzPolicyError::InvalidMemoryMb(64), "memoryMB"),
        (VzPolicyError::InvalidBootTimeoutMs(0), "bootTimeoutMs"),
    ];
    for (error, needle) in cases {
        let message = error.to_string();
        assert!(
            message.contains(needle),
            "error message {message:?} should mention {needle:?}"
        );
    }
}
