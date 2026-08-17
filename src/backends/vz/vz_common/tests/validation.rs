//! Validation tests for `containment: "vz"` policies.
//!
//! Contract under test (docs/macos-support/vz-backend.md, Decisions 1, 4, 5,
//! aligned with the upstream 0.8.0-dev config surface):
//! - The experimental flag is required to use vz.
//! - UI access requests (`ui.disable: false`, `ui.injection: true`, clipboard
//!   other than `none`), `network.proxy`, and non-empty `network.blockedHosts`
//!   are rejected with distinct, clear errors; all errors are collected.
//! - `filesystem.deniedPaths` entries are redundant (warning) unless they are
//!   equal to or inside a shared path, which is an error. Containment is
//!   lexical and component-wise.
//! - Blocks vz does not consume (other backends' options,
//!   `network.enforcementMode`) are accepted with warnings.
//! - Resource option bounds: cpuCount >= 1, memoryMB >= 128, bootTimeoutMs >= 1.
//! - All policy paths must be absolute.

use std::path::PathBuf;

use vz_common::policy::{ClipboardPolicy, Policy};
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
fn absent_containment_is_rejected_by_vz_validator() {
    // vz is experimental and never the OS-native default, so it must be
    // requested explicitly.
    let errors = errors_of(r#"{}"#);
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
fn ui_disable_false_is_rejected() {
    // ui.disable defaults to true upstream; an explicit false requests UI
    // access, which the vz guest cannot have.
    let errors = errors_of(r#"{ "containment": "vz", "ui": { "disable": false } }"#);
    assert!(errors.contains(&VzPolicyError::UiAccessUnsupported));
}

#[test]
fn ui_disable_true_is_accepted() {
    let validated = validate_vz_policy(
        &policy(r#"{ "containment": "vz", "ui": { "disable": true } }"#),
        true,
    )
    .expect("explicit ui.disable: true is fine");
    assert!(validated.warnings.is_empty());
}

#[test]
fn ui_injection_true_is_rejected() {
    let errors = errors_of(r#"{ "containment": "vz", "ui": { "injection": true } }"#);
    assert!(errors.contains(&VzPolicyError::UiInjectionUnsupported));
}

#[test]
fn clipboard_other_than_none_is_rejected() {
    for level in ["read", "write", "all"] {
        let errors = errors_of(&format!(
            r#"{{ "containment": "vz", "ui": {{ "clipboard": "{level}" }} }}"#
        ));
        assert!(
            errors
                .iter()
                .any(|e| matches!(e, VzPolicyError::ClipboardUnsupported(_))),
            "clipboard level {level} must be rejected"
        );
    }
}

#[test]
fn clipboard_none_is_accepted() {
    let validated = validate_vz_policy(
        &policy(r#"{ "containment": "vz", "ui": { "clipboard": "none" } }"#),
        true,
    )
    .expect("clipboard: none is the vz reality and is fine");
    assert!(validated.warnings.is_empty());
}

#[test]
fn network_proxy_is_rejected() {
    let errors = errors_of(
        r#"{
            "containment": "vz",
            "network": { "defaultPolicy": "block", "proxy": { "url": "http://10.0.3.1:3128" } }
        }"#,
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
fn enforcement_mode_warns_and_is_ignored() {
    // enforcementMode selects between backend mechanisms vz doesn't use
    // (host-side filtering is the only mechanism); accepted for portability.
    let validated = validate_vz_policy(
        &policy(
            r#"{
                "containment": "vz",
                "network": { "defaultPolicy": "block", "enforcementMode": "firewall" }
            }"#,
        ),
        true,
    )
    .expect("enforcementMode is not an error");
    assert!(validated
        .warnings
        .contains(&Warning::IgnoredField("network.enforcementMode".to_string())));
}

#[test]
fn allowed_hosts_under_block_validate_clean() {
    let validated = validate_vz_policy(
        &policy(
            r#"{
                "containment": "vz",
                "network": {
                    "defaultPolicy": "block",
                    "allowedHosts": ["140.82.112.22", "10.1.0.0/16", "api.github.com"]
                }
            }"#,
        ),
        true,
    )
    .expect("allowedHosts under block is the supported filtering shape");
    assert!(validated.warnings.is_empty(), "got: {:?}", validated.warnings);
}

#[test]
fn allowed_hosts_under_allow_warn_redundant() {
    // Upstream parity: a default of allow accepts everything, so allow
    // entries are no-ops — worth telling the author, not an error.
    let validated = validate_vz_policy(
        &policy(
            r#"{
                "containment": "vz",
                "network": { "defaultPolicy": "allow", "allowedHosts": ["api.github.com"] }
            }"#,
        ),
        true,
    )
    .expect("redundant allowedHosts are not an error");
    assert!(validated.warnings.contains(&Warning::RedundantAllowedHosts));
}

#[test]
fn invalid_allowed_hosts_entries_warn_skipped() {
    // Skipping an allow entry only restricts (upstream reports-and-skips);
    // surface each skip so a typo'd CIDR is visible, not silent.
    let validated = validate_vz_policy(
        &policy(
            r#"{
                "containment": "vz",
                "network": {
                    "defaultPolicy": "block",
                    "allowedHosts": ["10.0.0.0/99", "", "api.github.com"]
                }
            }"#,
        ),
        true,
    )
    .expect("invalid entries are skipped, not fatal");
    assert!(validated
        .warnings
        .contains(&Warning::SkippedAllowedHost("10.0.0.0/99".to_string())));
    assert!(validated
        .warnings
        .contains(&Warning::SkippedAllowedHost("".to_string())));
    assert_eq!(
        validated
            .warnings
            .iter()
            .filter(|w| matches!(w, Warning::SkippedAllowedHost(_)))
            .count(),
        2,
        "the valid hostname entry must not be skipped"
    );
}

#[test]
fn foreign_backend_blocks_warn_and_are_ignored() {
    let validated = validate_vz_policy(
        &policy(
            r#"{
                "containment": "vz",
                "seatbelt": { "guiAccess": true },
                "lxc": { "distribution": "alpine" }
            }"#,
        ),
        true,
    )
    .expect("other backends' option blocks are portability, not errors");
    assert!(validated
        .warnings
        .contains(&Warning::IgnoredField("seatbelt".to_string())));
    assert!(validated
        .warnings
        .contains(&Warning::IgnoredField("lxc".to_string())));
}

#[test]
fn all_errors_are_collected_not_just_the_first() {
    let errors = errors_of(
        r#"{
            "containment": "vz",
            "ui": { "disable": false, "injection": true },
            "network": {
                "defaultPolicy": "allow",
                "blockedHosts": ["evil.example.com"],
                "proxy": { "builtinTestServer": true }
            }
        }"#,
    );
    assert!(errors.contains(&VzPolicyError::UiAccessUnsupported));
    assert!(errors.contains(&VzPolicyError::UiInjectionUnsupported));
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
fn case_variant_denied_path_inside_share_is_rejected() {
    // TM-11: the share lives on the host's case-insensitive APFS, so
    // /Workspace/Secrets is the same directory as /workspace and the
    // deniedPath must still be caught as nested — a case bypass must fail.
    let errors = errors_of(
        r#"{
            "containment": "vz",
            "filesystem": {
                "readwritePaths": ["/workspace"],
                "deniedPaths": ["/Workspace/Secrets"]
            }
        }"#,
    );
    assert!(
        errors.iter().any(|e| matches!(
            e,
            VzPolicyError::DeniedPathInsideShare { denied, .. }
                if denied == &PathBuf::from("/Workspace/Secrets")
        )),
        "a case-variant deniedPath inside the share must be rejected (TM-11)"
    );
}

#[test]
fn interior_nul_in_a_path_is_rejected() {
    // A NUL byte would silently truncate the path at the C-string boundary
    // (TM-11). Build the policy programmatically since JSON can carry  .
    let json = "{\"containment\":\"vz\",\"filesystem\":{\"readwritePaths\":[\"/safe\\u0000/../etc\"]}}";
    let errors = errors_of(json);
    assert!(
        errors.iter().any(|e| matches!(e, VzPolicyError::PathContainsNul(_))),
        "a path with an interior NUL must be rejected, got: {errors:?}"
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
    // Every error must have a Display message that names the offending field,
    // mirroring existing seatbelt validation style.
    let cases: Vec<(VzPolicyError, &str)> = vec![
        (VzPolicyError::ExperimentalRequired, "experimental"),
        (VzPolicyError::UiAccessUnsupported, "ui.disable"),
        (VzPolicyError::UiInjectionUnsupported, "ui.injection"),
        (
            VzPolicyError::ClipboardUnsupported(ClipboardPolicy::Read),
            "ui.clipboard",
        ),
        (VzPolicyError::ProxyUnsupported, "network.proxy"),
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
