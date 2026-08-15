//! Parse-conformance smoke suite against upstream microsoft/mxc fixtures.
//!
//! Every vendored `tests/configs` fixture on the current (0.8.0) surface must
//! deserialize into our `Policy` type. This pins the cross-backend
//! portability contract (build plan, Phase 5): a vz policy is the same
//! document with `containment` swapped, so these structs must accept
//! everything the other backends accept.

use std::fs;
use std::path::PathBuf;

use vz_common::policy::{Containment, NetworkDefaultPolicy, Policy};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/upstream-configs")
}

fn fixture(name: &str) -> Policy {
    let path = fixtures_dir().join(name);
    let json = fs::read_to_string(&path).unwrap_or_else(|e| panic!("read {path:?}: {e}"));
    serde_json::from_str(&json).unwrap_or_else(|e| panic!("parse {name}: {e}"))
}

#[test]
fn every_upstream_fixture_parses() {
    let mut failures = Vec::new();
    let mut count = 0usize;

    for entry in fs::read_dir(fixtures_dir()).expect("fixtures dir must exist") {
        let path = entry.expect("dir entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        count += 1;
        let json = fs::read_to_string(&path).expect("fixture should be readable");
        if let Err(error) = serde_json::from_str::<Policy>(&json) {
            failures.push(format!(
                "{}: {error}",
                path.file_name().unwrap().to_string_lossy()
            ));
        }
    }

    assert!(
        count >= 60,
        "expected the vendored fixture set (61 files), found {count} — \
         did the fixtures directory move?"
    );
    assert!(
        failures.is_empty(),
        "{} of {count} upstream fixtures failed to parse:\n{}",
        failures.len(),
        failures.join("\n")
    );
}

#[test]
fn containment_values_in_fixtures_map_to_enum() {
    assert_eq!(
        fixture("bubblewrap_filesystem_object.json").containment,
        Some(Containment::Bubblewrap)
    );
    assert_eq!(
        fixture("wslc_denied_masking.json").containment,
        Some(Containment::Wslc)
    );
    assert_eq!(
        fixture("lxc_network_proxy.json").containment,
        Some(Containment::Lxc)
    );
    assert_eq!(
        fixture("processcontainer_denied_outside_grants.json").containment,
        Some(Containment::ProcessContainer)
    );
}

#[test]
fn fixture_without_containment_parses_as_none() {
    // `containment` is nullable upstream: the binary resolves the OS-native
    // backend when it is absent.
    let policy = fixture("wslc_state_aware_exec_basic.json");
    assert_eq!(policy.containment, None);
}

#[test]
fn nested_network_proxy_is_captured_not_dropped() {
    // Proxy lives under `network.proxy` on the current surface. The vz
    // validator rejects it, so the parser must not silently discard it.
    let policy = fixture("lxc_network_proxy.json");
    let network = policy.network.as_ref().expect("network block");
    assert_eq!(network.default_policy, Some(NetworkDefaultPolicy::Block));
    assert!(
        network.proxy.is_some(),
        "network.proxy must be modeled so vz validation can reject it"
    );
}

#[test]
fn ui_disable_false_is_captured_not_dropped() {
    // ui.disable: false is an explicit request for UI access; the vz
    // validator rejects it, so the parser must not silently discard it.
    let policy = fixture("processcontainer_denied_outside_grants.json");
    let ui = policy.ui.as_ref().expect("ui block");
    assert_eq!(ui.disable, Some(false));
}
