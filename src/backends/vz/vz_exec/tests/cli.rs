//! Integration tests driving the real `vz-exec` binary — the executor the
//! SDK spawns. The contract under test mirrors upstream's `mxc-exec-mac` /
//! `lxc-exec` shape: config via positional path / `--config` /
//! `--config-base64`; `--dry-run` validates without executing; script
//! stdout/stderr pass through verbatim; the guest exit code becomes the
//! process exit code; infrastructure failures print a JSON error envelope
//! on stderr.
//!
//! Execution end-to-end uses the testing transport (`MXC_VZ_AGENT_TCP`,
//! gated behind `--allow-testing-features`) against the REAL guest agent
//! served over TCP in-process — the same shape CI uses against QEMU.

use std::io::Write;
use std::net::TcpListener;
use std::process::{Command, Output};
use std::thread;

fn vz_exec() -> Command {
    Command::new(env!("CARGO_BIN_EXE_vz-exec"))
}

fn write_policy(dir: &std::path::Path, name: &str, json: &str) -> std::path::PathBuf {
    let path = dir.join(name);
    std::fs::File::create(&path)
        .and_then(|mut f| f.write_all(json.as_bytes()))
        .expect("write test policy");
    path
}

fn tempdir() -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!("vz-exec-test-{}", std::process::id()));
    std::fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

const VALID: &str = r#"{ "containment": "vz", "process": { "commandLine": "true" } }"#;

/// Serve one agent connection over TCP, returning the address to dial.
fn spawn_tcp_agent() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind test listener");
    let addr = listener.local_addr().expect("listener addr").to_string();
    thread::spawn(move || {
        if let Ok((stream, _)) = listener.accept() {
            let reader = stream.try_clone().expect("clone agent stream");
            vz_guest_agent::serve_connection(reader, stream);
        }
    });
    addr
}

fn stdout_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr_str(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

#[test]
fn no_config_is_an_error() {
    let output = vz_exec().output().expect("run vz-exec");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr_str(&output).contains("No config provided"),
        "stderr: {}",
        stderr_str(&output)
    );
}

#[test]
fn unknown_flag_is_a_usage_error() {
    let output = vz_exec().arg("--bogus").output().expect("run vz-exec");
    assert_eq!(output.status.code(), Some(2), "usage errors exit 2 (clap parity)");
    assert!(stderr_str(&output).contains("--bogus"));
}

#[test]
fn dry_run_accepts_a_valid_policy() {
    let path = write_policy(&tempdir(), "valid.json", VALID);
    let output = vz_exec()
        .args(["--dry-run", "--experimental", "--config"])
        .arg(&path)
        .output()
        .expect("run vz-exec");
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr_str(&output));
    assert!(stdout_str(&output).contains("validation passed"));
}

#[test]
fn positional_config_path_works() {
    let path = write_policy(&tempdir(), "positional.json", VALID);
    let output = vz_exec()
        .arg(&path)
        .args(["--dry-run", "--experimental"])
        .output()
        .expect("run vz-exec");
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr_str(&output));
}

#[test]
fn config_base64_works() {
    let encoded = base64_encode(VALID.as_bytes());
    let output = vz_exec()
        .args(["--dry-run", "--experimental", "--config-base64", &encoded])
        .output()
        .expect("run vz-exec");
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr_str(&output));
    assert!(stdout_str(&output).contains("validation passed"));
}

#[test]
fn dry_run_without_experimental_fails_with_the_reason() {
    let path = write_policy(&tempdir(), "no-experimental.json", VALID);
    let output = vz_exec()
        .args(["--dry-run", "--config"])
        .arg(&path)
        .output()
        .expect("run vz-exec");
    assert_eq!(output.status.code(), Some(1));
    let combined = format!("{}{}", stdout_str(&output), stderr_str(&output));
    assert!(combined.contains("validation failed"), "output: {combined}");
    assert!(combined.contains("experimental"), "output: {combined}");
}

#[test]
fn dry_run_rejects_proxy_with_a_clear_error() {
    let path = write_policy(
        &tempdir(),
        "proxy.json",
        r#"{ "containment": "vz",
             "process": { "commandLine": "true" },
             "network": { "defaultPolicy": "block", "proxy": { "localhost": 8080 } } }"#,
    );
    let output = vz_exec()
        .args(["--dry-run", "--experimental", "--config"])
        .arg(&path)
        .output()
        .expect("run vz-exec");
    assert_eq!(output.status.code(), Some(1));
    let combined = format!("{}{}", stdout_str(&output), stderr_str(&output));
    assert!(combined.contains("proxy"), "output: {combined}");
}

#[test]
fn malformed_config_is_a_request_error() {
    let path = write_policy(&tempdir(), "broken.json", "{ not json");
    let output = vz_exec()
        .args(["--experimental", "--config"])
        .arg(&path)
        .output()
        .expect("run vz-exec");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr_str(&output).contains("Request error"),
        "stderr: {}",
        stderr_str(&output)
    );
}

#[test]
fn probe_reports_platform_support_as_json() {
    let output = vz_exec().arg("--probe").output().expect("run vz-exec");
    assert_eq!(output.status.code(), Some(0), "stderr: {}", stderr_str(&output));
    let probe: serde_json::Value =
        serde_json::from_str(&stdout_str(&output)).expect("probe output must be JSON");
    let supported = probe["isSupported"].as_bool().expect("isSupported bool");
    if cfg!(target_os = "macos") {
        // On a Mac the answer is host-dependent (VMs report false); the
        // shape contract is what matters.
        assert!(probe["availableMethods"].is_array());
    } else {
        assert!(!supported, "vz must be unsupported off macOS");
        assert_eq!(probe["availableMethods"].as_array().map(Vec::len), Some(0));
        assert!(probe["reason"].as_str().unwrap_or_default().contains("macOS"));
    }
}

#[test]
fn tcp_exec_passes_through_stdout_stderr_and_exit_code() {
    let addr = spawn_tcp_agent();
    let path = write_policy(
        &tempdir(),
        "exec.json",
        r#"{ "containment": "vz",
             "process": { "commandLine": "echo out; echo err 1>&2; exit 5" } }"#,
    );
    let output = vz_exec()
        .args(["--experimental", "--allow-testing-features", "--config"])
        .arg(&path)
        .env("MXC_VZ_AGENT_TCP", &addr)
        .output()
        .expect("run vz-exec");
    assert_eq!(stdout_str(&output), "out\n");
    assert_eq!(stderr_str(&output), "err\n");
    assert_eq!(output.status.code(), Some(5), "guest exit code passes through");
}

#[test]
fn tcp_transport_requires_the_testing_features_flag() {
    let addr = spawn_tcp_agent();
    let path = write_policy(&tempdir(), "gated.json", VALID);
    let output = vz_exec()
        .args(["--experimental", "--config"])
        .arg(&path)
        .env("MXC_VZ_AGENT_TCP", &addr)
        .output()
        .expect("run vz-exec");
    assert_eq!(output.status.code(), Some(1));
    assert!(
        stderr_str(&output).contains("allow-testing-features"),
        "stderr: {}",
        stderr_str(&output)
    );
}

#[test]
fn tcp_timeout_force_stops_and_reports_the_envelope() {
    let addr = spawn_tcp_agent();
    let path = write_policy(
        &tempdir(),
        "timeout.json",
        r#"{ "containment": "vz",
             "process": { "commandLine": "sleep 30", "timeout": 400 } }"#,
    );
    let started = std::time::Instant::now();
    let output = vz_exec()
        .args(["--experimental", "--allow-testing-features", "--config"])
        .arg(&path)
        .env("MXC_VZ_AGENT_TCP", &addr)
        .output()
        .expect("run vz-exec");
    assert!(
        started.elapsed() < std::time::Duration::from_secs(10),
        "the executor must not wait out the guest command"
    );
    // Upstream convention: a timeout is exit -1 (255 observed) with the
    // machine-readable envelope on stderr.
    assert_eq!(output.status.code(), Some(255));
    let stderr = stderr_str(&output);
    let envelope_line = stderr
        .lines()
        .find(|l| l.starts_with('{'))
        .unwrap_or_else(|| panic!("no JSON envelope on stderr: {stderr}"));
    let envelope: serde_json::Value =
        serde_json::from_str(envelope_line).expect("envelope must be JSON");
    assert_eq!(envelope["error"]["code"], "backend_error");
    assert!(
        envelope["error"]["message"]
            .as_str()
            .unwrap_or_default()
            .contains("timeout"),
        "envelope: {envelope}"
    );
}

/// Minimal RFC 4648 encoder for test input (the binary owns the decoder).
fn base64_encode(data: &[u8]) -> String {
    const ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let b = [chunk[0], *chunk.get(1).unwrap_or(&0), *chunk.get(2).unwrap_or(&0)];
        let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
        out.push(ALPHABET[(n >> 18) as usize & 63] as char);
        out.push(ALPHABET[(n >> 12) as usize & 63] as char);
        out.push(if chunk.len() > 1 { ALPHABET[(n >> 6) as usize & 63] as char } else { '=' });
        out.push(if chunk.len() > 2 { ALPHABET[n as usize & 63] as char } else { '=' });
    }
    out
}
