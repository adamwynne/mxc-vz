//! `vz-exec` internals: argument parsing, config loading, and the
//! execute/outcome mapping shared by the VZ and testing transports.
//!
//! The CLI contract mirrors upstream's executors (`mxc-exec-mac`,
//! `lxc-exec`): config via positional path / `--config` / `--config-base64`
//! (base64 wins, then `--config`, then positional); `--dry-run` validates
//! and exits; script stdout/stderr pass through verbatim; the guest exit
//! code becomes the process exit code; infrastructure failures print a
//! one-line JSON error envelope on stderr (issue #564 parity); a timeout is
//! exit -1 with the envelope, matching upstream's `FailurePhase::Timeout`
//! responses.

use std::io::Write as _;
use std::path::PathBuf;
use std::time::Duration;

use vz_common::exec_plan::build_exec_request;
use vz_common::policy::Policy;
use vz_common::validate::{validate_vz_policy, ValidatedVzPolicy};
use vz_protocol::client::{exec_collect_with_timeout, ExecCompletion, ExecOutcome};

/// Default guest image directory, overridable with `--guest-image-dir` or
/// `MXC_VZ_GUEST_IMAGE_DIR`.
pub const DEFAULT_GUEST_IMAGE_DIR: &str = "/opt/mxc/vz-guest";

/// Environment variable naming a `host:port` where an already-running guest
/// agent listens over TCP. Testing-only (QEMU CI, integration tests): it
/// bypasses VM creation entirely, so it is gated behind
/// `--allow-testing-features` and must never be set in production.
pub const AGENT_TCP_ENV: &str = "MXC_VZ_AGENT_TCP";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ConfigSource {
    Path(PathBuf),
    Base64(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Cli {
    pub config: Option<ConfigSource>,
    pub debug: bool,
    pub experimental: bool,
    pub allow_testing_features: bool,
    pub dry_run: bool,
    pub probe: bool,
    pub log_file: Option<PathBuf>,
    pub guest_image_dir: Option<PathBuf>,
}

/// A usage error: printed with the usage line, exit 2 (clap parity).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UsageError(pub String);

pub const USAGE: &str = "usage: vz-exec [CONFIG_PATH] [--config <path>] [--config-base64 <b64>] \
[--dry-run] [--debug] [--experimental] [--allow-testing-features] \
[--log-file <path>] [--guest-image-dir <path>] [--probe]";

pub fn parse_args(args: impl IntoIterator<Item = String>) -> Result<Cli, UsageError> {
    let mut cli = Cli::default();
    let mut positional: Option<String> = None;
    let mut config_flag: Option<String> = None;
    let mut base64_flag: Option<String> = None;
    let mut args = args.into_iter();

    let value_of = |flag: &str, args: &mut dyn Iterator<Item = String>| {
        args.next().ok_or_else(|| UsageError(format!("{flag} requires a value")))
    };

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--config" => config_flag = Some(value_of("--config", &mut args)?),
            "--config-base64" => base64_flag = Some(value_of("--config-base64", &mut args)?),
            "--debug" => cli.debug = true,
            "--experimental" => cli.experimental = true,
            "--allow-testing-features" => cli.allow_testing_features = true,
            "--dry-run" => cli.dry_run = true,
            "--probe" => cli.probe = true,
            "--log-file" => cli.log_file = Some(value_of("--log-file", &mut args)?.into()),
            "--guest-image-dir" => {
                cli.guest_image_dir = Some(value_of("--guest-image-dir", &mut args)?.into())
            }
            other if other.starts_with('-') => {
                return Err(UsageError(format!("unknown flag: {other}")));
            }
            _ if positional.is_none() => positional = Some(arg),
            other => return Err(UsageError(format!("unexpected extra argument: {other}"))),
        }
    }

    // Upstream precedence: base64 > --config > positional.
    cli.config = if let Some(b64) = base64_flag {
        Some(ConfigSource::Base64(b64))
    } else if let Some(path) = config_flag {
        Some(ConfigSource::Path(path.into()))
    } else {
        positional.map(|p| ConfigSource::Path(p.into()))
    };

    Ok(cli)
}

/// Strict RFC 4648 base64 decoder (standard alphabet, `=` padding).
/// Hand-rolled to keep the executor dependency-free; the alphabet is the
/// same one upstream's `--config-base64` producers emit.
pub fn base64_decode(input: &str) -> Result<Vec<u8>, String> {
    fn value(byte: u8) -> Result<u32, String> {
        match byte {
            b'A'..=b'Z' => Ok(u32::from(byte - b'A')),
            b'a'..=b'z' => Ok(u32::from(byte - b'a') + 26),
            b'0'..=b'9' => Ok(u32::from(byte - b'0') + 52),
            b'+' => Ok(62),
            b'/' => Ok(63),
            _ => Err(format!("invalid base64 byte 0x{byte:02x}")),
        }
    }

    let input: Vec<u8> = input.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if !input.len().is_multiple_of(4) {
        return Err("base64 length must be a multiple of 4".to_string());
    }
    let mut out = Vec::with_capacity(input.len() / 4 * 3);
    for chunk in input.chunks(4) {
        let padding = chunk.iter().filter(|&&b| b == b'=').count();
        if padding > 2 || chunk[..4 - padding].contains(&b'=') {
            return Err("malformed base64 padding".to_string());
        }
        let mut n: u32 = 0;
        for &byte in &chunk[..4 - padding] {
            n = (n << 6) | value(byte)?;
        }
        n <<= 6 * padding as u32;
        out.push((n >> 16) as u8);
        if padding < 2 {
            out.push((n >> 8) as u8);
        }
        if padding < 1 {
            out.push(n as u8);
        }
    }
    Ok(out)
}

/// The whole run, returning the process exit code.
pub fn run(cli: &Cli) -> i32 {
    if cli.probe {
        return probe();
    }

    let Some(config) = &cli.config else {
        eprintln!("Error: No config provided. Use a positional path, --config, or --config-base64");
        return 1;
    };

    let bytes = match config {
        ConfigSource::Path(path) => match std::fs::read(path) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("Request error\ncould not read {}: {error}", path.display());
                return 1;
            }
        },
        ConfigSource::Base64(b64) => match base64_decode(b64) {
            Ok(bytes) => bytes,
            Err(error) => {
                eprintln!("Request error\ninvalid --config-base64: {error}");
                return 1;
            }
        },
    };

    let policy: Policy = match serde_json::from_slice(&bytes) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("Request error\nconfig does not parse as an MXC policy: {error}");
            return 1;
        }
    };

    let validated = match validate_vz_policy(&policy, cli.experimental) {
        Ok(validated) => validated,
        Err(errors) => {
            if cli.dry_run {
                println!("Dry run completed. Result: validation failed");
            }
            for error in &errors {
                eprintln!("validation error: {error}");
            }
            log_line(cli, &format!("validation failed ({} error(s))", errors.len()));
            return 1;
        }
    };
    if cli.debug {
        for warning in &validated.warnings {
            eprintln!("validation warning: {warning:?}");
        }
    }

    if cli.dry_run {
        println!("Dry run completed. Result: validation passed");
        log_line(cli, "dry run: validation passed");
        return 0;
    }

    if let Ok(addr) = std::env::var(AGENT_TCP_ENV) {
        if !cli.allow_testing_features {
            emit_envelope(&format!(
                "{AGENT_TCP_ENV} is a testing-only transport and requires --allow-testing-features"
            ));
            return 1;
        }
        return exec_over_tcp(cli, &policy, &addr);
    }

    exec_in_vm(cli, &policy, &validated)
}

/// `getPlatformSupport` analogue: report vz availability as JSON, exit 0.
fn probe() -> i32 {
    let (is_supported, reason) = platform_probe();
    let methods: Vec<&str> = if is_supported { vec!["vz"] } else { vec![] };
    let probe = serde_json::json!({
        "isSupported": is_supported,
        "reason": reason,
        "availableMethods": methods,
    });
    println!("{probe}");
    0
}

#[cfg(target_os = "macos")]
fn platform_probe() -> (bool, Option<String>) {
    if vz_darwin::vz::virtualization_supported() {
        (true, None)
    } else {
        (
            false,
            Some(
                "Virtualization.framework reports unsupported: requires Apple Silicon, \
                 macOS 13+, the com.apple.security.virtualization entitlement, and a \
                 non-virtualized host"
                    .to_string(),
            ),
        )
    }
}

#[cfg(not(target_os = "macos"))]
fn platform_probe() -> (bool, Option<String>) {
    (
        false,
        Some("the vz backend requires macOS 13+ on Apple Silicon".to_string()),
    )
}

/// Execute against an already-running agent over TCP (testing transport).
fn exec_over_tcp(cli: &Cli, policy: &Policy, addr: &str) -> i32 {
    use std::net::TcpStream;

    let request = match build_exec_request(policy) {
        Ok(request) => request,
        Err(reason) => {
            emit_envelope(&format!("policy translation failed: {reason}"));
            return 1;
        }
    };
    let stream = match TcpStream::connect(addr) {
        Ok(stream) => stream,
        Err(error) => {
            emit_envelope(&format!("could not connect to {AGENT_TCP_ENV}={addr}: {error}"));
            return 1;
        }
    };
    let reader = match stream.try_clone() {
        Ok(reader) => reader,
        Err(error) => {
            emit_envelope(&format!("could not clone agent stream: {error}"));
            return 1;
        }
    };
    let force_stop_handle = match stream.try_clone() {
        Ok(handle) => handle,
        Err(error) => {
            emit_envelope(&format!("could not clone agent stream: {error}"));
            return 1;
        }
    };

    let timeout = request.timeout_ms.map(Duration::from_millis);
    let completion = exec_collect_with_timeout(reader, stream, &request, None, timeout, move || {
        // Severing the transport mirrors what a VM force-stop does to the
        // vsock stream: the exec worker's blocking read fails over.
        let _ = force_stop_handle.shutdown(std::net::Shutdown::Both);
    });
    match completion {
        Ok(completion) => finish(cli, completion),
        Err(error) => {
            emit_envelope(&format!("exec failure: {error}"));
            1
        }
    }
}

#[cfg(target_os = "macos")]
fn exec_in_vm(cli: &Cli, policy: &Policy, validated: &ValidatedVzPolicy) -> i32 {
    use vz_common::vm_spec::build_vm_spec;
    use vz_darwin::session::{run_one_shot, SessionError, SessionOutcome};
    use vz_darwin::vz::VzDriver;

    let guest_image_dir = cli
        .guest_image_dir
        .clone()
        .or_else(|| std::env::var_os("MXC_VZ_GUEST_IMAGE_DIR").map(PathBuf::from))
        .unwrap_or_else(|| PathBuf::from(DEFAULT_GUEST_IMAGE_DIR));

    // run_one_shot re-derives the spec from the policy; this copy only
    // exists so the factory can build the driver on the VM thread.
    let spec = build_vm_spec(policy, validated, &guest_image_dir);
    let outcome = run_one_shot(policy, cli.experimental, &guest_image_dir, move || {
        VzDriver::new(&spec)
    });
    match outcome {
        Ok(SessionOutcome::Completed(outcome)) => {
            finish(cli, ExecCompletion::Completed(outcome))
        }
        Ok(SessionOutcome::TimedOut) => finish(cli, ExecCompletion::TimedOut),
        Err(SessionError::Validation(errors)) => {
            for error in &errors {
                eprintln!("validation error: {error}");
            }
            1
        }
        Err(error) => {
            emit_envelope(&error.to_string());
            1
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn exec_in_vm(_cli: &Cli, _policy: &Policy, _validated: &ValidatedVzPolicy) -> i32 {
    eprintln!(
        "vz-exec: the vz backend is only available on macOS. This binary was built for a \
         non-Darwin target and cannot execute scripts."
    );
    1
}

/// Map a completion to the executor's observable contract: script bytes
/// pass through verbatim, guest exit code becomes the process exit code, a
/// timeout is exit -1 with the envelope.
fn finish(cli: &Cli, completion: ExecCompletion) -> i32 {
    match completion {
        ExecCompletion::Completed(ExecOutcome { exit_code, stdout, stderr }) => {
            let _ = std::io::stdout().write_all(&stdout);
            let _ = std::io::stderr().write_all(&stderr);
            log_line(cli, &format!("exec completed, exit code {exit_code}"));
            exit_code
        }
        ExecCompletion::TimedOut => {
            emit_envelope(
                "process force-stopped after exceeding process.timeout (script timeout)",
            );
            log_line(cli, "exec timed out; VM force-stopped");
            -1
        }
    }
}

/// One-line machine-readable diagnostic on stderr (upstream issue #564:
/// never exit non-zero on an infrastructure failure without one).
fn emit_envelope(message: &str) {
    let envelope = serde_json::json!({
        "error": { "code": "backend_error", "message": message }
    });
    eprintln!("{envelope}");
}

fn log_line(cli: &Cli, line: &str) {
    let Some(path) = &cli.log_file else { return };
    if let Ok(mut file) = std::fs::OpenOptions::new().create(true).append(true).open(path) {
        let _ = writeln!(file, "vz-exec: {line}");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_roundtrips() {
        for input in ["", "a", "ab", "abc", "abcd", r#"{ "containment": "vz" }"#] {
            let encoded = encode(input.as_bytes());
            assert_eq!(base64_decode(&encoded).unwrap(), input.as_bytes(), "input: {input}");
        }
    }

    #[test]
    fn base64_rejects_garbage() {
        assert!(base64_decode("!!!!").is_err());
        assert!(base64_decode("abc").is_err());
        assert!(base64_decode("a=bc").is_err());
    }

    #[test]
    fn base64_accepts_embedded_whitespace() {
        // `base64` CLI output wraps lines; the decoder must not care.
        let encoded = format!("{}\n{}", "eyAiY29udGFpbm1lbnQi", "OiAidnoiIH0=");
        assert_eq!(base64_decode(&encoded).unwrap(), br#"{ "containment": "vz" }"#);
    }

    #[test]
    fn args_parse_with_upstream_precedence() {
        let cli = parse_args(
            ["pos.json", "--config", "flag.json", "--config-base64", "eHg=", "--dry-run"]
                .map(String::from),
        )
        .unwrap();
        assert_eq!(cli.config, Some(ConfigSource::Base64("eHg=".to_string())));
        assert!(cli.dry_run);

        let cli = parse_args(["pos.json", "--config", "flag.json"].map(String::from)).unwrap();
        assert_eq!(cli.config, Some(ConfigSource::Path("flag.json".into())));

        let cli = parse_args(["pos.json"].map(String::from)).unwrap();
        assert_eq!(cli.config, Some(ConfigSource::Path("pos.json".into())));
    }

    #[test]
    fn unknown_flags_and_missing_values_are_usage_errors() {
        assert!(parse_args(["--bogus".to_string()]).is_err());
        assert!(parse_args(["--config".to_string()]).is_err());
        assert!(parse_args(["a.json".to_string(), "b.json".to_string()]).is_err());
    }

    fn encode(data: &[u8]) -> String {
        const ALPHABET: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
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
}
