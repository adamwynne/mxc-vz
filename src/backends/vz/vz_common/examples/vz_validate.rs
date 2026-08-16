//! Validate a policy JSON file for the vz backend — the executable form of
//! the cross-backend portability contract (build plan, Phase 5): the same
//! document another backend executes must be accepted by vz validation with
//! only the `containment` field changed.
//!
//! Usage: vz_validate <policy.json>
//! Exit 0 and print resolved options on success; exit 1 with the collected
//! errors otherwise.

use vz_common::policy::Policy;
use vz_common::validate::validate_vz_policy;

fn main() {
    let path = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("usage: vz_validate <policy.json>");
        std::process::exit(2);
    });
    let json = std::fs::read_to_string(&path).unwrap_or_else(|error| {
        eprintln!("vz_validate: cannot read {path}: {error}");
        std::process::exit(2);
    });
    let policy: Policy = match serde_json::from_str(&json) {
        Ok(policy) => policy,
        Err(error) => {
            eprintln!("vz_validate: parse error: {error}");
            std::process::exit(1);
        }
    };
    match validate_vz_policy(&policy, true) {
        Ok(validated) => {
            println!(
                "vz_validate: OK — cpuCount={} memoryMB={} bootTimeoutMs={}",
                validated.options.cpu_count,
                validated.options.memory_mb,
                validated.options.boot_timeout_ms
            );
            for warning in &validated.warnings {
                println!("vz_validate: warning: {warning:?}");
            }
        }
        Err(errors) => {
            for error in &errors {
                eprintln!("vz_validate: error: {error}");
            }
            std::process::exit(1);
        }
    }
}
