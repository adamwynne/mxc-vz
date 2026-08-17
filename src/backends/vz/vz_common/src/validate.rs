//! Validation of `containment: "vz"` policies (Phase 0 rules, aligned with
//! the upstream 0.8.0-dev config surface).
//!
//! Rules implemented here (docs/macos-support/vz-backend.md):
//! - vz requires the experimental flag, and the policy's `containment` must
//!   be `"vz"` explicitly (the vz backend is never an OS-native default).
//! - UI access is unsupported in v1: the guest VM has no WindowServer access
//!   by construction. `ui.disable: false`, `ui.injection: true`, and any
//!   clipboard level other than `none` are rejected. `ui.disable: true` (or
//!   an absent/defaulted `ui` block) is trivially satisfied.
//! - `network.proxy` and non-empty `network.blockedHosts` are unsupported in
//!   v1 and rejected. Validation collects every error, not just the first.
//! - `filesystem.deniedPaths` entries are redundant on vz (nothing is shared
//!   by default) and produce warnings — unless equal to or lexically inside a
//!   shared path, which is an error (Decision 5: reject, do not split shares).
//! - All policy paths must be absolute.
//! - `experimental.vz` bounds: cpuCount >= 1, memoryMB >= 128, bootTimeoutMs >= 1.
//! - Blocks the vz backend does not consume (`seatbelt`, `lxc`,
//!   `processContainer`, `network.enforcementMode`) are accepted for
//!   cross-backend portability and reported as warnings.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::policy::{ClipboardPolicy, Containment, Policy, VzOptions};

pub const MIN_MEMORY_MB: u64 = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VzPolicyError {
    NotVzContainment,
    ExperimentalRequired,
    /// `ui.disable: false` — an explicit request for UI access.
    UiAccessUnsupported,
    /// `ui.injection: true`.
    UiInjectionUnsupported,
    /// `ui.clipboard` set to a level other than `none`.
    ClipboardUnsupported(ClipboardPolicy),
    /// `network.proxy` present.
    ProxyUnsupported,
    BlockedHostsUnsupported,
    DeniedPathInsideShare { denied: PathBuf, share: PathBuf },
    NonAbsolutePath(PathBuf),
    /// A path containing an interior NUL byte (TM-11): it would silently
    /// truncate when converted to a C string for the VZ file URL.
    PathContainsNul(PathBuf),
    InvalidCpuCount(u32),
    InvalidMemoryMb(u64),
    InvalidBootTimeoutMs(u64),
}

impl fmt::Display for VzPolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotVzContainment => {
                write!(f, "policy containment is not \"vz\"; this validator only accepts vz policies")
            }
            Self::ExperimentalRequired => {
                write!(f, "containment \"vz\" requires the experimental flag to be enabled")
            }
            Self::UiAccessUnsupported => {
                write!(f, "ui.disable: false is not supported by the vz backend: the guest VM has no WindowServer access")
            }
            Self::UiInjectionUnsupported => {
                write!(f, "ui.injection is not supported by the vz backend: the guest VM has no WindowServer access")
            }
            Self::ClipboardUnsupported(level) => {
                write!(f, "ui.clipboard level {level:?} is not supported by the vz backend; only \"none\" is accepted")
            }
            Self::ProxyUnsupported => {
                write!(f, "network.proxy is not supported by the vz backend in v1")
            }
            Self::BlockedHostsUnsupported => {
                write!(f, "network.blockedHosts is not supported by the vz backend in v1; use defaultPolicy \"block\" with allowedHosts")
            }
            Self::DeniedPathInsideShare { denied, share } => {
                write!(
                    f,
                    "filesystem.deniedPaths entry {} is inside shared path {}; deniedPaths may not overlap readonlyPaths/readwritePaths on vz",
                    denied.display(),
                    share.display()
                )
            }
            Self::NonAbsolutePath(path) => {
                write!(f, "policy path {} must be absolute", path.display())
            }
            Self::PathContainsNul(path) => {
                write!(f, "policy path {} contains a NUL byte", path.display())
            }
            Self::InvalidCpuCount(value) => {
                write!(f, "experimental.vz.cpuCount must be at least 1 (got {value})")
            }
            Self::InvalidMemoryMb(value) => {
                write!(f, "experimental.vz.memoryMB must be at least {MIN_MEMORY_MB} (got {value})")
            }
            Self::InvalidBootTimeoutMs(value) => {
                write!(f, "experimental.vz.bootTimeoutMs must be at least 1 (got {value})")
            }
        }
    }
}

impl std::error::Error for VzPolicyError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Warning {
    /// A deniedPaths entry that no share exposes: harmless on vz because
    /// nothing is shared by default; kept for cross-backend portability.
    RedundantDeniedPath(PathBuf),
    /// A policy field or block the vz backend does not consume (another
    /// backend's options block, or `network.enforcementMode`): accepted for
    /// cross-backend portability, ignored at runtime.
    IgnoredField(String),
    /// `allowedHosts` under `defaultPolicy: allow` — no-ops, because the
    /// default accepts everything anyway (upstream lxc semantics).
    RedundantAllowedHosts,
    /// An `allowedHosts` entry that does not parse as an IP, CIDR, or
    /// hostname. Skipped, matching upstream's report-and-skip: dropping an
    /// allow entry only ever restricts.
    SkippedAllowedHost(String),
}

#[derive(Debug, Clone, PartialEq)]
pub struct ValidatedVzPolicy {
    /// `experimental.vz` options with defaults applied.
    pub options: VzOptions,
    pub warnings: Vec<Warning>,
}

/// Validate a policy for the vz backend, collecting every error.
///
/// `experimental_enabled` is the caller-level experimental flag (e.g. the
/// SDK's `{ experimental: true }` spawn option or `--experimental`).
pub fn validate_vz_policy(
    policy: &Policy,
    experimental_enabled: bool,
) -> Result<ValidatedVzPolicy, Vec<VzPolicyError>> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if policy.containment != Some(Containment::Vz) {
        errors.push(VzPolicyError::NotVzContainment);
    }
    if !experimental_enabled {
        errors.push(VzPolicyError::ExperimentalRequired);
    }

    if let Some(ui) = &policy.ui {
        if ui.disable == Some(false) {
            errors.push(VzPolicyError::UiAccessUnsupported);
        }
        if ui.injection == Some(true) {
            errors.push(VzPolicyError::UiInjectionUnsupported);
        }
        if let Some(level) = ui.clipboard {
            if level != ClipboardPolicy::None {
                errors.push(VzPolicyError::ClipboardUnsupported(level));
            }
        }
    }

    if let Some(network) = &policy.network {
        if network.proxy.is_some() {
            errors.push(VzPolicyError::ProxyUnsupported);
        }
        if !network.blocked_hosts.is_empty() {
            errors.push(VzPolicyError::BlockedHostsUnsupported);
        }
        if network.enforcement_mode.is_some() {
            warnings.push(Warning::IgnoredField("network.enforcementMode".to_string()));
        }
        if !network.allowed_hosts.is_empty()
            && network.default_policy == Some(crate::policy::NetworkDefaultPolicy::Allow)
        {
            warnings.push(Warning::RedundantAllowedHosts);
        }
        for entry in &network.allowed_hosts {
            if vz_net::pattern::HostPattern::parse(entry).is_err() {
                warnings.push(Warning::SkippedAllowedHost(entry.clone()));
            }
        }
    }

    for (present, name) in [
        (policy.seatbelt.is_some(), "seatbelt"),
        (policy.lxc.is_some(), "lxc"),
        (policy.process_container.is_some(), "processContainer"),
    ] {
        if present {
            warnings.push(Warning::IgnoredField(name.to_string()));
        }
    }

    if let Some(fs) = &policy.filesystem {
        let all_paths = fs
            .readonly_paths
            .iter()
            .chain(&fs.readwrite_paths)
            .chain(&fs.denied_paths);
        for path in all_paths {
            if path_has_interior_nul(path) {
                errors.push(VzPolicyError::PathContainsNul(path.clone()));
            } else if !path.is_absolute() {
                errors.push(VzPolicyError::NonAbsolutePath(path.clone()));
            }
        }

        let shares: Vec<&PathBuf> = fs.readonly_paths.iter().chain(&fs.readwrite_paths).collect();
        for denied in &fs.denied_paths {
            match shares.iter().find(|share| path_contains(share, denied)) {
                Some(share) => errors.push(VzPolicyError::DeniedPathInsideShare {
                    denied: denied.clone(),
                    share: (*share).clone(),
                }),
                None => warnings.push(Warning::RedundantDeniedPath(denied.clone())),
            }
        }
    }

    let options = policy
        .experimental
        .as_ref()
        .and_then(|experimental| experimental.vz.clone())
        .unwrap_or_default();

    if options.cpu_count < 1 {
        errors.push(VzPolicyError::InvalidCpuCount(options.cpu_count));
    }
    if options.memory_mb < MIN_MEMORY_MB {
        errors.push(VzPolicyError::InvalidMemoryMb(options.memory_mb));
    }
    if options.boot_timeout_ms < 1 {
        errors.push(VzPolicyError::InvalidBootTimeoutMs(options.boot_timeout_ms));
    }

    if errors.is_empty() {
        Ok(ValidatedVzPolicy { options, warnings })
    } else {
        Err(errors)
    }
}

/// Lexical, component-wise containment: true when `candidate` is equal to or
/// a descendant of `ancestor`. Trailing slashes are irrelevant (components are
/// compared, not strings), and `/workspace-2` is not inside `/workspace`.
///
/// Comparison is **ASCII-case-insensitive** (TM-11, mirroring upstream's
/// canonical-path handling): the share side is the host's macOS filesystem,
/// which is case-insensitive on default APFS — `/Workspace/secrets` and
/// `/workspace/secrets` are the same directory there. Case-folding errs
/// toward *rejecting* an overlap (fail closed); a case-sensitive volume
/// would only make a rejected policy spuriously strict, never permissive.
fn path_contains(ancestor: &Path, candidate: &Path) -> bool {
    let ancestor: Vec<String> = ancestor
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect();
    let candidate: Vec<String> = candidate
        .components()
        .map(|c| c.as_os_str().to_string_lossy().to_ascii_lowercase())
        .collect();
    candidate.len() >= ancestor.len() && candidate[..ancestor.len()] == ancestor[..]
}

/// Interior NUL bytes silently truncate a path once it crosses into a C
/// string (`fileURLWithPath` and friends), turning `/safe\0/../etc` into
/// `/safe` — upstream's config parser rejects these and so do we.
fn path_has_interior_nul(path: &Path) -> bool {
    path.as_os_str().as_encoded_bytes().contains(&0)
}

#[cfg(test)]
mod tests {
    use super::{path_contains, path_has_interior_nul};
    use std::path::Path;

    #[test]
    fn containment_is_component_wise() {
        assert!(path_contains(Path::new("/workspace"), Path::new("/workspace")));
        assert!(path_contains(Path::new("/workspace"), Path::new("/workspace/a/b")));
        assert!(path_contains(Path::new("/workspace/"), Path::new("/workspace/a")));
        assert!(!path_contains(Path::new("/workspace"), Path::new("/workspace-2")));
        assert!(!path_contains(Path::new("/workspace/a"), Path::new("/workspace")));
    }

    #[test]
    fn containment_is_case_insensitive() {
        // APFS default is case-insensitive: these are the same host dirs.
        assert!(path_contains(Path::new("/workspace"), Path::new("/Workspace/secrets")));
        assert!(path_contains(Path::new("/WORKSPACE"), Path::new("/workspace/a")));
        assert!(!path_contains(Path::new("/workspace"), Path::new("/Workspace-2")));
    }

    #[test]
    fn interior_nul_is_detected() {
        use std::ffi::OsStr;
        use std::os::unix::ffi::OsStrExt;
        assert!(!path_has_interior_nul(Path::new("/workspace")));
        let evil = OsStr::from_bytes(b"/safe\0/../etc");
        assert!(path_has_interior_nul(Path::new(evil)));
    }
}
