//! Validation of `containment: "vz"` policies (Phase 0 rules).
//!
//! Rules implemented here (docs/macos-support/vz-backend.md):
//! - vz requires the experimental flag.
//! - `ui.guiAccess: true`, `proxy`, and non-empty `network.blockedHosts` are
//!   unsupported in v1 and rejected with distinct errors; validation collects
//!   every error rather than stopping at the first.
//! - `filesystem.deniedPaths` entries are redundant on vz (nothing is shared
//!   by default) and produce warnings — unless equal to or lexically inside a
//!   shared path, which is an error (Decision 5: reject, do not split shares).
//! - All policy paths must be absolute.
//! - `experimental.vz` bounds: cpuCount >= 1, memoryMB >= 128, bootTimeoutMs >= 1.

use std::fmt;
use std::path::{Path, PathBuf};

use crate::policy::{Containment, Policy, VzOptions};

pub const MIN_MEMORY_MB: u64 = 128;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum VzPolicyError {
    NotVzContainment,
    ExperimentalRequired,
    GuiAccessUnsupported,
    ProxyUnsupported,
    BlockedHostsUnsupported,
    DeniedPathInsideShare { denied: PathBuf, share: PathBuf },
    NonAbsolutePath(PathBuf),
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
            Self::GuiAccessUnsupported => {
                write!(f, "ui.guiAccess is not supported by the vz backend: the guest VM has no WindowServer access")
            }
            Self::ProxyUnsupported => {
                write!(f, "proxy is not supported by the vz backend in v1")
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
    /// A ui.* field other than guiAccess: trivially satisfied by the vz
    /// backend and ignored.
    IgnoredUiField(String),
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
/// SDK's `{ experimental: true }` spawn option).
pub fn validate_vz_policy(
    policy: &Policy,
    experimental_enabled: bool,
) -> Result<ValidatedVzPolicy, Vec<VzPolicyError>> {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();

    if policy.containment != Containment::Vz {
        errors.push(VzPolicyError::NotVzContainment);
    }
    if !experimental_enabled {
        errors.push(VzPolicyError::ExperimentalRequired);
    }

    if let Some(ui) = &policy.ui {
        if ui.gui_access == Some(true) {
            errors.push(VzPolicyError::GuiAccessUnsupported);
        }
        for field in ui.extra.keys() {
            warnings.push(Warning::IgnoredUiField(field.clone()));
        }
    }

    if policy.proxy.is_some() {
        errors.push(VzPolicyError::ProxyUnsupported);
    }

    if let Some(network) = &policy.network {
        if !network.blocked_hosts.is_empty() {
            errors.push(VzPolicyError::BlockedHostsUnsupported);
        }
    }

    if let Some(fs) = &policy.filesystem {
        let all_paths = fs
            .readonly_paths
            .iter()
            .chain(&fs.readwrite_paths)
            .chain(&fs.denied_paths);
        for path in all_paths {
            if !path.is_absolute() {
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
fn path_contains(ancestor: &Path, candidate: &Path) -> bool {
    candidate.starts_with(ancestor)
}

#[cfg(test)]
mod tests {
    use super::path_contains;
    use std::path::Path;

    #[test]
    fn containment_is_component_wise() {
        assert!(path_contains(Path::new("/workspace"), Path::new("/workspace")));
        assert!(path_contains(Path::new("/workspace"), Path::new("/workspace/a/b")));
        assert!(path_contains(Path::new("/workspace/"), Path::new("/workspace/a")));
        assert!(!path_contains(Path::new("/workspace"), Path::new("/workspace-2")));
        assert!(!path_contains(Path::new("/workspace/a"), Path::new("/workspace")));
    }
}
