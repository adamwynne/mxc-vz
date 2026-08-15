//! Serde types for the mxc policy config surface (0.8.0-dev) used by the vz
//! backend, aligned with upstream `schemas/dev/mxc-config.schema.0.8.0-dev.json`.
//!
//! Strictness mirrors the upstream schema exactly: the stable surface
//! (top-level object, `filesystem`, `network`, `ui`, `process`, `proxy`) is
//! closed (`deny_unknown_fields`), while the `experimental` block is
//! intentionally permissive — experimental backends are in flux, so unknown
//! fields there are tolerated rather than rejected.
//!
//! Blocks this crate does not translate (`lifecycle`, `phase`, `fallback`,
//! `seatbelt`, `lxc`, `processContainer`) are retained as raw JSON values so
//! nothing is silently dropped and validation can warn about them.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Containment backend (abstract intent or concrete backend), 0.8.0-dev
/// values plus the `vz` addition this repo introduces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Containment {
    /// OS-native process sandbox (resolved per host).
    #[serde(rename = "process")]
    Process,
    /// Windows AppContainer / BaseContainer.
    #[serde(rename = "processcontainer")]
    ProcessContainer,
    /// VM-class isolation (resolved per host).
    #[serde(rename = "vm")]
    Vm,
    /// Windows Sandbox (experimental).
    #[serde(rename = "windows_sandbox")]
    WindowsSandbox,
    /// Full Linux container.
    #[serde(rename = "lxc")]
    Lxc,
    /// NanVix micro-VM (experimental).
    #[serde(rename = "microvm")]
    Microvm,
    /// Hyperlight micro-VM (experimental).
    #[serde(rename = "hyperlight")]
    Hyperlight,
    /// WSL container (experimental).
    #[serde(rename = "wslc")]
    Wslc,
    /// macOS Seatbelt.
    #[serde(rename = "seatbelt")]
    Seatbelt,
    /// Windows IsolationSession (experimental).
    #[serde(rename = "isolation_session")]
    IsolationSession,
    /// Unprivileged Linux bubblewrap sandbox.
    #[serde(rename = "bubblewrap")]
    Bubblewrap,
    /// Apple Virtualization.framework micro-VM (experimental; this repo).
    #[serde(rename = "vz")]
    Vz,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    #[serde(rename = "$schema", default, skip_serializing_if = "Option::is_none")]
    pub schema: Option<String>,
    #[serde(rename = "_comment", default, skip_serializing_if = "Option::is_none")]
    pub comment: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub correlation_vector: Option<String>,
    /// Nullable upstream: the binary resolves the OS-native backend when absent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub containment: Option<Containment>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<Filesystem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui: Option<Ui>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<Process>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Experimental>,
    // Current-surface blocks not translated by the vz backend, retained
    // verbatim (see module docs).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lifecycle: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub phase: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fallback: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub seatbelt: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub lxc: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_container: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Filesystem {
    #[serde(default)]
    pub readonly_paths: Vec<PathBuf>,
    #[serde(default)]
    pub readwrite_paths: Vec<PathBuf>,
    #[serde(default)]
    pub denied_paths: Vec<PathBuf>,
}

/// Default network policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkDefaultPolicy {
    Allow,
    Block,
}

/// Network enforcement mechanism.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkEnforcement {
    Capabilities,
    Firewall,
    Both,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Network {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_policy: Option<NetworkDefaultPolicy>,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub blocked_hosts: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow_local_network: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enforcement_mode: Option<NetworkEnforcement>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<Proxy>,
}

/// Proxy configuration. Exactly one variant applies.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Proxy {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub builtin_test_server: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub localhost: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
}

/// Clipboard access level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ClipboardPolicy {
    None,
    Read,
    Write,
    All,
}

/// Cross-platform UI isolation policy. `disable` defaults to true upstream:
/// UI access is opt-in via `disable: false`.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ui {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub clipboard: Option<ClipboardPolicy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub disable: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub injection: Option<bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Process {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// `KEY=VALUE` entries.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,
    /// Milliseconds.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout: Option<u64>,
}

/// Experimental features (only honored with `--experimental`). Intentionally
/// permissive, matching upstream: other experimental backends' blocks
/// (`seatbelt`, `isolation_session`, `telemetry`, …) and in-progress fields
/// are tolerated, not rejected.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Experimental {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vz: Option<VzOptions>,
}

/// Backend options under `experimental.vz`. The whole object is optional and
/// every field has a default (design doc, Decision 1). Permissive to unknown
/// fields, following the upstream experimental-block convention.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct VzOptions {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub guest_image_path: Option<PathBuf>,
    pub cpu_count: u32,
    #[serde(rename = "memoryMB")]
    pub memory_mb: u64,
    pub boot_timeout_ms: u64,
}

pub const DEFAULT_CPU_COUNT: u32 = 2;
pub const DEFAULT_MEMORY_MB: u64 = 2048;
pub const DEFAULT_BOOT_TIMEOUT_MS: u64 = 30000;

impl Default for VzOptions {
    fn default() -> Self {
        Self {
            guest_image_path: None,
            cpu_count: DEFAULT_CPU_COUNT,
            memory_mb: DEFAULT_MEMORY_MB,
            boot_timeout_ms: DEFAULT_BOOT_TIMEOUT_MS,
        }
    }
}
