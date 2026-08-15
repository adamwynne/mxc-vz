//! Serde types for the 0.7.0-dev policy schema surface used by the vz backend.
//!
//! JSON field names are camelCase, matching the existing policy schema.
//! `experimental.vz` rejects unknown fields so typos fail loudly instead of
//! silently falling back to defaults.

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Registered containment backends in the 0.7.0-dev schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Containment {
    Seatbelt,
    Microvm,
    WindowsSandbox,
    Vz,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Policy {
    pub containment: Containment,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filesystem: Option<Filesystem>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<Network>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ui: Option<Ui>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<Process>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub proxy: Option<Proxy>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub experimental: Option<Experimental>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Filesystem {
    #[serde(default)]
    pub readonly_paths: Vec<PathBuf>,
    #[serde(default)]
    pub readwrite_paths: Vec<PathBuf>,
    #[serde(default)]
    pub denied_paths: Vec<PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum NetworkDefaultPolicy {
    Allow,
    Block,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Network {
    pub default_policy: NetworkDefaultPolicy,
    #[serde(default)]
    pub allowed_hosts: Vec<String>,
    #[serde(default)]
    pub blocked_hosts: Vec<String>,
}

/// `ui.*` policy surface. Only `guiAccess` has vz-specific validation; any
/// other field is retained in `extra` so validation can warn that it is
/// accepted-and-ignored on this backend.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Ui {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gui_access: Option<bool>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, serde_json::Value>,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Process {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub command_line: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub env: Option<BTreeMap<String, String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Proxy {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Experimental {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vz: Option<VzOptions>,
}

/// Backend options under `experimental.vz`. The whole object is optional and
/// every field has a default (design doc, Decision 1).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields, default)]
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
