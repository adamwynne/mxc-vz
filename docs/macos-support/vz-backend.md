# VZ Backend — Design (Phase 0)

Status: **Phase 0 complete** — decisions locked, schema surface defined and
implemented with validation in `src/backends/vz/vz_common`.

This document is the Phase 0 deliverable from the build plan: it records the
design decisions for the `vz` containment backend, which runs untrusted agent
code inside an Apple Virtualization.framework (VZ) Linux microVM on macOS,
providing a hardware hypervisor boundary instead of the process-scoped
Seatbelt (`sandbox_init()`) backend.

---

## Decision 1 — Backend name and schema surface

`"vz"` is registered as a new `containment` value in the dev schema
(**0.7.0-dev**). Backend options live under `experimental.vz`, following the
`experimental.seatbelt` precedent:

- The **experimental flag is required** to use `containment: "vz"`.
  Validation fails with a clear error if the flag is not set.
- The **options object is optional**; every field has a default.

```jsonc
{
  "containment": "vz",
  "experimental": {
    "vz": {
      "guestImagePath": "/opt/mxc/vz-guest",  // override; default: bundled image
      "cpuCount": 2,                           // default 2
      "memoryMB": 2048,                        // default 2048
      "bootTimeoutMs": 30000                   // default 30000
    }
  }
}
```

Unknown fields inside `experimental.vz` are rejected at parse time so that
typos (`memoryMb`, `cpus`) fail loudly rather than silently falling back to
defaults.

Bounds enforced at validation: `cpuCount >= 1`, `memoryMB >= 128`,
`bootTimeoutMs >= 1`.

## Decision 2 — Guest OS choice

**Minimal Linux** (Alpine or Buildroot-based), not a NanVix port. NanVix's
guest is WHP/KVM-targeted and i686/x86_64-focused; a stock Linux guest gets
virtio-fs, vsock, and ARM64 support for free and avoids a dependency on
NanVix's roadmap. Guest image pipeline is Phase 2.

## Decision 3 — Lifecycle model

**One-shot for v1**: spawn → exec → destroy, like seatbelt. The state-aware
lifecycle (provision → start → exec → stop → deprovision) is a fast-follow;
VM boot cost (~1–3 s cold, sub-second with a rootfs cache) makes it the
eventual right answer, but the state-aware path currently has a single
implementation (`isolation_session`, Windows) and wiring a second backend
into it is a separate workstream.

## Decision 4 — v1 scope exclusions

Rejected at validation (mirroring how `blockedHosts` is rejected on
seatbelt), with clear errors:

| Field | v1 behavior | Rationale |
|---|---|---|
| `ui.guiAccess: true` | **rejected** | No GUI. The guest has no WindowServer access by construction; asking for GUI access is a contract we cannot honor. |
| `proxy` | **rejected** | No proxy support in v1. |
| `network.blockedHosts` | **rejected** | v1 ships allow-list only; blockedHosts arrive with the host-side resolver/proxy fast-follow. |

Other `ui.*` fields are trivially satisfied (guest has no WindowServer) and
are **accepted and ignored** with a warning/debug log.

Runtime scope (not schema-visible): Apple Silicon only, no nested
virtualization. Intel VZ works but is EOL hardware; add later if demand
exists.

## Decision 5 — Filesystem semantics

**virtio-fs live shares** (`VZVirtioFileSystemDeviceConfiguration`), not
NanVix-style staging copy-in/copy-out:

- Preserves MXC's readonly/readwrite path contract directly — one share per
  path, per-share read-only flag, guest agent mounts at the identical path.
- Avoids copy-back-on-clean-exit-only semantics.
- Handles large workspaces without duplication.

### deniedPaths

Nothing is shared by default, so `deniedPaths` entries are **redundant** on
vz. They are still **accepted** for cross-backend config portability (the
same policy JSON should run under seatbelt and vz with only `containment`
changed), and each redundant entry produces a **warning**, not an error.

**Decision (was left open in the plan — "split shares or reject"): reject.**
A `deniedPaths` entry that is equal to or nested inside a `readonlyPaths` /
`readwritePaths` entry is a **validation error**. Splitting the share into
sibling sub-shares would silently change mount topology and inode/rename
semantics inside the share; an explicit error keeps the policy author in
control. Path containment is decided lexically, component-wise
(`/workspace/secrets` is inside `/workspace`; `/workspace-2` is not).

## Baseline-path semantics vs. seatbelt (documentation headline)

The seatbelt backend always emits read-only allows for `/usr/lib`, `/System`,
etc. so the dynamic linker works. The VZ equivalent is: **none** — the guest
rootfs ships its own userland; no host system paths are needed or exposed.

Consequently, binaries run in the sandbox are **Linux ARM64 binaries, not
macOS binaries**. Shell, python, node, git all work from the guest rootfs;
running a host macOS binary is out of scope (the same trade Docker-style
sandboxes make). Choose seatbelt for host-toolchain workloads, vz for
isolation strength.

## Policy → VM-config mapping (summary; implementation is Phase 4)

| Policy field | VZ mechanism |
|---|---|
| `filesystem.readonlyPaths` | virtio-fs share per path, read-only flag set |
| `filesystem.readwritePaths` | virtio-fs share, read-write |
| `filesystem.deniedPaths` | redundant (warning); error if inside/equal to a share |
| `network.defaultPolicy: "block"` | no network device attached — kernel-level absence |
| `network.defaultPolicy: "allow"` | `VZNATNetworkDeviceAttachment` |
| `network.allowedHosts` | host-side filtering DNS resolver + TCP proxy on the NAT interface |
| `network.blockedHosts` | rejected in v1; fast-follow via the same resolver/proxy |
| `ui.*` | accepted and ignored with a warning (`guiAccess: true` rejected) |
| `process.commandLine/env/timeout` | passed through the vsock exec protocol; timeout enforced by host-side VM force-stop |

## Schema artifacts

- `schemas/mxc-policy-0.7.0-dev.vz.schema.json` — JSON Schema diff for the
  `vz` containment value and the `experimental.vz` options object.
- `src/backends/vz/vz_common` — Rust source of truth: serde policy structs,
  option defaults, and the validation rules above, with the test suite in
  `src/backends/vz/vz_common/tests/`.
