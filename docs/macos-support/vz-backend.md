# VZ Backend — Design (Phases 0–1)

Status: **Phase 0 complete** — decisions locked, schema surface defined and
implemented with validation in `src/backends/vz/vz_common`, aligned with the
upstream `microsoft/mxc` 0.8.0-dev config surface and verified against
upstream's own config fixtures. **Phase 1 in progress** — VZ FFI bindings,
VM-config translation, and the runner-thread lifecycle are implemented (see
"Phase 1" below); the boot milestone itself needs Apple Silicon hardware.

This document is the Phase 0 deliverable from the build plan: it records the
design decisions for the `vz` containment backend, which runs untrusted agent
code inside an Apple Virtualization.framework (VZ) Linux microVM on macOS,
providing a hardware hypervisor boundary instead of the process-scoped
Seatbelt (`sandbox_init()`) backend.

---

## Decision 1 — Backend name and schema surface

`"vz"` is registered as a new `containment` value in the dev schema
(**0.8.0-dev**, upstream `schemas/dev/mxc-config.schema.0.8.0-dev.json`).
Backend options live under `experimental.vz`, following the
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

Strictness follows upstream exactly: the **stable surface is closed**
(`additionalProperties: false` — unknown top-level, `ui`, `network`,
`filesystem`, `process`, and `proxy` fields are rejected at parse time), while
the **`experimental` block is intentionally permissive** — experimental
backends are in flux, so unknown fields under `experimental` (including
inside `experimental.vz`) are tolerated rather than rejected.

Bounds enforced at validation: `cpuCount >= 1`, `memoryMB >= 128`,
`bootTimeoutMs >= 1`.

## Decision 2 — Guest OS choice

**Minimal Linux** (Alpine or Buildroot-based), not a NanVix port. NanVix's
guest is WHP/KVM-targeted and i686/x86_64-focused; a stock Linux guest gets
virtio-fs, vsock, and ARM64 support for free and avoids a dependency on
NanVix's roadmap. Guest image pipeline is Phase 2.

## Decision 3 — Lifecycle model

**One-shot for v1**: spawn → exec → destroy, like seatbelt. The state-aware
lifecycle (provision → start → exec → stop → deprovision; `lifecycle` /
`phase` config blocks) is a fast-follow; VM boot cost (~1–3 s cold,
sub-second with a rootfs cache) makes it the eventual right answer, but
wiring a second backend into it is a separate workstream. The vz structs
already parse `lifecycle`/`phase` blocks (retained verbatim) so state-aware
policies are not rejected at the schema level.

## Decision 4 — v1 scope exclusions

Rejected at validation (mirroring how seatbelt's runner rejects
`blockedHosts`), with clear errors:

| Field | v1 behavior | Rationale |
|---|---|---|
| `ui.disable: false` | **rejected** | Upstream `ui.disable` defaults to true; an explicit false requests UI access, which the vz guest cannot have — no WindowServer access by construction. |
| `ui.injection: true` | **rejected** | Same: no host UI to inject into. |
| `ui.clipboard` ≠ `"none"` | **rejected** | No host clipboard bridge in v1. `"none"` is accepted (it is the vz reality). |
| `network.proxy` | **rejected** | No proxy support in v1 (upstream nests proxy under `network`). |
| `network.blockedHosts` (non-empty) | **rejected** | v1 ships allow-list only; blockedHosts arrive with the host-side resolver/proxy fast-follow. |

Note: `guiAccess` is a **seatbelt options field** (upstream
`definitions.Seatbelt`), not a `ui` field — the plan's "guiAccess
unsupported" intent maps onto the `ui.*` rejections above on the current
surface. A stale `ui.guiAccess` placement fails at parse time because `ui`
is closed.

Accepted with a **warning** (cross-backend portability, ignored at runtime):
`network.enforcementMode` (vz has exactly one mechanism — host-side
filtering), and other backends' option blocks (`seatbelt`, `lxc`,
`processContainer`) when present alongside `containment: "vz"`.

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
| `network.defaultPolicy: "block"` (and the absent-default) | no network device attached — kernel-level absence |
| `network.defaultPolicy: "allow"` | `VZNATNetworkDeviceAttachment` |
| `network.allowedHosts` | host-side filtering DNS resolver + TCP proxy on the NAT interface |
| `network.blockedHosts` | rejected in v1; fast-follow via the same resolver/proxy |
| `network.proxy` | rejected in v1 |
| `network.enforcementMode`, `network.allowLocalNetwork` | ignored with warning / passthrough (vz has one mechanism) |
| `ui.*` | UI access requests rejected (see Decision 4); `disable: true` / `clipboard: "none"` trivially satisfied |
| `process.commandLine` (string), `env` (`KEY=VALUE` list), `cwd`, `timeout` (ms) | passed through the vsock exec protocol; timeout enforced by host-side VM force-stop |

## Alignment with upstream microsoft/mxc

The Rust surface in `vz_common` is modeled on upstream
`schemas/dev/mxc-config.schema.0.8.0-dev.json` at commit
`692275b84eaa3f83cd8582dc774bc5f354f46ccf`:

- `Containment` uses upstream's wire names verbatim (`processcontainer`,
  `windows_sandbox`, `isolation_session`, …) and is **nullable** — upstream
  resolves the OS-native backend when absent. The vz validator requires an
  explicit `"vz"`; an experimental backend is never a default.
- `Process`, `Ui`, `Network`, `Proxy`, `Filesystem` match upstream field
  names and types exactly (`commandLine` is a string, `env` is a
  `KEY=VALUE` list, `timeout` is milliseconds, proxy is nested under
  `network`).
- Blocks vz does not consume (`lifecycle`, `phase`, `fallback`, `seatbelt`,
  `lxc`, `processContainer`) are parsed and retained verbatim so nothing is
  silently dropped.
- Conformance is pinned by a smoke suite
  (`tests/upstream_conformance.rs`) that parses every vendored upstream
  `tests/configs` fixture on the 0.8.0 surface — 61 configs covering
  bubblewrap, lxc, processcontainer, and wslc (see
  `tests/fixtures/upstream-configs/README.md` for provenance). This is the
  build plan's Phase 5 cross-backend portability contract, tested at the
  parse level from day one.

## Phase 1 — FFI bindings, VM spec, and the runner thread

### Binding strategy

`objc2` + `objc2-virtualization` (0.3.2, pinned — the VZ API surface changes
across macOS releases), with `block2` for completion handlers and `dispatch2`
for the VM's serial queue. No hand-rolled `msg_send!` needed so far: the
generated bindings cover every class Phase 1 uses.

### Crate layout

- `vz_common::vm_spec` — platform-neutral policy → `VmSpec` translation:
  CPU count, memory bytes, direct-kernel-boot paths (`vmlinux` +
  `initramfs.cpio.gz` under the guest image dir, overridable via
  `experimental.vz.guestImagePath`), kernel cmdline (`console=hvc0 panic=1`),
  deterministic virtio-fs share tags (`mxcfs0`, `mxcfs1`, … — readonly shares
  first), network mode, and the fixed guest vsock agent port (28024).
  Only `network.defaultPolicy: "allow"` yields a NAT device; block/absent
  fail closed with **no** device.
- `vz_darwin::runner` — platform-neutral VM lifecycle: a dedicated thread
  owns the driver (created, driven, and dropped on that thread, because
  `VZVirtualMachine` is queue-affine and not `Send`); the `VmHandle` talks to
  it over channels. One-shot lifecycle (Decision 3): Created → Running →
  Stopped/Failed; a timed-out boot is force-stopped; dropping the handle
  stops a running VM and joins the thread. Tested against a fake driver.
- `vz_darwin::vz` (macOS-only) — `VzDriver`: builds the
  `VZVirtualMachineConfiguration` from the `VmSpec` (`VZLinuxBootLoader`
  direct kernel boot, one `VZVirtioFileSystemDeviceConfiguration` +
  `VZSingleDirectoryShare` per share, `VZNATNetworkDeviceAttachment` when
  allowed, `VZVirtioSocketDeviceConfiguration` for the Phase 3 exec channel),
  validates it (`validateWithError`), and drives start/stop from a private
  serial dispatch queue with completion handlers reporting over a channel —
  which is also how the boot deadline is enforced.

### Entitlements (the #1 contributor stumbling block)

`com.apple.security.virtualization` is mandatory; an unsigned binary is
SIGKILLed on its first VZ API call with no error message.
`scripts/vz.entitlements` holds the plist and `./build-mac.sh` ad-hoc signs
every VZ-touching artifact after building — rebuild via the script, not bare
`cargo`, because rebuilds strip the signature.

### Verified where

Everything platform-neutral (vm_spec translation, runner lifecycle) is unit
tested and runs on any host. The macOS driver compiles cleanly for
`aarch64-apple-darwin` (`cargo check`/`clippy`); the Phase 1 boot milestone —
boot Alpine, run `echo hi`, tear down — requires Apple Silicon hardware and
is the first thing to run once CI has macOS ARM64 runners (Phase 6).

## Schema artifacts

- `schemas/mxc-policy-0.8.0-dev.vz.schema.json` — JSON Schema diff for the
  `vz` containment value and the `experimental.vz` options object.
- `src/backends/vz/vz_common` — Rust source of truth: serde policy structs,
  option defaults, and the validation rules above, with the test suites in
  `src/backends/vz/vz_common/tests/`.
