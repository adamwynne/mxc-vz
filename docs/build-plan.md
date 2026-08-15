<!-- Imported from the Google Drive "experiments" folder ("MXC macOS VZ Backend — Build Plan"), 2026-08-15. -->

# MXC macOS Virtualization.framework Backend — Build Plan

**Goal:** Add a vz containment backend to microsoft/mxc that runs untrusted agent code inside an Apple Virtualization.framework (VZ) Linux microVM on macOS, providing a hardware hypervisor boundary instead of the current process-scoped Seatbelt (sandbox_init()) backend.

**Reference implementations in-repo:** seatbelt backend (mxc_darwin, seatbelt_common) for macOS plumbing and policy translation; NanVix microvm backend for the microVM staging/copy-back and guest-agent patterns; windows_sandbox daemon/guest split for the host↔guest IPC protocol.

## Phase 0 — Design and scoping (1–2 weeks)

**Decisions to lock down before writing code:**

1. **Backend name and schema surface.** Register "vz" as a new containment value in the dev schema (0.7.0-dev), with backend options under experimental.vz. Follow the experimental.seatbelt precedent: experimental flag required, options optional with defaults.
2. **Guest OS choice.** Minimal Linux (Alpine or Buildroot-based) vs. porting NanVix to ARM64/VZ. Recommendation: minimal Linux. NanVix's guest is WHP/KVM-targeted and i686/x86_64-focused; a stock Linux guest gets virtio-fs, vsock, and ARM64 support for free and avoids taking a dependency on NanVix's roadmap.
3. **Lifecycle model.** One-shot (spawn → exec → destroy, like seatbelt) for v1, with the state-aware lifecycle (provision → start → exec → stop → deprovision) as a fast-follow. VM boot cost (~1–3s cold, sub-second with a rootfs cache) makes state-aware the eventual right answer, but it currently has only one implementation (isolation_session, Windows), so wiring a second backend into it is a separate workstream.
4. **Scope exclusions for v1:** no GUI (guiAccess unsupported — rejected at validation, like blockedHosts on seatbelt), no proxy, no nested virtualization, Apple Silicon only (Intel VZ works but is EOL hardware; add later if needed).
5. **Filesystem semantics.** virtio-fs live shares (VZVirtioFileSystemDeviceConfiguration) vs. NanVix-style staging copy-in/copy-out. Recommendation: virtio-fs. It preserves MXC's readonly/readwrite path contract directly (per-share read-only flag), avoids copy-back-on-clean-exit-only semantics, and handles large workspaces without duplication. deniedPaths are enforced by simply not sharing them — stronger than seatbelt's deny-last SBPL rules.

**Deliverable:** design doc in docs/macos-support/vz-backend.md (mirroring seatbelt-backend.md structure), reviewed schema diff.

## Phase 1 — VZ FFI bindings and minimal VM boot (2–3 weeks)

The repo has no Objective-C bridging today; mxc_darwin calls sandbox_init via plain C FFI. VZ is an Objective-C framework, so this is new ground.

1. **Binding strategy.** Use objc2 + objc2-virtualization crates (maintained, cover VZVirtualMachine, VZLinuxBootLoader, VZVirtioSocketDevice, VZVirtioFileSystemDeviceConfiguration, VZNATNetworkDeviceAttachment). Fallback: hand-rolled objc2::msg_send! wrappers for just the ~15 classes needed. Pin versions; VZ API surface changes across macOS releases.
2. **New crates:** src/backends/vz/vz_darwin (host runner), src/backends/vz/vz_common (config structs, policy → VM-config translation, shared with schema validation), src/backends/vz/vz_guest_agent (cross-compiled to aarch64-unknown-linux-musl, statically linked).
3. **Runloop integration.** VZVirtualMachine must be driven from a dispatch queue / runloop thread; MXC's runner is synchronous Rust. Spawn a dedicated thread owning the VM object, communicate via channels. This is the fiddliest part of the FFI work — get it right early with a spike that boots a VM headless and shuts it down cleanly.
4. **Milestone:** mxc-exec-mac --experimental with containment: "vz" boots a stock Alpine kernel+initramfs to a shell, runs echo hi from vz, exits, VM torn down. No policy enforcement yet.
5. **Entitlements.** com.apple.security.virtualization is mandatory. Dev builds: ad-hoc sign with entitlements plist in build-mac.sh (codesign --entitlements vz.entitlements -s - mxc-exec-mac). Unsigned binaries get killed on VZ API use — document this loudly, it will be the #1 contributor stumbling block.

## Phase 2 — Guest image pipeline (2–3 weeks, parallelizable with Phase 3)

1. **Image contents:** ARM64 Linux kernel (virtio-fs, vsock, virtio-net, virtio-blk enabled; no modules — monolithic config for boot speed), minimal initramfs or squashfs rootfs with busybox + the guest agent as PID 1 (or launched by a 10-line init). Target < 50 MB total.
2. **Build:** Buildroot or Alpine mkimage in a containerized, reproducible pipeline (scripts/build-vz-guest.sh). Version the image with a content hash; the host runner validates the hash at boot.
3. **Distribution:** ship in sdk/bin/arm64/vz-guest/ alongside mxc-exec-mac, gated behind ./build-mac.sh --with-vz (mirrors build.bat --with-microvm). npm package size matters — consider a postinstall download with hash pinning as an alternative.
4. **Boot speed work:** measure cold boot; target < 1.5s to agent-ready. Options if too slow: strip kernel config, uncompressed kernel, direct kernel boot with minimal cmdline (VZLinuxBootLoader supports this natively — no bootloader stage needed).

## Phase 3 — Host↔guest exec protocol (2 weeks)

Model on the windows_sandbox split (daemon generates config → launches → rendezvous → bridges EXEC requests), but simpler because there's no pre-existing daemon requirement for one-shot mode.

1. **Transport:** vsock via VZVirtioSocketDevice. Host connects to a fixed guest port after boot; guest agent listens from init. No rendezvous-file polling needed (advantage over Windows Sandbox's approach) — vsock connect-with-retry is the readiness signal.
2. **Protocol:** newline-delimited JSON, mirroring the existing EXEC {json}\n convention: request carries command line, env, cwd (mapped to guest mount points), timeout; multiplexed channels (or length-prefixed frames on one connection) for stdin/stdout/stderr; final message carries exit code. Reuse mxc_pty semantics for the PTY case — allocate the PTY inside the guest, stream raw bytes.
3. **Timeout and teardown:** host enforces process.timeout by force-stopping the VM (VZVirtualMachine stop) — a hard guarantee Seatbelt cannot make against a fork bomb that outruns the process-tree kill.
4. **Milestone:** SDK spawnSandbox('long-running-cmd', policy, { experimental: true, containment: 'vz' }) streams output and honors timeout, PTY and non-PTY paths both working.

## Phase 4 — Policy translation (2 weeks)

Map the existing JSON policy schema to VM configuration. This is the mechanical part — the triple (readonly/readwrite/denied) already maps to five different backend mechanisms in-repo; virtio-fs shares are the sixth.

| Policy field | VZ mechanism |
| --- | --- |
| filesystem.readonlyPaths | virtio-fs share per path, read-only flag set; guest agent mounts at identical path |
| filesystem.readwritePaths | virtio-fs share, read-write |
| filesystem.deniedPaths | validated as redundant (nothing is shared by default) but accepted for cross-backend config portability; error if a deniedPath is inside a shared path (split shares or reject — decide in design doc) |
| network.defaultPolicy: "block" | no network device attached — kernel-level absence, not filtering |
| network.defaultPolicy: "allow" | VZNATNetworkDeviceAttachment |
| network.allowedHosts / blockedHosts | host-side filtering DNS resolver + TCP proxy bound to the NAT interface; guest resolv.conf points at it. This closes seatbelt's two documented gaps (no blockedHosts, best-effort connect-time filtering) with real per-host allow AND block. v1 can ship allow-list only; blockedHosts as fast-follow |
| ui.* | trivially satisfied — guest has no WindowServer access by construction; accept and ignore with a debug log |
| process.commandLine, env, timeout | passed through exec protocol |

**Baseline paths:** the seatbelt backend always emits read-only allows for /usr/lib, /System, etc. so the dynamic linker works. VZ equivalent: the guest rootfs ships its own userland — no host system paths needed or exposed. Document this difference: binaries run in the sandbox are *Linux ARM64* binaries, not macOS binaries. This is the headline semantic change vs. seatbelt and must be front-and-center in docs (workloads: shell, python, node, git — all fine from the guest rootfs; running a host macOS binary is out of scope, same trade Docker sbx makes).

## Phase 5 — SDK, schema, validation (1–2 weeks)

1. **Schema:** add vz to containment enum in 0.7.0-dev; add experimental.vz object: guestImagePath (override), cpuCount, memoryMB (defaults: 2 / 2048), bootTimeoutMs.
2. **SDK:** getPlatformSupport() reports vz availability (macOS 13+ check, entitlement presence probe); spawnSandbox routes containment: 'vz' to mxc-exec-mac; validation rejects proxy, guiAccess, and (v1) blockedHosts with clear errors, mirroring existing seatbelt validation style.
3. **Cross-backend config portability test:** the same policy JSON should run under seatbelt and vz with only the containment field changed (modulo documented unsupported fields).

## Phase 6 — Tests, CI, signing (2 weeks)

1. **Unit:** policy → VZ-config translation (vz_common), protocol framing, share-path validation edge cases (overlaps, symlinks, nonexistent paths).
2. **E2E** (extend wxc_e2e_tests pattern): boot, exec, exit-code propagation, timeout kill, stdout/stderr ordering, PTY resize, filesystem isolation probes (write to unshared path fails; write to readonly share fails; denied-inside-shared rejected at validation), network probes (no device = connect fails; NAT = succeeds; allow-list = only listed host resolves/connects).
3. **Escape-adjacent probes** (not a security boundary claim, per repo policy, but regression tripwires): guest cannot read host paths outside shares via virtio-fs traversal tricks; vsock port scan from guest reaches only the agent port.
4. **CI:** needs macOS ARM64 runners with virtualization support (GitHub Actions macos-14+ ARM runners support nested VZ). Signing/notarization with the virtualization entitlement added to the existing ci-macos / codesign-notarize pipeline steps.

## Phase 7 — Fast-follows (post-v1)

1. **State-aware lifecycle** — provision (unpack image, create VM config) / start (boot, agent handshake) / exec (n times) / stop / deprovision. Biggest payoff for agentic loops; amortizes boot cost to zero per exec.
2. **Warm-start snapshots** — NanVix uses a warm memory snapshot on WHP; VZ has no public save/restore for Linux VMs on all OS versions (macOS 14+ added VZVirtualMachine saveMachineStateTo for some configs). Investigate; fallback is a pool of pre-booted VMs.
3. **blockedHosts** via the host-side resolver/proxy.
4. **Rosetta 2 in-VM** (VZLinuxRosettaDirectoryShare) to run x86_64 Linux binaries on Apple Silicon guests.
5. **Intel host support** if demand exists.

## Risk register

| Risk | Likelihood | Mitigation |
| --- | --- | --- |
| objc2-virtualization API gaps or churn | Medium | Pin versions; hand-written msg_send fallback for missing classes |
| VM boot latency unacceptable for one-shot UX | Medium | Direct kernel boot, stripped config; accelerate state-aware lifecycle |
| Entitlement/signing friction for contributors and npm consumers | High | Ad-hoc signing in build script; prominent docs; ship signed binaries in npm package |
| Guest image bloats npm package | Medium | Postinstall download with content-hash pinning |
| virtio-fs performance on large repos (node_modules etc.) | Medium | Benchmark early vs. staging-copy fallback; cache tuning (VZ virtio-fs supports host caching modes) |
| Semantic surprise: Linux binaries not macOS binaries | Certain | Documentation, validation warning on first run, explicit positioning vs. seatbelt (choose seatbelt for host-toolchain workloads, vz for isolation) |

## Effort summary

Roughly 12–16 engineer-weeks for v1 (Phases 0–6), with Phases 2 and 3 parallelizable across two people. The three genuinely novel pieces are the VZ FFI/runloop integration, the guest image pipeline, and the vsock exec protocol; policy translation and SDK wiring are pattern-following against five existing backends.
