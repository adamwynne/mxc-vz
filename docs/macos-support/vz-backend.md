# VZ Backend — Design

Status: **Phases 0–5 implemented.** Schema + validation (`vz_common`),
VZ FFI bindings and the VM-config/runner lifecycle (`vz_darwin`), the
host↔guest exec protocol and one-shot session (`vz_protocol`,
`vz_guest_agent`), the guest-image pipeline with supply-chain pinning, the
`vz-exec` SDK executor, and the full `allowedHosts` egress datapath
(`vz_net`: dual-stack TCP/UDP/ICMP NAT + DNS proxy, with the TM-14/TM-15
hardening below) are all built and tested — the platform-neutral parts on
Linux (incl. QEMU end-to-end), the macOS driver by build/clippy/unit tests.
The one thing CI cannot cover is a real VZ boot: GitHub's macOS runners are
themselves VMs without nested virtualization (see "Verified where"), so the
boot milestone, the metal-only isolation probes, and the real vsock +
file-handle-attachment paths await Apple Silicon hardware.

This document records the design decisions for the `vz` containment
backend, which runs untrusted agent code inside an Apple
Virtualization.framework (VZ) Linux microVM on macOS, providing a hardware
hypervisor boundary instead of the process-scoped Seatbelt
(`sandbox_init()`) backend.

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

## Policy → VM-config mapping (implemented)

| Policy field | VZ mechanism |
|---|---|
| `filesystem.readonlyPaths` | virtio-fs share per path, read-only flag set |
| `filesystem.readwritePaths` | virtio-fs share, read-write |
| `filesystem.deniedPaths` | redundant (warning); error if inside/equal to a share |
| `network.defaultPolicy: "block"` (and the absent-default) | no network device attached — kernel-level absence |
| `network.defaultPolicy: "allow"` | `VZNATNetworkDeviceAttachment` |
| `network.allowedHosts` (under `defaultPolicy: "block"`) | `NetworkMode::FilteredNat`: L3/L4 egress gate on the host side of a file-handle network attachment (see below) |
| `network.allowedHosts` (under `defaultPolicy: "allow"`) | no-op with warning — the allow default accepts everything anyway (upstream lxc parity) |
| `network.blockedHosts` | rejected in v1; fast-follow via the same egress gate |
| `network.proxy` | rejected in v1 |
| `network.enforcementMode`, `network.allowLocalNetwork` | ignored with warning / passthrough (vz has one mechanism) |
| `ui.*` | UI access requests rejected (see Decision 4); `disable: true` / `clipboard: "none"` trivially satisfied |
| `process.commandLine` (string), `env` (`KEY=VALUE` list), `cwd`, `timeout` (ms) | passed through the vsock exec protocol; timeout enforced by host-side VM force-stop |

### `allowedHosts`: the TM-01 egress gate

TM-01 rules out DNS-only enforcement: a hostile guest ignores
`resolv.conf`, connects to hard-coded IPs, or runs its own DoH. The design
is therefore enforcement **at L3/L4 on the host side of the guest's
network attachment**, with DNS demoted to set-population:

- Entry semantics are upstream-lxc-compatible: IP literals, CIDR blocks
  (mask applied, family-split), or hostnames (exact match, no subdomain
  grant). Invalid entries are skipped with a warning — dropping an allow
  entry only restricts. IPv4-mapped IPv6 is normalized to IPv4 on both the
  pattern and the destination side.
- `vz_net::filter::EgressFilter` is the allowed-IP set: static IPs/CIDRs
  from the policy, plus a dynamic set populated **only** by DNS answers for
  allow-listed names, with TTLs clamped to [1 s, 300 s] so entries expire
  and re-resolve. `allows_ip(destination, now)` is the enforcement decision.
- The datapath (`vz_net::gate`): the guest attaches through a `SOCK_DGRAM`
  socketpair (`VZFileHandleNetworkDeviceAttachment`), so every frame
  crosses the host userspace gate — a smoltcp stack (pinned =0.12.0) that
  is the guest's gateway (10.0.2.2) and DNS server (10.0.2.3), with the
  guest at 10.0.2.15/24 (`mxc_net=static` in the kernel cmdline; same
  topology as the QEMU slirp tests on purpose).
  - **TCP NAT, tun2proxy-style:** each frame is peeked for a SYN before
    smoltcp processes it. Allowed destination → a listener is created for
    exactly that flow (`any_ip` + a gate self-route make smoltcp accept
    traffic to arbitrary IPs) and a real host socket connects to the
    destination in parallel; bytes relay between the two. Denied
    destination → a checksummed RST is synthesized and the frame is
    dropped before the stack ever sees it.
  - **DNS proxy** (`vz_net::dns`): answers A/AAAA queries for allow-listed
    names only (host resolver, fixed 60 s answer TTL feeding
    `observe_dns` *before* the guest hears the answer); other names get
    RCODE REFUSED. Compressed question names and non-query packets are
    dropped.
  - **UDP relay:** datagrams to allowed destinations get per-flow NAT
    state (a connected host socket per guest flow) with a 30 s idle
    timeout; an expired flow's next datagram simply re-NATs. The
    allowed-IP set is protocol-agnostic — a DNS-observed IP admits UDP
    the same as TCP. Denied datagrams are dropped silently (standard NAT
    behavior; TCP gets an RST because it can).
  - **Host-local egress guard (TM-15).** A terminating NAT re-originates
    the guest's connection from a host socket, so an over-broad
    `allowedHosts` entry could become SSRF against the host. The gate
    enforces a policy-independent invariant (`GateConfig::is_relayable`):
    it never relays to loopback, link-local (incl. the
    `169.254.169.254` cloud-metadata endpoint), unspecified, multicast,
    broadcast, or its own gateway/DNS/guest addresses — a destination must
    pass **both** the allowlist and this guard. RFC1918/ULA are *not*
    blocked (legitimate egress in real deployments), but an explicit
    metadata denylist refuses the instance-metadata endpoints
    unconditionally — including AWS's IPv6 `fd00:ec2::254`, a ULA the
    host-local ranges don't catch. The host's own interface addresses
    (enumerated at gate start via `getifaddrs`) are refused too, so an
    allow-listed CIDR covering the host cannot reach its services. DNS
    answers are filtered through the same guard at population time, so a
    poisoned allow-listed name cannot smuggle a host-local IP into the
    allowed set.
  - **Bounded NAT state (TM-14).** Concurrent TCP/UDP/ICMP flows and
    in-flight DNS resolutions are capped (`GateConfig`, default
    512/512/128/64); at a cap the new flow is dropped (the guest is
    throttled, the filter never bypassed), so a hostile guest cannot
    exhaust host threads, FDs, or memory.
  - The gate lives exactly as long as the `VzDriver`: dropping the driver
    stops the event loop and severs the guest's only path off the VM.
  - Tested end-to-end without a Mac: a second in-process smoltcp stack
    plays the guest over an in-memory frame pipe (ARP, DNS, handshakes,
    RSTs, and relayed bytes all cross it), with a real `TcpListener` as
    the far side of the NAT — plus the QEMU dgram-netdev CI job, where the
    real Alpine guest probes the gate and asserts its own egress.

#### Protocol support matrix

The gate is a *terminating* NAT, not a packet filter: each protocol is an
explicit implementation, and anything unimplemented fails closed.

| Protocol | Behavior when allowed | Behavior when denied |
|---|---|---|
| TCP | per-flow relay to a real host socket | synthesized RST (prompt failure) |
| UDP | per-flow NAT with 30 s idle expiry | dropped silently |
| DNS to the gate (10.0.2.3:53) | proxied for allow-listed names; answers populate the filter | RCODE REFUSED |
| ICMP echo (ping) | relayed via a host ping socket; guest echo id restored on replies | dropped silently |
| other ICMP types | dropped | dropped |
| IPv6 (TCP/UDP/gated DNS) | full dual-stack datapath: ULA topology `fd00:6d78:63::/64` mirroring v4 (guest ::15, gateway ::2, DNS ::3); v6 SYNs get per-flow listeners, denied ones a v6 RST; AAAA answers populate the filter | RST (TCP) / silent drop (UDP) / REFUSED (DNS) |
| ICMPv6 echo | relayed via ICMPv6 ping sockets (same privilege ladder; the kernel computes outgoing pseudo-header checksums, the gate computes them on synthesized replies) | dropped silently |
| ICMPv6 NDP etc. | never intercepted — handled by the gate's stack | — |

The ICMP relay acquires its host socket down a privilege ladder
(`vz_net::ping`): the unprivileged `SOCK_DGRAM`/`IPPROTO_ICMP` ping
socket first (macOS out of the box; Linux when
`net.ipv4.ping_group_range` covers the process), raw ICMP second (root),
and if neither is available the gate drops pings — fail closed, never an
error. Platform quirks are normalized: Linux ping sockets rewrite the
echo id (the gate restores the guest's) and strip the IP header on
receive; macOS keeps the header.

#### Enforcement compared with upstream backends

| Backend | Mechanism | Protocol scope | Known limitations |
|---|---|---|---|
| **vz (this)** | terminating userspace NAT; every frame crosses the filter | dual-stack TCP + UDP + ICMP echo + gated DNS | protocol-by-protocol support (anything unlisted fails closed) |
| lxc | host iptables/ip6tables | all protocols and ports | only under `enforcementMode: firewall\|both` (default `capabilities` mode parses but never enforces); hostnames resolved **once at rule install** — IP rotation breaks connectivity |
| WSLc | none | — | per-host filtering **rejected at config-parse time** (containers lack CAP_NET_ADMIN; no VM-level host enforcement) |
| hyperlight | unikraft allowlist | library-defined | list resolved at preflight (static, like lxc); allowedHosts and blockedHosts mutually exclusive |
| appcontainer / windows_sandbox | Windows Firewall rules | all protocols | gated on enforcement mode, like lxc |
| seatbelt | sandbox profile | — | documented gaps: no blockedHosts; best-effort connect-time filtering |

The vz trade: narrower protocol scope than the packet-filter backends, in
exchange for two properties none of them have — **per-query DNS
re-resolution** with TTL-bounded grants (CDN IP rotation keeps working),
and **structural interception** (enforcement is the wire itself, not a
rule set behind a mode flag).

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
tested and runs on any host. On macOS CI runners the driver builds, passes
unit tests, signs, and clippy-checks cleanly.

**Empirical finding (2026-08-15), contradicting the build plan's Phase 6
assumption:** GitHub-hosted `macos-14` and `macos-15` ARM64 runners do
**not** support Virtualization.framework — `VZVirtualMachine.isSupported`
returns false (the runners are themselves VMs, `kern.hv_vmm_present: 1`,
without nested virtualization). CI's boot-smoke step detects this and
reports it as a soft skip. Consequence: the Phase 1 boot milestone — boot
Alpine, hold, tear down (`examples/boot_smoke.rs` +
`scripts/fetch-alpine-guest.sh`) — runs in CI only up to the isSupported
probe; actually booting requires real Apple Silicon hardware (a developer
Mac, or a bare-metal CI provider such as a self-hosted runner). Phase 6 CI
planning must assume self-hosted/bare-metal macOS runners for e2e boot
coverage.

## Phase 3 — Host↔guest exec protocol

Implemented in `vz_protocol` (shared) and `vz_guest_agent` (guest side),
platform-neutral and fully tested on Linux.

**Framing (threat model TM-06 supersedes the plan's newline-JSON):** all
guest→host bytes are adversarial, so the transport is length-prefixed frames
— `[u32 LE payload_len][u8 channel][payload]` — with a hard 16 MiB payload
cap (matching upstream wslc/windows_sandbox framing caps) validated against
the declared length BEFORE any allocation, explicit
unknown-channel rejection, and truncation distinguished from clean close.
Channels: control (JSON), stdin, stdout, stderr. Control messages
(camelCase, tagged): `exec {commandLine, env[], cwd?, timeoutMs?}`,
`exit {code}`, `error {message}`. An empty stdin frame is the stdin-EOF
signal. Malformed input of any kind is an error, never a panic (pinned by
adversarial-bytes tests).

**Guest agent** (`vz_guest_agent`, cross-compiled to
`aarch64-unknown-linux-musl` per the plan): reads one exec request, runs it
via `/bin/sh -c` with env/cwd applied, pumps stdio as frames, reports
`exit` (128+signal for signal deaths) or `error` (e.g. spawn failure). The
binary listens on `vsock:<port>` in the real guest (AF_VSOCK via libc), or
`unix:`/`tcp:` for development.

**Host client** (`vz_protocol::client::exec_collect`): sends the request and
optional stdin, collects stdout/stderr until exit.
`exec_collect_with_timeout` bounds it by a wall-clock deadline: the exec
runs on a worker thread while the caller waits, and a missed deadline
invokes a `force_stop` hook and reports `TimedOut` (partial output is
discarded — a timed-out exec has no trustworthy result). PTY mode is a
fast-follow per the plan.

**Session orchestrator and vsock glue** (the mac-side wiring joining the VM
lifecycle to the exec protocol):

- `vz_common::exec_plan::build_exec_request` — the process half of policy
  translation: `process.commandLine`/`env`/`cwd` become the guest exec
  request; a policy without a command line cannot be a one-shot session.
- `vz_darwin::runner` grew the agent-stream plumbing: `VmDriver::
  open_agent_stream(port, timeout)` returns an `AgentStream` (boxed
  `Read`/`Write` halves — plain-`Send` handles, so the queue-affine VZ
  objects stay on the VM thread), and `VmHandle::connect` routes it through
  the VM thread like boot/stop. Connecting is only valid in the Running
  state.
- `vz_darwin::session::run_one_shot(policy, experimental, guest_image_dir,
  factory)` — the platform-neutral one-shot flow: validate → build
  VmSpec + ExecRequest (before any VM resource exists) → spawn → boot →
  connect → exec with `process.timeout` enforced by VM force-stop (never
  trusted to the guest) → outcome (`Completed {exit code, stdout, stderr}`
  or `TimedOut`) → teardown by drop on every exit path.
- `VzDriver::open_agent_stream` (macOS) — the vsock glue proper: on the
  VM's dispatch queue, `socketDevices()[0]` cast to `VZVirtioSocketDevice`,
  `connectToPort:completionHandler:`; the delivered
  `VZVirtioSocketConnection` owns its fd (closed when the object is
  released), so the handler `dup`s it and the dupe becomes a `UnixStream`.
  Connect-with-retry until the boot-timeout budget is the boot-readiness
  signal: the guest refuses until its agent listens, so refusals before the
  deadline mean "still booting".

Verified by tests/session.rs: the orchestrator drives a fake driver whose
agent stream is one half of a socketpair with the REAL guest agent serving
the other — covering the happy path, timeout-force-stop, validation
short-circuit, connect-before-boot rejection, and boot-failure surfacing.
Only the hypervisor itself is faked.

**Verified how:** the end-to-end suite runs the REAL agent against the REAL
client over a Unix socketpair on Linux — echo/exit-code/stderr separation,
stdin feeding, env and cwd, spawn-failure errors, 3 MiB multi-frame output,
and signal-death mapping. The same code paths run over vsock in the VM.

**Guest supply chain (TM-08):** the Alpine artifacts are pinned by sha256 in
`scripts/guest-pins.json` (NanVix-binaries pattern) and verified on every
fetch, so point releases cannot change the image silently. The scheduled
"guest image bump" workflow detects new Alpine artifacts and opens a PR
whose CI re-validates the image end to end (QEMU boot + exec) before merge
— routine guest patching is reviewing a green PR.

## Phase 5 — SDK wiring: the `vz-exec` executor

Upstream's SDKs launch containment backends through per-backend executor
binaries (`mxc-exec-mac` for seatbelt, `lxc-exec` for LXC), located via
`MXC_BIN_DIR` or the SDK's search paths and driven over a common CLI.
`vz-exec` conforms to that contract, so routing `containment: "vz"` to it
is a one-line SDK change (a `findVzExecutable` sibling of
`findSeatbeltExecutable` in `sdk/node/src/platform.ts`):

- **Config**: positional path, `--config <path>`, or `--config-base64`
  (precedence: base64 > `--config` > positional, matching upstream).
- **Flags**: `--dry-run` (validate, print the upstream
  `Dry run completed. Result: ...` line, exit 0/1), `--experimental`
  (required by vz validation), `--debug`, `--log-file <path>`,
  `--allow-testing-features`.
- **Outputs**: script stdout/stderr pass through verbatim; the guest exit
  code becomes the process exit code; infrastructure failures print the
  one-line `{"error":{"code":"backend_error",...}}` envelope on stderr
  (issue #564 parity); a timeout exits -1 after the host force-stops the
  VM, mirroring `FailurePhase::Timeout`.
- **`--probe`**: the `getPlatformSupport` analogue — prints
  `{"isSupported", "reason", "availableMethods"}` as JSON. On an unsigned
  build the probe itself is where the SIGKILL lands (first VZ API call);
  build via `build-mac.sh`, which signs `vz-exec`.
- **vz-specific**: `--guest-image-dir <path>` (default
  `/opt/mxc/vz-guest`, env `MXC_VZ_GUEST_IMAGE_DIR`).
- **Testing transport**: `MXC_VZ_AGENT_TCP=host:port` executes against an
  already-running agent instead of creating a VM — gated behind
  `--allow-testing-features`, used by the integration tests and the QEMU
  CI job to end-to-end the exact binary the SDK spawns from a Linux host.

## Schema artifacts

- `schemas/mxc-policy-0.8.0-dev.vz.schema.json` — JSON Schema diff for the
  `vz` containment value and the `experimental.vz` options object.
- `src/backends/vz/vz_common` — Rust source of truth: serde policy structs,
  option defaults, and the validation rules above, with the test suites in
  `src/backends/vz/vz_common/tests/`.
