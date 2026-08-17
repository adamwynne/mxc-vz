<!--
  Ready-to-file Feature Request for microsoft/mxc.

  I could not post this from the build session — GitHub write access there is
  out of the session's repo scope (reads work, writes are denied). File it
  yourself:

    1. https://github.com/microsoft/mxc/issues/new/choose
    2. Pick "🚀 Feature Request / Idea".
    3. Title: use the "## Title" line below.
    4. Paste the two sections into the template's two fields (they map 1:1:
       "Description of the new feature / enhancement" and
       "Proposed technical implementation details").
    5. Labels (Issue-Feature, Needs-Triage) and the "Feature" type are applied
       by the template automatically.

  Before filing: make sure https://github.com/adamwynne/mxc-vz is PUBLIC, or
  maintainers won't be able to open the link.
  Duplicate check done (2026-08-17): no existing VM/vz backend proposal on
  microsoft/mxc.
-->

## Title

New containment backend: macOS hardware isolation via Apple Virtualization.framework (VZ Linux microVM)

## Description of the new feature / enhancement

On macOS, the only containment backend today is **Seatbelt** (`sandbox_init()`), which is a process-scoped policy sandbox sharing the host kernel. I'd like to contribute a **hardware-hypervisor** containment tier for macOS: run the untrusted workload inside an **Apple Virtualization.framework (VZ)** Linux microVM, giving a hypervisor boundary instead of an in-kernel policy boundary — the macOS analogue of what `microvm`/`hyperlight`/`wslc` provide on other platforms.

**Why:** for higher-assurance workloads on macOS (e.g. running untrusted agent-generated code), a VM boundary is a materially stronger isolation guarantee than Seatbelt. The headline semantic difference is deliberate and worth calling out up front: **binaries run in this backend are Linux/ARM64 binaries, not macOS binaries** (the guest ships its own userland) — the same trade Docker-style sandboxes make. Seatbelt stays the right choice for host-toolchain workloads; this is for isolation strength.

**I intend to implement this myself.** A complete, working reference already exists and is public here — please feel free to look before we agree an approach:

**👉 https://github.com/adamwynne/mxc-vz**

It's a from-scratch implementation built against this repo's `0.8.0-dev` config surface (pinned at `692275b`), including a conformance suite that runs our validation against **61 of your own vendored config fixtures**. It is substantially verifiable on Linux CI today (unit + QEMU end-to-end), which matters given the CI finding below.

## Proposed technical implementation details

The reference implementation covers, all TDD with ~216 tests green:

- **Config + validation** — matches the `0.8.0-dev` wire surface (closed stable block, permissive `experimental`); rejects what a VM guest can't honour (`ui` access, `network.proxy`, v1 `blockedHosts`) and warns on cross-backend-portability fields.
- **VM lifecycle + driver** — `objc2-virtualization`; queue-affine VM on a dedicated thread; one-shot spawn→exec→destroy (mirroring Seatbelt).
- **Host↔guest exec protocol** — length-prefixed framing with hard caps (TM-06 style), a musl guest agent over vsock, timeout enforced by host-side VM force-stop (never trusted to the guest).
- **`allowedHosts` egress** — enforced host-side at L3/L4 (a terminating userspace NAT: dual-stack TCP/UDP/ICMP + a DNS proxy that only *populates* an allowed-IP set), because DNS/`resolv.conf` in an untrusted guest is advisory. Includes SSRF guards (no relay to loopback/link-local/cloud-metadata v4+v6/host-own addresses) and bounded NAT state.
- **Guest image** — minimal Alpine ARM64, sha256-pinned in the NanVix-binaries style, with a weekly auto-bump.
- **Executor** — a `vz-exec` binary conforming to the `mxc-exec-mac`/`lxc-exec` CLI contract, so SDK routing is a small change.
- **Docs + threat model** under `docs/macos-support/`.

**Two things I'd like maintainer guidance on before writing the upstream PR(s)** (per CONTRIBUTING's "agree an approach first"):

1. **Schema shape.** The wire model already reserves a **`Vm`** containment ("VM-class isolation, resolved per host") which is currently unimplemented on macOS — `From<wire::Containment>` maps macOS `Vm → ContainmentBackend::Vm` with no runner. Would you prefer this backend to **implement the existing `Vm` value on macOS** (like `Vm→WindowsSandbox` on Windows), or to land it first behind a new **`experimental.vz`** per the standard experimental-feature path in `docs/authoring-a-new-feature.md`? This decision shapes the schema/codegen change, so I'd like your call before coding it upstream.

2. **macOS CI for a VM backend.** Empirically, **GitHub-hosted `macos-14`/`macos-15` ARM64 runners do *not* support VZ** — they are themselves VMs (`kern.hv_vmm_present: 1`) without nested virtualization, so `VZVirtualMachine.isSupported` returns `false`. The platform-neutral logic, a QEMU-emulated boot+exec end-to-end, and the egress datapath all run on your existing Linux runners, but the *real VZ boot* needs bare-metal Apple Silicon. How would you want metal macOS CI handled (1ES pools / self-hosted)? I can provide the boot-smoke workflow as a template.

Assuming you're open to it, I'd propose a **staged PR series** (design doc → schema+validation+conformance → protocol+agent → darwin runner+session → egress gate → engine/SDK dispatch → guest image + CI), each independently green, rather than one large drop. Happy to write a short design doc under `docs/` first if you'd like to converge on the schema question in writing. I'll sign the CLA on the first PR.

Thanks for building MXC in the open — the backend-per-crate structure and the vendored config fixtures made building against your surface genuinely pleasant.
