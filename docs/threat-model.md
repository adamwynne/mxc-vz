<!-- Imported from the Google Drive "experiments" folder ("mxc-vz-backend-threat-model.md"), 2026-08-15. -->

# Threat Model — MXC macOS Virtualization.framework (VZ) Backend

**Status:** Draft v0.1 (for review)
**Scope of source:** "MXC macOS Virtualization.framework Backend — Build Plan" (design as written)
**Audience:** Engineering, security review, red team
**Classification:** Internal

---

## 1. Purpose and scope

This document models the security of the proposed **vz** containment backend for `mxc`, which runs untrusted agent code inside an Apple Virtualization.framework (VZ) Linux microVM on macOS. It exists to (a) make the trust boundaries explicit, (b) enumerate threats against those boundaries, and (c) specify where each control must be *enforced* so that implementation and red-team testing have a shared reference.

**In scope:** the VZ backend one-shot lifecycle (v1) and the state-aware / pooled lifecycle (fast-follow); virtio-fs sharing; NAT + host-side network filtering; the vsock exec protocol; the guest image supply chain; entitlements/signing.

**Out of scope:** Seatbelt backend internals except as a comparison baseline; Windows/Linux backends; physical attacks on the host; a malicious host operator; the security of workloads' *own* logic.

---

## 2. Methodology

Threats are organized by **trust boundary** rather than by STRIDE category, because the central design question here is *where* each control is enforced, not *what class* each threat belongs to. Each threat has an ID (`TM-nn`), a severity, a likelihood, and — most importantly — the **enforcement point** the control must live at to be valid.

Severity/likelihood are qualitative (Critical / High / Medium / Low).

---

## 3. Core security principle

> **In this architecture the guest VM is fully hostile.** Untrusted code runs in the guest as root and as PID 1. It can load kernel modules, ignore mount options, rewrite its own config files, and craft arbitrary syscalls and network packets. **Any control that depends on the guest behaving is not a security control.**

Every finding below is, at root, an instance of a control that is (or risks being) implemented guest-side or that trusts guest-supplied data. The design's genuine strength — a hardware hypervisor boundary — only holds if enforcement lives on the **host** side of each boundary.

---

## 4. Assets

| ID | Asset | Why it matters |
|----|-------|----------------|
| AS-1 | Host filesystem data outside intended shares | Primary confidentiality/integrity target |
| AS-2 | Host OS integrity / control of the host | Full compromise; hypervisor escape objective |
| AS-3 | Other tenants' data, VMs, and in-memory state | Multi-user deployment; cross-tenant isolation |
| AS-4 | Secrets passed to exec (env vars, credentials, tokens) | Present in guest memory and the control channel |
| AS-5 | Network position (ability to reach the bank's internal network from the guest) | Lateral movement / egress objective |
| AS-6 | Integrity of the guest image and build pipeline | Supply-chain foothold affecting every VM |
| AS-7 | Host runner process integrity (the parser/bridge) | Guest→host code-execution pivot |

---

## 5. Adversary model

| ID | Adversary | Capability | Goal |
|----|-----------|-----------|------|
| A1 | **Untrusted agent code in the guest** (primary) | Root in guest; arbitrary syscalls, packets, filesystem ops within shares; can drive every virtio device | Escape to host (AS-2), read/write unshared host data (AS-1), exfiltrate over network (AS-5), contaminate other tenants (AS-3), steal secrets (AS-4) |
| A2 | Malicious/careless policy author | Writes the policy JSON | Widen access via ambiguous or no-op fields |
| A3 | Supply-chain attacker | Compromises guest image, npm artifact, or download endpoint | Persistent foothold across all VMs (AS-6) |
| A4 | Network adversary at install time | MITM on postinstall download | Substitute guest image (AS-6) |

---

## 6. Trust boundaries and data flow

```
 ┌──────────────────────── HOST (macOS, trusted) ────────────────────────┐
 │                                                                       │
 │  external network ◄──[TB3]── host-side DNS resolver + TCP proxy       │
 │                              + NAT filter ──┐                         │
 │                                             │                         │
 │  mxc-exec-mac (host runner / parser /       │                         │
 │  bridge) ◄──[TB4]── vsock ──────────────┐   │                         │
 │                                         │   │                         │
 │  virtio-fs daemon (host FS              │   │                         │
 │  exposed) ──[TB2]──────────────────┐    │   │                         │
 │                                    │    │   │                         │
 │  guest image + npm artifact ──[TB5]│    │   │                         │
 │  entitlements/signing ──[TB6]      ▼    ▼   ▼                         │
 │        ┌──────────── GUEST VM (untrusted) ────────────┐               │
 │        │  ── [TB1: hypervisor boundary, enforced      │               │
 │        │      by VZ] ──                                │               │
 │        │  root PID1 agent + untrusted workload         │               │
 │        └───────────────────────────────────────────────┘               │
 │        [TB7: between tenants/execs]                                    │
 └────────────────────────────────────────────────────────────────────────┘
```

| Boundary | Between | Enforced by | Notes |
|----------|---------|-------------|-------|
| **TB1** | Guest VM ↔ Host | VZ hypervisor + its virtio device model | The load-bearing boundary |
| **TB2** | Guest ↔ host filesystem (virtio-fs shares) | Host virtio-fs backend | Largest deliberate hole in TB1 |
| **TB3** | Guest ↔ external network (NAT) | Host packet filter (must be), not guest resolv.conf | See TM-01 |
| **TB4** | Guest agent ↔ host runner (vsock) | Host-side parser robustness | Guest→host data is adversarial |
| **TB5** | Build/distribution ↔ runtime | Content-hash validation + signing | Supply chain |
| **TB6** | Host runner ↔ macOS | Entitlement + code signature | VM-creation privilege |
| **TB7** | One workload ↔ the next (pooling/snapshots) | Reset-to-pristine per exec | Only relevant once VMs are reused |

---

## 7. Threat catalog

### TB3 — Network egress

**TM-01 — `allowedHosts` enforced via guest `resolv.conf` is bypassable.**
*Severity: High · Likelihood: High*
The plan routes per-host policy through a host-side DNS resolver + TCP proxy, with the guest's `resolv.conf` pointing at it. A hostile guest ignores `resolv.conf` entirely: it connects to hard-coded IPs over the NAT interface, runs its own DNS/DoH, or uses the proxy only when convenient. Name resolution is advisory; the guest is untrusted.
**Enforcement requirement:** Egress policy must be enforced at **L3/L4 on the host side of the NAT/vmnet interface** (packet filter keyed on destination IP), with the DNS resolver used only to *populate* the allowed-IP set (bounded TTL, re-resolve). DNS/proxy config inside the guest is convenience, never control. If transparent SNI filtering is used, document domain-fronting/ESNI bypasses.
**Design consequence:** Do **not** ship `allowedHosts` in v1 unless host-side L3/L4 enforcement exists. Accepting the field while enforcing it only via DNS is worse than rejecting it — it manufactures false assurance. `defaultPolicy: block` (no device attached) is unaffected and remains strong.

### TB2 — virtio-fs filesystem shares

**TM-02 — Symlink traversal escapes a share onto the host filesystem.**
*Severity: High (Critical if a writable share covers a sensitive parent) · Likelihood: Medium*
If the host-side virtio-fs backend resolves guest-created symlinks against the *host* filesystem, the guest can plant a symlink inside a writable share pointing at `/` or a denied path and read/write outside the share. This is the classic 9p/virtio-fs/shared-folder escape.
**Enforcement requirement:** Symlink resolution must be confined to the share root on the host side (`openat2(RESOLVE_BENEATH/RESOLVE_NO_SYMLINKS)`-style semantics, or the equivalent VZ virtio-fs behavior). **Verify empirically what VZ's virtio-fs actually does** — the backend inherits its behavior. Also consider hardlinks and guest-side bind/mount tricks.

**TM-03 — Read-only shares enforced only by the guest mount are not read-only.**
*Severity: High · Likelihood: Medium*
"Guest agent mounts read-only" is not a control; a hostile guest remounts `rw` or writes via a second handle.
**Enforcement requirement:** The read-only flag must be enforced by the **host** virtio-fs backend so guest write attempts fail regardless of guest mount options. Confirm VZ's per-share read-only flag is hypervisor-enforced, not advisory.

**TM-04 — `deniedPath` inside a shared path handled by "splitting" the share.**
*Severity: High · Likelihood: Medium*
The plan leaves "split shares or reject" open. Carving a denied subdirectory out of a share by splitting it reintroduces the symlink/TOCTOU surface of TM-02 around the carve-out edges.
**Enforcement requirement:** **Fail closed — reject** the configuration when a `deniedPath` falls inside a share. Do not split.

**TM-11 — Path matching bypass via case-insensitivity / non-canonical paths.**
*Severity: Medium · Likelihood: Medium*
macOS/APFS is frequently case-insensitive. Share/denied-path comparison that is case-sensitive or that skips canonicalization lets `/Secret` vs `/secret`, `..`, trailing-slash, or Unicode-normalization variants defeat intent.
**Enforcement requirement:** Canonicalize and case-fold (per the host volume's semantics) all paths before any allow/deny comparison, host-side.

**TM-07 — Host disk exhaustion via a writable share.**
*Severity: Medium · Likelihood: Medium*
CPU/RAM are bounded by VM config (2 vCPU / 2048 MB defaults), but virtio-fs writes land on the host filesystem. A guest can fill the host disk through a `readwrite` share (DoS affecting the host and all other tenants).
**Enforcement requirement:** Per-share or per-VM write quota; defined behavior on `ENOSPC`; monitor host free space.

### TB4 — vsock control channel

**TM-06 — Host-side exec parser processes adversarial guest output.**
*Severity: Medium · Likelihood: Medium*
The guest streams stdout/stderr/exit codes as newline-delimited JSON over vsock, and the guest is untrusted. The host parser, stream de-multiplexer, and exit-code handling become an attack surface: unbounded line length (host memory DoS), channel-confusion between multiplexed streams, injected control frames, malformed JSON.
**Enforcement requirement:** Treat all guest→host bytes as hostile. Prefer length-prefixed frames with hard size caps over newline-delimited parsing; a hardened/fuzzed parser; strict channel separation; no trust that a "stdout" frame reflects the real child process rather than a subverted agent. Fuzz this path in CI.

**TM-13 — vsock reachability beyond the agent port.**
*Severity: Medium · Likelihood: Low*
A guest that can reach host services over vsock beyond the intended agent port widens TB4.
**Enforcement requirement:** Confirm only the single agent port/CID pairing is reachable from the guest; probe with a port scan from inside the guest (already noted in the plan's tripwires — promote to a required test).

**TM-15 — Egress NAT becomes SSRF against the host or its link.**
*Severity: High · Likelihood: Medium · Status: mitigated (host-local egress guard)*
The `allowedHosts` datapath is a terminating NAT: the guest's connection is re-originated from a host socket. If the gate relays to *any* allow-listed destination without further checks, a broad or careless `allowedHosts` entry (a CIDR, or a literal like `127.0.0.1` / `169.254.169.254`) turns the guest into an SSRF client against the host's own loopback services, its link-local neighbours, or — critically — the cloud metadata endpoint `169.254.169.254`.
**Enforcement requirement:** The gate enforces a policy-independent invariant (`GateConfig::is_relayable`): it never relays to loopback, link-local, unspecified, multicast, broadcast, or its own gateway/DNS/guest addresses, regardless of the allowlist. A destination must pass **both** the allowlist and this guard. RFC1918/ULA are intentionally *not* blocked (legitimate in real deployments). The guard is unconditionally on in production; only tests that use loopback as an internet stand-in disable it. Two SSRF-adjacent refinements: (a) a small **cloud-metadata denylist** (`is_cloud_metadata`) refuses the instance-metadata endpoints unconditionally — the v4 `169.254.169.254` (already link-local) plus AWS's IPv6 `fd00:ec2::254`, which is a **ULA** and would otherwise slip past the host-local ranges, and Alibaba's `100.100.100.200`; (b) DNS answers are filtered through `is_relayable` at **population time**, so an attacker who controls DNS for an allow-listed name cannot point it at a host-local/metadata IP — the address is stripped from the answer and never enters the allowed set (the connect-time guard would refuse it regardless; this is defense in depth). Verified by `loopback_is_refused_even_when_allow_listed`, `cloud_metadata_ip_is_refused_even_when_allow_listed`, `ipv6_cloud_metadata_is_refused_even_when_allow_listed`, `cloud_metadata_is_refused_even_in_relay_mode`, `gate_own_gateway_is_never_relayed`, `poisoned_allow_listed_name_resolving_to_metadata_is_filtered_at_dns`, `host_local_classification`.

**Known residual (follow-up):** the guard does not yet exclude the host's *own routable* interface addresses (e.g. a corporate `10.x` the host sits on), so a policy allow-listing a CIDR that covers the host could reach host services on that interface. Closing it means enumerating host interface addresses at gate start. Tracked; not yet implemented.

**TM-14 — NAT state-table exhaustion from the guest (DoS).**
*Severity: Medium · Likelihood: Medium · Status: mitigated (bounded flow tables)*
Each TCP flow the gate opens spawns a host connect thread and allocates smoltcp buffers; each UDP flow binds a host socket; each ICMP flow opens a ping socket; each DNS query for an allow-listed name spawns a resolver thread. A hostile guest that opens flows with varying source ports/destinations without bound could exhaust host threads, file descriptors, and memory — a local DoS against the host from inside the sandbox.
**Enforcement requirement:** All NAT state is bounded (`max_tcp_flows`, `max_udp_flows`, `max_icmp_flows`, `max_inflight_dns` in `GateConfig`, default 512/512/128/64). At a cap, the new flow is **dropped** — the guest is throttled (it retransmits), the filter is never bypassed, and the gate stays fail-safe. Idle UDP/ICMP flows already expire (30 s). Verified by `udp_flow_table_cap_drops_excess_flows`.

### TB7 — Cross-tenant / VM reuse

**TM-05 — Pooled or snapshot-restored VMs leak state between workloads.**
*Severity: High (Critical in multi-tenant) · Likelihood: Medium (only once pooling/warm-start ships)*
One-shot (spawn → exec → destroy) is clean. Phase-7 warm-start snapshots and "pool of pre-booted VMs" mean a VM that ran workload A is reused for workload B. Without a full reset, this leaks filesystem overlay state, in-memory secrets (AS-4), and residual processes across tenants.
**Enforcement requirement:** Commit now that any reused VM is **reset to a pristine snapshot** (memory *and* writable overlay) between execs, or that pooling is **per-tenant only**. Document this as a hard invariant of the state-aware lifecycle before it is built. Snapshots that persist memory must be handled as secret-bearing at rest.

### TB1 — Hypervisor boundary (VZ itself)

**TM-09 — Guest-driven exploitation of the VZ virtio device model (host escape).**
*Severity: Critical (impact) · Likelihood: Low*
The real host-escape surface is not the guest kernel but VZ's own device implementations (virtio-fs, vsock, virtio-net) driven by a hostile guest. A VZ CVE here defeats TB1 directly.
**Enforcement requirement:** Track macOS/VZ security updates; define a minimum supported macOS version and a response SLA for VZ CVEs. Minimize attached devices (each device is surface — do not attach network when policy is `block`; this is already the design). Keep the guest kernel current too (in-guest escalation matters for pooled VMs and reduces the set of usable primitives).

### TB5 — Supply chain

**TM-08 — Postinstall guest-image download is a network-trust dependency.**
*Severity: Medium · Likelihood: Low–Medium*
Boot-time content-hash validation is good, but the "postinstall download with hash pinning" option adds an install-time trust dependency (endpoint compromise, TLS, and hash-in-the-same-artifact-that-was-compromised).
**Enforcement requirement:** For a bank deployment, **ship the guest image inside the signed npm artifact** and validate its hash at boot. If a download is unavoidable, pin the hash out-of-band from the artifact that carries the payload, over TLS with certificate pinning, and fail closed on mismatch.

**TM-10 — Cross-backend "portability" masks silent semantic gaps.**
*Severity: Low–Medium · Likelihood: Medium*
"Same JSON, change only `containment`" is ergonomic but risks operators assuming equivalence. `deniedPaths` is "accepted but redundant"; `ui.*` is "accept and ignore." Individually fine, but a policy relied upon under one backend may be a no-op under vz.
**Enforcement requirement:** Document explicitly that parity is not guaranteed; enumerate which fields are no-ops under vz; emit a validation warning when a field is accepted-but-ignored. Never silently accept a *restriction* the backend cannot enforce (see TM-01).

### TB6 — Host entitlements

**TM-12 — VM-creation entitlement and signing friction.**
*Severity: Low · Likelihood: Medium*
`com.apple.security.virtualization` is a powerful entitlement; ad-hoc signing for contributors and shipped signed binaries must be managed so the entitlement is not attached to an untrusted or tamperable binary. Not a guest-driven threat, but part of the host TCB.
**Enforcement requirement:** Signed, notarized release binaries; protect signing keys; document that unsigned/ad-hoc builds are for development only.

---

## 8. Governance / process finding

**TM-00 — Ambiguous boundary claim.**
The build plan hedges "not a security boundary claim, per repo policy," while the product's entire value proposition is a hardware isolation boundary. For a regulated (bank) deployment this must be resolved: publish an explicit threat model statement (this document) declaring what VZ **is** and **is not** relied upon to contain, and whether the boundary is defense-in-depth or load-bearing. Red-team scope, sign-off, and any control attestation depend on this being unambiguous.

---

## 9. Control summary — required enforcement points

| Control | Must be enforced at | Must NOT rely on |
|---------|---------------------|------------------|
| Network allow/block | Host L3/L4 packet filter on NAT interface | Guest `resolv.conf` / guest proxy config |
| Read-only share | Host virtio-fs backend | Guest mount options |
| Share confinement | Host-side symlink resolution bounded to share root | Guest cooperation |
| Denied path | Config rejection (fail closed) | Split shares |
| Path matching | Host-side canonicalization + case-fold | Raw string compare |
| Resource bounds | VM CPU/RAM config + host FS quota | Guest self-restraint |
| Control channel | Hardened, size-capped host parser | Well-formed guest output |
| Tenant isolation (pooled) | Reset-to-pristine snapshot per exec | Guest cleanup |
| Image integrity | In-artifact signed image + boot hash check | Postinstall download alone |

---

## 10. Validation matrix (red-team / CI probes)

| Threat | Probe | Pass criterion |
|--------|-------|----------------|
| TM-01 | From guest, connect to a non-allowed IP directly (no DNS); run in-guest DoH | Connection blocked at host filter |
| TM-02 | Plant symlink in a writable share → host path outside share; read/write via it | Resolution stays within share; op fails |
| TM-03 | Remount read-only share `rw` in guest; write via alternate handle | Write fails |
| TM-04 | Submit policy with `deniedPath` inside a share | Rejected at validation |
| TM-05 | Run workload A writing a marker + secret in memory; reuse VM for workload B | B sees pristine state; no marker/secret |
| TM-06 | Emit oversized / malformed / channel-confused frames from guest agent | Host parser bounded, no crash, correct de-mux |
| TM-07 | Fill a writable share to capacity | Quota enforced; host unaffected |
| TM-11 | Access `/Secret` when `/secret` is denied (and vice-versa); use `..` | Blocked |
| TM-13 | Port-scan vsock CID from guest | Only agent port reachable |

---

## 11. Assumptions and dependencies

- VZ (the hypervisor) and its virtio device model are part of the trusted computing base; their correctness is assumed but tracked for CVEs (TM-09).
- The host OS, the `mxc-exec-mac` runner, the build pipeline, and signing keys are trusted.
- Findings TM-01, TM-02, TM-03 depend on **observed VZ virtio-fs and NAT behavior**, not on the build plan's description. These must be verified against the implementation before the corresponding controls are claimed.
- The guest workload itself is untrusted and assumed hostile at all times.

---

## 12. Accepted / well-designed decisions (retain)

- `defaultPolicy: block` implemented as **no network device attached** — kernel-level absence beats filtering; strongest possible form.
- **Timeout via VM force-stop** — a hard guarantee Seatbelt cannot make against a process that outruns a process-tree kill.
- **Guest ships its own userland** — no host `/usr/lib`, `/System` exposure; materially smaller attack surface than Seatbelt's mandatory allows.
- **vsock-connect-as-readiness** and **port-scoped** control channel — sound, avoids rendezvous-file races.
- **Content-hash validation** of the guest image at boot.

---

*End of draft. Open items requiring a decision before v1 sign-off: TM-01 (network enforcement point), TM-04 (reject vs. split), TM-05 (pooling invariant), TM-00 (boundary claim). Findings TM-02/TM-03 require empirical VZ verification.*
