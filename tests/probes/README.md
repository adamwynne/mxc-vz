# Sentinel probe suite

Policy-driven isolation probes in the style of upstream microsoft/mxc's
`tests/configs` fixtures (see e.g. `bubblewrap_denied_symlink_file.json`
upstream): the probe logic runs **inside** the sandbox as the workload
`process.commandLine`, and the harness only asserts on sentinel strings in
stdout. The sandbox is the system under test; the probe script is the
adversary's viewpoint.

## Format

Each probe is a pair of files:

- `<name>.json` — a **valid vz policy** (`containment: "vz"`) whose
  `process.commandLine` is the probe script. The policy schema is closed
  (unknown fields are rejected — `src/backends/vz/vz_common/src/policy.rs`),
  so probe expectations cannot be embedded in the policy; the `_comment`
  field carries the human-readable intent and the threat-model mapping.
- `<name>.expect` — the sentinel contract, one entry per line:
  - `exitcode:<n>` — optional, first line only: expected remote exit code
    (defaults to `0`);
  - `<sentinel>` — required: must appear in the probe's stdout;
  - `!<sentinel>` — forbidden: must NOT appear in the probe's stdout;
  - blank lines and `#` comments are ignored.
- `<name>.reject` — replaces `.expect` for **validation probes**: the policy
  must be *rejected* by `vz_validate` (the probe passes by never running).

## Sentinel convention

Probe scripts emit exactly one sentinel per checked property:

- `*_OK` — the sandbox behaved correctly;
- `*_LEAK` — an isolation violation (data/access crossed a boundary it must
  not cross);
- `*_BUG` — a plumbing failure (something the probe needs is broken, e.g. a
  share that should have been mounted is missing).

`.expect` files list every `*_OK` sentinel as required and every `*_LEAK` /
`*_BUG` the script can emit as forbidden (`!`-prefixed), so a violation is
caught both by the missing `_OK` and by the present `_LEAK`.

## Runner

```
cargo build -p vz_protocol --example exec_tcp
scripts/run-guest-probes.sh <addr> <probes-dir>
```

For each probe the runner extracts `process.commandLine`, executes it against
the live agent via `exec_tcp` (exit code = remote exit code, stdout passes
through), checks the `.expect` contract, and prints a PASS/FAIL table,
exiting nonzero on any failure. `.reject` probes are skipped by the runner
(they are validation-time, not run-time) and covered by the CI step that runs
`cargo run -p vz_common --example vz_validate` over every probe policy,
asserting acceptance — or rejection for `.reject` probes.

## guest-local/ — runs in CI today

Probes that need only the guest image itself (Alpine initramfs + busybox +
the agent as init): no virtio-fs shares, no host paths, no VZ NAT. CI boots
the image under QEMU (job `guest-image` in `.github/workflows/ci.yml`) and
runs this directory against it after the echo milestone.

| Probe | Checks | Threat-model ref |
|-------|--------|------------------|
| `hostpath_absence` | `/Users`, `/System`, `/Library`, `/Volumes`, `/Applications` do not exist in the guest | AS-1; §12 "guest ships its own userland" |
| `tmpfs_write` | guest `/tmp` write / read-back / unlink round-trip | baseline viability |
| `procfs_sysfs` | `/proc` and `/sys` are mounted before the workload runs | init contract (`scripts/guest-init.sh`) |
| `userland` | busybox `sh`/`cat`/`grep` present; a pipeline round-trips | probe toolbox baseline |
| `pid_sanity` | the workload shell is not PID 1 | §3: workload is a child of the agent |
| `exit_code_load` | 2000-line stdout stream arrives head-to-tail AND exit code 42 is reported exactly | TM-06 (TB4 de-mux/exit integrity) |
| `envleak` | no `GITHUB_*`/`CARGO_*`/`RUSTUP_*`/`SSH_*`/`CI=`/… host variables in the workload env | AS-4 (secrets in the control channel) |

Note: these probes assert **guest** truths. Running them against an agent
started directly on a dev host (e.g. `cargo run -p vz_guest_agent -- tcp:...`)
exercises the runner mechanics, but `envleak` (and on macOS also
`hostpath_absence`) will legitimately FAIL there — that failure is the probe
correctly detecting that it is not inside the guest image.

## metal-only/ — staged for the bare-metal VZ runner

Probes that need real VZ semantics — virtio-fs shares and NAT device policy —
which QEMU-on-ubuntu CI cannot provide (the QEMU harness attaches no shares,
and its slirp NIC is required for the TCP control channel, so "no network
device" cannot be asserted there). **Not wired into CI yet.** They run once
the self-hosted bare-metal macOS runner (docs/self-hosted-runner.md) executes
policies end-to-end; until then only their *validation* is exercised in CI.

| Probe | Checks | Threat-model ref |
|-------|--------|------------------|
| `denied_path_inside_share` | **validation probe** (`.reject`): `deniedPaths` inside a share is rejected, fail-closed, never split | TM-04 |
| `readonly_share_write` | direct write and remount-rw+write into a `readonlyPaths` share both fail (host-enforced ro) | TM-03 |
| `symlink_share_escape` | symlink / `..`-link planted in a writable share cannot reach host files outside the share | TM-02 |
| `network_block_nodevice` | `defaultPolicy: block` ⇒ no NIC besides `lo`; direct-to-IP egress fails | TM-01 |

Harness prerequisites for the metal runner (to be scripted with it):

- `readonly_share_write`: host dir `/tmp/mxc-probe-ro` exists, shared ro;
- `symlink_share_escape`: host dir `/tmp/mxc-probe-rw` shared rw, and host
  file `/tmp/mxc-probe-outside/secret.txt` containing `MXC_HOST_SECRET`
  outside every share (the escape target);
- `network_block_nodevice`: nothing — the probe passes exactly when the VM
  gets no virtio-net device.

Remaining validation-matrix rows (docs/threat-model.md §10) not yet covered:
TM-05 (pooled-VM reset — no pooling exists yet), TM-06 host-parser fuzzing
(covered separately by protocol tests, not a guest probe), TM-07 (quota),
TM-11 (case-fold path matching), TM-13 (vsock port scan — needs vsock
tooling in the guest image).
