# Bare-metal macOS runner for the vz boot smoke

GitHub-hosted macOS runners are themselves VZ virtual machines, and Apple's
nested virtualization exists only for **Linux** guests (M3+/macOS 15+) — a
macOS VM never gets virtualization capability. So the real Phase 1 boot
milestone needs **bare-metal Apple Silicon**. Verified empirically: CI's
boot-smoke probe reports `VZVirtualMachine.isSupported == false` on both
`macos-14` and `macos-15` hosted runners.

## One-command Scaleway provisioning

Scaleway rents bare-metal Mac minis (M4 ≈ EUR 0.22/h, **24-hour minimum
allocation** — expect ~EUR 5.30 even for a ten-minute test).

```bash
# Needs: a Scaleway API secret key + project ID with an SSH key registered,
# and a GitHub PAT with repo admin (to mint the runner registration token).
SCW_SECRET_KEY=... SCW_PROJECT_ID=... GH_PAT=... \
    ./scripts/provision-scaleway-runner.sh
```

The script creates the Mac (auto-picking an M4 type in `fr-par-1`), waits for
it to boot, SSHes in, installs the toolchain and the GitHub Actions runner
agent (labels: `vz-metal`, launchd service), and registers it against this
repo. Then run the **"vz metal boot smoke"** workflow (workflow_dispatch) —
it builds, signs, fetches the Alpine guest, and boots a real VM, treating
"VZ unsupported" as a hard failure (a metal runner must support it).

**Deleting** (after the 24h minimum):

```bash
SCW_SECRET_KEY=... ./scripts/provision-scaleway-runner.sh delete <server-id>
```

Also deregister the dead runner under repo Settings → Actions → Runners.

## Any other Apple Silicon Mac

The same setup script works on any Mac you own:

```bash
GH_PAT=<repo-admin PAT> GH_REPO=adamwynne/mxc-vz bash scripts/setup-macos-runner.sh
```

## Security note

A self-hosted runner executes workflow code. Keep it on repos you trust
(GitHub disables self-hosted runners for PRs from forks by default on
private repos; for public repos, require approval for outside collaborators
under Settings → Actions → General).
