#!/bin/bash
# Run ON a bare-metal Apple Silicon Mac (e.g. a Scaleway Mac mini) to turn it
# into a GitHub Actions self-hosted runner for this repo, labeled `vz-metal`.
# Installs: Xcode Command Line Tools (for clang/ld), rustup, and the GitHub
# Actions runner as a launchd service.
#
# Usage (on the Mac):
#   GH_PAT=<PAT with repo admin> GH_REPO=owner/repo bash setup-macos-runner.sh
# or with a pre-fetched registration token instead of a PAT:
#   GH_RUNNER_TOKEN=<token> GH_REPO=owner/repo bash setup-macos-runner.sh
set -euo pipefail

GH_REPO="${GH_REPO:-adamwynne/mxc-vz}"
RUNNER_DIR="$HOME/actions-runner"
RUNNER_VERSION="${RUNNER_VERSION:-2.328.0}"
RUNNER_LABELS="${RUNNER_LABELS:-vz-metal}"

if [[ "$(uname -s)/$(uname -m)" != "Darwin/arm64" ]]; then
    echo "error: this script must run on an Apple Silicon Mac" >&2
    exit 1
fi

# Xcode Command Line Tools (non-interactive). Needed for the linker.
if ! xcode-select -p >/dev/null 2>&1; then
    echo "installing Xcode Command Line Tools..."
    touch /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
    label="$(softwareupdate -l 2>/dev/null | grep -o 'Command Line Tools for Xcode-[0-9.]*' | tail -1)"
    softwareupdate -i "$label" --agree-to-license
    rm -f /tmp/.com.apple.dt.CommandLineTools.installondemand.in-progress
fi

# Rust toolchain.
if ! command -v cargo >/dev/null 2>&1 && [[ ! -x "$HOME/.cargo/bin/cargo" ]]; then
    echo "installing rustup..."
    curl -fsSL https://sh.rustup.rs | sh -s -- -y --profile minimal
fi

# Registration token: either provided directly, or minted from a PAT.
if [[ -z "${GH_RUNNER_TOKEN:-}" ]]; then
    : "${GH_PAT:?set GH_PAT (repo admin PAT) or GH_RUNNER_TOKEN}"
    echo "requesting runner registration token for $GH_REPO..."
    GH_RUNNER_TOKEN="$(curl -fsS -X POST \
        -H "Authorization: token $GH_PAT" \
        -H "Accept: application/vnd.github+json" \
        "https://api.github.com/repos/$GH_REPO/actions/runners/registration-token" \
        | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')"
fi

mkdir -p "$RUNNER_DIR"
cd "$RUNNER_DIR"
if [[ ! -x ./config.sh ]]; then
    echo "downloading actions runner $RUNNER_VERSION..."
    curl -fsSL -o runner.tar.gz \
        "https://github.com/actions/runner/releases/download/v$RUNNER_VERSION/actions-runner-osx-arm64-$RUNNER_VERSION.tar.gz"
    tar xzf runner.tar.gz && rm runner.tar.gz
fi

./config.sh --unattended \
    --url "https://github.com/$GH_REPO" \
    --token "$GH_RUNNER_TOKEN" \
    --name "$(hostname -s)-vz-metal" \
    --labels "$RUNNER_LABELS" \
    --replace

# Run as a launchd service so it survives reboots and SSH disconnects.
./svc.sh install
./svc.sh start
./svc.sh status || true

echo
echo "runner registered for $GH_REPO with labels: $RUNNER_LABELS"
echo "sanity check on this host:"
sysctl kern.hv_vmm_present 2>/dev/null || true
echo "(kern.hv_vmm_present: 0 expected on bare metal — VZ will be supported)"
