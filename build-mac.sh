#!/bin/bash
# Build the vz backend host binaries on macOS (Apple Silicon).
#
# Virtualization.framework requires the com.apple.security.virtualization
# entitlement. THIS IS THE #1 STUMBLING BLOCK: a binary that is not signed
# with the entitlement is killed by the kernel on its first VZ API call —
# no error message, just SIGKILL. Dev builds therefore ad-hoc sign
# (identity "-") with scripts/vz.entitlements after every build; ad-hoc
# signatures are machine-local, which is fine for development.
set -euo pipefail

cd "$(dirname "$0")"

if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "error: this script must run on macOS (Apple Silicon)" >&2
    exit 1
fi
if [[ "$(uname -m)" != "arm64" ]]; then
    echo "error: the vz backend targets Apple Silicon only (see design doc, Decision 4)" >&2
    exit 1
fi

PROFILE="${1:-debug}"
CARGO_FLAGS=()
if [[ "$PROFILE" == "release" ]]; then
    CARGO_FLAGS+=(--release)
fi

cargo build -p vz_darwin "${CARGO_FLAGS[@]}"
cargo test -p vz_common -p vz_darwin "${CARGO_FLAGS[@]}"

# Sign every produced test/binary artifact that will touch VZ APIs. For now
# the deliverable is the library + tests; the mxc-exec-mac executable joins
# this list in a later phase.
sign() {
    codesign --force --sign - --entitlements scripts/vz.entitlements "$1"
    echo "signed: $1"
}

# Ad-hoc sign the vz_darwin test binaries so `cargo test` can exercise real
# VZ boots (Phase 1 milestone) without being killed.
for artifact in target/"$PROFILE"/deps/runner-* target/"$PROFILE"/deps/vz_darwin-*; do
    if [[ -f "$artifact" && -x "$artifact" ]]; then
        sign "$artifact"
    fi
done

echo
echo "Build complete. If a VZ API call dies with SIGKILL, the binary lost its"
echo "signature (rebuilds strip it) — re-run this script rather than cargo directly."
