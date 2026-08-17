#!/bin/bash
# One-shot metal validation for the vz backend on a real Apple Silicon Mac.
#
# Runs the whole "does it actually boot under Virtualization.framework?"
# gauntlet and prints a single clear PASS/FAIL summary you can paste back.
#
# Usage (from the repo root, on macOS):
#   ./scripts/metal-smoke.sh
#
# Prereqs (install once): Xcode command line tools (`xcode-select --install`)
# and a Rust toolchain (`curl https://sh.rustup.rs -sSf | sh`).
#
# This is intentionally read-only to the machine beyond a local build; nothing
# is installed system-wide and there is no cleanup to do besides `cargo clean`.
set -uo pipefail
cd "$(dirname "$0")/.."

pass=0
fail=0
note() { printf '\n=== %s ===\n' "$1"; }
ok()   { printf '  PASS: %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  FAIL: %s\n' "$1"; fail=$((fail + 1)); }

note "0. Host check"
arch="$(uname -m)"
osver="$(sw_vers -productVersion 2>/dev/null || echo '?')"
printf '  arch=%s  macOS=%s\n' "$arch" "$osver"
if [ "$arch" != "arm64" ]; then
    bad "not Apple Silicon (uname -m = $arch); VZ needs an arm64 Mac. Stopping."
    printf '\nSUMMARY: %d passed, %d failed\n' "$pass" "$fail"
    exit 1
fi
ok "Apple Silicon host"

note "1. Build + ad-hoc sign (build-mac.sh)"
if ./build-mac.sh; then
    ok "built and signed with the virtualization entitlement"
else
    bad "build-mac.sh failed — fix build errors before booting"
    printf '\nSUMMARY: %d passed, %d failed\n' "$pass" "$fail"
    exit 1
fi

note "2. Fetch the pinned Alpine guest"
if ./scripts/fetch-alpine-guest.sh guest; then
    ok "guest kernel + initramfs fetched and pin-verified"
else
    bad "guest fetch failed (network? pin mismatch?)"
    printf '\nSUMMARY: %d passed, %d failed\n' "$pass" "$fail"
    exit 1
fi

note "3. First real VZ boot (boot_smoke)"
set +e
target/debug/examples/boot_smoke guest/vmlinux guest/initramfs-virt
code=$?
set -e 2>/dev/null || true
printf '  boot_smoke exit code: %s\n' "$code"
case "$code" in
    0)   ok "REAL VZ BOOT SUCCEEDED — the milestone 🚀" ;;
    2)   bad "isSupported=false — VZ unavailable on this host (unexpected on a real Mac)" ;;
    137) bad "SIGKILL — missing/stripped entitlement; re-run ./build-mac.sh (do not use bare cargo)" ;;
    *)   bad "boot failed (exit $code) — capture the output above and send it back" ;;
esac

note "4. Real driver paths (vsock + file-handle) — vz_darwin tests"
if [ "$code" = "0" ]; then
    set +e
    cargo test -p vz_darwin 2>&1 | tail -25
    tcode=${PIPESTATUS[0]:-$?}
    set -e 2>/dev/null || true
    if [ "$tcode" = "0" ]; then
        ok "vz_darwin tests passed on real hardware"
    else
        bad "vz_darwin tests failed (exit $tcode) — send the tail above"
    fi
else
    printf '  skipped (boot did not succeed)\n'
fi

printf '\n================ SUMMARY: %d passed, %d failed ================\n' "$pass" "$fail"
[ "$fail" = "0" ] && printf 'All green on metal. Metal-only isolation probes are the next step.\n'
exit "$fail"
