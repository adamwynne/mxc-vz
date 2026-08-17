#!/bin/bash
# Run the metal-only isolation probes end-to-end through a REAL
# Virtualization.framework VM on Apple Silicon.
#
# Unlike run-guest-probes.sh (which drives an already-running agent over TCP
# and so cannot exercise virtio-fs shares or network-device policy), this
# feeds each probe's WHOLE policy to `vz-exec`, which boots a real VZ VM with
# the shares and NAT device the policy asks for. That is the only way to
# observe the properties QEMU-on-Linux CI can't:
#
#   symlink_share_escape   TM-02  virtio-fs symlink confinement
#   readonly_share_write   TM-03  host-enforced read-only shares
#   denied_path_inside_share TM-04 (validation) deniedPath in a share -> reject
#   network_block_nodevice TM-01  defaultPolicy block => no NIC but lo
#
# Usage (Apple Silicon macOS, from the repo root):
#   ./scripts/run-metal-probes.sh [guest-dir]
#
# Missing prerequisites are built for you: build-mac.sh (signs vz-exec with the
# virtualization entitlement) and build-vz-guest.sh (kernel + initramfs).
#
# bash 3.2 compatible (macOS ships 3.2): no associative arrays, no mapfile.
set -uo pipefail
cd "$(dirname "$0")/.."

GUEST_DIR="${1:-guest}"
PROBES_DIR="tests/probes/metal-only"
VZ_EXEC="target/debug/vz-exec"

pass=0
fail=0
note() { printf '\n=== %s ===\n' "$1"; }
ok()   { printf '  PASS: %s\n' "$1"; pass=$((pass + 1)); }
bad()  { printf '  FAIL: %s\n' "$1"; fail=$((fail + 1)); }

summary_and_exit() {
    printf '\n================ SUMMARY: %d passed, %d failed ================\n' "$pass" "$fail"
    [ "$fail" = "0" ] && printf 'All metal isolation probes green.\n'
    exit "$fail"
}

note "0. Host check"
arch="$(uname -m)"
if [ "$(uname -s)" != "Darwin" ] || [ "$arch" != "arm64" ]; then
    bad "must run on Apple Silicon macOS (uname = $(uname -s)/$arch). Stopping."
    summary_and_exit
fi
printf '  arch=%s  macOS=%s\n' "$arch" "$(sw_vers -productVersion 2>/dev/null || echo '?')"

note "1. Prerequisites"
if [ ! -x "$VZ_EXEC" ]; then
    echo "  vz-exec not built — running ./build-mac.sh"
    ./build-mac.sh || { bad "build-mac.sh failed"; summary_and_exit; }
fi
if [ ! -f "$GUEST_DIR/vmlinux" ] || [ ! -f "$GUEST_DIR/initramfs.cpio.gz" ]; then
    echo "  guest image missing in $GUEST_DIR — running ./scripts/build-vz-guest.sh $GUEST_DIR"
    ./scripts/build-vz-guest.sh "$GUEST_DIR" || { bad "guest build failed"; summary_and_exit; }
fi
printf '  vz-exec: %s\n  guest:   %s\n' "$VZ_EXEC" "$GUEST_DIR"

note "2. Host fixtures for the share probes"
# readonly_share_write: a read-only share.
mkdir -p /tmp/mxc-probe-ro
echo "host-provided read-only content" > /tmp/mxc-probe-ro/readme 2>/dev/null || true
# symlink_share_escape: a writable share, plus a secret OUTSIDE every share.
rm -rf /tmp/mxc-probe-rw && mkdir -p /tmp/mxc-probe-rw
mkdir -p /tmp/mxc-probe-outside
echo "MXC_HOST_SECRET" > /tmp/mxc-probe-outside/secret.txt
printf '  /tmp/mxc-probe-ro (ro share), /tmp/mxc-probe-rw (rw share), /tmp/mxc-probe-outside/secret.txt (escape target)\n'

WORKDIR="$(mktemp -d "${TMPDIR:-/tmp}/mxc-metal-probes.XXXXXX")"
trap 'rm -rf "$WORKDIR"' EXIT

# Check a probe's stdout/exit against its .expect contract. Sets `problems`.
check_expect() {
    local expect="$1" stdout_file="$2" code="$3"
    problems=""
    local expected_code first_line line sentinel
    expected_code=0
    first_line="$(head -n 1 "$expect" 2>/dev/null || true)"
    case "$first_line" in
        exitcode:*) expected_code="${first_line#exitcode:}" ;;
    esac
    if [ "$code" != "$expected_code" ]; then
        problems="${problems}exit=$code (want $expected_code); "
    fi
    while IFS= read -r line || [ -n "$line" ]; do
        case "$line" in
            ''|'#'*|exitcode:*) continue ;;
            '!'*)
                sentinel="${line#!}"
                if grep -F -q -- "$sentinel" "$stdout_file"; then
                    problems="${problems}forbidden '$sentinel' present; "
                fi
                ;;
            *)
                if ! grep -F -q -- "$line" "$stdout_file"; then
                    problems="${problems}missing '$line'; "
                fi
                ;;
        esac
    done < "$expect"
}

note "3. Probes (each boots a real VZ VM)"
for json in "$PROBES_DIR"/*.json; do
    name="$(basename "$json" .json)"
    base="${json%.json}"

    if [ -e "$base.reject" ]; then
        # Validation probe: vz-exec must REJECT the policy (exit != 0).
        "$VZ_EXEC" --experimental --dry-run "$json" >/dev/null 2>&1
        code=$?
        if [ "$code" != "0" ]; then
            ok "$name (validation rejected, exit $code — TM-04 fail-closed)"
        else
            bad "$name accepted a policy that must be rejected (validation opened)"
        fi
        continue
    fi

    if [ ! -f "$base.expect" ]; then
        bad "$name has neither .expect nor .reject"
        continue
    fi

    stdout_file="$WORKDIR/$name.stdout"
    stderr_file="$WORKDIR/$name.stderr"
    "$VZ_EXEC" --experimental --guest-image-dir "$GUEST_DIR" "$json" \
        >"$stdout_file" 2>"$stderr_file"
    code=$?

    check_expect "$base.expect" "$stdout_file" "$code"
    if [ -z "$problems" ]; then
        ok "$name (exit $code)"
    else
        bad "$name — $problems"
        echo "    --- probe stdout ---"
        sed 's/^/    /' "$stdout_file" | head -30
        if [ -s "$stderr_file" ]; then
            echo "    --- vz-exec stderr ---"
            sed 's/^/    /' "$stderr_file" | head -20
        fi
    fi
done

summary_and_exit
