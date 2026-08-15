#!/bin/bash
# Fetch a minimal Linux guest for the vz boot smoke test: Alpine's aarch64
# netboot kernel + initramfs. This is a Phase 2 stopgap — the real guest
# image pipeline (busybox + mxc guest agent, content-hash pinned) replaces it.
#
# Usage: ./scripts/fetch-alpine-guest.sh [dest-dir]
# Env:   ALPINE_VERSION (default v3.23)
#
# Produces in dest-dir (default ./guest):
#   vmlinux         - uncompressed ARM64 kernel Image (VZLinuxBootLoader input)
#   initramfs-virt  - initramfs as shipped (kernel unpacks it itself)
set -euo pipefail

ALPINE_VERSION="${ALPINE_VERSION:-v3.23}"
DEST="${1:-guest}"
BASE="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/releases/aarch64/netboot"

mkdir -p "$DEST"

fetch() {
    local url="$1" out="$2"
    echo "fetching $url"
    curl -fsSL --retry 3 --retry-delay 2 -o "$out" "$url" || {
        echo "error: download failed: $url" >&2
        exit 1
    }
    # Guard against CDN error pages saved as files.
    if [[ ! -s "$out" || $(stat -f%z "$out" 2>/dev/null || stat -c%s "$out") -lt 1000000 ]]; then
        echo "error: $out is implausibly small for a kernel/initramfs — bad URL or mirror?" >&2
        exit 1
    fi
}

fetch "$BASE/vmlinuz-virt" "$DEST/vmlinuz-virt.download"
fetch "$BASE/initramfs-virt" "$DEST/initramfs-virt"

# VZLinuxBootLoader wants a kernel it can load directly; normalize to an
# uncompressed ARM64 Image so we do not depend on the loader's gzip support.
if [[ "$(head -c2 "$DEST/vmlinuz-virt.download" | od -An -tx1 | tr -d ' \n')" == "1f8b" ]]; then
    echo "decompressing gzip kernel -> vmlinux"
    gunzip -c "$DEST/vmlinuz-virt.download" > "$DEST/vmlinux"
else
    echo "kernel is not gzip-compressed; using as-is"
    cp "$DEST/vmlinuz-virt.download" "$DEST/vmlinux"
fi
rm -f "$DEST/vmlinuz-virt.download"

# ARM64 Image magic: "ARM\x64" at byte offset 56.
if [[ "$(dd if="$DEST/vmlinux" bs=1 skip=56 count=4 2>/dev/null)" != $'ARM\x64' ]]; then
    echo "error: $DEST/vmlinux does not look like an ARM64 kernel Image (bad magic)" >&2
    exit 1
fi

echo
echo "guest artifacts in $DEST/ (sha256 for the record):"
shasum -a 256 "$DEST/vmlinux" "$DEST/initramfs-virt" 2>/dev/null \
    || sha256sum "$DEST/vmlinux" "$DEST/initramfs-virt"
echo
echo "run: target/debug/examples/boot_smoke $DEST/vmlinux $DEST/initramfs-virt"
