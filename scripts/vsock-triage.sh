#!/bin/bash
# One-shot, read-only triage for the guest AF_VSOCK gap (no rebuild, no boot).
#
# The metal run showed the guest kernel panics because socket(AF_VSOCK) returns
# EAFNOSUPPORT — Alpine's -virt initramfs does not ship the virtio-vsock
# modules. This script gathers the exact facts needed to bundle the
# version-matched modules into the guest image: the kernel version, whether the
# base initramfs already carries any vsock module, which host tools are
# available to unpack them, and — from the version-matched Alpine sources — the
# real module filenames and their compression.
#
# Run from the repo root on the Mac (after ./scripts/build-vz-guest.sh guest,
# so guest/ exists). Paste the whole output back.
set -uo pipefail
cd "$(dirname "$0")/.."

GUEST_DIR="${1:-guest}"
ALPINE_VERSION="$(python3 -c "import json; print(json.load(open('scripts/guest-pins.json'))['alpine_version'])" 2>/dev/null || echo v3.23)"
ARCH=aarch64
BASE="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/main/${ARCH}"
NETBOOT="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/releases/${ARCH}/netboot"

echo "== 1. kernel version (module dir) from the built initramfs"
KVER=""
if [ -f "$GUEST_DIR/initramfs.cpio.gz" ]; then
    KVER="$(gzip -dc "$GUEST_DIR/initramfs.cpio.gz" 2>/dev/null | cpio -it 2>/dev/null \
        | sed -n 's#.*lib/modules/\([^/]*\)/.*#\1#p' | head -1)"
fi
echo "   KVER=${KVER:-<unknown>}"

echo "== 2. does the base initramfs already carry any vsock module?"
if [ -f "$GUEST_DIR/initramfs.cpio.gz" ]; then
    hits="$(gzip -dc "$GUEST_DIR/initramfs.cpio.gz" 2>/dev/null | cpio -it 2>/dev/null | grep -i vsock || true)"
    if [ -n "$hits" ]; then echo "$hits" | sed 's/^/   /'; else echo "   (none — confirms the gap)"; fi
else
    echo "   $GUEST_DIR/initramfs.cpio.gz not found — run ./scripts/build-vz-guest.sh $GUEST_DIR first"
fi

echo "== 3. host tools available for unpacking modules"
for t in gzip gunzip xz unxz zstd unzstd unsquashfs tar cpio curl; do
    printf '   %-12s ' "$t:"; command -v "$t" >/dev/null 2>&1 && command -v "$t" || echo MISSING
done

echo "== 4. version-matched linux-virt APK: module filenames + compression"
# Map module dir (e.g. 6.18.36-0-virt) -> apk pkgver (6.18.36-r0).
APKVER="$(printf '%s' "${KVER:-}" | sed -E 's/-virt$//; s/-([0-9]+)$/-r\1/')"
echo "   derived APKVER=${APKVER:-<unknown>}  (URL: $BASE/linux-virt-${APKVER}.apk)"
tmp="$(mktemp -d)"
if [ -n "$APKVER" ] && curl -fsSL "$BASE/linux-virt-${APKVER}.apk" -o "$tmp/lv.apk" 2>/dev/null; then
    echo "   fetched linux-virt-${APKVER}.apk ($(wc -c < "$tmp/lv.apk") bytes)"
    ( cd "$tmp" && tar xf lv.apk 2>/dev/null || tar xzf lv.apk 2>/dev/null )
    found="$(find "$tmp" -path '*vmw_vsock*' -o -name 'vsock.ko*' 2>/dev/null)"
    if [ -n "$found" ]; then
        echo "$found" | sed "s#$tmp/##; s/^/   ko: /"
    else
        echo "   no vsock modules found in the extracted APK (tar may not handle the apk multi-stream here)"
        echo "   top-level entries:"; find "$tmp" -maxdepth 2 -type d | sed "s#$tmp#   #" | head
    fi
else
    echo "   could not fetch the APK (network policy? version moved on the mirror?)"
fi

echo "== 5. is the version-matched modloop-virt available? (squashfs, needs unsquashfs)"
if curl -fsSIL "$NETBOOT/modloop-virt" >/dev/null 2>&1; then
    echo "   modloop-virt is reachable at $NETBOOT/modloop-virt"
else
    echo "   modloop-virt not reachable"
fi

rm -rf "$tmp"
echo "== triage complete — paste the whole output back =="
