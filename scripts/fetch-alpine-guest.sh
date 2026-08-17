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
#
# Kernel normalization: VZLinuxBootLoader needs a raw (or gzip) ARM64 Image.
# Modern arm64 distro kernels (Alpine 3.23 included) ship as an EFI zboot PE
# ("MZ" + "zimg" magic, compressed payload at an offset in the header), which
# the loader cannot read — so we unwrap gzip and zboot layers until we reach
# the raw Image, and verify its "ARM\x64" magic at offset 56.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PINS_FILE="$SCRIPT_DIR/guest-pins.json"

# The Alpine branch comes from the pins file (so the bump workflow controls
# it) unless overridden via env.
if [[ -z "${ALPINE_VERSION:-}" && -f "$PINS_FILE" ]]; then
    ALPINE_VERSION="$(python3 -c "import json,sys; print(json.load(open(sys.argv[1]))['alpine_version'])" "$PINS_FILE")"
fi
ALPINE_VERSION="${ALPINE_VERSION:-v3.23}"
DEST="${1:-guest}"
BASE="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/releases/aarch64/netboot"

mkdir -p "$DEST"

file_size() {
    stat -f%z "$1" 2>/dev/null || stat -c%s "$1"
}

fetch() {
    local url="$1" out="$2"
    echo "fetching $url"
    curl -fsSL --retry 3 --retry-delay 2 -o "$out" "$url" || {
        echo "error: download failed: $url" >&2
        exit 1
    }
    # Guard against CDN error pages saved as files.
    if [[ ! -s "$out" || $(file_size "$out") -lt 1000000 ]]; then
        echo "error: $out is implausibly small for a kernel/initramfs — bad URL or mirror?" >&2
        exit 1
    fi
}

hex_at() {
    # hex of $3 bytes at offset $2 of file $1
    dd if="$1" bs=1 skip="$2" count="$3" 2>/dev/null | od -An -tx1 | tr -d ' \n'
}

# Unwrap kernel container formats until we reach a raw ARM64 Image. Each
# level unwraps into its own temp file (recursing with a shared name would
# make a nested unwrap read and write the same file).
normalize_kernel() {
    local src="$1" out="$2" tmp
    tmp="$(mktemp "${out}.XXXXXX")"
    if [[ "$(hex_at "$src" 0 2)" == "1f8b" ]]; then
        echo "unwrapping gzip layer"
        gunzip -c "$src" > "$tmp"
        normalize_kernel "$tmp" "$out"
        rm -f "$tmp"
        return
    fi
    if [[ "$(hex_at "$src" 4 4)" == "7a696d67" ]]; then  # "zimg"
        echo "unwrapping EFI zboot layer"
        python3 - "$src" "$tmp" <<'PY'
import struct, sys
src, out = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()
assert data[4:8] == b"zimg", "not an EFI zboot image"
offset, size = struct.unpack_from("<II", data, 8)
assert 0 < offset < len(data) and 0 < size <= len(data) - offset, "bad zboot payload bounds"
open(out, "wb").write(data[offset:offset + size])
PY
        normalize_kernel "$tmp" "$out"
        rm -f "$tmp"
        return
    fi
    if [[ "$(hex_at "$src" 0 4)" == "28b52ffd" ]]; then
        echo "unwrapping zstd layer"
        zstd -dc "$src" > "$tmp" || {
            echo "error: kernel payload is zstd-compressed but zstd is not installed" >&2
            exit 1
        }
        normalize_kernel "$tmp" "$out"
        rm -f "$tmp"
        return
    fi
    rm -f "$tmp"
    cp "$src" "$out"
}

fetch "$BASE/vmlinuz-virt" "$DEST/vmlinuz-virt.download"
fetch "$BASE/initramfs-virt" "$DEST/initramfs-virt"

# modloop-virt (the full module squashfs) is large and only the guest-image
# build needs it (for the virtio-vsock modules absent from initramfs-virt), so
# it is fetched only when FETCH_MODLOOP=1. When fetched it is pinned as a
# first-class artifact alongside the kernel/initramfs so bumps keep all three
# in lockstep; otherwise its existing pin is preserved untouched.
if [[ "${FETCH_MODLOOP:-0}" == "1" ]]; then
    fetch "$BASE/modloop-virt" "$DEST/modloop-virt"
fi

normalize_kernel "$DEST/vmlinuz-virt.download" "$DEST/vmlinux"
rm -f "$DEST/vmlinuz-virt.download"

# ARM64 Image magic: "ARM\x64" (41 52 4d 64) at byte offset 56.
if [[ "$(hex_at "$DEST/vmlinux" 56 4)" != "41524d64" ]]; then
    echo "error: $DEST/vmlinux does not look like an ARM64 kernel Image (bad magic)" >&2
    echo "first bytes: $(hex_at "$DEST/vmlinux" 0 64)" >&2
    exit 1
fi

echo
echo "guest artifacts in $DEST/ (sha256 for the record):"
shasum -a 256 "$DEST/vmlinux" "$DEST/initramfs-virt" 2>/dev/null \
    || sha256sum "$DEST/vmlinux" "$DEST/initramfs-virt"

# Supply-chain pinning (TM-08): the fetched artifacts must match
# scripts/guest-pins.json exactly, so Alpine point releases cannot change
# our image silently — updates are deliberate, CI-validated bump PRs (see
# .github/workflows/guest-image-bump.yml). GUEST_PINS_UPDATE=1 rewrites the
# pins from what was just fetched (used by the bump workflow).
python3 - "$PINS_FILE" "$DEST" "$ALPINE_VERSION" "${GUEST_PINS_UPDATE:-0}" <<'PY'
import hashlib, json, os, sys
pins_file, dest, version, update = sys.argv[1:5]

# The artifacts fetched this run (modloop only when FETCH_MODLOOP=1 asked for
# it). Only these are hashed/verified; any others already pinned are preserved.
managed = ["vmlinux", "initramfs-virt", "modloop-virt"]
current = {
    name: hashlib.sha256(open(os.path.join(dest, name), "rb").read()).hexdigest()
    for name in managed
    if os.path.exists(os.path.join(dest, name))
}

if update == "1":
    existing = {}
    if os.path.exists(pins_file):
        existing = json.load(open(pins_file)).get("artifacts", {})
    # Merge: refresh what we fetched, preserve the rest (e.g. modloop-virt on a
    # kernel-only run, or vice versa) so no pinned artifact is silently dropped.
    existing.update({n: {"sha256": h} for n, h in current.items()})
    with open(pins_file, "w") as f:
        json.dump({"alpine_version": version, "artifacts": existing}, f, indent=2)
        f.write("\n")
    print(f"pins updated: {pins_file} ({', '.join(sorted(current))})")
elif os.path.exists(pins_file):
    pinned = json.load(open(pins_file))["artifacts"]
    mismatches = [
        f"  {name}: pinned {pinned[name]['sha256']}\n"
        f"           fetched {digest}"
        for name, digest in current.items()
        if pinned.get(name, {}).get("sha256") != digest
    ]
    if mismatches:
        print("error: fetched guest artifacts do not match scripts/guest-pins.json:",
              file=sys.stderr)
        print("\n".join(mismatches), file=sys.stderr)
        print("Alpine likely published a point release. Update deliberately via the\n"
              "'guest image bump' workflow (or GUEST_PINS_UPDATE=1 locally) so CI\n"
              "re-validates the new artifacts.", file=sys.stderr)
        sys.exit(1)
    print(f"pins verified: artifacts match scripts/guest-pins.json ({', '.join(sorted(current))})")
PY

echo
echo "run: target/debug/examples/boot_smoke $DEST/vmlinux $DEST/initramfs-virt"
