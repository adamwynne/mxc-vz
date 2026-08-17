#!/bin/bash
# Build the vz guest image (Phase 2): ARM64 kernel + initramfs with the mxc
# guest agent as init. Runs on any Linux/macOS host with Rust — no cross
# toolchain needed (rust-lld self-contained linking) and no cpio binary
# needed (python writer).
#
# Layers:
#   1. Alpine netboot kernel (normalized to a raw Image) + initramfs — the
#      Phase 2 stopgap base providing busybox and its userland.
#   2. Overlay cpio: /init (scripts/guest-init.sh) + /sbin/vz_guest_agent
#      (static aarch64-unknown-linux-musl build). Concatenated cpio.gz
#      segments are merged by the kernel with later files winning, so the
#      overlay's /init replaces Alpine's.
#
# Output in <dest> (default ./guest): vmlinux, initramfs.cpio.gz (the names
# vz_common::vm_spec expects) and manifest.json with sha256 content hashes
# (the host runner will validate these at boot).
#
# Usage: ./scripts/build-vz-guest.sh [dest-dir]
set -euo pipefail

cd "$(dirname "$0")/.."
DEST="${1:-guest}"
TARGET=aarch64-unknown-linux-musl

echo "== building static guest agent ($TARGET)"
rustup target add "$TARGET" >/dev/null 2>&1 || true
RUSTFLAGS="-C linker=rust-lld -C link-self-contained=yes -C target-feature=+crt-static" \
    cargo build -p vz_guest_agent --release --target "$TARGET"
AGENT="target/$TARGET/release/vz_guest_agent"

echo "== fetching alpine base (kernel + initramfs)"
./scripts/fetch-alpine-guest.sh "$DEST"

echo "== staging version-matched vsock modules (AF_VSOCK for the control channel)"
# Alpine's -virt initramfs ships no virtio-vsock module, so the guest kernel
# cannot open AF_VSOCK. The version-matched modules live in the netboot
# modloop-virt squashfs; pull just those three out with the dependency-free
# reader (macOS has no unsquashfs/xz). vermagic must match the pinned kernel.
ALPINE_VERSION="$(python3 -c "import json; print(json.load(open('scripts/guest-pins.json'))['alpine_version'])")"
NETBOOT="https://dl-cdn.alpinelinux.org/alpine/${ALPINE_VERSION}/releases/aarch64/netboot"
sha256_of() { shasum -a 256 "$1" 2>/dev/null | awk '{print $1}' || sha256sum "$1" | awk '{print $1}'; }
curl -fsSL --retry 3 --retry-delay 2 -o "$DEST/modloop-virt" "$NETBOOT/modloop-virt"
PIN="$(python3 -c "import json; print(json.load(open('scripts/guest-pins.json')).get('artifacts',{}).get('modloop-virt',{}).get('sha256',''))")"
GOT="$(sha256_of "$DEST/modloop-virt")"
if [ -n "$PIN" ]; then
    [ "$PIN" = "$GOT" ] || { echo "error: modloop-virt sha mismatch (pinned $PIN, got $GOT)" >&2; exit 1; }
    echo "modloop-virt pin verified"
else
    echo "modloop-virt sha256=$GOT (add to scripts/guest-pins.json artifacts['modloop-virt'] to pin)"
fi
python3 scripts/extract-modloop-modules.py "$DEST/modloop-virt" "$DEST/vsock-modules" \
    vsock.ko vmw_vsock_virtio_transport_common.ko vmw_vsock_virtio_transport.ko
rm -f "$DEST/modloop-virt"

echo "== building initramfs overlay"
python3 scripts/make-initramfs-overlay.py "$DEST/overlay.cpio" \
    "init=scripts/guest-init.sh:0755" \
    "sbin/vz_guest_agent=$AGENT:0755" \
    "lib/mxc-modules/vsock.ko=$DEST/vsock-modules/vsock.ko:0644" \
    "lib/mxc-modules/vmw_vsock_virtio_transport_common.ko=$DEST/vsock-modules/vmw_vsock_virtio_transport_common.ko:0644" \
    "lib/mxc-modules/vmw_vsock_virtio_transport.ko=$DEST/vsock-modules/vmw_vsock_virtio_transport.ko:0644"
rm -rf "$DEST/vsock-modules"
gzip -9 -n -c "$DEST/overlay.cpio" > "$DEST/overlay.cpio.gz"

echo "== assembling final initramfs"
cat "$DEST/initramfs-virt" "$DEST/overlay.cpio.gz" > "$DEST/initramfs.cpio.gz"
rm -f "$DEST/overlay.cpio" "$DEST/overlay.cpio.gz" "$DEST/initramfs-virt"

echo "== writing manifest"
python3 - "$DEST" <<'PY'
import hashlib, json, os, sys
dest = sys.argv[1]
manifest = {"files": {}}
for name in ("vmlinux", "initramfs.cpio.gz"):
    path = os.path.join(dest, name)
    digest = hashlib.sha256(open(path, "rb").read()).hexdigest()
    manifest["files"][name] = {"sha256": digest, "bytes": os.path.getsize(path)}
with open(os.path.join(dest, "manifest.json"), "w") as f:
    json.dump(manifest, f, indent=2, sort_keys=True)
print(json.dumps(manifest, indent=2, sort_keys=True))
PY

echo
echo "guest image ready in $DEST/ (vmlinux + initramfs.cpio.gz + manifest.json)"
