#!/usr/bin/env python3
"""Extract named kernel modules from an Alpine `modloop-virt` squashfs image.

Alpine's `-virt` netboot initramfs does not ship the virtio-vsock modules, so
the guest kernel can't create AF_VSOCK sockets (the host<->guest control
channel). The version-matched modules DO live in the netboot `modloop-virt`
squashfs, but macOS has no `unsquashfs`/`xz`/`zstd`/`brew`. This is a
dependency-free reader (Python stdlib only: `zlib` for gzip, `lzma` for xz)
that pulls just the requested module files out of a SquashFS 4.0 image.

Usage:
    extract-modloop-modules.py <modloop.squashfs> <out-dir> <name.ko> [<name.ko> ...]

It walks the whole directory tree and extracts every file whose basename
matches one of the requested names (module names are unique across the tree,
so a plain name match is enough and is robust to layout differences). Exits
non-zero if any requested module is not found.

Only the SquashFS features Alpine's modloop actually uses are implemented:
version 4.0, gzip or xz block compression, basic/extended directory and file
inodes, and tail fragments (small files — every vsock .ko is one block or
less, so it lives entirely in a fragment).
"""

import lzma
import os
import struct
import sys
import zlib

SQUASHFS_MAGIC = 0x73717368
META_UNCOMPRESSED = 0x8000
SIZE_MASK = 0x7FFF
BLOCK_UNCOMPRESSED = 0x1000000  # bit 24 in a block/fragment size word
NO_FRAGMENT = 0xFFFFFFFF

# Inode types (SquashFS 4.0).
INODE_DIR = 1
INODE_FILE = 2
INODE_SYMLINK = 3
INODE_LDIR = 8  # extended directory
INODE_LFILE = 9  # extended file


class Squashfs:
    def __init__(self, path):
        self.f = open(path, "rb")
        sb = self.f.read(96)
        if len(sb) < 96:
            raise SystemExit("not a squashfs: file too small")
        (self.magic, self.inode_count, self.mtime, self.block_size,
         self.frag_count, self.comp, self.block_log, self.flags,
         self.id_count, self.ver_maj, self.ver_min) = struct.unpack("<IIIIIHHHHHH", sb[:32])
        (self.root_ref, self.bytes_used, self.id_table, self.xattr_table,
         self.inode_table, self.dir_table, self.frag_table,
         self.export_table) = struct.unpack("<QQQQQQQQ", sb[32:96])

        if self.magic != SQUASHFS_MAGIC:
            raise SystemExit("bad squashfs magic 0x%08x" % self.magic)
        if self.ver_maj != 4:
            raise SystemExit("unsupported squashfs version %d.%d" % (self.ver_maj, self.ver_min))
        if self.comp == 1:
            self._decomp = zlib.decompress
        elif self.comp == 4:
            self._decomp = lzma.decompress
        else:
            raise SystemExit("unsupported squashfs compression id %d (need gzip=1 or xz=4)" % self.comp)

        self._meta_cache = {}

    # -- metadata (inode/dir/fragment tables): 8 KiB blocks, 2-byte framed --

    def _read_metadata_block(self, offset):
        cached = self._meta_cache.get(offset)
        if cached is not None:
            return cached
        self.f.seek(offset)
        hdr = struct.unpack("<H", self.f.read(2))[0]
        size = hdr & SIZE_MASK
        raw = self.f.read(size)
        data = raw if (hdr & META_UNCOMPRESSED) else self._decomp(raw)
        result = (data, offset + 2 + size)
        self._meta_cache[offset] = result
        return result

    def _read_meta(self, table_start, block_off, in_off, nbytes):
        """Decompressed bytes: skip `block_off` compressed bytes from
        table_start, then `in_off` decompressed bytes, return `nbytes`."""
        pos = table_start + block_off
        buf = b""
        while len(buf) < in_off + nbytes:
            block, pos = self._read_metadata_block(pos)
            if not block:
                break
            buf += block
        return buf[in_off:in_off + nbytes]

    # -- fragments (tails of small files) --

    def _fragment(self, index):
        # Indirect table: ceil(frag_count/512) u64 pointers at frag_table.
        ptr_count = (self.frag_count + 511) // 512
        self.f.seek(self.frag_table)
        pointers = struct.unpack("<%dQ" % ptr_count, self.f.read(8 * ptr_count))
        block_ptr = pointers[index // 512]
        entries, _ = self._read_metadata_block(block_ptr)
        off = (index % 512) * 16
        start, size, _unused = struct.unpack("<QII", entries[off:off + 16])
        return start, size

    def _read_data_block(self, offset, size_word):
        size = size_word & 0xFFFFFF
        if size == 0:
            return b""  # sparse hole
        self.f.seek(offset)
        raw = self.f.read(size)
        if size_word & BLOCK_UNCOMPRESSED:
            return raw
        return self._decomp(raw)

    # -- inode parsing --

    def _inode_at(self, ref):
        block_off = (ref >> 16) & 0xFFFFFFFF
        in_off = ref & 0xFFFF
        header = self._read_meta(self.inode_table, block_off, in_off, 16)
        itype, perm, uid, gid, mtime, inum = struct.unpack("<HHHHII", header)
        return itype, block_off, in_off

    def read_file(self, block_off, in_off, ext):
        """Return the full contents of a (basic/extended) file inode."""
        if ext:
            hdr = self._read_meta(self.inode_table, block_off, in_off, 16 + 40)
            (blocks_start, file_size, sparse, nlink, frag_index, frag_off,
             xattr) = struct.unpack("<QQQIIII", hdr[16:16 + 40])
            sizes_off = 16 + 40
        else:
            hdr = self._read_meta(self.inode_table, block_off, in_off, 16 + 16)
            blocks_start, frag_index, frag_off, file_size = struct.unpack("<IIII", hdr[16:16 + 16])
            sizes_off = 16 + 16

        has_frag = frag_index != NO_FRAGMENT
        if has_frag:
            n_full = file_size // self.block_size
        else:
            n_full = (file_size + self.block_size - 1) // self.block_size

        raw = self._read_meta(self.inode_table, block_off, in_off, sizes_off + 4 * n_full)
        block_sizes = struct.unpack("<%dI" % n_full, raw[sizes_off:sizes_off + 4 * n_full])

        out = b""
        pos = blocks_start
        for sw in block_sizes:
            out += self._read_data_block(pos, sw)
            pos += sw & 0xFFFFFF
        if has_frag:
            fstart, fsize = self._fragment(frag_index)
            frag_data = self._read_data_block(fstart, fsize)
            tail = file_size - len(out)
            out += frag_data[frag_off:frag_off + tail]
        return out[:file_size]

    # -- directory walk --

    def _dir_listing(self, block_off, in_off, ext):
        if ext:
            hdr = self._read_meta(self.inode_table, block_off, in_off, 16 + 24)
            (nlink, file_size, start_block, parent, idx_count, blk_off,
             xattr) = struct.unpack("<IIIIHHI", hdr[16:16 + 24])
        else:
            hdr = self._read_meta(self.inode_table, block_off, in_off, 16 + 16)
            start_block, nlink, file_size, blk_off, parent = struct.unpack("<IIHHI", hdr[16:16 + 16])

        # The listing size counts a phantom 3 bytes; the real bytes are size-3.
        listing = self._read_meta(self.dir_table, start_block, blk_off, max(file_size - 3, 0))

        entries = []
        p = 0
        while p + 12 <= len(listing):
            count, start_blk, inode_base = struct.unpack("<III", listing[p:p + 12])
            p += 12
            for _ in range(count + 1):
                if p + 8 > len(listing):
                    break
                e_off, e_inode_delta, e_type, name_size = struct.unpack("<hhHH", listing[p:p + 8])
                p += 8
                name = listing[p:p + name_size + 1].decode("utf-8", "replace")
                p += name_size + 1
                ref = (start_blk << 16) | (e_off & 0xFFFF)
                entries.append((name, e_type, ref))
        return entries

    def walk_extract(self, wanted, out_dir):
        found = {}
        self.seen_names = set()  # every file basename, for diagnostics
        # Root inode ref is (block<<16 | offset) already in root_ref.
        stack = [self.root_ref]
        seen = set()
        while stack:
            ref = stack.pop()
            if ref in seen:
                continue
            seen.add(ref)
            itype, block_off, in_off = self._inode_at(ref)
            if itype in (INODE_DIR, INODE_LDIR):
                for name, e_type, child in self._dir_listing(block_off, in_off, itype == INODE_LDIR):
                    if e_type in (INODE_DIR, INODE_LDIR):
                        stack.append(child)
                    elif e_type in (INODE_FILE, INODE_LFILE):
                        self.seen_names.add(name)
                        if name in wanted and name not in found:
                            c_type, c_bo, c_io = self._inode_at(child)
                            data = self.read_file(c_bo, c_io, c_type == INODE_LFILE)
                            dst = os.path.join(out_dir, name)
                            with open(dst, "wb") as fh:
                                fh.write(data)
                            found[name] = (dst, len(data))
        return found


def main():
    if len(sys.argv) < 4:
        sys.exit(__doc__)
    modloop, out_dir = sys.argv[1], sys.argv[2]
    wanted = set(sys.argv[3:])
    os.makedirs(out_dir, exist_ok=True)
    sq = Squashfs(modloop)
    found = sq.walk_extract(wanted, out_dir)
    for name in sorted(wanted):
        if name in found:
            dst, size = found[name]
            print("extracted %s (%d bytes) -> %s" % (name, size, dst))
        else:
            print("NOT FOUND: %s" % name)
    missing = wanted - set(found)
    if missing:
        hints = sorted(n for n in getattr(sq, "seen_names", set()) if "vsock" in n.lower())
        if hints:
            print("vsock-ish files present in the image: %s" % ", ".join(hints))
        else:
            print("no vsock-named files in the image at all")
        sys.exit("missing modules: %s" % ", ".join(sorted(missing)))


if __name__ == "__main__":
    main()
