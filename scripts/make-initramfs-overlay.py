#!/usr/bin/env python3
"""Write a newc-format cpio archive for the vz guest initramfs overlay.

Used by build-vz-guest.sh because a `cpio` binary is not guaranteed on build
hosts. The kernel unpacks concatenated cpio.gz segments in order, with later
entries overwriting earlier ones — this overlay rides on top of the Alpine
netboot initramfs and replaces /init.

Usage: make-initramfs-overlay.py <output.cpio> <spec>...
  spec: dest=source[:mode]   e.g. init=guest-init.sh:0755
"""

import sys


def newc_entry(name: str, mode: int, body: bytes, ino: int) -> bytes:
    name_bytes = name.encode() + b"\x00"
    header = (
        b"070701"
        + f"{ino:08X}".encode()          # inode
        + f"{mode:08X}".encode()          # mode
        + b"00000000" * 2                  # uid, gid (root)
        + f"{1:08X}".encode()             # nlink
        + b"00000000"                      # mtime (0: reproducible)
        + f"{len(body):08X}".encode()     # filesize
        + b"00000000" * 4                  # devmajor/minor, rdevmajor/minor
        + f"{len(name_bytes):08X}".encode()
        + b"00000000"                      # checksum (none for 070701)
    )
    out = header + name_bytes
    out += b"\x00" * ((4 - len(out) % 4) % 4)   # pad header+name to 4
    out += body
    out += b"\x00" * ((4 - len(body) % 4) % 4)  # pad body to 4
    return out


def main() -> None:
    if len(sys.argv) < 3:
        sys.exit(__doc__)
    output, specs = sys.argv[1], sys.argv[2:]

    archive = b""
    ino = 100
    seen_dirs: list[str] = []
    for spec in specs:
        dest, _, rest = spec.partition("=")
        source, _, mode_text = rest.partition(":")
        mode = int(mode_text or "0644", 8)

        # Parent directories (0755), each exactly once.
        parts = dest.split("/")[:-1]
        for depth in range(1, len(parts) + 1):
            directory = "/".join(parts[:depth])
            if directory and directory not in seen_dirs:
                seen_dirs.append(directory)
                archive += newc_entry(directory, 0o040755, b"", ino)
                ino += 1

        with open(source, "rb") as f:
            body = f.read()
        archive += newc_entry(dest, 0o100000 | mode, body, ino)
        ino += 1

    archive += newc_entry("TRAILER!!!", 0, b"", 0)
    with open(output, "wb") as f:
        f.write(archive)
    print(f"wrote {output}: {len(archive)} bytes, {len(specs)} files")


if __name__ == "__main__":
    main()
