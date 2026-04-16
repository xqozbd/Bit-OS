#!/usr/bin/env python3
import os
import stat
import sys


def pad4(f, size):
    rem = size % 4
    if rem:
        f.write(b"\0" * (4 - rem))


def write_entry(f, name, st_mode, st_mtime, data):
    namesz = len(name) + 1
    filesize = len(data)
    fields = [
        "070701",
        f"{0:08x}",  # ino
        f"{st_mode & 0xFFFFFFFF:08x}",
        f"{0:08x}",  # uid
        f"{0:08x}",  # gid
        f"{1:08x}",  # nlink
        f"{int(st_mtime) & 0xFFFFFFFF:08x}",
        f"{filesize:08x}",
        f"{0:08x}",  # devmajor
        f"{0:08x}",  # devminor
        f"{0:08x}",  # rdevmajor
        f"{0:08x}",  # rdevminor
        f"{namesz:08x}",
        f"{0:08x}",  # check
    ]
    f.write("".join(fields).encode("ascii"))
    f.write(name.encode("utf-8") + b"\0")
    pad4(f, 110 + namesz)
    if data:
        f.write(data)
    pad4(f, filesize)


def rel_name(root, path):
    rel = os.path.relpath(path, root)
    if rel == ".":
        return "."
    return "./" + rel.replace("\\", "/")


def main():
    if len(sys.argv) != 3:
        print("usage: mkinitramfs.py <root> <out>", file=sys.stderr)
        return 1
    root, out = sys.argv[1], sys.argv[2]
    entries = []
    for cur, dirs, files in os.walk(root):
        dirs.sort()
        files.sort()
        entries.append(cur)
        for fn in files:
            entries.append(os.path.join(cur, fn))
    with open(out, "wb") as f:
        for path in entries:
            st = os.lstat(path)
            name = rel_name(root, path)
            if stat.S_ISDIR(st.st_mode):
                data = b""
            elif stat.S_ISREG(st.st_mode):
                with open(path, "rb") as rf:
                    data = rf.read()
            else:
                continue
            write_entry(f, name, st.st_mode, st.st_mtime, data)
        write_entry(f, "TRAILER!!!", stat.S_IFREG, 0, b"")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
