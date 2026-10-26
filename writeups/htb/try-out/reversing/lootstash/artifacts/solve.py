#!/usr/bin/env python3
"""lootstash: read the loot table from the stash binary without running it.

main() seeds rand() with time(NULL), takes one rand() value and prints
gear[(r % 2040) / 8]. The table is an array of 255 pointers in .data. Their
values are R_X86_64_RELATIVE relocations, so the strings are not in the file
at those slots. This script reads the relocation addends and dereferences them.
The flag is one of the 255 entries, and the program only prints it when the
seed picks that index.

usage: python3 solve.py <stash binary>
"""
import struct
import sys

R_X86_64_RELATIVE = 8
SHT_RELA = 4
PT_LOAD = 1
GEAR_VADDR = 0x7060  # gear[] in .data, found with nm; slots are 8 bytes each
GEAR_COUNT = 255     # index is (r % 2040) / 8, so 0..254


def load_segments(data):
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    segs = []
    for i in range(phnum):
        p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + i * phentsize)
        if p_type == PT_LOAD:
            segs.append((p_vaddr, p_filesz, p_offset))
    return segs


def vaddr_to_offset(segs, addr):
    for vaddr, filesz, offset in segs:
        if vaddr <= addr < vaddr + filesz:
            return addr - vaddr + offset
    raise SystemExit(f"address {addr:#x} is not in a loaded segment")


def relative_relocs(data):
    """Map r_offset -> addend for every R_X86_64_RELATIVE in .rela sections."""
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    relocs = {}
    for i in range(shnum):
        sh_type, = struct.unpack_from("<I", data, shoff + i * shentsize + 4)
        if sh_type != SHT_RELA:
            continue
        sh_offset, sh_size = struct.unpack_from("<QQ", data, shoff + i * shentsize + 24)
        for off in range(sh_offset, sh_offset + sh_size, 24):
            r_offset, r_info, r_addend = struct.unpack_from("<QQq", data, off)
            if r_info & 0xFFFFFFFF == R_X86_64_RELATIVE:
                relocs[r_offset] = r_addend
    return relocs


def read_cstring(data, segs, addr):
    off = vaddr_to_offset(segs, addr)
    return data[off:data.index(b"\0", off)].decode("latin1")


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <stash binary>", file=sys.stderr)
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        data = f.read()

    segs = load_segments(data)
    relocs = relative_relocs(data)
    for i in range(GEAR_COUNT):
        ptr = relocs.get(GEAR_VADDR + 8 * i)
        if ptr is None:
            continue
        entry = read_cstring(data, segs, ptr)
        if entry.startswith("HTB{"):
            print(f"[{i}] {entry}")
            return
    raise SystemExit("flag entry not found")


if __name__ == "__main__":
    main()
