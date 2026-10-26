#!/usr/bin/env python3
"""flagcasino: recover the flag from the casino binary without running it.

main() reads 29 characters with scanf(" %c"). For each one it calls srand(c),
takes the first rand() and compares it with check[i]. c is loaded with movzx and
then movsx, so the seed is the signed char value. Each character is therefore the
one seed (out of 256) whose first rand() equals check[i].

glibc's rand() is reimplemented here, so the solver runs on any host.

usage: python3 solve.py <casino binary>
"""
import struct
import sys

COUNT = 29  # main() loops while i <= 0x1c
SHT_SYMTAB = 2
PT_LOAD = 1


def c_div(a, b):
    q = abs(a) // abs(b)
    return q if (a >= 0) == (b >= 0) else -q


def c_rem(a, b):
    return a - b * c_div(a, b)


def glibc_rand_first(seed):
    """First rand() after srand(seed) with glibc's TYPE_3 generator."""
    seed &= 0xFFFFFFFF
    if seed == 0:
        seed = 1
    word = struct.unpack("<i", struct.pack("<I", seed))[0]
    r = [word]
    for _ in range(1, 31):
        hi = c_div(word, 127773)
        lo = c_rem(word, 127773)
        word = 16807 * lo - 2836 * hi
        if word < 0:
            word += 2147483647
        r.append(word)
    for i in range(31, 34):
        r.append(r[i - 31])
    for i in range(34, 345):
        r.append((r[i - 31] + r[i - 3]) & 0xFFFFFFFF)
    return (r[344] & 0xFFFFFFFF) >> 1


def find_symbol(data, name):
    """Address of a symbol in .symtab (the binary is not stripped)."""
    shoff, = struct.unpack_from("<Q", data, 0x28)
    shentsize, shnum = struct.unpack_from("<HH", data, 0x3A)
    # sh_type is field 1, sh_offset field 4, sh_size field 5, sh_link field 6
    sections = [struct.unpack_from("<IIQQQQIIQQ", data, shoff + i * shentsize) for i in range(shnum)]
    for sh in sections:
        if sh[1] != SHT_SYMTAB:
            continue
        strtab = sections[sh[6]]
        for off in range(sh[4], sh[4] + sh[5], 24):
            st_name, _, _, _, st_value, _ = struct.unpack_from("<IBBHQQ", data, off)
            start = strtab[4] + st_name
            if data[start:data.index(b"\0", start)] == name.encode():
                return st_value
    raise SystemExit(f"symbol {name} not found")


def vaddr_to_offset(data, addr):
    phoff, = struct.unpack_from("<Q", data, 0x20)
    phentsize, phnum = struct.unpack_from("<HH", data, 0x36)
    for i in range(phnum):
        p_type, _, p_offset, p_vaddr, _, p_filesz, _, _ = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + i * phentsize)
        if p_type == PT_LOAD and p_vaddr <= addr < p_vaddr + p_filesz:
            return addr - p_vaddr + p_offset
    raise SystemExit(f"address {addr:#x} is not in a loaded segment")


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <casino binary>", file=sys.stderr)
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        data = f.read()

    check = struct.unpack_from(f"<{COUNT}i", data, vaddr_to_offset(data, find_symbol(data, "check")))

    flag = ""
    for i, target in enumerate(check):
        seeds = [c for c in range(-128, 128) if glibc_rand_first(c) == target]
        if len(seeds) != 1:
            raise SystemExit(f"index {i}: expected one seed, got {seeds}")
        flag += chr(seeds[0])
    print(flag)


if __name__ == "__main__":
    main()
