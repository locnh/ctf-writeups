#!/usr/bin/env python3
"""dont-panic: recover the flag from the Rust binary without running it.

check_flag() asserts the input is 31 bytes. Then, for each byte i, it calls
table[i](input[i]). Each table entry is a closure that compares the byte with a
constant K and panics if the byte is below K or above K. Only the exact byte K
returns without a panic, so the flag byte at index i is K.

This script reads the closure addresses from the stores in check_flag, then
reads the `cmp dil, K` immediate from each closure. It uses objdump for the
disassembly.

usage: python3 solve.py <dontpanic binary>
"""
import re
import subprocess
import sys

CHECK_FLAG_START = 0x9060  # _ZN3src10check_flag..., found with nm
CHECK_FLAG_END = 0x91F6
TABLE_BASE = 0x10          # closures are stored at [rsp + 0x10 + 8*i]
FLAG_LEN = 31


def disasm(binary, start, stop):
    out = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", "-M", "intel",
         f"--start-address={start}", f"--stop-address={stop}", binary],
        capture_output=True, text=True, check=True)
    return out.stdout.splitlines()


def closure_table(binary):
    """Map table index -> closure address, from check_flag's stores."""
    lea_target = {}
    table = {}
    for line in disasm(binary, CHECK_FLAG_START, CHECK_FLAG_END):
        m = re.search(r"lea\s+(\w+), \[rip [+-] 0x[0-9a-f]+\]\s+# (0x[0-9a-f]+)", line)
        if m:
            lea_target[m.group(1)] = int(m.group(2), 16)
            continue
        m = re.search(r"mov\s+qword ptr \[rsp \+ (0x[0-9a-f]+)\], (\w+)$", line)
        if m and m.group(2) in lea_target:
            off = int(m.group(1), 16)
            if off >= TABLE_BASE and (off - TABLE_BASE) % 8 == 0 and (off - TABLE_BASE) // 8 < FLAG_LEN:
                table[(off - TABLE_BASE) // 8] = lea_target[m.group(2)]
    if len(table) != FLAG_LEN:
        raise SystemExit(f"expected {FLAG_LEN} closures, found {len(table)}")
    return table


def expected_byte(binary, addr):
    """The constant K from the first `cmp dil, K` in a closure."""
    for line in disasm(binary, addr, addr + 0x20):
        m = re.search(r"cmp\s+dil, (0x[0-9a-f]+)", line)
        if m:
            return int(m.group(1), 16)
    raise SystemExit(f"no compare found in closure at {addr:#x}")


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <dontpanic binary>", file=sys.stderr)
        sys.exit(1)
    binary = sys.argv[1]
    table = closure_table(binary)
    flag = "".join(chr(expected_byte(binary, table[i])) for i in range(FLAG_LEN))
    print(flag)


if __name__ == "__main__":
    main()
