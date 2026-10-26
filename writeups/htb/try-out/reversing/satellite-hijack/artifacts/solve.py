#!/usr/bin/env python3
"""satellite-hijack: recover the flag from library.so without running it.

library.so hides a routine in its .text: the 4 KiB at vaddr 0x11a9 is XOR-ed
with 0x2a (memfrob) when SAT_PROD_ENVIRONMENT is set. The decoded routine
checks the 28 bytes after "HTB{" in a message. Each byte must satisfy
input[i] == key[i] ^ i, where key is built on the stack from a few movabs
immediates. The flag is "HTB{" + those 28 bytes.

This script decodes the blob, reads the stack stores that build the key, and
prints the flag. It does not run the binary.

usage: python3 solve.py <library.so>
"""
import struct
import sys

BLOB_VADDR = 0x11A9   # start of the XOR-ed region, from send_satellite_message's helper
BLOB_SIZE = 0x1000
XOR_KEY = 0x2A        # memfrob
CHECK_OFFSET = 0x8C   # the check routine inside the decoded blob
KEY_LEN = 28          # the check loops while i != 0x1c


def file_offset(data, vaddr):
    # .text in this library has vaddr == file offset, so no translation is needed
    return vaddr


def decode_blob(data):
    start = file_offset(data, BLOB_VADDR)
    return bytes(b ^ XOR_KEY for b in data[start:start + BLOB_SIZE])


def build_key(blob):
    """Replay the stack stores that build the key at [rsp - 0x28]."""
    mem = {}
    regs = {}
    pos = CHECK_OFFSET
    while pos < len(blob):
        op = blob[pos:pos + 2]
        if op in (b"\x48\xb8", b"\x48\xba"):  # movabs rax / rdx, imm64
            regs["rax" if op == b"\x48\xb8" else "rdx"] = struct.unpack_from("<Q", blob, pos + 2)[0]
            pos += 10
        elif blob[pos:pos + 4] in (b"\x48\x89\x44\x24", b"\x48\x89\x54\x24"):  # mov [rsp+d8], rax / rdx
            reg = "rax" if blob[pos + 2] == 0x44 else "rdx"
            disp = struct.unpack("<b", blob[pos + 4:pos + 5])[0]
            value = regs[reg]
            base = disp + 0x28  # key starts at rsp-0x28
            for i in range(8):
                mem[base + i] = (value >> (8 * i)) & 0xFF
            pos += 5
        else:
            break  # end of the key stores (the next instruction is mov eax, 0)
    return bytes(mem.get(i, 0) for i in range(KEY_LEN))


def main():
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <library.so>", file=sys.stderr)
        sys.exit(1)
    with open(sys.argv[1], "rb") as f:
        data = f.read()
    key = build_key(decode_blob(data))
    inner = bytes(k ^ i for i, k in enumerate(key))
    print("HTB{" + inner.decode("latin1"))


if __name__ == "__main__":
    main()
