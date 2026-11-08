#!/usr/bin/env python3
"""Lucky Dice (HTB) - answer 100 rounds of "who rolled the most" fast enough.

Each round the server prints every player's dice, then asks who wins. The
solver sums the printed dice and answers at once, because the server rejects
answers that take longer than 0.3 seconds. A tie goes to the highest-numbered
player, matching the server's sorted(...)[-1] on a dict of sums.

Usage:
    python3 solve.py <target_ip> <target_port>
"""
import re
import socket
import sys

PLAYER_LINE = re.compile(rb"^Player (\d+): ([\d ]+)$", re.M)
FLAG = re.compile(rb"HTB\{[^}\r\n]*\}")


def read_until(sock, buf, marker):
    while marker not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise EOFError(f"connection closed waiting for {marker!r}")
        buf += chunk
    idx = buf.index(marker) + len(marker)
    return buf[:idx], buf[idx:]


def winner_from(block):
    sums = {}
    for m in PLAYER_LINE.finditer(block):
        sums[int(m.group(1))] = sum(int(x) for x in m.group(2).split())
    best = max(sums.values())
    return max(p for p, s in sums.items() if s == best)


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <target_ip> <target_port>", file=sys.stderr)
        return 2
    sock = socket.create_connection((sys.argv[1], int(sys.argv[2])), timeout=15)

    # Intro ends with the "Yes / No" prompt.
    block, buf = read_until(sock, b"", b"> ")
    sock.sendall(b"1\n")

    for rnd in range(100):
        block, buf = read_until(sock, buf, b"> ")
        if b"Who wins this round?" not in block:
            print(f"[-] round {rnd + 1}: unexpected output {block[-200:]!r}", file=sys.stderr)
            return 1
        sock.sendall(str(winner_from(block)).encode() + b"\n")

    # Drain the rest of the output: the last answer's result and the flag.
    # A wrong answer prints one of the rejection messages instead of a flag.
    sock.settimeout(3)
    tail = buf
    try:
        while True:
            chunk = sock.recv(65536)
            if not chunk:
                break
            tail += chunk
    except socket.timeout:
        pass

    if b"Check your system" in tail or b"scorring is off" in tail:
        print(f"[-] answer rejected: {tail[-300:]!r}", file=sys.stderr)
        return 1
    match = FLAG.search(tail)
    if not match:
        print(f"[-] no flag in output: {tail[-300:]!r}", file=sys.stderr)
        return 1
    print(match.group(0).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
