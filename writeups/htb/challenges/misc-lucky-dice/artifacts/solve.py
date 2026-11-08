#!/usr/bin/env python3
"""Lucky Dice (HTB) - answer 100 rounds of "who rolled the most" fast enough.

Each round the server prints every player's dice, then asks who wins. The
solver sums the printed dice and answers at once, because the server rejects
answers that take longer than 0.3 seconds. A tie goes to the highest-numbered
player, matching the server's sorted(...)[-1] on a dict of sums.

Progress goes to stderr, so stdout carries only the flag.

Usage:
    python3 solve.py <target_ip> <target_port>
"""
import re
import socket
import sys

PLAYER_LINE = re.compile(rb"^Player (\d+): ([\d ]+)$", re.M)
ROUND_LINE = re.compile(rb"Round (\d+)")
FLAG = re.compile(rb"HTB\{[^}\r\n]*\}")
REJECTIONS = [
    b"too slow",
    b"scorring is off",
    b"Check your system",
]


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def read_until(sock, buf, marker):
    while marker not in buf:
        chunk = sock.recv(65536)
        if not chunk:
            raise EOFError(f"connection closed waiting for {marker!r}")
        buf += chunk
    idx = buf.index(marker) + len(marker)
    return buf[:idx], buf[idx:]


def sums_from(block):
    sums = {}
    for m in PLAYER_LINE.finditer(block):
        sums[int(m.group(1))] = sum(int(x) for x in m.group(2).split())
    return sums


def winner_from(sums):
    best = max(sums.values())
    return max(p for p, s in sums.items() if s == best)


def verdict_of(text):
    """Return the server's verdict for the previous answer, if it is in text."""
    for marker in REJECTIONS:
        if marker in text:
            return "rejected (" + marker.decode() + ")"
    if b"Correct" in text:
        return "correct"
    return None


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <target_ip> <target_port>", file=sys.stderr)
        return 2
    host, port = sys.argv[1], int(sys.argv[2])
    log(f"[*] connecting to {host}:{port}")
    sock = socket.create_connection((host, port), timeout=15)

    # Intro ends with the "Yes / No" prompt.
    block, buf = read_until(sock, b"", b"> ")
    log("[*] intro received, starting the game")
    sock.sendall(b"1\n")

    for rnd in range(100):
        block, buf = read_until(sock, buf, b"> ")

        # The verdict for the previous answer is printed before the next round.
        prev = verdict_of(block)
        if prev is not None:
            log(f"    server verdict for round {rnd}: {prev}")
            if prev != "correct":
                log("[-] answer rejected, stopping")
                return 1

        if b"Who wins this round?" not in block:
            log(f"[-] round {rnd + 1}: unexpected output {block[-200:]!r}")
            return 1

        header = ROUND_LINE.search(block)
        round_no = header.group(1).decode() if header else str(rnd + 1)
        sums = sums_from(block)
        winner = winner_from(sums)
        totals = ", ".join(f"P{p}={s}" for p, s in sorted(sums.items()))
        log(f"[+] round {round_no}/100: {len(sums)} players, {totals} -> answer {winner}")
        sock.sendall(str(winner).encode() + b"\n")

    # Last answer's verdict and the flag come after round 100.
    log("[*] all 100 answers sent, waiting for the flag")
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

    prev = verdict_of(tail)
    if prev is not None:
        log(f"    server verdict for round 100: {prev}")
    if prev not in (None, "correct"):
        log("[-] answer rejected, stopping")
        return 1

    match = FLAG.search(tail)
    if not match:
        log(f"[-] no flag in output: {tail[-300:]!r}")
        return 1
    log("[+] flag received")
    print(match.group(0).decode())
    return 0


if __name__ == "__main__":
    sys.exit(main())
