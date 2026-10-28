#!/usr/bin/env python3
import hashlib
import re
import socket
import sys

# The custom hash maps each byte with ((b >> 4) | (b << 3)) & 0xff before SHA-256.
# The two shifted parts overlap at bit 3, so different bytes can map to the same value.
# Changing one byte to a partner with the same mapped value keeps the digest and
# changes the message, which is what the server checks.

ORIGINAL = b"ready_play_one!"


def rotate(b):
    return ((b >> 4) | (b << 3)) & 0xFF


def digest(message):
    return hashlib.sha256(bytes(rotate(b) for b in message)).hexdigest()


def collision_for(index, original):
    target = rotate(original[index])
    for cand in range(256):
        if cand != original[index] and rotate(cand) == target:
            forged = bytearray(original)
            forged[index] = cand
            return bytes(forged)
    return None


def forge(original_digest):
    for index in range(len(ORIGINAL)):
        forged = collision_for(index, ORIGINAL)
        if forged is not None and digest(forged) == original_digest:
            return forged
    return None


def exchange(host, port):
    with socket.create_connection((host, int(port)), timeout=10) as sock:
        conn = sock.makefile("rw", encoding="utf-8", newline="\n")
        line = conn.readline()
        match = re.search(r"[0-9a-f]{64}", line)
        if not match:
            raise SystemExit(f"[!] No digest in server banner: {line!r}")
        original_digest = match.group(0)

        forged = forge(original_digest)
        if forged is None:
            raise SystemExit("[!] No single-byte collision found")

        conn.write(forged.hex() + "\n")
        conn.flush()
        return conn.readline().strip()


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <target_ip> <target_port>", file=sys.stderr)
        sys.exit(1)

    response = exchange(sys.argv[1], sys.argv[2])
    print(f"[+] Server: {response}")


if __name__ == "__main__":
    main()
