#!/usr/bin/env python3
import base64
import binascii
import re
import sys

# encode() in source.py hex-encodes the flag, applies base64 three times, and
# writes the result as hex. Decoding reverses each step in the opposite order.


def decode(data):
    m = binascii.unhexlify(data)
    for _ in range(3):
        m = base64.b64decode(m)
    return binascii.unhexlify(m).decode()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <output.txt>")
        sys.exit(1)

    with open(sys.argv[1]) as f:
        text = decode(f.read().strip())
    flag = re.search(r"HTB\{[^}]*\}", text)
    if not flag:
        raise RuntimeError("flag not found in decoded text")
    print(f"[+] Flag:\n{flag.group(0)}")
