#!/usr/bin/env python3
import sys


def decrypt(ciphertext):
    plaintext = ""
    for i, ch in enumerate(ciphertext):
        if not ch.isalpha():
            plaintext += ch
        else:
            # The encryption adds the position to each letter mod 26, so subtract it back
            plaintext += chr((ord(ch) - 0x41 - i) % 26 + 0x41)
    return plaintext


def solve(output_path):
    with open(output_path) as f:
        lines = f.read().splitlines()

    # Line 1 is a hint, line 2 is the ciphertext
    ciphertext = lines[1]
    print(f"[+] HTB{{{decrypt(ciphertext)}}}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <output.txt>")
        sys.exit(1)

    solve(sys.argv[1])
