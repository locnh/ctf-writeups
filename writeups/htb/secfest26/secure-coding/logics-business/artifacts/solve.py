#!/usr/bin/env python3
import hashlib
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

# The editor at / exposes /editor_api/* and reads and writes files under
# /www/application. This script replaces blueprints/routes.py with the patched
# version next to it, restarts the service, and asks /verify for the flag.


def request(base, method, path, body=None, query=None):
    url = f"{base}{path}"
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method)
    if data is not None:
        req.add_header("Content-Type", "application/json")
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, resp.read().decode()
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode()


def md5(text):
    return hashlib.md5(text.encode()).hexdigest()


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <target_ip> <target_port>", file=sys.stderr)
        sys.exit(1)

    base = f"http://{sys.argv[1]}:{sys.argv[2]}"
    path = "blueprints/routes.py"
    patched = open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "routes_patched.py")).read()

    status, body = request(base, "GET", "/editor_api/file", query={"path": path})
    if status != 200:
        print(f"[-] cannot read {path}: {status} {body}")
        sys.exit(1)
    current = json.loads(body)["content"]

    if current == patched:
        print(f"[*] {path} already patched")
    else:
        print(f"[*] patching {path} (current md5 {md5(current)})")
        status, body = request(base, "POST", "/editor_api/save",
                               body={"path": path, "content": patched, "client_md5": md5(current)})
        if status != 200:
            print(f"[-] save failed: {status} {body}")
            sys.exit(1)
        print(f"[+] saved: {body.strip()}")

    status, body = request(base, "POST", "/editor_api/restart")
    print(f"[*] restart: {status} {body.strip()}")

    # The service needs a moment to come back before /verify can reach it
    import time
    time.sleep(8)

    status, body = request(base, "GET", "/editor_api/verify")
    try:
        result = json.loads(body)
    except json.JSONDecodeError:
        result = {}
    if "flag" in result:
        print(f"[+] Flag: {result['flag']}")
    else:
        print(f"[-] verify failed ({status}): {result.get('error', body.strip())}")
        sys.exit(1)


if __name__ == "__main__":
    main()
