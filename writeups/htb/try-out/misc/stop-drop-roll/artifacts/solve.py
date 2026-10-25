#!/usr/bin/env python3
import sys
import re
import socket
from pwn import *

# Disable verbose pwntools logging
context.log_level = 'error'

# Mapping dictionary based on the challenge rules
MAPPING = {
    "GORGE": "STOP",
    "PHREAK": "DROP",
    "FIRE": "ROLL"
}

def solve_gauntlet(host, port):
    print(f"[+] Connecting to target {host}:{port}...")
    
    try:
        conn = remote(host, port, timeout=5)
        
        # 1. Handle the readiness prompt: "Are you ready? (y/n)"
        prompt = conn.recvuntil(b"(y/n)", timeout=3).decode()
        print(f"[*] Server prompt:\n{prompt.strip()}")
        
        print("[*] Sending 'y' to start...")
        conn.sendline(b"y")
        
        # 2. Main loop to handle rounds of scenarios
        round_count = 1
        while True:
            try:
                line = conn.recvline(timeout=3).decode().strip()
                if not line:
                    continue
                    
                print(f"[*] Received: {line}")
                
                # Check if the server returned the flag
                if "HTB{" in line:
                    print(f"\n[+] FLAG FOUND: {line}")
                    # Try to read any trailing characters if flag spans across lines
                    try:
                        extra = conn.recvall(timeout=2).decode().strip()
                        if extra:
                            print(extra)
                    except:
                        pass
                    break
                
                # Check if the line contains scenario keywords
                if any(kw in line for kw in MAPPING.keys()):
                    # Find all scenario keywords in the exact order they appear
                    found_scenarios = re.findall(r'(GORGE|PHREAK|FIRE)', line)
                    
                    if found_scenarios:
                        answer = "-".join([MAPPING[s] for s in found_scenarios])
                        print(f"[-] Round {round_count} -> Sending answer: {answer}")
                        conn.sendline(answer.encode())
                        round_count += 1
                        
            except socket.timeout:
                continue
            except EOFError:
                print("[-] Connection closed by server.")
                break
            except Exception as e:
                print(f"[-] Loop error: {e}")
                break
                
        conn.close()
        
    except Exception as e:
        print(f"[-] Connection Error: {e}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <IP> <PORT>")
        sys.exit(1)
        
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    solve_gauntlet(target_ip, target_port)