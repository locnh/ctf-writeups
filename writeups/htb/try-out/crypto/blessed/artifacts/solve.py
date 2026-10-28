#!/usr/bin/env python3
"""Solve crypto/blessed: recover the RNG state, pass the cut-and-choose proof with a rogue
key, then forge the aggregate signature for unveil_secrets.

usage: python3 solve.py <target_ip> <target_port>
needs: pip install py_ecc, and a C compiler (search.c is built into ./search on first run)
"""
import json
import os
import secrets
import socket
import subprocess
import sys
import threading
from concurrent.futures import ThreadPoolExecutor

from py_ecc.bls.ciphersuites import G2ProofOfPossession as bls
from py_ecc.bls.g2_primitives import G1_to_pubkey, pubkey_to_G1
from py_ecc.bls.point_compression import compress_G1
from py_ecc.optimized_bls12_381.optimized_curve import G1, add, curve_order, multiply, neg

p = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF
a = p - 3
b = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B
Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296
Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5
G = (Gx, Gy)  # P-256 generator, used by the server RNG
HERE = os.path.dirname(os.path.abspath(__file__))
SEARCH = os.path.join(HERE, "search")
KEEPALIVE = 60  # seconds between help commands while recovery runs


def build_search():
    if not os.path.exists(SEARCH):
        subprocess.run(["cc", "-O3", "-o", SEARCH, os.path.join(HERE, "search.c")], check=True)


def F(x):
    return (x * x * x - 3 * x + b) % p


def init_values(X0, Y0):
    f0, f1, f2 = F(X0), F(X0 + 1), F(X0 + 2)
    d1 = (f1 - f0) % p
    d2 = (f2 - 2 * f1 + f0) % p
    g0 = Y0 * Y0 % p
    s0 = (2 * Y0 + 1) % p
    return [p, 6, f0, d1, d2, g0, s0]


def ec_add(P1, P2):
    if P1 is None:
        return P2
    if P2 is None:
        return P1
    x1, y1 = P1
    x2, y2 = P2
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    if P1 == P2:
        lam = (3 * x1 * x1 + a) * pow(2 * y1, -1, p) % p
    else:
        lam = (y2 - y1) * pow(x2 - x1, -1, p) % p
    x3 = (lam * lam - x1 - x2) % p
    return x3, (lam * (x1 - x3) - y1) % p


def ec_mul(k, P1):
    R = None
    while k:
        if k & 1:
            R = ec_add(R, P1)
        P1 = ec_add(P1, P1)
        k >>= 1
    return R


def on_curve(P1):
    x, y = P1
    return (y * y - F(x)) % p == 0


def candidates(xhi, yhi, B=7, workers=os.cpu_count()):
    """Meet-in-the-middle over the low 32 bits of x and y; yields exact points."""
    X0, Y0 = xhi << 32, yhi << 32
    init = "\n".join(format(v, "x") for v in init_values(X0, Y0)) + "\n"

    def run(k):
        out = subprocess.run([SEARCH, str(B), str(k)], input=init, capture_output=True, text=True, check=True)
        return out.stdout.split("\n")

    with ThreadPoolExecutor(max_workers=workers) as ex:
        for lines in ex.map(run, range(1 << B)):
            for line in lines:
                if not line:
                    continue
                u, v = map(int, line.split())
                pt = (X0 + u, Y0 + v)
                if on_curve(pt):
                    yield pt


class Remote:
    def __init__(self, host, port):
        self.sock = socket.create_connection((host, port), timeout=60)
        self.buf = b""

    def read_until(self, token):
        while token not in self.buf:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise EOFError(self.buf.decode(errors="replace"))
            self.buf += chunk
        end = self.buf.index(token) + len(token)
        out, self.buf = self.buf[:end], self.buf[end:]
        return out.decode(errors="replace")

    def send_line(self, line):
        self.sock.sendall(line.encode() + b"\n")

    def cmd(self, payload):
        self.send_line(json.dumps(payload))
        body = self.read_until(b"> ")[:-2].strip()
        return json.loads(body)


def yield_at(W1, n):
    """Value of the n-th RNG yield (1-based). Yields are W1.x, W1.y, W2.x, W2.y, ... (high 224 bits)."""
    k = (n + 1) // 2
    Wk = ec_add(W1, ec_mul(k - 1, G)) if k > 1 else W1
    return (Wk[0] >> 32) if n % 2 else (Wk[1] >> 32)


def recover_w1(ids):
    W1 = list(candidates(ids[0], ids[1]))
    assert len(W1) == 1, f"recovery returned {len(W1)} points"
    W1 = W1[0]
    # Cross-check with the next point: yields 3 and 4 must equal W2 = W1 + G
    assert yield_at(W1, 3) == ids[2] and yield_at(W1, 4) == ids[3], "prediction mismatch"
    print("[*] Recovered RNG state, predictions match observed robot ids")
    return W1


def recover_with_keepalive(remote, ids):
    """Run recovery in a thread and send `help` (no RNG use) so the server keeps the socket."""
    result = {}

    def work():
        try:
            result["W1"] = recover_w1(ids)
        except Exception as exc:  # re-raised below in the main thread
            result["error"] = exc

    worker = threading.Thread(target=work)
    worker.start()
    while worker.is_alive():
        worker.join(KEEPALIVE)
        if worker.is_alive():
            remote.cmd({"cmd": "help"})
    if "error" in result:
        raise result["error"]
    return result["W1"]


def solve(host, port):
    build_search()
    remote = Remote(host, port)
    remote.read_until(b"> ")

    created = remote.cmd({"cmd": "create"})
    sk = int(created["sk"], 16)
    print(f"[*] Created robot {created['robot_id']}")

    robots = remote.cmd({
        "cmd": "list",
        "robot_id": created["robot_id"],
        "sig": bls.Sign(sk, b"list").hex(),
    })
    ids = [int(r["robot_id"], 16) for r in robots]  # yields 1..5
    pks = [bytes.fromhex(r["pk"]) for r in robots]
    print(f"[*] Listed {len(pks)} robots")

    W1 = recover_with_keepalive(remote, ids)

    # Rogue key: sum of the verified keys + rogue = a * G1, and we do not know the rogue's secret
    total = None
    for pk in pks:
        point = pubkey_to_G1(pk)
        total = point if total is None else add(total, point)
    a_sk = secrets.randbelow(curve_order - 1) + 1
    rogue = add(multiply(G1, a_sk), neg(total))
    rogue_pk = G1_to_pubkey(rogue)

    joined = remote.cmd({"cmd": "join", "pk": rogue_pk.hex()})
    print(f"[*] Joined as robot {joined['robot_id']}")
    # The join consumes yield 6. Verify rounds consume yields 7..70, one bit each.
    assert int(joined["robot_id"], 16) == yield_at(W1, 6), "join robot_id mismatch"

    remote.send_line(json.dumps({"cmd": "verify", "robot_id": joined["robot_id"]}))
    remote.read_until(b"(hex): ")
    rogue_pt = pubkey_to_G1(rogue_pk)
    for i in range(64):
        bit = yield_at(W1, 7 + i) & 1
        if bit:  # x-branch: C = x * G1, reveal x
            x = secrets.randbelow(curve_order - 1) + 1
            C = multiply(G1, x)
            reply = x
        else:  # sk-branch: C = s * G1 - pk, reveal s = sk + x
            s = secrets.randbelow(curve_order - 1) + 1
            C = add(multiply(G1, s), neg(rogue_pt))
            reply = s
        remote.send_line(hex(compress_G1(C))[2:])
        branch = remote.read_until(b"(hex): ")
        if ("Give me x (hex)" in branch) != bool(bit):
            print(f"[!] round {i}: branch mismatch", file=sys.stderr)
        remote.send_line(hex(reply)[2:])
        if i < 63:
            remote.read_until(b"(hex): ")
    print(f"[*] verify: {remote.read_until(b'> ').strip()}")

    all_pks = pks + [rogue_pk]
    agg_sig = bls.Sign(a_sk, b"unveil_secrets")
    assert bls.FastAggregateVerify(all_pks, b"unveil_secrets", agg_sig)
    result = remote.cmd({"cmd": "unveil_secrets", "sig": agg_sig.hex()})
    print(f"[+] {result}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"usage: python3 {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)
    solve(sys.argv[1], int(sys.argv[2]))
