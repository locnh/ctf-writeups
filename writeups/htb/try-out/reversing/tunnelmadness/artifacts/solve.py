#!/usr/bin/env python3
"""tunnelmadness: walk the 3D maze from the tunnel binary to the vault.

The binary keeps a position (x, y, z) in a 20x20x20 maze. main() asks for a
direction each turn and stops when the cell at the position has type 3, which
calls get_flag(). Type 2 is a wall. Moves off the grid are refused.

The maze is read from .rodata, so the solver parses the binary as data. It runs
a BFS from (0, 0, 0) to the goal cell and sends the moves to the service.

usage: python3 solve.py <target_ip> <target_port> [tunnel binary]
"""
import socket
import struct
import sys
from collections import deque

N = 20
MAZE_OFFSET = 0x20E0  # maze[] in .rodata, found with nm; file offset equals vaddr here
CELL_SIZE = 16
TYPE_WALL = 2
TYPE_GOAL = 3
# direction letter -> offset applied to (x, y, z), as in prompt_and_update_pos
MOVES = {"L": (-1, 0, 0), "R": (1, 0, 0), "B": (0, -1, 0),
         "F": (0, 1, 0), "D": (0, 0, -1), "U": (0, 0, 1)}


def load_types(path):
    with open(path, "rb") as f:
        data = f.read()
    types = {}
    for x in range(N):
        for y in range(N):
            for z in range(N):
                idx = 400 * x + 20 * y + z  # same index as get_cell()
                fields = struct.unpack_from("<4i", data, MAZE_OFFSET + CELL_SIZE * idx)
                types[(x, y, z)] = fields[3]
    return types


def find_path(types):
    start = (0, 0, 0)
    prev = {start: None}
    queue = deque([start])
    goal = None
    while queue:
        p = queue.popleft()
        if types[p] == TYPE_GOAL:
            goal = p
            break
        for letter, (dx, dy, dz) in MOVES.items():
            n = (p[0] + dx, p[1] + dy, p[2] + dz)
            if not all(0 <= c < N for c in n) or types[n] == TYPE_WALL or n in prev:
                continue
            prev[n] = (p, letter)
            queue.append(n)
    if goal is None:
        raise SystemExit("no path to the goal cell")
    moves = []
    p = goal
    while prev[p] is not None:
        p, letter = prev[p]
        moves.append(letter)
    return "".join(reversed(moves))


def send_moves(host, port, moves):
    with socket.create_connection((host, port), timeout=15) as s:
        s.sendall(moves.encode())
        out = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            out += chunk
    return out.decode(errors="replace")


def main():
    if len(sys.argv) not in (3, 4):
        print(f"usage: {sys.argv[0]} <target_ip> <target_port> [tunnel binary]", file=sys.stderr)
        sys.exit(1)
    host, port = sys.argv[1], int(sys.argv[2])
    binary = sys.argv[3] if len(sys.argv) == 4 else "tunnel"
    moves = find_path(load_types(binary))
    output = send_moves(host, port, moves)
    flag = [line for line in output.splitlines() if line.startswith("HTB{")]
    print(flag[0] if flag else output)


if __name__ == "__main__":
    main()
