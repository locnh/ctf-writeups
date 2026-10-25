import argparse
from pwn import *

def parse_args():
    parser = argparse.ArgumentParser(description="Grid path solver for CTF (100 tests)")
    parser.add_argument("host", type=str, help="Target host")
    parser.add_argument("port", type=int, help="Target port")
    return parser.parse_args()

def solve():
    args = parse_args()
    io = remote(args.host, args.port)

    print("[*] Starting automated solver for 100 tests...")

    # The server prints "> " without a newline, so recvline would wait for a timeout.
    # Wait for each "Test X/100" header instead.
    for test in range(1, 101):
        io.recvuntil(f"Test {test}/100\n".encode())
        rows, cols = map(int, io.recvline().split())

        # The matrix may span several lines, so read until all cells are in
        grid_nums = []
        while len(grid_nums) < rows * cols:
            grid_nums.extend(int(x) for x in io.recvline().split())
        grid = [grid_nums[i * cols:(i + 1) * cols] for i in range(rows)]

        # Minimum path sum, moving only right or down
        dp = [[0] * cols for _ in range(rows)]
        dp[0][0] = grid[0][0]
        for j in range(1, cols):
            dp[0][j] = dp[0][j-1] + grid[0][j]
        for i in range(1, rows):
            dp[i][0] = dp[i-1][0] + grid[i][0]
        for i in range(1, rows):
            for j in range(1, cols):
                dp[i][j] = min(dp[i-1][j], dp[i][j-1]) + grid[i][j]

        ans = dp[rows-1][cols-1]
        print(f"[+] Test {test}/100 ({rows}x{cols}): sending {ans}")
        io.sendline(str(ans).encode())

    # The flag should follow the last answer
    print(io.recvall(timeout=10).decode(errors="replace"))

if __name__ == "__main__":
    solve()
