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

    while True:
        try:
            line = io.recvline(timeout=5).decode('utf-8', errors='ignore')
            if not line:
                break
            print(line, end='')
            
            line_str = line.strip()

            # When encountering "Test X/100"
            if "Test " in line_str and "/100" in line_str:
                # Read the next line containing matrix dimensions (rows cols)
                dim_line = io.recvline(timeout=5).decode('utf-8', errors='ignore')
                print(dim_line, end='')
                
                parts = dim_line.strip().split()
                if len(parts) == 2 and parts[0].isdigit() and parts[1].isdigit():
                    rows, cols = int(parts[0]), int(parts[1])
                else:
                    continue

                # Collect all matrix elements (may span across multiple lines)
                grid_nums = []
                while len(grid_nums) < rows * cols:
                    data_line = io.recvline(timeout=5).decode('utf-8', errors='ignore')
                    if not data_line:
                        break
                    print(data_line, end='')
                    
                    nums = [int(x) for x in data_line.strip().split() if x.isdigit()]
                    grid_nums.extend(nums)

                if len(grid_nums) >= rows * cols:
                    grid = [grid_nums[i * cols:(i + 1) * cols] for i in range(rows)]
                    
                    # Compute minimum path sum using dynamic programming
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
                    print(f"[+] Sending Answer: {ans}")
                    io.sendline(str(ans).encode())

        except Exception as e:
            print(f"[-] Error: {e}")
            break

    io.interactive()

if __name__ == "__main__":
    solve()
