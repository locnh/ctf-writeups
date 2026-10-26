---
title: code/dynamic-paths
platform: HTB
event: try-out
category: code
tags: [dynamic-programming, minimum-path-sum, grid, scripting, netcat]
status: solved
difficulty: 2
---

# code/dynamic-paths

**Flag:** `HTB{b3h3M07H_5h0uld_H4v3_57ud13D_dYM4m1C_pr09r4mm1n9_70_C47ch_y0u_REDACTED}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`

## Summary

The service is a grid maze. It sends 100 grids in a row. For each grid you must return the minimum sum of the numbers on a path from the top-left cell to the bottom-right cell, moving only right or down. After the 100th correct answer the service prints the flag. The problem is the classic minimum path sum, solved with dynamic programming in O(rows × cols) per grid.

No source code was provided. The challenge is treated as a black box, and all the information comes from the service itself:

- The banner states the rules: `2 <= i, j <= 100`, each cell value `1 <= n <= 50`, moves are right or down only, and the answer is the minimum sum.
- Each test starts with a `Test X/100` header, then a line with `rows cols`, then the cell values. The cells can run over several lines.
- After each answer the server prints `> ` with no newline. That detail matters for the script (see Problems hit).

## Attack chain

- Each grid is different, and the sizes range up to 100 × 100. The DP runs in well under a millisecond per grid, so the time limit is not an issue.
- In a raw-socket probe, before the script was fixed, the server accepted the DP answers for tests 1–7 with no error.
- The service keeps the connection open until the last answer, then sends the flag and closes.

## Steps

1. Connect to the endpoint and read the banner and the first grid.
2. Parse the header, the dimensions, and the cell values. Read the matrix until all `rows × cols` values are collected.
3. Compute the DP table: `dp[0][0] = g[0][0]`, the first row and column are cumulative sums, and every other cell is `min(dp[i-1][j], dp[i][j-1]) + g[i][j]`.
4. Send the answer as a line, then wait for the next `Test X/100` header.
5. After test 100 the service sends the flag.

The solve script does steps 2–4 in a loop over the 100 tests.

Check against the example in the banner: the 4×3 grid gives 17 along `2 -> 5 -> 2 -> 1 -> 3 -> 4`, which matches the DP result.

The flag is `HTB{b3h3M07H_5h0uld_H4v3_57ud13D_dYM4m1C_pr09r4mm1n9_70_C47ch_y0u_REDACTED}`.

## Problems hit

- **The first script stopped after test 6.** The existing `solve.py` read each line with `recvline(timeout=5)`. After an answer the server prints `> ` with no trailing newline, so `recvline` waited for the timeout, got nothing, and the loop broke. The server was not rejecting the answers. I confirmed this with a raw-socket probe, which showed the server accepted the correct answers for tests 1–7 with no error.
- **The fix.** The rewritten script waits for the exact header `Test X/100\n` with `recvuntil`, which handles the missing newline. It also reads the matrix by cell count instead of by line, because a grid can span several lines.
- The first test's dimensions and values are different on each connection, so the solver must compute the answer for each run. A hard-coded answer list does not work.

## Defense

- **Do not trust the client for the work it is asked to do without checking.** This challenge only tests the solver, so there is no real security impact. Services that ask for computed answers should also set a time limit and a per-session attempt limit, so a brute-force answer search cannot pass.
- **Use a protocol parser that handles partial reads.** A parser that depends on one line per message breaks on prompts with no newline. Read until a known delimiter, not until a newline.
- **Keep the validation separate from the generator.** If a grid can be guessed or precomputed from a seed, the challenge is not a real test. Use a fresh random source per session.

## Lessons

- Read the protocol before trusting a generic solver. The `recvline` pattern works for line-based services and fails silently on prompts like `> `.
- A bug that looks like a wrong answer can be a read bug. Probe the raw socket before changing the algorithm, because the DP was correct all along.
- For a service with no source, the banner is the spec. Check your reading of the rules against the example before you trust the solver.
