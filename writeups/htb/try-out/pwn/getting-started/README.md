---
title: pwn/getting-started
platform: HTB
event: try-out
category: pwn
tags: [stack-overflow, scanf, stack-layout, no-canary]
status: solved
---

# pwn/getting-started

**Flag:** `HTB{b0f_tut0r14l5_4r3_REDACTED}`

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <ip> <port>`.

## Summary

The service is a small x86-64 ELF that teaches stack layout. It prints the stack frame, then reads input with `scanf("%s", buf)`. `buf` is 32 bytes at `rbp-0x30`, and the 8-byte `target` is at `rbp-0x8`, which is 40 bytes after the start of `buf`. `scanf("%s")` has no length limit, so the input can overwrite `target`. At the end of `main`, the program compares `target` with `0xdeadbeef`. If the values are equal, it prints a space. If they differ, it calls `win()`, which prints the flag.

## Source review

The archive contains the binary `gs`, a bundled glibc, `flag.txt`, and a sample `wrapper.py`. Disassembly shows:

- `main` reads with `__isoc99_scanf("%s", rbp-0x30)`.
- `cmp qword [rbp-0x8], 0xdeadbeef`, then `jne` to `win` if the values differ.
- No stack canary is used.

## Steps

1. Fill `buf` with 40 bytes so the next 8 bytes land on `target`.
2. Write any value other than `0xdeadbeef` to those 8 bytes. The solve sends `B` x 8.
3. End with a newline. `scanf` stops at whitespace, so the newline ends the input.
4. The comparison fails, `win()` runs, and the flag is printed.

The sample `wrapper.py` sends `A` x 10. That does not reach `target`, so the program takes the success branch and does not print the flag.

## Problems hit

- The stack diagram shown by the program prints the target location, which confirms the 40-byte offset. No guessing was needed.
- Sending exactly `0xdeadbeef` gives the non-win branch, so the payload must change the value, not set it.

## Defense

- **Use a length limit.** `scanf("%s")` writes until whitespace, so the buffer size is not checked. Use `%31s` or `fgets`.
- **Do not use a stack value as the only check.** A value next to a buffer can be overwritten. Use a separate access control flag and check bounds on input.
- **Enable stack protection.** A canary placed before the return address would detect this overflow.

## Lessons

- The offset between a buffer and a neighbouring variable is set by the compiler layout. Read the disassembly to confirm it.
- `scanf` with `%s` has the same risk as `gets`; it does not check the length.
