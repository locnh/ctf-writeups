---
title: pwn/regularity
platform: HTB
event: try-out
category: pwn
tags: [stack-overflow, shellcode, rwx-stack, jmp-rsi]
status: solved
difficulty: 3
---

# pwn/regularity

**Difficulty:** 🌶️🌶️🌶️ (3/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <ip> <port>`. The shellcode source is in `artifacts/shellcode.s`.

## Summary

The service is a static, non-PIE x86-64 binary. It prints a greeting, reads up to 0x110 bytes into a 0x100 byte stack buffer, prints a second message, and exits. The read overflows the buffer and overwrites the saved return address. The stack is `rwx`, and when `read` returns, `rsi` still points at the start of the buffer. The binary also has a `jmp rsi` gadget at `0x401041`, so the overflow can jump to the buffer and run shellcode there. The flag file is `flag.txt` in the working directory.

## Attack chain

The binary is the only file in the archive, with a placeholder `flag.txt`. Disassembly shows the relevant code:

- `_start` writes a 42-byte greeting, calls `read`, writes a 39-byte message, then jumps to `exit`.
- `read` allocates `0x100` bytes with `sub rsp, 0x100`, calls `read(0, rsp, 0x110)`, then does `add rsp, 0x100` and `ret`. The request is 0x10 bytes larger than the buffer, so the saved return address at `rsp+0x100` is overwritten.
- `0x401041` is `jmp rsi` (the tail of the `movabs rsi, 0x40106f; jmp rsi` sequence in `_start`).
- The program headers show `GNU_STACK` with flags `rwx`, so the stack is executable. There is no stack canary.

## Steps

1. Put the shellcode at the start of the 256-byte payload. Pad it to 256 bytes.
2. Write `0x401041` as the next 8 bytes. These overwrite the saved return address.
3. Add 8 more bytes so the total is exactly 0x110 bytes, which is the length `read` asks for.
4. When `read` returns, `ret` jumps to `0x401041`. `jmp rsi` then runs the shellcode at the buffer start.
5. The shellcode runs `open("flag.txt")`, `read` into a stack area below `rsp`, and `write` to fd 1. Fd 1 is the TCP socket, so the flag reaches the client.

The shellcode (70 bytes):

- `call` and `pop` put the address of the string `flag.txt` in `rdi`.
- `open(path, O_RDONLY)` gives the fd in `eax`.
- `read(fd, rsp-0x400, 0x100)`.
- `write(1, rsp-0x400, count)`.
- `exit(0)`.

**Flag:** `HTB{juMp1nG_w1tH_tH3_r3gIsT3rS?_REDACTED}`

## Problems hit

- The first shellcode read into `rsp-0x100`. After `ret`, `rsp` is the saved-return slot plus 8, which is `buffer+8`. The `read` overwrote the shellcode that was still running, and the process crashed. Reading into `rsp-0x400` (below the buffer) fixed it.
- An early attempt with an empty payload returned only the greeting. The shellcode extraction regex had failed, so the payload had no shellcode. A diagnostic payload that writes `HIT!` confirmed that code runs at the buffer.
- The first shellcode gave no output while `open("flag.txt")` looked correct. A shell (`execve("/bin/sh")`) on the remote confirmed `/home/ctf/flag.txt` exists. The actual cause was the read overwrite above.

## Defense

- **Check the size passed to `read`.** The call requests 0x110 bytes into a 0x100 buffer. Pass the buffer size, or read at most `sizeof(buf)`.
- **Turn on stack protection and NX.** The binary has no canary, and `GNU_STACK` is `rwx`, so the overflow can run shellcode directly. A non-executable stack stops this variant. Stack canaries stop the return-address overwrite.
- **Do not leave useful gadgets next to the input path.** A `jmp rsi` in the binary gave a direct path to the buffer. Build with `-z noexecstack` and a hardened toolchain.

## Lessons

- A static binary with no PIE has fixed gadget addresses. Here the stack is executable, so no leak is needed.
- After `read`, `rsi` still holds the buffer address. A `jmp rsi` gadget is enough to reach the shellcode without knowing the stack address.
- Pick the write target of the shellcode's `read` carefully. A buffer relative to `rsp` can sit inside the code that is still running.
