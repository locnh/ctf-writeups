---
title: pwn/labyrinth
platform: HTB
event: try-out
category: pwn
tags: [stack-overflow, fgets-overflow, ret2win, stack-alignment, no-canary]
status: solved
difficulty: 2
---

# pwn/labyrinth

**Flag:** `HTB{3sc4p3_fr0m_REDACTED}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <ip> <port>`.

## Summary

The service is a small x86-64 ELF with a door-choosing game. `main` prints the board for doors 1 to 100 and then reads a choice with `fgets`. If the choice starts with `69`, the program prints a message and calls `fgets` with a size of 0x44 on a 0x30-byte stack buffer. `fgets` writes up to 67 bytes plus a NUL, so the write goes past the buffer and reaches the saved `rbp` and the return address. The binary has no stack canary and no PIE. `escape_plan()` opens `./flag.txt` and prints it, so the exploit returns into it.

## Attack chain

The archive contains the binary `labyrinth`, a bundled glibc, and a local `flag.txt`. `checksec` reports:

- No canary.
- NX enabled.
- No PIE, so `escape_plan` is at a fixed address `0x401255`.
- Full RELRO.

Disassembly of the relevant parts:

- `main` at `0x401405`:
  - `fgets(rbp-0x10 (malloc'd), 5)` reads the door choice.
  - `strncmp(choice, "69", 2) == 0` opens the overflow path at `0x4015a2`. If the first compare fails, the second compare, `strncmp(choice, "069", 3)`, is tried, and the same path is taken on a match.
  - `fgets(rbp-0x30, 0x44, stdin)` is the overflow. The buffer is 0x30 bytes, so `rbp+0` is the saved `rbp` and `rbp+8` is the return address.
- `escape_plan` at `0x401255`:
  - `push rbp; mov rbp, rsp; sub rsp, 0x10`.
  - `open("./flag.txt", O_RDONLY)`, then a `read`/`fputc` loop that prints the file, then `fprintf` of the "Congratulations" line.
- `setup` calls `setvbuf` with `_IONBF` on stdin and stdout, so `fgets` reads one byte at a time and output is not buffered.

## Steps

1. Send `69\n`. `fgets(buf, 5)` reads it, and `strncmp` takes the overflow path.
2. Send the overflow payload, which is 65 bytes:
   - 48 bytes of `A`, filling `buf`.
   - 8 bytes for the saved `rbp`, set to `0x404800`. That address is writable and in the `.bss` page, and `escape_plan` uses `rbp` for its locals.
   - 8 bytes for the return address, set to `0x401259`, which is `escape_plan+4` (`sub rsp, 0x10`).
   - `\n`, which ends the `fgets`.
3. `main` runs `leave; ret` and jumps to `0x401259`. `escape_plan` opens `./flag.txt`, prints it, and then the program crashes on the bad return. The flag is already on the socket by then.

**Flag:** `HTB{3sc4p3_fr0m_REDACTED}`

## Problems hit

- **Crash after the art, before the flag.** The first payload jumped to `0x401255`. The output stopped after the `fwrite` of the art, and `fprintf` never printed. `main` returns with `rsp` 8 bytes off 16-byte alignment, so `escape_plan` is entered with `rsp ≡ 0 (mod 16)`. Its `push rbp` makes it `≡ 8`, and the `fprintf` call inside glibc needs the stack aligned. The `movaps` in glibc faults. Jumping to `0x401259`, which is after `push rbp` and `mov rbp, rsp`, keeps `rsp` aligned at the calls.
- **The fake `rbp` must be writable.** After the jump, `escape_plan` writes to `[rbp-0x4]` and `[rbp-0x5]`. The saved `rbp` slot is where those locals point, so it has to be a valid address, and `0x404800` works.
- **`fgets` caps input at 67 bytes.** A simple fix would be to return to a `ret` gadget (`0x401254`) and chain `escape_plan` after it. That needs a second 8-byte address after the return address, so the payload would be 73 bytes and would not fit. Jumping straight to `0x401259` fits in 65 bytes and gives the same alignment.
- **Local testing on Apple Silicon.** The binary is x86-64 Linux, so it does not run directly on macOS. Running it in an emulated Docker container did not finish in this environment, so the payload was tested against the remote instance.
- **"YOU FAILED TO ESCAPE!" is expected.** The overflow path always prints this line before returning. The program prints it, then `main` returns, and the flag appears only after the return into `escape_plan`.

## Defense

- **Match the `fgets` size to the buffer.** The read size is `0x44`, which is 68 bytes into a 48-byte buffer. Use `sizeof(buf)`.
- **Enable stack protection and PIE.** A canary would catch the overwrite before `ret`. PIE would make `escape_plan` address unknown.
- **Do not leave a flag-printing function reachable by a return address.** `escape_plan` prints the flag with no check of the caller, so any control of the return address reaches it.

## Lessons

- A plain `ret2win` can still fail when the target function uses `movaps`-aligned calls. Check `rsp` alignment at the target entry, and jump past the prologue if it is off by 8.
- Skipping the prologue requires a valid `rbp` for the function's locals. Set the saved `rbp` slot to a writable address.
- `fgets(buf, N)` bounds the input, but a bound larger than the buffer still overflows. Count the bytes between the buffer and the return address, then check that the payload fits in the read limit.
