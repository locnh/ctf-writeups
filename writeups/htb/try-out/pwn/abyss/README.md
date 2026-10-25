---
title: pwn/abyss
platform: HTB
event: try-out
category: pwn
tags: [unbounded-copy, loop-index-overwrite, return-address, no-shellcode, ret-into-function]
status: solved
---

# pwn/abyss

**Flag:** `HTB{sH0u1D_h4v3-NU11-t3rmIn4tEd_buf!_REDACTED}`

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <ip> <port>`.

## Summary

The service is a small command loop with three commands: `LOGIN`, `READ`, and `EXIT`. `READ` opens and prints any file, but only after `LOGIN` succeeds. The login credentials are random, and the server reads them from `.creds` at startup. The bug is in `cmd_login`. It copies the `USER` and `PASS` values byte by byte from a 512-byte buffer into 512-byte stack arrays, with no bounds check, and the copy loops run past the buffer until they see a NUL byte. The `PASS` copy can reach the saved return address of `cmd_login`. The NUL-stop behavior limits what can be written, so the exploit writes only three bytes of the return address. It returns into `cmd_read`, just past the `logged_in` check, and reads `flag.txt` directly.

## Source review

- `cmd_login` has three stack arrays: `pass` at `rbp-0x210`, `user` at `rbp-0x410`, and `buf` at `rbp-0x610`. `i` (the loop counter) is at `rbp-0x4`, inside the range that the `pass` copy writes.
- The `PASS` copy writes `pass[i-5] = buf[i]` while `buf[i] != 0`. The source is `buf`, and when `i` passes 512 it continues into `user`, so the source is contiguous memory that the attacker controls.
- The `strcmp` checks come after the copies. A failed check (`jne` at `0x401469`) leaves `ZF=0`, and the `leave; ret` returns to whatever address is on the stack.
- `cmd_read` has `jne 0x401500` at `0x4014ed`. It checks `logged_in`, then jumps to the read path when `logged_in` is nonzero. The instruction at `0x4014ed` is preceded by `test eax, eax`, which takes the flags from the `logged_in` load. Jumping to `0x4014ed` after a failed `strcmp` still gives `ZF=0`, so the jump is taken.
- The binary is not PIE and has no stack canary. `RELRO` is off.

## Steps

1. Send `LOGIN` (int `0`) so that `main` calls `cmd_login`.
2. Send the `USER` line. The `USER` value is 32 bytes, then a NUL. Its bytes are:
   - `[0..16]`: nonzero filler, copied into the `PASS` source.
   - `[17]`: `0x1c`. The `PASS` copy writes it into `i` (see below).
   - `[18..28]`: filler.
   - `[29..31]`: bytes 0 to 2 of the return target `0x4014ed`, which are `ed 14 40`.
   - `[32]`: NUL, from the copy.
3. Send the `PASS` line as `PASS ` followed by 507 nonzero bytes, 512 bytes total.
4. The `PASS` copy writes `pass[0..523]` from the source, so `pass[524]` is written from `buf[529]`, which is `user[17] = 0x1c`. That write lands on the low byte of `i` (at `rbp-4`). After the write, `i` is `0x21c`, and the increment makes it `0x21d`.
5. From `i = 0x21d`, the copy reads `user[29..31]` and writes them to `rbp+8..rbp+10`, which is the low three bytes of the return address. `user[32]` is NUL, so the loop stops, and the terminator writes `0` to `rbp+0xb`, the fourth byte of the return address. The upper bytes were already zero, so the return address is `0x4014ed`.
6. `cmd_login` runs `leave; ret`, which goes to `0x4014ed`. The `jne` is taken, so `cmd_read` runs `read(0, buf, 0x200)`.
7. Send `flag.txt\0`. `open` uses the NUL, `read` loads the file, and `write(1, ...)` sends it to the socket.

## Problems hit

- **NUL bytes stop the copy.** The copy loop stops at the first zero byte in its source, and that byte is written as the terminator. A normal return address has zero high bytes, so it cannot be written in one piece. The exploit writes only the low three bytes; the terminator writes byte three, and the other bytes were already zero.
- **Return address with a zero low byte.** The first candidate was `0x401500`, the first instruction after the `logged_in` check. Its low byte is `0x00`, which the copy cannot write. The `jne` at `0x4014ed` has the same effect and has a nonzero low byte.
- **Flags at return time.** The `jne` uses the flags from the last `test` executed before the return. In `cmd_login`, that `test` is the `strcmp` result check. A nonzero `strcmp` result gives `ZF=0`, so the jump is taken. A zero result would fall through, but the exploit's `USER` value cannot match the random username.
- **Send timing.** The server calls `read` separately for `USER` and `PASS`. Each send has a 0.3 s sleep so that one `read` sees one message.

## Defense

- **Check the copy bounds.** Compare the index against `sizeof(user)` and `sizeof(pass)` before each write, and do not rely on the input containing a NUL byte.
- **Use `strncpy` or `fgets` semantics with explicit length.** The copy loops in `cmd_login` have no length limit, so one bad byte in the source sends the write past the array.
- **Turn on stack protection and PIE.** A stack canary catches the return-address overwrite, and PIE makes the target address unknown. The binary has neither. `RELRO` is also off.
- **Do not check authorization after the sensitive code is reached by a plain jump.** The `logged_in` check is a single conditional, and a return into the middle of `cmd_read` skips it. Put the check where the sensitive operation happens, or keep the sensitive state in a separate session object.

## Lessons

- When the copy stops at NUL, a single return address can still be written if the copy ends right after its low bytes and the high bytes are already zero. Choose a target whose low three bytes have no zero byte in positions the copy must write.
- An overflow that reaches a loop counter gives control over the next write position. Here, one byte of the `USER` value set `i` to the right offset.
- Returning into the middle of a function is useful when the flags at return time already satisfy the next branch. Check the flags before picking the jump target.
