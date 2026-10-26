---
title: pwn/void
platform: HTB
event: try-out
category: pwn
tags: [stack-overflow, blind, ret2dlresolve, csu-gadgets, stack-pivot, no-canary]
status: solved
difficulty: 5
---

# pwn/void

**Flag:** `HTB{pwnt00l5_h0mep4g3_15_REDACTED}`

**Difficulty:** 🌶️🌶️🌶️🌶️🌶️ (5/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <ip> <port> [fd]`. The default `fd` is 5, which is the descriptor the server's `open` returns.

## Summary

The service is a tiny x86-64 ELF. `main` calls `vuln`, which does `read(0, buf, 200)` into a 64-byte stack buffer. There is no canary and no PIE, so the saved `rbp` and return address are reachable.

The server never writes anything back. The binary imports only `read`, so there is no `puts`, `write`, or `system` to call, and no leak. The exploit has to be blind. It uses ret2dlresolve to resolve `open`, `read`, and `write` from libc at runtime, so no libc address is needed. The stack is pivoted into `.bss` first, because the 200-byte overflow is too small for the whole chain.

## Attack chain

- `checksec`: no canary, NX on, no PIE, partial RELRO. `.got.plt` is writable, and `.got` is read-only after startup.
- `vuln` at `0x401122`: `read(0, rbp-0x40, 0xc8)`. The buffer is 64 bytes, so the return address is at offset 72.
- `vuln` ends with `leave; ret` at `0x401141`, and `ret` at `0x401142`.
- `main` calls `vuln`, then `leave; ret`.
- `__libc_csu_init` has two useful gadgets:
  - `0x4011b2`: `pop rbx; pop rbp; pop r12; pop r13; pop r14; pop r15; ret`.
  - `0x401198`: `mov rdx,r14; mov rsi,r13; mov edi,r12d; call [r15+rbx*8]`, followed by the fall-through at `0x4011ae`, which is `add rsp,8` and the same pops. That gives control of three arguments and a call through a pointer.
- The binary has only `read` in its dynamic symbols, so `PLT0` at `0x401020` is the only resolver entry.
- Glibc 2.31 is bundled.

## Steps

The exploit runs in two stages.

**Stage A** is the 200-byte overflow:

1. Fill 64 bytes, then set saved `rbp` to `STAGE` (`0x404d58`).
2. Call `read(0, STAGE, STAGE_LEN)` through `0x4011b2` and `0x401198`. `STAGE_LEN` is the number of bytes left in the writable page from `STAGE`, so 680.
3. Return to `0x401141` (`leave; ret`) with `rbp = STAGE`. This pivots the stack to `STAGE`.

**Stage B** is sent second and is read into `STAGE`. It contains:

1. A dummy `rbp` at `STAGE+0`, which `leave` pops.
2. A chain that calls `open("flag.txt", 0, 0)` through ret2dlresolve. A harmless call to `ret` at `RETSLOT` sets `rdi`, `rsi`, and `rdx`. Then the chain returns to `PLT0` with the relocation index for `open`. The resolver resolves `open` and jumps to it with those registers.
3. `read(fd, BUF, 0x60)` through `GOT[read]`. The fd is what `open` returned, which is 5 on this server.
4. The same trick for `write(1, BUF, 0x60)`. A harmless call sets the arguments, then `PLT0` with the relocation index for `write` resolves and calls it.

The fake `Elf64_Sym` and `Elf64_Rela` structures for `open` and `write` are placed in `.bss` next to the chain. The relocation index is chosen so that `JMPREL + index*24` falls inside them. The symbol name is written next to them. `solve.py` builds these the same way pwntools does.

After `write` returns, the chain returns into garbage and crashes. The flag is already in the socket buffer, so it arrives before the connection closes.

**Flag:** `HTB{pwnt00l5_h0mep4g3_15_REDACTED}`

## Problems hit

- **The output is never visible.** The first probe sent 200 `A` bytes and got nothing back, so the exploit had to work without any output channel.
- **The fd is not 3.** The first attempt read from fd 3, and the remote timed out. The likely cause is that fd 3 is a socket, so `read` blocked waiting for input. The server's `open` returns 5. A probe over fds 2–5 showed that only 5 gives the flag. Fds 2–4 also time out, which fits the same explanation, but this was not checked directly.
- **The resolver needs about 0xd80 bytes of stack below `rsp`.** `_dl_runtime_resolve_xsavec` saves the full extended register state, and `_dl_fixup` and `_dl_lookup_symbol_x` add their own frames. The first staging address was `0x404400`, and the save area ran down into the GOT. The next attempt at `0x404800` was still too low. The working layout puts `rsp` at the open resolution near `0x404d80`. That leaves room below it within the writable page.
- **The chain has to fit in the writable page.** The chain, the resolver structures, the flag buffer, and the room below `rsp` all have to fit between `0x404038` and `0x404fff`. The final version drops the trailing gadget block, since the process crashes right after the flag is sent anyway.
- **Local debugging.** The binary is x86-64 Linux, so the test ran in a Debian container under qemu-user. `qemu-x86_64 -strace -d guest_errors,cpu` showed the fault RIP and syscalls, and `-d in_asm` showed the translated code, which pointed at the faulting frame. The same chain then passed locally with a fake flag and against the remote.

## Defense

- **Match the `read` length to the buffer.** `read(0, buf, 0xc8)` on a 64-byte buffer is the whole bug. Use `sizeof(buf)`.
- **Enable a stack canary and PIE.** A canary catches the overwrite before `ret`. PIE hides the gadget addresses. Neither one is enough on its own, since a leak would still give the libc base.
- **Keep the overflow out of the binary.** Nothing else in this program is reachable without it. ret2dlresolve works only because the attacker controls the input length.

## Lessons

- With no output channel, ret2dlresolve is still usable: the resolver lets you call any libc function by name, and the flag can go out through `write` on a known fd.
- The fd that `open` returns is set by the server, so probe it. A `read` on the wrong fd, if that fd is a socket, blocks instead of failing.
- Stack room matters more than the layout on paper. The resolver needs roughly a page's worth of stack below `rsp`, so the pivot target has to be near the top of the writable page.
- Debug with qemu-user tracing when the target is a non-native binary. `-strace` and `-d cpu` give the register state at the fault, which is enough to find which frame runs out of room.
