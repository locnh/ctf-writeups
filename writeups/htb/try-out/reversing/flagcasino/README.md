---
title: reversing/flagcasino
platform: HTB
event: try-out
category: reversing
tags: [reversing, elf, prng, glibc-rand, srand, brute-force, scanf]
status: solved
difficulty: 2
---

# reversing/flagcasino

**Flag:** `HTB{r4nd_REDACTED}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <casino binary>`. It uses only the standard library and reads the binary as data, so the binary is never executed.

## Summary

`casino` is a 64-bit Linux ELF (not stripped). It prints a banner and then asks for 29 characters, one at a time. For each character it calls `srand(c)`, takes the first `rand()` value, and compares it with the matching entry of a 29-element `check[]` table. Each match prints `CORRECT`. The binary never prints the flag itself: the 29 characters you type are the flag (`HTB{...}` is exactly 29 bytes). The seed is the typed character, and the seed space is only 256 values, so each `check[i]` can be inverted by trying every character.

## Attack chain

The disassembly of `main` (`objdump -d -M intel`) shows the loop:

- `main` prints the banner, then loops `i` from 0 while `i <= 0x1c`, so 29 iterations.
- Each iteration calls `scanf(" %c", &c)` and then `movzx eax, byte [c]` and `movsx eax, al`. The seed is the signed char value, so bytes 0x80 to 0xFF become negative seeds.
- `srand(seed)` and `rand()` run next. The result is compared with `check[i]` (`cmp eax, edx`). A mismatch prints `INCORRECT` and exits.
- `check` is a symbol in `.symtab`. Its 29 `int` values are at vaddr `0x4080`, which is file offset `0x3080`.

The check table is therefore the flag encoded as seed-to-first-output pairs. To recover it, for each `i` find the seed `c` where glibc's first `rand()` after `srand(c)` equals `check[i]`. The solver does this with a Python reimplementation of glibc's TYPE_3 generator. The generator was checked against a known value: seed 1 gives 1804289383, which is glibc's output.

Each index has exactly one matching seed, so the 29 characters are unambiguous.

## Steps

1. Extract the archive. The binary is `rev_flagcasino/casino`.
2. Read `main` to confirm the loop bound (`cmp eax, 0x1c`), the input format (`" %c"`), and the seeding (`movsx`, then `srand`, then `rand`).
3. Find the table. `check` is a symbol, so `solve.py` gets its address from `.symtab` and converts it to a file offset with the `PT_LOAD` program headers. Its 29 values are the expected first outputs of `rand()`.
4. Run the solver on a copy of the binary, from a scratch folder:

   ```
   python3 solve.py casino
   ```

   Sample output (flag masked):

   ```
   HTB{r4nd_REDACTED}
   ```

5. The recovered string is the flag, `HTB{r4nd_REDACTED}`. Typing it at the prompt prints `CORRECT` 29 times and then the closing banner. This was run in a `linux/amd64` Debian container with `--network none` and the binary mounted read-only.

## Problems hit

- The first version read `check` at the virtual address `0x4080` instead of the file offset. The result was garbage and every index had zero matching seeds. The file offset of `.data` is `0x3080`, which is vaddr minus `0x1000`. The solver now finds the symbol and maps it through the `PT_LOAD` headers, so it no longer depends on a hard-coded offset.
- No `gdb` or `radare2` was installed on the analysis host, so the analysis used `objdump` only. The binary is a Linux ELF and cannot run directly on macOS. It was run in a `linux/amd64` container (Docker on Apple Silicon, emulated) with `--network none`, and all 29 characters printed `CORRECT`.

## Defense

- **Do not use a PRNG seeded by user input as a secret check.** The seed comes from one typed byte, so the search space is 256 per character. Any check that the attacker can run offline is breakable.
- **Do not ship the expected values in the binary.** Even with a stronger scheme, the `check` table is enough to recover the input. Compare a keyed hash of the input against a value that is derived from a secret kept on the server, or keep the check on the server.

## Lessons

- `rand()` is not a secret source. glibc's generator is fully determined by its seed, and the seed here is a single byte, so inverting it takes a few hundred operations per character.
- A table of `rand()` outputs is a precomputed answer key. Once the generator is known, the input can be read off the table with a short brute force.
- Check a reimplemented generator against a known output before trusting it. Seed 1 giving 1804289383 is what confirmed the solver's `rand()` matches glibc.
