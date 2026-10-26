---
title: reversing/lootstash
platform: HTB
event: try-out
category: reversing
tags: [reversing, elf, relocations, time-seed, rand, pointer-table]
status: solved
difficulty: 2
---

# reversing/lootstash

**Flag:** `HTB{n33dl3_REDACTED}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <stash binary>`. It uses only the standard library and reads the binary as data, so the binary is never executed.

## Summary

`stash` is a 64-bit Linux ELF (not stripped). It prints a short intro and then "dives into the stash": it prints five dots, one per second, and then one random loot item. The loot items are 255 strings, and the flag `HTB{n33dl3_REDACTED}` is one of them. The program only prints the flag when its random seed picks that entry, which is about 1 run in 255. So running the binary is not enough. The flag has to be read out of the table.

## Attack chain

The disassembly of `main` (`objdump -d -M intel`) shows the logic:

- `srand(time(NULL))`, then the intro and a loop that prints `.` and calls `sleep(1)` five times.
- One `rand()` call. The value is reduced to an index with the compiler's constant-division trick: `(r % 2040) >> 3`, which gives 0..254.
- `gear[index]` is loaded from `.data` at vaddr `0x7060` and printed with `printf`.

The table is an array of pointers. The strings are not stored in the slots directly. In a PIE binary the loader fills each slot with a `R_X86_64_RELATIVE` relocation, and the addend is the address of the string in `.rodata`. Reading the file alone gives zeros at these slots, so a plain dump of `.data` does not show the strings.

The solver reads `.rela.dyn`, collects the `R_X86_64_RELATIVE` addends at the 255 slots, dereferences each addend in `.rodata`, and prints the entry that starts with `HTB{`. That entry is at index 97.

To confirm the table is read correctly, the program was run in a container and its output was compared with the index it would compute:

- A run at `1793033001`–`1793033009` printed `Phantom, Favor of the Covenant`. That entry is index 223 in the table.
- Recomputing the index for each second in that window gives index 223 at second `1793033004`. So the seed is the time at which `main` started, and the index formula matches the binary.

## Steps

1. Extract the archive. The binary is `rev_lootstash/stash`.
2. Read `main` to get the seed (`time(0)`), the index formula (`2040` and `>> 3`), and the table address (`0x7060`).
3. Run the solver on a copy of the binary, from a scratch folder:

   ```
   python3 solve.py stash
   ```

   Sample output (flag masked):

   ```
   [97] HTB{n33dl3_REDACTED}
   ```

4. The flag is `HTB{n33dl3_REDACTED}`.

## Problems hit

- The first container run failed on `GLIBC_2.34`. The binary needs a newer glibc than `debian:bullseye-slim` provides, so the run used `debian:bookworm-slim`.
- A plain dump of `.data` shows zeros at the table slots. The strings come from the `R_X86_64_RELATIVE` relocations, so the solver reads those.
- Container startup adds a few seconds before `main` runs, so the seed is not exactly the moment `docker run` starts. The seed was found by matching the printed item against the seed window, not by guessing the start time.
- Trying to force a run that prints the flag by timing the start was not reliable. A run at one of the chosen seeds printed a different item. The flag was confirmed from the table, not from a run that printed it.

## Defense

- **Do not keep secrets in a table that ships in the binary.** Every entry is recoverable from the file with the relocation table. Keep the secret out of the binary, or check it on a server.
- **Do not use `time()` as a seed for a value that matters.** The seed is predictable within a few seconds, and the program's output depends only on it.
- **Do not rely on rarity to hide a value.** The flag appears in one run out of 255, but the whole table is in the file, so rarity protects nothing.

## Lessons

- In PIE binaries, read `.rela.dyn` when a pointer table looks empty. The data is in relocations, not in the file bytes.
- A random choice driven by `time()` is a small search space. Each second maps to one index, so the output can be predicted once the formula is known.
- Check a model against a real run before trusting it. The seed window matched the printed item here, which confirmed the formula.
