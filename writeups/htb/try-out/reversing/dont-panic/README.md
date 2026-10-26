---
title: reversing/dont-panic
platform: HTB
event: try-out
category: reversing
tags: [reversing, rust, closures, panic, binary-analysis, objdump]
status: solved
difficulty: 3
---

# reversing/dont-panic

**Flag:** `HTB{d0nt_REDACTED}`

**Difficulty:** 🌶️🌶️🌶️ (3/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <dontpanic binary>`. It needs `objdump` on the path. It reads the binary as data and never executes it.

## Summary

`dontpanic` is a Rust program for Linux x86-64. It is not stripped and has debug info. It reads one line from stdin and passes it to `check_flag`. If the input is correct, it prints `All is well`. If not, it prints `You made me panic!`. The program never prints the flag, so the input itself is the flag. It is 31 bytes (`HTB{` + 26 bytes + `}`).

The check uses panics as a yes/no signal. Each byte is checked by its own closure, and the closure panics if the byte is too small or too large.

## Attack chain

The symbols show the user's code under `src::`: `main`, `remove_newline`, and `check_flag`. `main` reads a line, removes the trailing newline, and calls `check_flag` (`objdump -d -M intel`).

`check_flag` does two things:

- It asserts the length is 31. Otherwise it calls `assert_failed`.
- It loops over the 31 bytes. For byte `i` it calls `table[i](input[i])`. The table is built on the stack with 31 `lea` / `mov` pairs, and each entry points to a closure.

Each closure is a `call_once` thunk with the same shape:

```
cmp dil, K
jb  panic_below      ; byte < K
jne panic_above      ; byte > K
ret                  ; byte == K
```

So each closure accepts exactly one byte value, `K`. The flag byte at index `i` is that `K`. Reading the immediate from each of the 31 closures gives the whole flag.

## Steps

1. Extract the archive. The binary is `rev_dontpanic/dontpanic`.
2. Confirm it is Rust (`rustc` strings) and find the user code (`nm`, the `src::` symbols).
3. Disassemble `check_flag` and confirm the length check (`cmp rsi, 0x1f`) and the loop that calls `[rsp + 8*rax + 0x10]`.
4. Disassemble one closure to see the pattern: `cmp dil, K`, then two panic branches. The panic path prints the message, and the match path returns.
5. Collect the closure address for each index from the stores in `check_flag`, then read the `cmp` constant of each closure. `solve.py` does this step.
6. Run the solver on a copy of the binary, from a scratch folder:

   ```
   python3 solve.py dontpanic
   ```

   Sample output (flag masked):

   ```
   HTB{d0nt_REDACTED}
   ```

7. Check the result. The flag is `HTB{d0nt_REDACTED}`. Run the binary in a `linux/amd64` container with `--network none` and the binary mounted read-only, then pipe the flag on stdin. It prints `All is well`, exit 0. Changing the last character to `!` prints `You made me panic!`.

## Problems hit

- The first look at the strings was noisy. The Rust standard library contains a lot of text, so the user code was easier to find through the `src::` symbols.
- The closures look alike. Reading only the first closure gives one byte, so the solver reads all 31 and maps them through the table stores, in order.
- The binary is for Linux. It was run in a container, as with the earlier challenges.

## Defense

- **Do not use panics as a comparison oracle.** Whether the program panics depends only on each byte, so each byte can be found one at a time.
- **Do not put the flag in a constant that the binary checks directly.** Every constant is visible in the disassembly. Compare against a keyed hash or check the answer on a server.
- **Strip debug info and symbols for release builds.** The `src::` names made the check easy to find. Stripping does not stop this kind of analysis, but it slows it down.

## Lessons

- A check that compares each input byte with its own constant can be read one byte at a time, without any search.
- In Rust binaries, the user code is a small part of the file. Look for the crate's own symbols (`src::`) and skip the standard library.
- A table of closures on the stack is still a table. Reading the stores that build it gives the order.
