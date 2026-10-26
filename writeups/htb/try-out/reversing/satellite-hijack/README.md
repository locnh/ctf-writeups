---
title: reversing/satellite-hijack
platform: HTB
event: try-out
category: reversing
tags: [reversing, shared-library, xor-blob, memfrob, mmap, stack-strings, environment-variable, offline]
status: solved
difficulty: 4
---

# reversing/satellite-hijack

**Flag:** `HTB{l4y3r5_REDACTED}`

**Difficulty:** 🌶️🌶️🌶️🌶️ (4/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <library.so>`. It uses only the standard library and reads the library as data, so nothing is executed. The challenge has no remote endpoint, so the script works offline.

## Summary

The challenge is a two-part Linux program: `satellite` (a main program that sends a message) and `library.so` (which implements `send_satellite_message`). The program reads a line from its input and passes it to the library. Without any setup, the message is echoed as `Sending ...`.

The library has a hidden routine. When the environment variable `SAT_PROD_ENVIRONMENT` is set, the library maps a page, copies 4 KiB of its own `.text` into it, and XORs the copy with `0x2a` (`memfrob`). That routine is a validator. It checks that the text after `HTB{` satisfies `input[i] == key[i] ^ i` for 28 bytes. The key is built on the stack from eight `movabs` constants. When the validator accepts the input, the program prints `ERROR READING DATA` and clears the message. The flag is the 28-byte string that the validator accepts, wrapped in `HTB{...}`.

## Attack chain

- **Entry point.** `main` in `satellite` calls `send_satellite_message(0, "START")`, then reads up to `0x400` bytes from file descriptor `1`, and then calls `send_satellite_message(0, buffer)`. Reading fd 1 is an artifact of the design: the challenge expects a socket for both stdin and stdout.
- **Library.** `send_satellite_message` in `library.so` calls `getenv` with a name that it builds on the stack by subtracting 1 from each byte of a constant. The decoded name is `SAT_PROD_ENVIRONMENT`. If the variable is set, the library calls a helper that maps `0x2000` bytes (RWX), copies `0x1000` bytes from `.text` at `0x11a9`, and XORs them with `0x2a`. The page is then used for the validator.
- **Decoded routine.** The decoded routine (at offset `0x0` in the blob) has two paths. For mode `1`, it reads the message, looks for the marker `HTB{` (`0x7b425448`), and calls the validator on the bytes after it. If the validator returns `1`, it clears the buffer and returns `-1`. That return value is what main reports as `ERROR READING DATA`.
- **Validator.** At offset `0x8c` the routine stores a 28-byte key on the stack with four 8-byte writes (two `movabs` and two `mov [rsp+d8], reg` pairs per half). Two writes overlap, so the key is the last write to each byte. The validator loops over `i` from `0` to `27`, computes `input[i] ^ key[i]`, and requires the result to equal `i`. So `input[i] = key[i] ^ i`.
- **Flag.** Replaying the stores gives the key `l5{0v0Y7fVf?u>|:O!|Lx!o$j,;f`. XOR with the index gives the 28 bytes that end the flag, so the flag is `HTB{l4y3r5_REDACTED}`.

## Steps

1. Extract the archive. The files are `rev_satellitehijack/satellite` and `rev_satellitehijack/library.so`.
2. Read `main` and the `send_satellite_message` function in `library.so`. Note the `getenv` call and the environment variable name built on the stack.
3. Find the XOR-ed region (`0x11a9`) and decode it with `0x2a`. Disassemble the result. The first function is the entry point, and the one at `0x8c` is the validator.
4. Replay the stack stores that build the key, then XOR with the index to recover the 28 bytes.
5. Run the solver on a copy of `library.so` from a scratch folder:

   ```
   python3 solve.py library.so
   ```

   Sample output (flag masked):

   ```
   HTB{l4y3r5_REDACTED}
   ```

6. Check the validator directly. Run the program in a `linux/amd64` container with `--network none`, a socket for fd 1, and `SAT_PROD_ENVIRONMENT=1`. The exact flag gives `ERROR READING DATA`. Changing the last character to `?` gives `Sending ...`. This confirms the validator accepts only the recovered string.

## Problems hit

- The program reads from fd 1, not stdin. A plain pipe gives `ERROR READING DATA` on every loop, and the loop never exits on EOF. The working harness passes a socket pair as both stdin and stdout.
- Running the program with a pipe for stdin and then for stdout made the output look like a failure. That was the fd problem above, not the validator.
- The validator only runs in `SAT_PROD_ENVIRONMENT` mode. Without the variable, the same input is only echoed, so it is easy to miss the hidden routine.
- The challenge has no endpoint, so the flag could not be submitted to the server. The answer is confirmed by the validator's own accept/reject behavior, not by a server response.

## Defense

- **Do not hide a validator behind an environment variable in the same binary.** The variable is a simple switch, and the decoded code is still in the file. Move the check to a server.
- **Do not use XOR with a constant as obfuscation.** `memfrob` with a fixed key is trivially reversed, and the key is recovered from the same bytes.
- **Do not store a secret as stack constants.** The key is built from immediates that are easy to read in the disassembly. Store the check output only, as a keyed hash, and compare on the server.

## Lessons

- A program can hide logic behind an environment switch. Look for `getenv` calls and the code that runs after them, even if the output looks the same without the switch.
- A decoded routine often shows its own checks. Here the validator's loop and its `i` term gave the mapping from key to flag.
- Test a recovered answer against the binary's own accept/reject behavior. A one-character change that flips the output is strong evidence, even when no server is available.
