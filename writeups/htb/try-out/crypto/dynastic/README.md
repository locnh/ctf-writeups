---
title: crypto/dynastic
platform: HTB
event: try-out
category: crypto
tags: [position-shift, caesar, trithemius, classical-cipher]
status: solved
---

# crypto/dynastic

**Flag:** `HTB{REDACTED}`

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <output.txt>`. The script works offline.

## Summary

The challenge gives a ciphertext and a hint line. The cipher is a Caesar-like shift, but the shift depends on the position of each letter instead of being fixed. Each letter is moved by its index in the string, mod 26. Non-letter characters keep their place and are not shifted, but they still count in the index. Because the shift is known, the cipher can be reversed directly. The hint line says the decrypted text must be wrapped in the HTB flag format.

## Source review

The challenge ships with two files: a Python encryption script and the output. The script is kept in `private/` and is not reproduced here. Only the logic matters for the write-up:

- Each letter `ch` at index `i` becomes `(ch - 'A' + i) mod 26`, then mapped back to a letter.
- Non-letters are copied unchanged. The index `i` still counts them, so they affect the shift of every letter after them.
- The flag is written after a fixed line, so the output has no braces. The braces come from the HTB format and are added by the solver.

## Steps

1. Read `output.txt`. The first line is the hint, and the second line is the ciphertext.
2. For each letter at index `i`, subtract `i` from its position in the alphabet, mod 26. Leave other characters as they are.
3. The result is the plaintext. Wrap it as `HTB{...}`.
4. Check the result by encrypting the plaintext again. It must match the ciphertext exactly.

The solve script does steps 2 and 3. Step 4 was checked with a separate encryption script kept in `private/`, not in the public repo.

## Observations

- The output is a single line of uppercase letters with punctuation (`?!`, `_`) mixed in. The `_` characters are not letters, so they keep their position and still count in the index.
- The shift is by the position, not by a fixed key. A frequency analysis does not work well here, but the cipher is trivial to reverse once the rule is known.
- The hint on the first line tells you the format of the answer and names the cipher family. It gives the plaintext format, not the key.

## Problems hit

None. The first decryption was correct. The main risk was the index, because the non-letter characters still count in it. The re-encryption check confirmed the answer.

## Defense

- **Do not use a position-only shift as encryption.** The key is public: anyone who knows the rule can reverse it. Use an authenticated cipher with a secret key, such as AES-GCM.
- **Keep the logic and the output separate from the key.** The flag was in the same program as the cipher. A secret must never be stored next to the rule that reads it.
- **Test the reverse path.** A cipher that cannot be decrypted by its owner is also a bug. Check round trips in tests.

## Lessons

- A cipher that looks like Caesar but uses the index is a Trithemius-style progressive shift, and the hint names the family.
- Count every character in the index if the encryption does. Skipping non-letters changes every later letter.
- Re-encrypting the answer is a cheap check that catches off-by-one errors in the index.
