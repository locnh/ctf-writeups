---
title: crypto/based0x
platform: HTB
event: secfest26
category: crypto
tags: [encoding, base64, hex, reversible-encoding]
status: solved
difficulty: 1
---

# crypto/based0x

**Flag:** `HTB{enc0d1ng_REDACTED}`

**Difficulty:** 🌶️ (1/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <output.txt>`. It works offline and needs no instance.

## Summary

The challenge gives `source.py` and `output.txt`. `source.py` does not encrypt anything. `encode()` hex-encodes the flag, applies base64 three times, and writes the final bytes as hex. The key is that base64 and hex are encodings with no secret, so the whole chain can be reversed.

The decoded text is a long paragraph of filler text, and the flag is at the end: `Here is your flag : HTB{...}`.

### Vulnerable code

The encoder is in `private/htb/secfest26/crypto-based0x/src/crypto_based0x/source.py`, lines 5 to 9:

```python
def encode(m):
    m = m.hex().encode()
    for _ in range(3):
        m = base64.b64encode(m)
    return m
```

## Attack chain

1. **Read the encoder.** `encode(m)` runs `m.hex().encode()`, then `base64.b64encode` three times. `main` writes `encoded_flag.hex()` to `output.txt`.
2. **Reverse the layers.** Unhex `output.txt`, base64-decode three times, unhex once more. The result is UTF-8 text.
3. **Find the flag.** The text ends with the flag.

## Steps

1. Run `solve.py` with the path to `output.txt`. It applies the reverse of `encode()`, then searches the text for `HTB{...}`.
2. The flag is printed as `[+] Flag:`. The flag is `HTB{enc0d1ng_REDACTED}`.

## Sample output

Output of `python3 solve.py <output.txt>`, with the flag masked. Pasted from the run, not written by hand.

```
[+] Flag:
HTB{enc0d1ng_REDACTED}
```

## Problems hit

- **The decoded text is long.** It is about 5 KB of English filler before the flag. Printing the whole result hides the flag, so the solver searches for `HTB{...}` instead.
- **Each layer is a plain encoding.** No key or nonce is involved, so there was nothing to recover. The trial was to check that each step decodes cleanly, which it does.

## Defense

- **Do not treat encoding as protection.** Hex and base64 are reversible by anyone, so any secret that goes through them is exposed.
- **Use real encryption with a key.** If the data must be hidden, use an authenticated cipher such as AES-GCM with a key that is not in the output.
- **Do not put secrets in output files that leave the trusted system.** Keep the flag or secret on the server side.

## Lessons

- Read the function that produced the output first. It shows which operations were applied, and their order is the reverse of the decoding.
- Repeated base64 can look random at first. Each pass produces another base64 string, so decoding has to repeat the same number of times.
- Check the decoded result for a known format such as `HTB{`, rather than reading the whole output.
