---
title: crypto/me-is-mey
platform: HTB
event: secfest26
category: crypto
tags: [hash-collision, custom-hash, bit-manipulation, sha256, second-preimage]
status: solved
difficulty: 2
---

# crypto/me-is-mey

**Flag:** `HTB{sh4256_REDACTED}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`.

## Summary

The server gives the SHA-256 digest of `ready_play_one!`, which is computed by a custom `hash` class. The class does not hash the message directly. It first maps each byte with `((b >> 4) | (b << 3)) & 0xff`, then hashes the mapped bytes with SHA-256. The server asks for a different message with the same digest. The flag is printed when the digests match and the message is not the original.

The hint talks about bit manipulation and transposition. The code has no transposition step, only the bit map. The map is not one-to-one. The right shift puts bits 4 to 7 into positions 0 to 3, and the left shift puts bits 0 to 4 into positions 3 to 7. They overlap at bit 3, so two different bytes can give the same mapped value.

### Vulnerable code

The custom hash is in `private/htb/secfest26/crypto-me-is-mey/src/crypto_me_is_me/server.py`, lines 10 to 15:

```python
    def rotate(self, message):
        return [((b >> 4) | (b << 3)) & 0xff for b in message]

    def hexdigest(self):
        rotated = self.rotate(self.message)
        return sha256(bytes(rotated)).hexdigest()
```

## Attack chain

1. **Read the hash.** `rotate` is a per-byte map on the message, then SHA-256 is applied to the result. The map is not invertible, so the input can be changed without changing the output.
2. **Find byte collisions.** For each byte value, look for a different byte with the same mapped value. For example, `0x65` (`e`) and `0xe4` both map to `0x2e`. Each group has three members, for example `1`, `128` and `129` all map to `8`.
3. **Change one byte.** Replace one byte of `ready_play_one!` with its partner. The mapped bytes, and so the SHA-256 digest, stay the same, but the message is different.
4. **Send the message.** Send it as hex. The server prints the flag.

## Steps

1. Run `solve.py`. It reads the digest from the server banner. For each byte index it looks for a partner byte, and it returns the first forged message whose digest matches the server's. The forged message is sent as hex.
2. The server replies with the flag, which the solver prints after `[+] Server:`. The flag is `HTB{sh4256_REDACTED}`.

## Sample output

Output of `python3 solve.py <target_ip> <target_port>` against the live instance, with the flag masked. Pasted from the run, not written by hand.

```
[+] Server: Enter your message: HTB{sh4256_REDACTED}
```

## Problems hit

- **No transposition step in the code.** The hint mentions transposition, but `rotate` only maps each byte. The collision comes from the overlapping bit at position 3 and needs no inversion of a transposition.
- **The prompt has no newline.** The server writes `Enter your message: ` with no line break, so the reply line starts with the prompt. The solver prints the full reply, so the flag is still visible.

## Defense

- **Do not use a non-injective byte map as a hash input.** The map `((b >> 4) | (b << 3)) & 0xff` loses information, so many messages share a digest. A hash should be built from a standard primitive applied to the full message.
- **Use a proper hash function.** Pass the raw message to SHA-256 directly, or use an HMAC if a keyed value is needed.
- **Check the message, not only the digest.** The server checks that the digests match and the message differs, but an attacker can always find a partner. Avoid using this kind of check as a security property.

## Lessons

- A hash that changes or drops bits before SHA-256 is not collision resistant, even if SHA-256 is strong.
- When the description and the code disagree, trust the code. The hint mentions transposition, but the bit map alone is enough.
- A collision can often be found by a per-byte search when the mapping is small and not one-to-one.
