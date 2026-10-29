---
title: crypto/the-gazorpazorps
platform: HTB
event: secfest26
category: crypto
tags: [aes-cbc, bit-flipping, iv-manipulation, cookie-forgery, flask]
status: solved
difficulty: 3
---

# crypto/the-gazorpazorps

**Flag:** `HTB{CBC_REDACTED}`

**Difficulty:** 🌶️🌶️🌶️ (3/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`.

## Summary

The shop issues a `buyer_info` cookie. Its format is `b64(plaintext) "." b64(iv + AES-CBC(plaintext))`. The plaintext is `certified=False&user=guest&expiry=...` for a guest. `POST /order/` shows the flag only when `certified` is `True`.

The cookie check (`signature.integrity`) takes the IV from the first 16 bytes of the segment, encrypts the plaintext from the first part again with that IV, and compares the whole result with the segment. The check is correct, but it only checks that the ciphertext matches the IV the client sends. The IV is part of the attacker's input.

The first ciphertext block is `E(P1 ⊕ IV)`. If the attacker changes the plaintext block to `P1'` and sets `IV' = IV ⊕ P1 ⊕ P1'`, the first block stays the same. Every later block depends only on the previous ciphertext block, so it stays the same too. The forged cookie passes the check, and the decrypted plaintext is never used. The server only reads the plaintext from the first part of the cookie, so the attacker also writes the new plaintext there.

### Vulnerable code

The IV default is in `private/htb/secfest26/crypto-the-gazorpazorps/src/crypto_the_gazorpazops/application/models.py`, line 59:

```python
    def create(secret, hashing_input, iv=urandom(BLOCK_SIZE)):
```

The integrity check is in the same file, lines 68 to 74:

```python
    @staticmethod
    def integrity(hashing_input, crypto_segment):
        if signature.create(KEY, signature.decode(hashing_input),
                            signature.decode(crypto_segment)
                            [:AES.block_size]) == crypto_segment:
            return True
        return False
```

## Attack chain

1. **Get a guest cookie.** `GET /` without a cookie returns a 302 and sets `buyer_info`.
2. **Read the first block.** The plaintext starts with `certified=False&`, which is exactly 16 bytes.
3. **Choose the new first block.** `certified=True&&` is also 16 bytes. The `&&` is an empty parameter that `parse_qs` ignores. The rest of the plaintext is unchanged.
4. **Compute the new IV.** `IV' = IV ⊕ "certified=False&" ⊕ "certified=True&&"`, which is the IV bit-flip.
5. **Send the cookie.** Use the new plaintext in the first part and `IV' + ciphertext` in the second part. `POST /order/` with that cookie returns the flag.

## Steps

1. Run `solve.py`. It gets a guest cookie with `GET /`, builds the forged cookie as described above, and sends `POST /order/` with it.
2. The response has the flag, which the solver prints after `[+] Flag:`. The flag is `HTB{CBC_REDACTED}`.

## Sample output

Output of `python3 solve.py <target_ip> <target_port>` against the live instance, with the flag masked. Pasted from the run, not written by hand.

```
[+] Flag:
HTB{CBC_REDACTED}
```

## Problems hit

- **The plaintext in the cookie must change too.** The first attempt only changed the IV. The integrity check passed, but the plaintext still said `certified=False`, so the server rejected it. The IV change only keeps the ciphertext valid. The plaintext in the first part of the cookie must be changed to match.
- **The archive has no `secret.py`.** The app imports `application.secret.flag`, which is not in the download. The solve was checked on a local copy with a dummy `secret.py`, then run against the instance.
- **The IV is reused.** The default argument `iv=urandom(BLOCK_SIZE)` is evaluated once per process, so every cookie in one process has the same IV. This did not matter for the attack, but it is a second weakness.

## Defense

- **Authenticate the plaintext, not only the ciphertext.** Use an HMAC over the plaintext, or an authenticated mode such as AES-GCM. Do not compare the output of encryption with a value the client sent.
- **Do not let the client choose the IV.** The IV should come from the server and be bound to the message by the authentication.
- **Use a fresh random IV per message.** Generate the IV inside `create()` for each call, not once at import time.
- **Keep privilege out of the cookie.** `certified` should be looked up on the server from the account, not read from a client-held value.

## Lessons

- CBC bit-flipping does not always need a decryption oracle. Here the server checked the cookie by encrypting, so the IV alone gave control of the first block.
- Changing the ciphertext and changing the plaintext are different steps. Both have to match for the server's comparison to pass.
- Test the forged value against the server's own check function (`integrity`) and against the parsed privilege (`validate_login`) separately. That showed the plaintext was still wrong.
