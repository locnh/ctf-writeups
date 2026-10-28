---
title: crypto/blessed
platform: HTB
event: try-out
category: crypto
tags: [bls, rogue-key, cut-and-choose, zkp, ec-lcg, p256, meet-in-the-middle]
status: solved
difficulty: 4
---

# crypto/blessed

**Flag:** `HTB{uNv31leD_5eCre7s_0f_BLS_r0gu3_k3y_4t7aCk_w1th_cu5t0m_zkp_4nd_ec-lcg!!_REDACTED}`

**Difficulty:** 🌶️🌶️🌶️🌶️ (4/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`. It needs `pip install py_ecc` and a C compiler. On the first run it builds `./search` from `artifacts/search.c` with `cc -O3`. The run takes about 18 minutes, most of it in RNG recovery.

## Summary

The service is a "SuperComputer" that registers BLS robots and runs three commands: `create`, `join` (add a robot with a public key), and `verify` (prove you know the secret key). Once every registered robot is verified, `unveil_secrets` returns the flag if the client sends an aggregate BLS signature from all verified keys over `unveil_secrets`.

Two weaknesses combine:

- **The robot IDs leak the RNG state.** The RNG walks a P-256 curve. Each step adds the generator `G`, and every output is the high 224 bits of the x or y coordinate. The IDs are the outputs, so they reveal the state.
- **The proof of possession can be cheated.** `verify` is a 64-round cut-and-choose. The challenge bit for each round is one bit of the same RNG. If the attacker can predict the bits, they can answer every round for a public key they do not know the secret for.

Together, the attacker predicts all the challenge bits, registers a rogue key that makes the aggregate key equal to a key they control, and signs `unveil_secrets` with that key.

## Attack chain

- **Robot IDs.** The server creates 4 robots at start, and `create` adds a 5th. Those are yields 1 to 5. `join` takes yield 6. Each `verify` round takes one yield, so rounds 1 to 64 use yields 7 to 70. The bit for a round is bit 32 of the x or y coordinate of the walk point that the yield came from.
- **Recovering the first point.** Yields 1 and 2 are the high 224 bits of `W1.x` and `W1.y`, where `W1 = seed·G + B + G`. The low 32 bits of each coordinate are unknown. The curve equation gives `F(X0 + u) = (Y0 + v)^2 mod p` with `u, v < 2^32`. A meet-in-the-middle search over `u` and `v` finds the answer. The C helper runs it in 2^7 passes, and the Python side checks each candidate on the curve. The solution is unique.
- **Checking the state.** Yields 3 and 4 must equal `W2 = W1 + G`. If they match, the state is right.
- **Rogue key.** The attacker gets every verified key `pk_i` from `list` and sums them to `total`. They choose `a` at random and set `pk' = a·G1 − total`. Then `pk_i` sum with `pk'` equals `a·G1`, so a signature by `a` over `unveil_secrets` verifies against all the keys.
- **Cut-and-choose.** The attacker sends `join` with `pk'`, then answers the 64 rounds using the predicted bits:
  - Bit 1 (x-branch): commit `C = x·G1` and reveal `x`.
  - Bit 0 (sk-branch): commit `C = s·G1 − pk'` and reveal `s`.
- **Forging.** After the proof passes, `pk'` counts as verified. The attacker signs `unveil_secrets` with `a`, and the server returns the flag.

## Steps

1. Create a robot and sign `list` with its key. Read the 5 robot IDs and the public keys.
2. Recover `W1` from the first two IDs (`search.c`, meet-in-the-middle). Check the result with IDs 3 and 4.
3. Compute `pk'` and send `join`. Check that the returned ID equals yield 6.
4. Send `verify` for that ID. For each of the 64 rounds, predict the bit from yield `7 + i`, send the commitment for that branch, then send the answer.
5. Sign `unveil_secrets` with `a` and send `unveil_secrets`. The response contains the flag.

Recovery takes about 18 minutes, and the server closes idle connections after roughly that long. The solver sends a `help` command every 60 seconds during recovery to keep the connection open. `help` does not use the RNG.

## Sample output

Sample output (flag masked):

```
[*] Created robot 30dd8a7c1a41d6b15a33469df89f698d7c085cd707f392bb79a46c7f
[*] Listed 5 robots
[*] Recovered RNG state, predictions match observed robot ids
[*] Joined as robot a204a9df9f97dd637310c9aa63aab30f2e6e8d8e8512f5041d891663
[*] verify: {"msg": "Robot verified"}

>
[+] {'msg': 'Secrets have been unveiled!', 'flag': 'HTB{uNv31leD_5eCre7s_0f_BLS_r0gu3_k3y_4t7aCk_w1th_cu5t0m_zkp_4nd_ec-lcg!!_REDACTED}'}
```

## Problems hit

- **Predicting the RNG was off by one at first.** The first attempt mixed up the yield index, so the predicted bits did not match the server. The fix was to take yield `7 + i` for round `i`, and yield 6 for `join`.
- **The local source and the live server disagree.** `src/crypto_blessed/server.py` asks for `C = x * pk` in the x-branch, but the live service asks for `C = x * G1`. A local test built on the source would fail on the x-branch. The solver follows the live service. Test against the live prompt text, not only the source.
- **Recovery is slow with pure meet-in-the-middle.** It needs about 2^32 operations per side, which is why it takes minutes even in C. A lattice (LLL) over 6 values recovers the same state much faster, but it needs Sage or fpylll.
- **Idle timeout during recovery.** The 18-minute recovery is longer than the server's idle timeout. The `help` keepalive fixed it.

## Defense

- **Do not expose RNG outputs as identifiers.** The robot IDs are the RNG output, and the output reveals the state. Use a CSPRNG and do not expose its output.
- **Do not use a proof of possession that can be simulated.** A cut-and-choose proof is only sound if the challenge bits are unpredictable. Use a standard PoP for BLS, such as signing the public key with its secret key.
- **Check the aggregate key on registration.** The rogue key only works because the server accepts any key that passes the broken proof. A standard PoP check would stop this attack.

## Lessons

- A cut-and-choose proof is only as strong as its challenge. If the attacker can predict the challenge, they can answer every round.
- When the aggregate key is a sum of user-chosen keys, one unverified key can cancel out the rest. This is why BLS aggregation needs proof of possession.
- The source in the challenge folder can differ from what is deployed. Check the live prompts before trusting the source.
- Meet-in-the-middle is a fallback. For recovering a point from partial coordinates, a lattice attack is faster when it fits.
