---
title: misc/character
platform: HTB
event: try-out
category: misc
tags: [oracle, information-disclosure, scripting]
status: solved
difficulty: 2
---

# misc/character

**Flag:** `HTB{tH15_1s_4_r3aLly_l0nG_fL4g_i_h0p3_f0r_REDACTED}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`

## Summary

The service asks for an index into the flag and replies with the character at that position. Nothing limits how many indices can be requested, and the flag is returned one character at a time. Requesting indices in order from `0` and stopping at the closing `}` recovers the whole flag.

## Steps

1. Connect to the service. The first prompt is `Which character (index) of the flag do you want? Enter an index:`.
2. Send an index, for example `0`. The reply has the form `Character at Index 0: H`.
3. Parse the character after the colon and append it to the result.
4. Increase the index and repeat until the character is `}`.

The solve script uses a single persistent connection and `pwntools` to read each prompt and reply. It stops when it reads a `}`, or when the connection closes.

## Observations

- The reply always has the form `Character at Index N: c`, so parsing is a split on `:`.
- The index keeps working well beyond the end of the visible flag prefix. The flag is 103 characters long, ending with `}` at index 103.
- No rate limiting or connection limit showed up during the run.

## Problems hit

None significant. The script's default `pwntools` logging was already quiet, so the output only shows one line per index.

## Defense

- The service is a per-character oracle. Any client that can make requests can recover the whole secret, so the secret should never be exposed through an index-based lookup.
- If the flag must be checked interactively, the service should accept a guess and return only pass or fail, never a character.
- Rate limiting and a cap on the number of requests per connection would make the attack slower, but they do not remove the leak.

## Lessons

- A prompt that returns one character per request is a classic oracle, and it works even when the input looks harmless. A loop with a stop condition is enough to solve it.
