---
title: misc/stop-drop-roll
platform: HTB
event: try-out
category: misc
tags: [scripting, automation, protocol]
status: solved
difficulty: 1
---

# misc/stop-drop-roll

**Flag:** `HTB{1_wiLl_sT0p_dR0p_4nD_r0Ll_mY_REDACTED}`

**Difficulty:** 🌶️ (1/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`

## Summary

The service is a game called "The Fray". It sends a list of scenarios and expects one answer per scenario, mapped as follows:

| Scenario | Answer |
|---|---|
| `GORGE` | `STOP` |
| `PHREAK` | `DROP` |
| `FIRE` | `ROLL` |

When a round lists several scenarios, the answer is the mapped words joined with `-`, in the same order. For example, `GORGE, FIRE, PHREAK` needs `STOP-ROLL-DROP`.

The game runs for 500 rounds. After the last correct answer it prints the flag. Each round is a fixed mapping, so a script can answer every round without any game logic of its own.

## Steps

1. Connect and answer `y` to `Are you ready? (y/n)`.
2. Read each round line `What do you do? <scenarios>`.
3. Split the line into scenario names with a regex, map each name, and join the answers with `-`.
4. Send the answer and repeat. After round 500, the reply contains the flag.

The solve script does this with `pwntools` and a single connection. It uses a regex on the keywords, so it ignores the rest of each line.

## Observations

- The round lists vary in length, from one to five scenarios. The script handles all of them with the same code.
- The run took 500 rounds and ended with the flag. The script did not send any wrong answers, so how the server handles a wrong answer was not tested.

## Problems hit

None in the run. The flag line also starts with `What do you do?`, so the script checks for `HTB{` before it looks for scenario keywords.

## Defense

- Game logic that is fully deterministic can be scripted by anyone. If the challenge needs to resist automation, add a time limit per round, a random answer delay, or a token tied to each round.

## Lessons

- A protocol that is a simple mapping for 500 rounds is a scripting task. The useful step is to read the rules from the banner and map them to a regex, not to play it by hand.
