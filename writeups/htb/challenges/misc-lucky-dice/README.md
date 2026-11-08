---
title: misc/lucky-dice
platform: HTB
event: challenge
category: misc
tags: [scripting, netcat, timing, python, tie-breaking]
status: solved
difficulty: 3
---

# misc/lucky-dice

**Flag:** `HTB{r0LL1ng_REDACTED}`

**Difficulty:** 🌶️🌶️🌶️ (3/5)

**Solve script:** `artifacts/solve.py`, run as `python3 solve.py <target_ip> <target_port>`.

## Summary

Lucky Dice is a TCP service that plays a dice game 100 times. Each round the server prints every player's dice, then asks which player has the highest sum. Answering all 100 rounds correctly prints the flag. The service accepts an answer only if it arrives within 0.3 seconds of the question, and it ends the session on the first wrong answer.

The answer can be computed from the output. The only hard parts are the timing limit, which rules out a human, and the tie rule, which must match the server's `sorted(...)[-1]` exactly.

## Attack chain

1. **Read the source.** `challenge.py` is a single file. `rounds = 100`, and `player_nr = random.randint(8, 13)` is not seeded, so the player count changes on every run.
2. **Parse the round.** For round `r`, the server prints `dice_nr = r * 2 + 2` dice per player (so 2 dice in round 1, up to 200 in round 100). The solver sums each `Player N:` line.
3. **Pick the winner.** The winner is the player with the highest sum. On a tie, the server sorts `dice_sum.items()` by sum and takes the last element, so the tie goes to the highest-numbered player.
4. **Answer within the window.** The server measures time between the printed question and the answer. The solver sends the answer as soon as it has the full round.
5. **Read the flag.** After round 100 the server prints `Nice job!` and the flag.

## Code analysis

Relevant lines of `challenge.py`:

```python
rounds = 100
player_nr = random.randint(8, 13)
timeout = 0.3

def loop(rnd):
    dice_nr = rnd * 2 + 2
    ...
    for player in range(player_nr):
        ...
        for dice in range(dice_nr):
            dice_res[rpd] = int(random.randint(1, 6))
            dice_sum[rp] += dice_res[rpd]
        print('Player ' + str(player+1) + ': {dices}'.format(dices = ' '.join(map(str, dice_list))))

    result = sorted(dice_sum.items(), key=lambda x:x[1])[-1][0][1].split('_')[1]

    start = time.time()
    answer = input('> ')

    if time.time() - start > timeout:
        print("Mate... your are too slow! It seems your CPU is too old!")
        return False

    if answer != result:
        print('Hey! I think your scorring is off... Check your RAM... It may be corrupted!')
        return False
```

- The dice are printed, so every sum the server uses is visible on the wire. The solver does not need to predict the RNG.
- `sorted(dice_sum.items(), key=lambda x: x[1])[-1]` returns the largest sum. `sorted` is stable, so among equal sums the last one inserted wins, and the insertion order is player 1, 2, ..., N. The highest-numbered player wins ties.
- `timeout = 0.3` is measured from the prompt to the `input()` return. A human cannot meet it for 100 rounds, but a local parser can.
- `answer != result` compares strings. The solver sends `str(winner)`, so `"3"` must match `"3"` exactly. Leading or trailing text fails.
- The `time.sleep(0.1)` calls run while the dice are printed, before the timer starts. The timer starts only at `start = time.time()`, just before the answer `input()`. The solver reads up to the `> ` that follows `Who wins this round?`, so the answer is sent after the question is printed and as soon as the winner is computed.
- The flag is read from `flag.txt` next to `challenge.py` and printed only after round 100.

## Steps

1. **Connect and start the game.** The intro ends with `1. Yes / 2. No`. Send `1`.

   ```
   $ nc 154.57.164.78 39660
   ...
   > 1
   ```

2. **Answer each round.** For each round, parse every `Player N: d1 d2 ...` line, compute sums, and send the winner's number.

   ```
   -----------   Round 1    -----------
   Player 1: 3 5
   Player 2: 6 2
   ...
   Who wins this round?
   1. Player1
   ...
   > 
   ```

   Both players sum to 8, so it is a tie, and the tie goes to the highest-numbered player: answer `2`. The solver repeats this 100 times.

3. **Read the flag.** After round 100 the output contains `Nice job!` and the flag.

   ```
   $ python3 solve.py 154.57.164.78 39660
   HTB{r0LL1ng_REDACTED}
   ```

## Sample output

Output of the documented solve command, with the flag masked.

```
$ python3 solve.py 154.57.164.78 39660
HTB{r0LL1ng_REDACTED}
```

## Problems hit

- **Round count.** The number of dice doubles every two rounds (`rnd * 2 + 2`), so the late rounds print roughly 200 dice per player. Reading the whole round before answering keeps the answer correct; answering on the first line would give the wrong winner.
- **Tie rule.** A first guess was "first player wins a tie". The source uses `sorted(...)[-1]`, which gives the highest-numbered player. The solver implements this rule, and `max(p ...)` over player numbers matches it.
- **Timing.** The server's 0.3-second limit is enforced by `time.time()` around `input()`. The solver does not wait between rounds, so the window is not an issue as long as the full round is parsed first.
- **Random player count.** `player_nr` is not seeded, so the player count (8–13) changes per run. The solver reads the count from the output, so it does not hard-code it.

## Defense

- A response-time check is not a human check: any script that parses the output passes it. If the game must limit bots, use a stronger control (for example a proof-of-work or a CAPTCHA), not a timer.
- The round's winner is fully determined by the printed dice. That is by design for this game, so the challenge is a scripting exercise. If the answer were meant to be secret, do not print the inputs that determine it.
- Make the tie rule explicit in the rules shown to players. The intro says "the player who rolled the last dice wins", but the code breaks ties by player number. A mismatch between the stated rule and the implemented rule is a correctness bug.

## Lessons

- Read the tie rule from the source, not from the rules printed to the player. The intro says "the player who rolled the last dice wins", but the code implements a different rule (highest-numbered player on equal sums). The source is the spec.
- A timing check on `input()` is only as strong as the client's parser speed. Here it is a deliberate barrier that a script clears easily.
- Read the full output of a round before deciding. Answering from the first lines of a round gives a different winner.
