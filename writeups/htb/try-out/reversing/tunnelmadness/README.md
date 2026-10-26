---
title: reversing/tunnelmadness
platform: HTB
event: try-out
category: reversing
tags: [reversing, maze, 3d, bfs, elf, rodata, scripting, netcat]
status: solved
difficulty: 3
---

# reversing/tunnelmadness

**Flag:** `HTB{tunn3l1ng_REDACTED}`

**Difficulty:** 🌶️🌶️🌶️ (3/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port> [tunnel binary]`. The binary defaults to `tunnel` in the current folder. It reads the maze from the binary and sends the path to the service over TCP.

## Summary

`tunnel` is a 64-bit Linux ELF (not stripped). It is a text game on a 20 × 20 × 20 maze. The player starts at `(0, 0, 0)` and enters one direction per turn: `L`/`R` change `x`, `B`/`F` change `y`, and `D`/`U` change `z`. Moving into a wall or off the grid prints `Cannot move that way`. The game ends when the player reaches the goal cell, which calls `get_flag()`. That function reads `/flag.txt` on the server. The local copy has a placeholder flag in its place.

The maze is a static table in `.rodata`, so the path can be found from the file without running it. A BFS from the start to the goal gives a 59-move path.

## Attack chain

The disassembly (`objdump -d -M intel`) shows four functions in the user code: `main`, `prompt_and_update_pos`, `get_cell`, and `get_flag`.

- **Position.** `main` stores `(x, y, z)` as three `int`s on the stack and passes it to `prompt_and_update_pos` and `get_cell`.
- **Cell lookup.** `get_cell` computes the index `400*x + 20*y + z` and returns the address `maze + 16*index`. Each cell is four `int`s. The fourth one, at offset `0xc`, is the type: `2` is a wall, `3` is the goal, and the others are open.
- **Moves.** `prompt_and_update_pos` reads one character, uppercases it, and jumps through a 20-entry table indexed by `letter - 'B'`. Reading the table gives `B`/`F` for `y-1`/`y+1`, `L`/`R` for `x-1`/`x+1`, `D`/`U` for `z-1`/`z+1`, and `Q` for exit. The other letters do nothing.
- **Win.** After each move, `main` checks `get_cell(pos)->type == 3`. If it is true, it calls `get_flag()`.

The solver reads the maze from the file: the cells start at `0x20e0`, which equals the vaddr in `.rodata`. There is one goal cell at `(19, 19, 19)`, and there are 63 open cells, so the BFS finds a short path. The moves are then sent to the service in one line.

## Steps

1. Extract the archive. The binary is `rev_tunnelmadness/tunnel`.
2. Read `main` for the win condition (`cmp dword ptr [rax + 0xc], 0x3`), then `get_cell` for the index formula, and `prompt_and_update_pos` for the direction table.
3. Find the maze address in `.rodata` (`maze` symbol, `0x20e0`). Parse the 8000 cells with Python.
4. Run the solver from a scratch folder against the service, with the binary copied there:

   ```
   python3 solve.py <target_ip> <target_port> tunnel
   ```

   Sample output (flag masked):

   ```
   HTB{tunn3l1ng_REDACTED}
   ```

5. The real flag is read from the server's `/flag.txt`. The local copy only prints the fake flag, so the real one has to come from the remote instance.

## Problems hit

- The first local run printed the fake flag, which confirmed the win path. It did not confirm the real flag. Only the remote instance returns the real one.
- The maze has 8000 cells, and only 63 are open, so a naive walk gets stuck. A BFS over the parsed table gave the path directly.
- Sending the moves as a single line works because `scanf(" %c")` skips the whitespace between letters. Newlines are not needed.

## Defense

- **Do not put the win condition in a static table in the binary.** The maze, the goal, and the moves are all in the file, so the answer can be computed without playing.
- **Do not return the flag from a path that only checks a position.** The flag is printed once the position matches, with no rate limit or per-session secret.
- **Keep the flag file out of reach of the game process if possible.** It is read directly from `/flag.txt` when the goal is reached.

## Lessons

- Game logic with a fixed map is a graph problem. Parse the map from the binary, then run a search.
- Reading the jump table of a `switch` gives the mapping from input to action. Here it turned `L/R/B/F/D/U` into axis moves.
- Check the solution on a local copy first, then on the remote service. The local flag is fake, so a match there only shows the path reaches the goal.
