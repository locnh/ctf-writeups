---
title: web/flag-command
platform: HTB
event: try-out
category: web
tags: [api-exposure, hidden-command, client-side-logic, flask]
status: solved
difficulty: 2
---

# web/flag-command

**Flag:** `HTB{D3v3l0p3r_t00l5_4r3_b35t_wh4t_y0u_Th1nk??!_REDACTED}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`

## Summary

The app is a text adventure in a terminal-style page. Players type commands, and the browser sends each one to `POST /api/monitor` with `{"command": ...}`. The server replies with a story message. The intended route is to walk through four story steps and win.

The game options come from `GET /api/options`. That endpoint returns the full `allPossibleCommands` object, including a `secret` key. The client accepts commands from that list too, but never shows them. The `secret` entry holds a single command, and sending it to `/api/monitor` returns the flag.

Relevant code: no source code was provided. The client JavaScript (`static/terminal/js/main.js`) shows the behavior:

- `startCommander` calls `fetchOptions`, which loads `/api/options` and stores `allPossibleCommands` as `availableOptions`.
- `CheckMessage` sends the typed command to `/api/monitor` if it is in `availableOptions[currentStep]` or in `availableOptions['secret']`.
- When the response text contains `HTB{`, the client calls `playerWon()`.
- The UI shows only the current step's options. The `secret` list is never displayed.

Because the full options object is public, anything listed under `secret` is known to any client that reads the API response.

## Attack chain

1. Request `GET /api/options` and read the `secret` array.
2. Send that string as the `command` field to `POST /api/monitor`.
3. The response message contains the flag.

Observations from testing:

- The secret command bypasses the step check. The server accepts it at any point in the game, without starting the game or choosing the earlier options.
- Other commands are rejected with `What are you trying to break??`. That message only shows the server handles the input; it does not show that the input is a template or an injection.
- The normal path (`HEAD NORTH` and so on) works. Its first response is a story line. I did not play through to the end, because the secret command already returned the flag.

## Steps

1. `curl http://<target>/api/options` and find `"secret": ["Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"]`.
2. `POST /api/monitor` with `{"command": "Blip-blop, in a pickle with a hiccup! Shmiggity-shmack"}`.
3. The `message` field is the flag: `HTB{D3v3l0p3r_t00l5_4r3_b35t_wh4t_y0u_Th1nk??!_REDACTED}`.

The solve script does steps 1 and 2 with `requests` and prints the response.

## Problems hit

None. The secret command was in the options response the whole time, and it returned the flag on the first try.

## Defense

- **Do not return secrets from a public API.** `/api/options` should return only the commands the current step allows. The list of secret commands belongs on the server, and a client should never receive it.
- **Enforce game rules on the server.** `/api/monitor` should check the current game state and the player's step before it returns story or secret responses. Right now the server accepts any command in the options list at any step.
- **Do not rely on the client to hide commands.** Hiding options in the UI is not an access control. Anything the client receives can be read.
- **Avoid returning the flag in game responses.** If the flag must be in a response, release it only after the server confirms the win condition.

## Lessons

- An API that returns more data than the UI shows can leak secrets. Check every API response, not just the parts the page displays.
- A client-side allowlist is not a security check. Here the client copied the server's full list, including the secret entry.
- When a game client has a "hidden" branch, read its API responses first. The secret was in the same response as the visible options.
