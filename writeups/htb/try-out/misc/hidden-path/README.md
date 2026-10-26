---
title: misc/hidden-path
platform: HTB
event: try-out
category: misc
tags: [command-injection, unicode, express, nodejs]
status: solved
difficulty: 2
---

# misc/hidden-path

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`

## Summary

The page offers six radio buttons (`free -m`, `uptime`, `iostat`, `mpstat`, `netstat`, `ps aux`). Each one posts an index to `/server_status`, and the server runs the matching command with `child_process.exec`. The index is checked against the array length, so only the six listed commands look reachable.

The array has a seventh entry. In `app.js`, the request body is destructured as `const { choice, ㅤ } = req.body;`, where `ㅤ` is the Hangul filler character U+3164. That name is valid in JavaScript, but it is invisible in most editors and in the rendered source. The array then contains `'ps aux', ㅤ`, so `commands[6]` is whatever the client sends under the field `ㅤ`. Sending `choice=6` and `ㅤ=cat flag.txt` runs that string through `exec`.

Source review:

- `app.js` has one route that matters: `POST /server_status`.
- `choice` is converted with `+choice` and checked with `isNaN` and a bounds check against `commands.length`. The bounds check uses the array length, which includes the hidden seventh element, so index 6 passes.
- The seventh element is not a constant. It is the value of the hidden field, so user input goes straight into `exec()`.
- `public/js/index.js` only sends `choice`. Nothing in the frontend shows the hidden field, so the only way to find it is to read the source.

## Attack chain

- The exploit runs without any extra setup. The response has status 200 and the flag as plain text.
- The Dockerfile runs the app as root in the container. The flag is in `/www/flag.txt` and readable by the app process. No privilege escalation was needed.
- Index 6 is accepted because the bounds check runs against `commands.length`, which is 7 with the hidden element.

## Steps

1. Read the source and find the invisible identifier U+3164 in both the destructuring and the array.
2. Send a form-encoded POST to `/server_status` with `choice=6` and the field named `ㅤ` (U+3164) with the value `cat flag.txt`.
3. The server returns the output of `cat flag.txt` in the response body.

The solve script does step 2 with `requests` and prints the response.

The flag is `HTB{1nvi5IBl3_cH4r4cT3rS_n0t_sO_v1SIbL3_REDACTED}`.

## Problems hit

None. The hidden key was the only tricky part. The existing script already used the right codepoint, which I confirmed as U+3164 before running it.

## Defense

- **Do not pass user input to `exec`.** Use `execFile` with a fixed binary and fixed arguments, or pick from a fixed list by index and never by a user-supplied string.
- **Do not use unicode identifiers you cannot see.** Restrict identifiers to ASCII in the project's lint rules, or flag any non-ASCII identifier in review. A variable that renders as blank should stop the review.
- **Validate the index against the list you intend to expose.** A bounds check on `commands.length` is correct only if the list has no extra entries. Keep the list constant and check it against a fixed count.
- **Do not put user input into the commands array.** The array is data that should be built from constants before any request arrives.

## Lessons

- A command injection can hide in a variable name. The app looked like it only allowed six commands, but the seventh entry was user data.
- The frontend and the backend disagreed about what the valid choices were. When the UI and the code do not match, read the code first.
