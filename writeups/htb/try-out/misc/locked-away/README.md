---
title: misc/locked-away
platform: HTB
event: try-out
category: misc
tags: [python-sandbox, blacklist-bypass, exec, jail]
status: solved
---

# misc/locked-away

**Flag:** `HTB{bYp4sSeD_tH3_fIlT3r5?_aLw4Ys_b3_c4RefUL!_REDACTED}`

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`

## Summary

The service is a Python "jail". It reads a line, rejects it if it contains a word from a blacklist, and otherwise runs it with `exec()`. The blacklist blocks the usual ways to reach the flag: `open`, `read`, `flag`, `print`, `eval`, quotes, brackets, and others. But the program defines a function `open_chest()` that prints `flag.txt`, and the blacklist does not stop the input from reaching it. The bypass builds the name `open_chest` from `chr()` calls, looks it up in `globals()`, and calls it.

## Source review

The whole program is `challenge/main.py`:

- `open_chest()` opens `flag.txt` and prints it. Nothing else in the program calls it.
- `blacklist` is a list of substrings. A command is rejected if any entry appears anywhere in the string, so `print` also rejects `pprint`, and `os` also rejects `possess`.
- The loop calls `exec(command)` on the input. Any exception prints `You have been locked away...` and exits.

The blacklist is a substring check on the raw input. It does not limit what the code can do once it runs.

## Steps

1. Connect to the service. The prompt is `The chest lies waiting... `.
2. Send the payload below. Each character of `open_chest` is a separate `chr()` call, so the name never appears in the input. `globals()` returns the module's global namespace, and `.get()` returns the function object. The trailing `()` calls it.

   ```python
   globals().get(chr(111)+chr(112)+chr(101)+chr(110)+chr(95)+chr(99)+chr(104)+chr(101)+chr(115)+chr(116))()
   ```

3. `open_chest()` prints the contents of `flag.txt`, which appears in the reply.

The solve script sends this payload in one connection and prints the line that contains `HTB{`.

## Observations

- The payload is accepted on the first try. None of the blacklisted words appear in it.
- The reply includes the flag and then the prompt again, so the script looks for the `HTB{` line instead of reading the whole reply.
- The service keeps running after the call, so a second payload could also be sent.

## Problems hit

None. The one-line payload in the earlier notes already worked. The script adds the connection and reads the reply.

## Defense

- **Do not `exec()` user input.** A blacklist cannot cover every way to reach a function. Any name, attribute, or string that can be built at runtime bypasses it.
- **Use an allowlist for the expression language.** If the service needs to evaluate expressions, parse them with `ast` and allow only the node types the task needs, such as numbers and arithmetic. Do not expose `globals()`, `getattr`, or `__import__`.
- **Keep secrets out of the process that evaluates input.** `open_chest()` is in the same namespace as the evaluator. A separate process with no flag file would have nothing to read.
- **Blacklisting is fragile.** Substring blacklists are easy to bypass with `chr()`, string concatenation, or unicode tricks. The fix is to change the design, not to add more words to the list.

## Lessons

- A blacklist protects against the words you thought of. In a Python jail, `globals()` and `chr()` are enough to reach any name in the module.
- When a function you want to call has a name you cannot type, build the name from characters. Check whether the namespace can be reached first.
