---
title: web/timekorp
platform: HTB
event: try-out
category: web
tags: [command-injection, php, shell-quoting, exec]
status: solved
difficulty: 2
---

# web/timekorp

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`

## Summary

The app is a PHP 7.4 site behind nginx and php-fpm. The index page shows the current time, and the `format` query parameter controls the output format. The page links to `?format=%H:%M:%S` and `?format=%Y-%m-%d`.

The `format` value goes into a shell command. `TimeModel` builds `date '+<format>' 2>&1` and runs it with PHP's `exec()`. The format is wrapped in single quotes but never escaped, so a value containing `'` can end the quoted string and add new shell commands.

Relevant code:

- `Router.php` maps `GET /` to `TimeController@index`.
- `TimeController::index` reads `$_GET['format']` (default `%H:%M:%S`) and passes it to `new TimeModel($format)`.
- `TimeModel::__construct` sets `$this->command = "date '+" . $format . "' 2>&1"`. Nothing checks the value.
- `TimeModel::getTime` runs `exec($this->command)` and returns the result. The view prints it with `<?= $time ?>`.
- The flag is at `/flag`. The app runs as `www` (uid 1000), and `/flag` is readable by that user.

## Attack chain

1. Break out of the quoted format with `'`.
2. Add `;cat /flag;` to run a second command.
3. End the injected text with `#` so the trailing `' 2>&1` from the original command is ignored.
4. The output of `cat /flag` is printed in the page heading.

Observations from testing:

- The output appears in the `<h1>` heading, after `It's`.
- PHP's `exec()` returns only the last line of the command output. The flag is a single line, so it is returned in full.
- `%` in the format is a `date` format specifier. The injected part (`';cat /flag;#`) has no `%`, so it does not interact with `date`.

## Steps

1. Confirm the injection. `format=%Y';id;#` renders `uid=1000(www) gid=1000(www) groups=1000(www)` in the heading.
2. Read the flag. `format=%Y';cat /flag;#` renders the flag: `HTB{t1m3_f0r_th3_ult1m4t3_pwn4g3_REDACTED}`.

The solve script does step 2 with `requests` and prints the heading.

## Problems hit

- A payload that ends with `';cat /flag;echo '` does not work. The original command ends with `' 2>&1`, so the closing quote is left unbalanced and `sh` reports a syntax error. Ending the payload with `#` comments out the rest of the command.
- `exec()` returns only the last output line. This is fine for a single-line result, but multi-line output would show only its last line.

## Defense

- **Do not build shell commands from user input.** Call the date function in PHP (`date($format)`) instead of `date` through a shell. The format is then just an argument to a function, not part of a command string.
- **If a shell is required, escape the argument.** Use `escapeshellarg()` on the whole format string, or `proc_open()` with an argument array, so quotes in the input cannot end the argument.
- **Allowlist the format.** Accept only known `date` specifiers such as `%H:%M:%S` and `%Y-%m-%d`, and reject everything else.
- **Limit the process.** Run the web app with a user that cannot read `/flag`. Here the app user can read it, so one injected command was enough.

## Lessons

- A value that is "just a format string" can still be a command. Check every place user input reaches `exec`, `system`, or `shell_exec`, even when the command looks harmless.
- Quoting in the surrounding command matters. The payload has to close the quote and comment out the rest, and the comment (`#`) is the simplest way to do that.
- `exec()` output is line-based. When the page shows only one value, it helps to know that only the last line is kept.
