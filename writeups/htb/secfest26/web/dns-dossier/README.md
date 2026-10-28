---
title: web/dns-dossier
platform: HTB
event: secfest26
category: web
tags: [command-injection, os-command, shell-metacharacters, php]
status: solved
difficulty: 2
---

# web/dns-dossier

**Flag:** `HTB{1nv3nt3d_REDACTED}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`.

## Summary

The app is a PHP 7.4 DNS lookup page served by nginx. The form sends a `host` value to `/`, and the page shows the output of a DNS query. The value is put into a shell command without escaping, so a `;` ends the lookup and starts a second command. Its output appears in the same page.

The web server runs as `www` (uid 1000). The flag is in `/flag.txt`, which is readable by all users, so no privilege escalation is needed.

Relevant behaviour, seen from the outside:

- `GET /?host=example.com` returns the normal lookup output.
- `GET /?host=example.com;id` returns the lookup output followed by `uid=1000(www) gid=1000(www) groups=1000(www)`. This confirms that the second command runs.
- `GET /?host=example.com;cat /flag.txt` returns the lookup output followed by the flag, inside the page's `<pre>` block.

## Attack chain

1. **Confirm injection.** Send `host=example.com;id`. The page shows the output of `id` after the DNS answer.
2. **Find the flag.** Send `host=example.com;ls -la /`. `/flag.txt` is in the root directory, readable by `www`.
3. **Read the flag.** Send `host=example.com;cat /flag.txt`. The page shows the flag.

### Trial and error

Steps tried before the flag was found, in order:

1. `GET /` shows the lookup form. My first request with `host=example.com` was filtered by a `sed` pattern that matched nothing, so I searched the whole response instead.
2. `host=example.com;id` returned `uid=1000(www) gid=1000(www) groups=1000(www)` after the DNS answer. This showed that a `;` reaches a shell.
3. `host=example.com;ls -la /` listed `flag.txt` in the root directory, owned by root and readable by all (`-rw-r--r--`).
4. `host=example.com;cat /flag.txt` returned the flag. In the same request I also listed `/var/www` and `/home` to see where the app runs.

## Steps

1. Run `solve.py`. It sends `host=example.com;cat /flag.txt` to `/`, then prints the first `HTB{...}` in the page.
2. The flag is printed as `[+] Flag:`. The flag is `HTB{1nv3nt3d_REDACTED}`.

## Sample output

Output of `python3 solve.py <target_ip> <target_port>` against the live instance, with the flag masked. Pasted from the run, not written by hand.

```
[+] Flag:
HTB{1nv3nt3d_REDACTED}
```

## Problems hit

- **The lookup output hides the injected output at first.** A plain `;id` returns the DNS answer first and the `id` line further down, inside the same `<pre>` block. Searching for `uid=` in the page finds it.

## Defense

- **Do not build shell commands from user input.** Call `dig` or `getaddrinfo` through a library, or pass the host as a separate argument with `escapeshellarg()` (or `proc_open` with an argument array).
- **Validate the hostname.** Accept only a hostname pattern (letters, digits, dots, hyphens) and reject everything else before the lookup runs.
- **Run the web process with minimal rights.** This does not stop the injection, but it limits what can be read or changed.
- **Keep secrets out of world-readable paths.** `/flag.txt` was readable by every user on the system.

## Lessons

- A feature that takes a name and runs a tool on it is a command injection candidate. Test shell separators (`;`, `|`, `&&`, backticks) on every parameter.
- The output can be hidden in the middle of a normal answer. Look through the whole page, not only the first lines.
- A `;` is the simplest separator to test first, because it does not depend on how the original command ends.
