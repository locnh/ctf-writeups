---
title: web/labyrinth-linguist
platform: HTB
event: try-out
category: web
tags: [ssti, velocity, java, spring-boot, rce]
status: solved
difficulty: 3
---

# web/labyrinth-linguist

**Difficulty:** 🌶️🌶️🌶️ (3/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`

## Summary

The app is a Spring Boot site that "translates" English to a fictional language. The `text` query parameter goes into a Velocity template. `Main.index` reads `templates/index.html` and replaces the literal `TEXT` with the user's input, then parses the result with Velocity and returns it.

Because the input is inserted before Velocity parses the file, any Velocity directive in the input runs on the server. That is server-side template injection (SSTI). Velocity 1.7 allows method calls on any Java object, so the input can reach `java.lang.Runtime` and run commands.

Relevant code:

The archive is password-protected with the standard HTB password, `hackthebox`.

- `Main.index` is mapped to `/`. It takes `text` (default `Example text`).
- `readFileToString` reads `/app/src/main/resources/templates/index.html` and replaces every `TEXT` with the input. This happens before any template parsing.
- The modified text is parsed with `runtimeServices.parse(...)` and merged with `VelocityContext` (which has `name=World`). The result is the HTTP response body.
- `index.html` has one `TEXT` placeholder, inside `<h2 class="fire">`.
- `pom.xml` pins `velocity` 1.7, which allows reflective method calls on objects in the template.
- The flag is at `/flag.txt` in the image. The entrypoint is meant to rename it to `flag<hex>.txt` at startup, but on this instance the file kept its name.

## Attack chain

1. Confirm that the input is parsed as Velocity. `text=$name` renders `World`, and `text=#set($x="a")$x.class.name` renders `java.lang.String`.
2. Get `java.lang.Runtime` through reflection with `$x.class.forName("java.lang.Runtime")`.
3. Run a command with `getRuntime().exec(...)`.
4. Read the command's output with `getInputStream().readAllBytes()`, and base64-encode it with `java.util.Base64`. The page shows the base64 text, which the script decodes.

Observations from testing:

- `Runtime.exec(String)` splits on spaces and does not expand shell globs. `cat /flag*` would not match the file, so the script uses the exact name.
- Base64 keeps the output on one line, so it survives the HTML page. The script takes it from the `class="fire"` element.

## Steps

1. Run the solve script. It runs `ls /` to show the root directory, then `cat /flag.txt`.
2. The flag is printed after `[*] Reading /flag.txt...`: `HTB{f13ry_t3mpl4t35_fr0m_th3_d3pth5!!_REDACTED}`.

## Problems hit

- Early payloads used `$x` before defining it with `#set`. Velocity leaves an undefined reference as literal text, so the output showed `$b`. Defining `$x` at the start fixed it.
- The flag name in `/` was `flag.txt`, not the random `flag<hex>.txt` the entrypoint script suggests. The solve script reads `/flag.txt` directly.

## Defense

- **Do not put user input into a template before parsing.** Use the template as a fixed resource and pass the input through the context as data (`context.put("text", input)`).
- **Do not use `String.replace` to fill templates.** It treats the user's text as template syntax. Use the template engine's own variable substitution.
- **Upgrade or restrict Velocity.** Use Velocity's sandboxed introspection (`SecureUberspector`) or a version that restricts reflection, so templates cannot call arbitrary methods like `Class.forName`.
- **Limit the process.** Run the app as a user with no access to `/flag.txt`, and do not let it spawn processes if it does not need to.

## Lessons

- Any template engine that parses input after a string substitution is an injection point. Check where user input enters the template, not just what the template does with it.
- Velocity's reflection gives full Java access, so a single `$x.class.forName` is enough to reach `Runtime`.
- When a page shows only one value, encode command output (here base64) so multi-line and special characters come through intact.
