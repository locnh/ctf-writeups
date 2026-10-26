---
title: web/guild
platform: HTB
event: try-out
category: web
tags: [ssti, jinja2, flask, blacklist-bypass, rce]
status: solved
difficulty: 3
---

# web/guild

**Difficulty:** 🌶️🌶️🌶️ (3/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`

## Summary

The app is a Flask guild site with signup, login, a verification upload, a profile bio, and a share page. The share page at `/user/<link>` renders the user's bio as a Jinja2 template with `render_template_string`. The bio is first passed through a keyword blacklist (`checkInput`), which blocks words like `__`, `attr`, `class`, `globals`, `os`, `[`, and `%`.

The blacklist is a substring check on the raw text. Jinja2 string literals support `\x..` escapes, and Jinja expands them when the template is rendered. A payload can therefore spell the blocked words as escapes and rebuild them at runtime. That gives server-side template injection (SSTI) and command execution as the app user, and the flag is in `/app/flag.txt`.

Relevant code: no source code was provided in the challenge archive. The app source (`website/views.py`, `website/auth.py`, `website/models.py`) was reviewed locally.

- `/user/<link>` (`views.share`) looks up `Validlinks` by `validlink == link`, reads `Verification.bio` for that user, and runs `render_template_string(temp % bio, ...)`. The `temp` file is `newtemplate/shareprofile.html`, and `%s` in it is replaced with the bio before rendering. So the bio is treated as Jinja2 source.
- `/profile` (`views.profile`) is the only way to set `bio`. It runs `checkInput(bio)` first and rejects the bio if any blacklist word appears.
- `/getlink` (`views.create_share`) creates a `Validlinks` row with `validlink` equal to the caller's username, so the share URL is `/user/<username>`.
- `/profile` only accepts a bio after a `Verification` row exists, so the user has to upload a file to `/verification` first. The file is not checked for content.

## Attack chain

1. Sign up and log in.
2. Upload any file to `/verification`. This creates the `Verification` row that `/profile` needs.
3. Set the bio to the SSTI payload through `/profile`. The payload passes `checkInput`.
4. Call `/getlink` to create the share link for your username.
5. Request `/user/<username>`. The bio is rendered as a template and runs the payload.

Payload:

```
{{ ((((lipsum,)|map("\x61ttr","\x5f\x5f\x67lobals\x5f\x5f")|first).get("\x6fs"),)|map("\x61ttr","\x70open")|first)("cat /app/flag.txt").read() }}
```

Step by step (inside Jinja2):

- `lipsum` is a Jinja2 global function. `map("attr", "__globals__")` returns its globals dict. `\x5f\x5f\x67lobals\x5f\x5f` is `__globals__`.
- `.get("os")` reads the `os` module from that dict. `.get` is used because the `attr` filter does not fall back to dict keys.
- `map("attr", "popen")` gets `os.popen` from the module. `\x70open` is `popen`.
- Calling it with `"cat /app/flag.txt"` runs the command, and `.read()` returns the output.

The blacklist words used in the payload (`attr`, `__`, `globals`, `os`, `popen`) do not appear in the raw text. `\x61ttr`, `\x5f\x5f\x67lobals\x5f\x5f`, `\x6fs` and `\x70open` are the same words after Jinja2 expands the escapes.

Observations from testing:

- The payload was tested locally against Flask 3.1.3 and Jinja2 3.1.6 before the live run. The live app returned the flag on the first attempt.
- The app is in `/app` inside the container, so the flag path is `/app/flag.txt`.
- `temp % bio` and `render_template_string` both take untrusted data as code. The blacklist is not a control because it checks the text and the template engine decodes escapes afterwards.
- Other issues noticed but not used: the reset token in `/forgetpassword` is `sha256(email)`, which can be computed by anyone who knows the email.

## Steps

1. Run the solve script against the target. It performs all five attack steps.
2. The flag is in the `<p class="para-class">` element of the response: `HTB{mult1pl3_lo0p5_mult1pl3_h0les_REDACTED}`.

## Problems hit

- The first version of the chain applied `map` with `|first` between steps. `|first` returns the module, and the next `|map` iterates it as a sequence. Calling `map` on each result directly fixed that.
- Jinja2's `attr` filter does not look up dict keys. The first attempt to read `os` from the globals dict with `map("attr", "os")` returned `Undefined`. Calling `.get("os")` on the dict works.

## Defense

- **Do not render user data as a template.** Use `render_template` with the bio as a variable, and let Jinja2 escape it. Do not build the template text with `%` or string concatenation.
- **Do not use a keyword blacklist as a security control.** Blacklists on raw text can be bypassed by escapes, encodings, or other forms the template engine decodes later.
- **Validate input against the format the field needs.** A bio is plain text, so store it as text and render it with autoescape on.
- **Limit what the app process can read and run.** The flag was readable by the app user, and `os.popen` was reachable from the template.

## Lessons

- A blacklist on raw text cannot stop a template engine that decodes escapes after the check. The escaped words only exist at render time.
- SSTI payloads without `__` and `attr` are possible with `map` filters and `.get` calls. Reading the Jinja2 docs and testing each piece locally made the chain quick to build.
- The `temp % bio` line looks like string formatting, but its output is still rendered as a Jinja2 template.
