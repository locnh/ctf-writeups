---
title: web/reactoops
platform: HTB
event: challenge
category: web
tags: [nextjs, react, rsc, cve-2025-55182, cve-2025-66478, rce]
status: solved
difficulty: 1
---

# web/reactoops

**Flag:** `HTB{jus7_1n_c4s3_REDACTED}`

**Difficulty:** 🌶️ (1/5)

**Solve script:** `artifacts/solve.py`, run as `python3 solve.py <target_ip> <target_port>`.

## Summary

ReactOOPS is a static Next.js marketing page for a fictional AI assistant. There are no forms, no server actions, no parameters, and no database. `app/page.tsx` returns a fixed tree.

The flaw is not in the app. It is in the React Server Components deserializer that Next.js bundles. The image pins `next` 16.0.6, which is one release before the fix for CVE-2025-55182 / CVE-2025-66478 (React2Shell). Every App Router route accepts a Flight payload when the request carries a `Next-Action` header, and the reply decoder runs before the action id is looked up. The payload can supply its own `_response` object, including `_prefix` and `_formData`, which the parser trusts. Setting `_formData.get` to the `Function` constructor and `_prefix` to JavaScript source makes the parser compile and then invoke that source. The result is unauthenticated remote code execution.

## Attack chain

1. **Recon.** The response advertises Next.js, and the page source has no dynamic parts. The source archive pins `next` 16.0.6 and `react` `^19`.
2. **Version check.** Next.js 16.0.6 is vulnerable to CVE-2025-66478, the Next.js instance of CVE-2025-55182. It is fixed in 16.0.7.
3. **Flight payload.** POST a multipart body to any route with a `Next-Action` header. Build the chunks so that chunk 1 is a resolved model whose `then` re-enters the parser and whose nested value has `then` pointing at `$B<n>`.
4. **Gadget.** `$B3` makes the parser call `response._formData.get(response._prefix + 3)`. With `_formData.get` resolved to `[].constructor.constructor` (the `Function` constructor), the parser compiles `_prefix` as a function body. The parser treats that function as a thenable and calls it, so the body runs.
5. **Exfiltrate.** The command runs during deserialization, before any action exists, so the HTTP response is an error. Ordinary errors are reduced to an opaque digest, but a `NEXT_REDIRECT` digest is copied into the `x-action-redirect` response header. Throwing one with the flag in the URL leaks the flag. The read target is `/app/flag.txt`.

## Code analysis

The app code gives nothing to attack. `app/page.tsx` is a static component tree, and a search of `app/` finds no `"use server"`, no `<form>`, no `action=`, and no `searchParams`. The only app-level code reachable from a request is the static page. The bug is in the framework, so the relevant code is in `next/dist`, not in the challenge tree.

Relevant files from the challenge source (`src/web_reactoops/challenge/`):

- `package.json`: `"next": "16.0.6"`, `"react": "^19"`, `"react-dom": "^19"`. The `^19` range is not the vulnerable piece. The lockfile is not in the archive, so the exact bundled version is inferred from `next`.
- `next.config.mjs`: `output: 'standalone'`, so the server runs from `.next/standalone/server.js` (see the Dockerfile).
- `Dockerfile` (`node:20-alpine`): copies `challenge/flag.txt` to `/app/flag.txt`, exposes 1337 in the image. The solver used the published port 30179 on the host.

What the exploit relies on, in the framework's deserializer:

- `decodeReply` accepts a multipart Flight body and resolves `$`-references against a `_response` object. Because the attacker controls the whole payload, the attacker can supply `_response` fields (`_prefix`, `_formData`, `_chunks`) that the parser treats as trusted internals.
- `$3:constructor:constructor` resolves to `Function` through the prototype chain of an array. The parser then calls `_formData.get(_prefix + 3)`, which becomes `Function(_prefix + 3)`. `_prefix` is the JavaScript body, so the body runs with `process` in scope.
- The action id (`Next-Action: x`) is looked up after decoding. A bogus id still reaches the gadget, which is why the solver does not need a real server action.
- Errors are sanitized before they reach the response: a normal error becomes an opaque digest, and `NEXT_REDIRECT` keeps its digest and is copied to `x-action-redirect`. The solver throws that digest with the file contents. This is the observed behaviour; the exact sanitizer function inside `next/dist` was not traced.

The solver (`artifacts/solve.py`) is a direct port of the published lachlan2k PoC. Its `build()` function produces the five fields, `read_flag_js()` produces the gadget body, and `main()` reads the redirect header. The solver does not write files or touch `public/`.

## Steps

1. **Fingerprint the target.**

   ```
   $ curl -sI http://<target>/ | grep -iE 'x-powered-by|^HTTP'
   HTTP/1.1 200 OK
   X-Powered-By: Next.js
   ```

2. **Read the source.** `package.json` pins `next` 16.0.6. `app/page.tsx` is static and `next.config.mjs` only sets `output: 'standalone'`. There is no server action to call.

3. **Confirm the patch status.** 16.0.6 is affected by CVE-2025-66478 (fixed in 16.0.7). The installed `react` version does not matter, because Next uses its own bundled copy of `react-server-dom` (`next/dist/compiled/react-server-dom-turbopack`).

4. **Send the payload.** The solver builds five multipart fields (`0`–`4`) from the published React2Shell PoC and sends them with `Next-Action: x`, `Accept: text/x-component`. A bogus action id is enough: decoding happens before the id is resolved.

   ```
   $ python3 solve.py <target_ip> <target_port>
   ```

5. **Read the flag.** The solver decodes the URL-encoded value from the `x-action-redirect` header and prints it.

## Sample output

Output of the documented solve command against the live instance, with the flag masked.

```
$ python3 solve.py 154.57.164.71 30179
HTB{jus7_1n_c4s3_REDACTED}
```

## Problems hit

- The first payload was hand-written and produced `SyntaxError: Unterminated string in JSON`. The Flight body must be exact; using the original published PoC structure fixed it.
- The response is an HTTP 500 even when the exploit works. Code execution happens during `decodeReply`, and there is no matching server action to return a normal result.
- Error details are sanitized: a normal thrown error becomes an opaque digest and nothing else. The redirect digest is the one value that survives to a response header, which is why it carries the flag.
- Writing the flag into `public/` or `.next/static/` and requesting it back returns 404. Next builds its static file map at startup, so files created at runtime are not served.
- The version that matters is the one bundled inside `next`, not the `react` range in `package.json`. The `^19` range does not pin a version, so the bundled deserializer was identified from `next` 16.0.6 instead.

## Defense

- Upgrade to Next.js 16.0.7 or later (or the patched React release for standalone RSC), which validates the reply's `_response` and stops attacker-supplied `_formData`/`_prefix` from being used.
- Treat every App Router route as an RSC endpoint. "The app has no server actions" is not a mitigation.
- Do not rely on WAF rules over the action body. They help during the upgrade window, not after it.
- Strip or hash all error digests, and avoid reflecting attacker-controlled data in `x-action-redirect`.
- Audit the framework version at build time. A caret range on `react` can hide a vulnerable bundled copy.

## Lessons

- Framework code parses requests before application code runs. A page with no input can still be attacked through the framework's input path.
- For React2Shell, the Next.js version is the deciding fact, not the `react` version in `package.json`.
- When the response channel is sanitized, look for a second channel (headers, redirects, timing) that the framework does not sanitize the same way.
