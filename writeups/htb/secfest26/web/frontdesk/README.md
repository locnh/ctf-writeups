---
title: web/frontdesk
platform: HTB
event: secfest26
category: web
tags: [broken-authentication, cookie-forgery, unsigned-session, client-side-trust]
status: solved
difficulty: 1
---

# web/frontdesk

**Flag:** `HTB{N3v3r_REDACTED}`

**Difficulty:** 🌶️ (1/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`.

## Summary

The app is an Express site, "NOR.GOV Digital Access". It has a register and login flow, and a support form that is open to anyone. Registration fails for every input tried (see Problems hit), so the exploit does not depend on a real account.

Submitting the support form sets a `session` cookie. The cookie is base64 JSON, `{"user":"guest"}`, with no signature. The server trusts the `user` value it finds there. Changing it to `{"user":"admin"}` makes `/admin` return the "NDAS Admin Dashboard". The dashboard shows the flag in its "Internal only" banner.

Relevant behaviour, seen from the outside:

- `/admin` returns `403 Access denied` for the guest cookie and `200` for the admin one.
- `POST /support/message` returns `302` to `/support/done?ref=NDAS-2026-...` and sets `session=eyJ1c2VyIjoiZ3Vlc3QifQ%3D%3D`.

The source archive was not on disk and no download link was given, so this was solved against the live instance only.

## Attack chain

1. **Get a cookie.** Submit the support form, through `/support` and `/support/topic`, to `POST /support/message`. The response sets `session`, which decodes to `{"user":"guest"}`.
2. **Confirm the gate.** Send the guest cookie to `/admin`. It returns `403`.
3. **Forge the identity.** Replace the value with base64 of `{"user":"admin"}`, which is `eyJ1c2VyIjoiYWRtaW4ifQ==`, and keep the same cookie name.
4. **Read the flag.** `GET /admin` returns the dashboard, and the banner contains the flag.

### Trial and error

Steps tried before the cookie was found, in order:

1. `GET /` redirects to `/login`. I probed about 30 common paths (`/register`, `/robots.txt`, `/.git/HEAD`, `/package.json`, `/static/`, `/api`, `/dashboard`, `/logout`, `/health`, and others). All returned `404`, apart from `/login`, `/register` and `/support`.
2. `/admin`, `/admin/` and `/admin/login` all returned `403 Access denied`. The `403` suggested an access check, so I looked for what the check used.
3. Registration returned a generic `400` ("An error occurred while trying to register") for `@example.com`, `@nor.gov`, `@test.com`, `a@b.c`, a long password, and a JSON body. This was a dead end.
4. The support form (`/support` → `/support/topic` → `/support/message`) is public. A test message returned `302` to `/support/done?ref=NDAS-2026-000124` and set `session=eyJ1c2VyIjoiZ3Vlc3QifQ%3D%3D`.
5. The cookie decodes to `{"user":"guest"}` with no signature part. Replacing it with base64 of `{"user":"admin"}` and keeping the same name opened `/admin`. The paths under `/admin/` I tried after that (`/admin/tickets`, `/admin/users`, and others) returned `404`, so the dashboard was the only admin page.

## Steps

1. Run `solve.py` with the instance address. It builds the admin cookie, requests `/admin`, and prints the first `HTB{...}` in the page.
2. The flag is printed as `[+] Flag:`. The flag is `HTB{N3v3r_REDACTED}`.

## Sample output

Output of `python3 solve.py <target_ip> <target_port>` against the live instance, with the flag masked. Pasted from the run, not written by hand.

```
[+] Flag:
HTB{N3v3r_REDACTED}
```

## Problems hit

- **Registration does not work.** `POST /register` returns `400` with "An error occurred while trying to register" for every input tried. That includes `@nor.gov` and `@example.com` emails, a long password, and a JSON body. The login route has no account to use. None of this was needed, because the cookie only has to name a user.
- **The 403 is not a password check.** `/admin` returns `403` before any login. The cookie is the only thing it checks, so forging the value is enough.
- **Source was not available.** The challenge download was not on disk, so the review was done from the live responses only.

## Defense

- **Sign the session.** Use a signed cookie, such as a JWT or Express's `cookie-session` with a secret, or keep only a random session ID that the server maps to a user in its store. Reject any cookie whose signature does not verify.
- **Check the role on the server.** The role should come from the server's user record, not from a field the client can edit.
- **Keep secrets out of templates.** The flag should not be shown to any role because a banner says "internal". An admin page should not hold the secret in plain HTML.
- **Return the same error for missing and invalid sessions.** A `403` only for a valid but unprivileged user avoids telling an attacker which values to try.

## Lessons

- A cookie that the client can edit is not an identity. Check the signature before you read the value, and treat the role as data the server owns.
- Base64 is encoding, not protection. A cookie that is base64 JSON without a signature can be decoded, edited, and sent back.
- When a flow looks broken, such as registration here, check whether the bug blocks the goal. Here it did not, because the cookie was enough.
