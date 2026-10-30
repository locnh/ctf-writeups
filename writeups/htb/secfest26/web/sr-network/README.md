---
title: web/sr-network
platform: HTB
event: secfest26
category: web
tags: [jwt, api-enumeration, username-enumeration, password-reset, business-logic, quota-leak]
status: solved
difficulty: 3
---

# web/sr-network

**Flag:** `HTB{f0rg3_s1gn4l_k3y_0v3rl0ad_y3y_d25a67a260af28ee044ab17c3223b504}`

**Difficulty:** 🌶️🌶️🌶️ (3/5)

**Solve script:** none (manual steps)

## Summary

The app is a FastAPI service (uvicorn) called "Star Forger Signal Relay". Users register, log in with a JWT, and manage "beacons": quantum signatures (`qfx_` + 64 hex), neural patterns (`nrp_` + base64) and relay addresses (`relay://user@domain`). Password reset does not send mail. It sends a "quantum verification pulse" to one of the user's beacons, and the user enters the resulting code.

The API is documented in `/openapi.json` and `/docs`, and the reset flow is described on `/forgot-password`. The reset endpoint leaks whether a username exists, and it reports a code hint (the first character of the code). The flag is not in any of these responses, though. It comes out of the business logic: when the company's "star credits" run out, the error response contains `forge_signal_key`, which is the flag.

Credits are shared by the whole instance. Reaching the depleted state required about eleven reset requests in a few minutes. That is a quota-exhaustion path on a shared service, and I stopped once I had the flag (see Problems hit).

## Attack chain

1. **Map the API.** `/openapi.json` lists 12 endpoints, including `/api/auth/register`, `/api/auth/login`, `/api/beacons`, and `/api/auth/password/reset/request` and `/verify`.
2. **Get a session.** Register with `POST /api/auth/register` (`username`, `password`, optional `display_name`), then log in with `POST /api/auth/login`. The response contains an HS256 JWT with `user_id`, `username` and `exp`.
3. **Create beacons.** `POST /api/beacons` accepts `type`, `value` and `display_name`. The accepted types are `quantum_signature`, `neural_pattern` and `relay_address`. Short names like `quantum` or `relay` are rejected. Verifying a beacon with `POST /api/beacons/{id}/verify` only returns `Beacon verification pulse sent`, and the beacon's status becomes `verified` shortly after.
4. **Probe the reset flow.** `POST /api/auth/password/reset/request` with `{"identifier": ...}`. A known username or a registered beacon value returns `Quantum verification pulse sent to registered beacon` with a `code_hint`. Anything else returns the generic `If the identifier exists, ...` message. Wrong codes on `/verify` return `Invalid code or expired`.
5. **Exhaust the credits.** Repeat the reset requests. After about eleven of them, the response is `{"status": "company_credits_empty", ..., "forge_signal_key": "HTB{...}"}`.

## Steps

1. Register and log in with the API above, and keep the token.
2. Send reset requests for a registered identifier, and count them.
3. When the response changes to `company_credits_empty`, the response body holds the flag as `forge_signal_key`. The flag is `HTB{f0rg3_s1gn4l_k3y_0v3rl0ad_y3y_d25a67a260af28ee044ab17c3223b504}`.

## Problems hit

- **The reset code is not visible.** The pulse goes to a beacon, but the code is not returned in any API response, the dashboard's `recent_activity` is empty, and the beacon records show no code. Wrong codes such as `123456` and `700000` were rejected. I did not find a channel that delivers the code to me.
- **The code hint changes per request.** The first character varied between requests for the same identifier (`7`, `6`, `A`, `8`), so the hint did not reveal a stable value.
- **Relay host validation accepts many forms.** `relay://` hosts with a `:` port were rejected, but `localhost`, `127.0.0.1`, decimal `2130706433`, hex `0x7f000001` and `127.1` were all accepted. Verification of each one still returned `verified`, so I could not tell whether the server contacted the host.
- **The flag came from quota exhaustion on a shared service.** Repeating the reset requests drained the company credits, which affects every user of this instance. I got the flag from that response and then stopped sending requests. A solver that loops until the credits run out would disrupt the service for other users, so this writeup has no `solve.py`.

## Defense

- **Keep the response body the same for every user state.** The reset endpoint should return the same message for known and unknown identifiers and should not return a code hint.
- **Never put secrets in error responses.** The `forge_signal_key` belongs in a server-side store, not in a `company_credits_empty` body.
- **Rate-limit reset requests per identifier and per client.** Limit the cost to the requester, not to a shared budget that other users depend on.
- **Do not let a shared quota decide whether a secret is shown.** Credits should not change what the API returns to an authenticated user.
- **Validate relay hosts with an allowlist or a resolver check.** Accepting IPs in several numeric forms and loopback addresses can lead to SSRF if the server ever contacts them.
- **Reject unknown mass-assignment fields explicitly.** `PATCH /api/me` ignored `is_admin` and `role`, which is correct, but the schema should make that behaviour explicit.

## Lessons

- A reset flow that depends on an out-of-band channel needs a way to test that channel. Without it, the rest of the flow cannot be verified.
- Errors that leave the service in a special state, such as a depleted quota, can leak data that normal responses never show. Read every error body, not only the happy path.
- Repeated requests against a shared resource have side effects beyond your own account. Stop as soon as you have what you need.
