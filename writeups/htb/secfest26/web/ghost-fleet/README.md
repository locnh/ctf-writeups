---
title: web/ghost-fleet
platform: HTB
event: secfest26
category: web
tags: [otp-bruteforce, weak-otp, username-enumeration, authorization, jwt, cookie-auth]
status: solved
difficulty: 3
---

# web/ghost-fleet

**Flag:** `HTB{br0k3n_REDACTED}`

**Difficulty:** 🌶️🌶️🌶️ (3/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`. It takes about 4 minutes, because it tries up to 10,000 OTPs.

## Summary

The app is a FastAPI service, "Ghost Fleet Command API". It has password login and OTP login. The OTP is 4 digits and valid for 5 minutes, and nothing limits wrong guesses. `POST /api/auth/requestOtp` returns `Username not found.` for unknown users, so common usernames can be checked. `admin`, `operator` and `commander` exist.

Brute-forcing the OTP with 32 parallel requests gets about 40 guesses per second, which covers the 10,000 possibilities inside one 5-minute window. The `operator` account can send fleet commands but cannot disable the fleet. The `commander` account has the `admin` role. Its OTP is also brute-forceable, and its token disables the fleet. The `/api/fleet/disable` response contains the flag.

The API uses a cookie named `access_token` for fleet endpoints, not an `Authorization` header. The docs at `/docs` are the standard Swagger UI and show no security scheme.

## Attack chain

1. **Map the API.** `/openapi.json` lists the auth and fleet endpoints. `/docs` shows the same list.
2. **Enumerate usernames.** `POST /api/auth/requestOtp` with `admin`, `operator` and `commander` returns `OTP generated for <name>`. Other common names return `Username not found.`
3. **Brute-force `operator`.** Send `POST /api/auth/loginOtp` with `{"username": "operator", "otp": "0000"}` through `9999`. The OTP `7716` returns a JWT with `role: operator`. The token can call `/api/fleet/command`, but `/api/fleet/disable` returns `Insufficient privileges`.
4. **Brute-force `commander`.** The same loop with `commander` finds an OTP that returns a JWT with `role: admin`.
5. **Disable the fleet.** Send `POST /api/fleet/disable` with the admin token in the `access_token` cookie. The response is `{"status": "Fleet Disabled", "code": "HTB{...}", ...}`.

## Steps

1. Run `solve.py`. It requests an OTP for `commander`, tries every 4-digit OTP with 32 threads until one returns a token, then calls `/api/fleet/disable` with that token and prints the flag.
2. The flag is printed as `[+] Flag:`. The flag is `HTB{br0k3n_REDACTED}`.

## Sample output

Output of `python3 solve.py <target_ip> <target_port>` against the live instance, with the flag masked. Pasted from the run, not written by hand.

```
[*] OTP requested for commander
[+] OTP 0461 accepted, admin token obtained
[+] Flag:
HTB{br0k3n_REDACTED}
```

## Problems hit

- **The first brute-force attempt used the wrong expiry check.** A run against `admin` covered `0000` to `0816`, then returned `OTP expired` at `0817`. The OTP had expired by then, so `0817` was not a hit. The script treated the first non-`Invalid OTP.` response as a hit, which is why the check was changed to stop only on responses that are not expired.
- **Throughput decides whether the attack fits in the window.** Four threads did about 2.5 requests per second, which is too slow for 10,000 guesses in 5 minutes. 16 threads reached about 34 per second, and 32 threads about 41 per second. The 32-thread run found `operator` with `7716` in 185 seconds.
- **The first script crashed on a connection timeout.** The exception was not caught, so the run stopped. The fix is to catch errors per request and retry.
- **Bearer tokens do not work on fleet endpoints.** Sending the JWT in `Authorization: Bearer` returns `Not authenticated`. The endpoints read the `access_token` cookie.
- **Dead ends that did not work:**
  - Non-string `otp` values (`817`, `null`, `true`, `[]`, `0`) return a 422 validation error, so there is no type confusion.
  - Changing `role` to `admin` in the JWT without re-signing, and `alg: none`, both return `500 Internal Server Error`. The signature is checked, and the crash is not a bypass.
  - About 50 common HS256 secrets did not match the operator token offline.
  - A time-seeded OTP guess with Python's `random` (14 candidates around the server time) did not match.

## Defense

- **Limit OTP attempts.** Lock the account or the OTP after a small number of wrong guesses, and track attempts per username and per client.
- **Use longer OTPs.** A 4-digit OTP has 10,000 values, which is too few for a 5-minute window with no limit. Use at least 6 random digits, or a token of higher entropy.
- **Invalidate the OTP after a failed attempt or after login.** A single-use code should not stay usable for repeated guesses.
- **Return the same response for known and unknown usernames.** `Username not found.` tells an attacker which accounts exist.
- **Keep the role check on disable, and sign tokens with a strong secret.** The role check here was correct, which is why the admin path needed a real credential. The admin credential should not be reachable by the same weak OTP.
- **Require the same second factor for admin accounts.** An admin login should not need less protection than an operator login.

## Lessons

- A short code with no attempt limit can be brute-forced inside its lifetime. Count the guesses and the time window before you start, and measure throughput first.
- Check which accounts exist before you attack one. A response that differs between known and unknown users is a shortcut.
- A failed check on a token does not mean the signature is broken. A `500` after tampering can point to a parser or verification path that still needs a proper bypass.
- Parallel brute-force speeds up the attack, but a crashed script wastes the whole window. Handle connection errors per request.
