---
title: web/omniwatch
platform: HTB
event: try-out
category: web
tags: [crlf-injection, cache-poisoning, varnish, xss, bot, lfi, sqli, jwt-forgery]
status: solved
difficulty: 4
---

# OmniWatch

**Difficulty:** 🌶️🌶️🌶️🌶️ (4/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port> [seconds]`. Payload is in `artifacts/payload.js`.

## Summary

The stack is Varnish in front of a Zig oracle service (`http.zig`) and a Flask controller. A Chromium bot logs in as the moderator every 30 seconds. The attack has four parts:

1. The oracle echoes the URL-decoded `deviceId` into a response header, so `%0d%0a` injects arbitrary headers.
2. Varnish keys its cache only on the `CacheKey` request header, not on the URL. A response with `CacheKey: enable` is cached for 10 seconds.
3. The poisoned page is served to the bot on its own origin. Its script can read the `jwt` cookie (not HttpOnly).
4. The bot's script then reads `jwt_secret.txt` through a path traversal, forges an admin JWT, inserts the matching signature with SQL injection, and reads `/controller/admin`.

Its result leaves the bot the same way, through the cache. The poisoned object stores the output under `CacheKey: omni-<tag>`, and the attacker reads it back.

Relevant code (`src/challenge`):

- `oracle/src/main.zig`: `oracle()` sets `res.header("DeviceId", decodedDeviceId)`. In `json` mode the response is JSON. Otherwise it returns HTML with `decodedMode` unescaped.
- `controller/application/blueprints/routes.py`: `/firmware` POST opens `os.path.join(os.getcwd(), "application", "firmware", patch)`. `/device/<id>` and `/admin` are reachable only through the middleware.
- `controller/application/util/database.py`: `fetch_device` builds `SELECT ... WHERE device_id = '{device_id}'` and runs it with `multi=True`, which splits on `;`.
- `config/cache.vcl`: `vcl_hash` only does `hash_data(req.http.CacheKey)`. `/controller/home` with a cookie uses `hash`.

## Attack chain

1. **CRLF injection.** `GET /oracle/<mode>/1%0d%0aCacheKey:%20enable` returns `CacheKey: enable` in the response headers.
2. **Cache poisoning.** Injecting `Content-Type: text/html` makes the reflected HTML render. The cache key is empty (no `CacheKey` header), so every request without a `CacheKey` header gets this object for 10 seconds. This covers `/controller/login`, and it also covers `/controller/home` after the bot's login.
3. **Payload.** The poisoned page contains the login form, so the bot can still log in. The `<script>` runs only when `document.cookie` has `jwt=`, which is true on the bot's post-login page.
4. **LFI.** The script calls `POST /controller/firmware` with `patch=../../../jwt_secret.txt`. The path resolves to `/app/jwt_secret.txt`.
5. **Forge.** The script signs `{"user_id": <random>, "username": "admin", "account_type": "administrator"}` with HS256 using WebCrypto.
6. **SQLi.** `/controller/device/1';INSERT INTO signatures(user_id,signature)VALUES(<uid>,'<sig>')-- -`. The statement runs before the `SELECT` result is read, and `mysql-connector-python` commits after each statement. The signature row is what the middleware compares against.
7. **Admin.** The script sets the forged cookie and fetches `/controller/admin`. `/readflag` prints the flag into the page.
8. **Exfil.** Each step sends a message back as `GET /oracle/<msg>/1%0d%0aCacheKey:%20enable` with `CacheKey: omni-<tag>`. The poller reads `omni-S0`..`omni-F`.

## Steps

1. Artifacts are in `artifacts/`: `solve.py` and `payload.js`, which must sit in the same directory. Requires Python 3 and the `requests` package (`pip install requests`).
2. Run the solver with the target IP, port, and an optional time limit in seconds (default 180):

   ```
   python3 solve.py <target_ip> <target_port> [seconds]
   ```

3. The script keeps poisoning the cache and polls each step's key. It prints a line for each step the bot reports, and stops once it sees the flag. The bot runs every 30 seconds, so allow at least one full cycle. A 240-second run is enough in practice.

Sample output (flag masked):

```
$ python3 solve.py 154.57.164.81 35113 240
S0 -> S0 200
S1 -> S1 status=200
S2 -> S2 len=16
S3 -> S3 signed
S4 -> S4 inserted
F -> HTB{h3110_41w4y5_i_s3e_y0u4nd_1m_w4tch1ng_REDACTED}
done {'S0': 'S0 200', 'S1': 'S1 status=200', 'S2': 'S2 len=16', 'S3': 'S3 signed', 'S4': 'S4 inserted', 'F': 'HTB{h3110_41w4y5_i_s3e_y0u4nd_1m_w4tch1ng_REDACTED}'}
```

Each step line shows the bot's progress: `S0` the payload started, `S1` the firmware read returned, `S2` the secret length, `S3` the admin token was signed, `S4` the signature row was inserted, and `F` the flag. If the run stops at a step before `F`, the bot did not reach the next step, so check the step lines first.

## Problems hit

- **Slashes in the injected header.** A raw `/` in `Content-Type: text/html` splits the route, so the request returns 404. The header value must be `text%2Fhtml`.
- **Cookies bypass the cache.** A request with a `Cookie` header is passed by Varnish and never stored. The exfil `fetch` needs `credentials: "omit"`.
- **Missing a step result.** The exfil cache keeps only the last object per key. Using one key per step made the progress visible.
- **Instance reachability.** The instance stopped answering for a while during testing. It came back after a short wait.

## Defense

- Reject CR and LF in any value that goes into a response header. Upgrade the HTTP library, or validate header values before they are set.
- Do not reflect user input into HTML responses served from the same origin as the app. Set `Content-Type` explicitly, and send a strict `Content-Security-Policy`.
- Configure Varnish to key on the full request (URL, host, and relevant headers), and never let a client set a header that controls caching. Remove `CacheKey` handling from the backend response.
- Mark the session cookie `HttpOnly` so scripts on the page cannot read it.
- Build file paths with a fixed base directory and reject `..` or absolute paths. `os.path.join` with a user value is not a sandbox.
- Use parameterized queries, and do not run multi-statement queries from user input. Use a DB user without write access to the signature table.

## Lessons

- A cache is an authorization boundary: if the cache key misses part of the request, one user's response can be served to another.
- Injection points that look harmless in one service (a debug header in the oracle) can become the first step of a chain across several services.
- A headless browser with a logged-in session is an oracle for the attacker. The bot's own requests can carry the attacker's payload and return the result through a side channel.
- Test with the same tools and timing as the target. Chrome's cookie handling and Varnish's cache rules caused most of the failed runs.
