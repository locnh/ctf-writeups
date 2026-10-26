---
title: web/omniwatch
platform: HTB
event: try-out
category: web
tags: [crlf-injection, cache-poisoning, varnish, xss, bot, lfi, sqli, jwt-forgery]
status: solved
difficulty: 4
---

# web/omniwatch

**Flag:** `HTB{h3110_41w4y5_i_s3e_y0u4nd_1m_w4tch1ng_REDACTED}`

**Difficulty:** 🌶️🌶️🌶️🌶️ (4/5)

**Solve script:** `artifacts/solve.py` with `artifacts/payload.js` in the same directory. Run `python3 solve.py [seconds]`. The script hard-codes the target `http://154.57.164.81:35113`, so change `BASE` for another instance. It keeps poisoning the cache for `seconds` (default 180) and prints each step as the bot reports it. It stops once it sees the flag.

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

## Problems hit

- **Slashes in the injected header.** A raw `/` in `Content-Type: text/html` splits the route, so the request returns 404. The header value must be `text%2Fhtml`.
- **Cookies bypass the cache.** A request with a `Cookie` header is passed by Varnish and never stored. The exfil `fetch` needs `credentials: "omit"`.
- **Missing a step result.** The exfil cache keeps only the last object per key. Using one key per step made the progress visible.
- **Instance reachability.** The instance stopped answering for a while during testing. It came back after a short wait.

## Steps

1. Run `python3 solve.py 240`.
2. Watch the step output. The `F` line contains the `HTB{...}` flag once the bot finishes.
