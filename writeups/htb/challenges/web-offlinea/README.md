---
title: web/offlinea
platform: HTB
event: challenge
category: web
tags: [parameter-pollution, ssrf, format-string-injection, python-str-format, jwt, selenium, pdf]
status: solved
difficulty: 2
---

# web/offlinea

**Flag:** `HTB{ac950a25_REDACTED}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run as `python3 solve.py <target_ip> <target_port>` (needs `pip install pypdf`).

## Summary

Offlinea is two services under one supervisor. A PHP frontend (`php -S`, port 8000) takes a `url` parameter, filters it, and proxies the request to a Flask backend on `127.0.0.1:5000/generate`. The backend drives headless Chrome, prints the page to a PDF under `service/pdfs/`, and records the URL in a SQLite `history` table. `/logs` renders that history through `str.format()`. The flag is a row in `secrets`, returned by `/bartender` only with a JWT signed by a random per-process `SECRET_KEY`.

The filter can be bypassed with a duplicate parameter: PHP's `$_GET['url']` keeps the **last** value while Flask's `request.args.get('url')` keeps the **first**. The frontend therefore validates a harmless public URL while the backend scrapes `127.0.0.1`, which it considers safe because any IP literal passes `is_request_safe`. A history entry containing `{logify.__globals__[app].config[SECRET_KEY]}` is then evaluated by `str.format()`, leaking the signing key into a PDF. The key lets us forge a token that passes the broken `token_required` check (`username != 'bartender'` is accepted), and a second SSRF makes Chrome fetch `/bartender`, putting the flag in another PDF.

## Attack chain

1. **Two parsers, one query string.** `bartender.php` checks `$_GET['url']` (last duplicate wins) and forwards `$_SERVER['QUERY_STRING']` verbatim. Flask reads `request.args.get('url')` (first wins). Sending `url=<private>&...&url=<public>` passes the PHP private-range filter on the public value while Flask scrapes the private one.
2. **SSRF.** `is_request_safe` returns `True` immediately for any hostname that parses as an IP, including `127.0.0.1`. `validate_url` only requires an `http`/`https` scheme.
3. **Format-string injection.** `/generate` inserts the scraped URL into `history`. `/logs` builds its output with `history_1.format(logify=logify)`, so a stored URL containing `{logify.__globals__[app].config[SECRET_KEY]}` is evaluated and the secret key is rendered into the page.
4. **PDF exfil.** The backend port is not exposed. Chrome's printed page is the only channel back: the frontend redirects to `/pdfs/results-<time>.pdf`, which is served statically.
5. **JWT logic bug.** `token_required` rejects only when `not is_admin and username == 'bartender'`; any other username is accepted provided the signature is valid. The leaked key gives a valid signature.
6. **Flag.** A second scrape points Chrome at `http://127.0.0.1:5000/bartender?token=<forged>`. The JSON response, including the flag from the `secrets` table, is printed to a PDF.

## Code analysis

The source has two services plus a supervisor config. Relevant files under `challenge/`:

- `service/bartender.php`: the frontend. Lines 92–99 read `$_GET['url']`, validate it, then forward the raw query string.
- `internal/app.py`: the backend. Lines 35–53 (`is_request_safe`), 55–60 (`logify`), 116–130 (`token_required`), and 145–163 (`/generate`).
- `internal/init_db.py`: seeds `secrets` with the flag.

Frontend check (`bartender.php`):

```php
$urlunsanitized = $_GET['url'];
if (!no_way_trick_me($urlunsanitized)) { header('location: /pdfs/no_way.pdf'); exit(); }
$final_url = $api_scraper.$_SERVER['QUERY_STRING']."&time=".$t;
```

`no_way_trick_me` checks only the **last** `url` value, rejects `{` and `}` in it, and rejects private IPv4 ranges. It then forwards the whole query string. Flask (`request.args.get('url')`) reads the **first** `url` value. The two components disagree about which URL is being requested.

Backend (`app.py`):

```python
def is_request_safe(url, min_ttl=40):
    hostname = urlparse(url).hostname or url
    try:
        ipaddress.ip_address(hostname)
        return True          # any IP literal is accepted
    except ValueError:
        pass
    ...
def logify(rec):
    ...
    log = history_1.format(logify=logify)   # user-stored URL used as a format string
```

`is_request_safe` never blocks an IP literal, so Chrome can be pointed at `127.0.0.1:5000`. `logify` treats stored history as a format template, which is what lets a stored `{logify.__globals__[app].config[SECRET_KEY]}` read the Flask secret. `token_required` (lines 116–130) only rejects when `not is_admin and username == 'bartender'`, so a valid signature with any other username passes.

The check-URL list in `artifacts/solve.py` is a fallback order, not a set of tested bypasses. Only `https://example.com/` was used on the live instance. The IPv6/hex/decimal variants are untested; they were listed because they are candidate ways to satisfy the PHP check without reaching the frontend.

## Steps

1. **Confirm the parameter-pollution bypass.** The last `url` is the one PHP validates (a public page returning HTTP 200), the first is what Flask scrapes.

   ```
   $ curl -s -D - -o /dev/null \
       'http://<target>/bartender.php?url=http%3A%2F%2F127.0.0.1%3A5000%2Flogs&name=a&secret=b&url=https%3A%2F%2Fexample.com%2F'
   HTTP/1.1 302 Found
   location: /pdfs/results-1794157195.pdf
   ```

   A `location: /pdfs/no_way.pdf` means the frontend rejected the request; a `results-*.pdf` location means Chrome rendered the private URL.

2. **Plant the payload URL.** Ask the backend to scrape a URL that carries the format field:

   ```
   http://127.0.0.1:5000/logs?x={logify.__globals__[app].config[SECRET_KEY]}
   ```

   The scrape succeeds and the URL is stored in `history`. The PHP filter rejects `{` or `}` in the URL it validates, and it validates only the last `url` value. The payload sits in the first value, which PHP never inspects, so the braces get through.

3. **Render `/logs` again.** With the payload now in the history table, the page is built by `str.format()` and the field resolves to the Flask `SECRET_KEY`. Chrome prints the page, and the frontend redirects to the PDF.

4. **Download the PDF and extract the key.** The PDF uses subset fonts, so read it with a real parser (`pypdf`) instead of `strings`; the key is a 64-character hex string.

5. **Forge the token and fetch the flag.** Sign `{"username": "guest"}` with HS256 and the leaked key, then scrape `http://127.0.0.1:5000/bartender?token=<jwt>`, download the resulting PDF, and extract the flag.

## Sample output

Output of the documented solve command against the live instance, with the flag and the leaked key masked.

```
$ python3 solve.py 154.57.164.80 37952
[+] working check url: https://example.com/
[+] payload url stored in history
[+] leaked SECRET_KEY: 1f5b2e2f_REDACTED
HTB{ac950a25_REDACTED}
```

## Problems hit

- **Self-inflicted deadlock.** The first attempt used the challenge's own public address (`154.57.164.78:32667`) as the PHP-safe URL. `php -S` has a single worker, so the frontend's validation `curl` called back into itself while its only worker was busy, and the instance stopped answering permanently. The URL used to satisfy the PHP check must point at something other than the frontend itself (a public page, or the backend when it can be reached by an alternate representation).
- PHP emits the header as lowercase `location`. Converting the response headers to a plain `dict` made the lookup case-sensitive, so the redirect was missed and the solver reported "no usable check url". Keeping the `HTTPMessage` object fixed it.
- The first attempt's check URL was the challenge's own public address, which caused the deadlock above. The solver now tries `https://example.com/` first; the IP-literal fallbacks are untested.

## Defense

- Parse the request once. Reject duplicate query parameters, or make both services consume the same normalized value instead of relying on each parser's duplicate-key rule.
- Enforce the private-range block in the service that actually fetches the URL (Flask), not only in the frontend. Treat IP literals as untrusted: resolve the host, pin the resolved address, and reject loopback, link-local, and private ranges after resolution.
- Never pass user-controlled data to `str.format()`. A format string is a data-access primitive (`{obj.attr[item]}`); use a template engine that escapes values, or build the log with concatenation.
- Fix the authorization check. `not is_admin and username == 'bartender'` accepts every other username; reject anything that is not an authenticated bartender.
- Do not expose an internal service to a browser that can be pointed at arbitrary URLs. If you must, run the browser in a sandbox with egress filtering that blocks loopback and private ranges.
- Do not treat a PDF rendered by a trusted browser as a safe artifact; it is a data-exfiltration channel when the URL is attacker-controlled.

## Lessons

- When two components parse the same input, the discrepancy between their parsers is the vulnerability. PHP's last-wins and Werkzeug's first-wins turn one parameter into two different URLs.
- `str.format` is dangerous for the same reason as SSTI: it can traverse attributes and indexes. A log line is not a safe place to put user input.
- The weak JWT condition alone is not exploitable without the key, but the format-string leak converts a small logic bug into full access to the flag route.
- A frontend that fetches URLs on the user's behalf can deadlock itself if the checked URL points back at the same single-worker server; always pick an out-of-band check target.
- The `/pdfs/results-<time>.pdf` filename takes a user-controlled `time` value. The `results-` prefix and `.pdf` suffix bound the traversal, so it was not useful here.
