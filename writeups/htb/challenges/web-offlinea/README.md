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

   The scrape succeeds and the URL is stored in `history`. The braces never reach the PHP filter because they are percent-encoded inside the first `url` value and PHP only inspects the last one.

3. **Render `/logs` again.** With the payload now in the history table, the page is built by `str.format()` and the field resolves to the Flask `SECRET_KEY`. Chrome prints the page, and the frontend redirects to the PDF.

4. **Download the PDF and extract the key.** The PDF uses subset fonts, so read it with a real parser (`pypdf`) instead of `strings`; the key is a 64-character hex string.

5. **Forge the token and fetch the flag.** Sign `{"username": "guest"}` with HS256 and the leaked key, then scrape `http://127.0.0.1:5000/bartender?token=<jwt>`, download the resulting PDF, and extract the flag.

## Sample output

Output of the documented solve command against the live instance, with the flag and the leaked key masked.

```
$ python3 solve.py 154.57.164.80 37952
[+] working check url: https://example.com/
[+] payload url stored in history
[+] leaked SECRET_KEY: 1f5b2e2f...REDACTED
HTB{ac950a25_REDACTED}
```

## Problems hit

- **Self-inflicted deadlock.** The first attempt used the challenge's own public address (`154.57.164.78:32667`) as the PHP-safe URL. `php -S` has a single worker, so the frontend's validation `curl` called back into itself while its only worker was busy, and the instance stopped answering permanently. The URL used to satisfy the PHP check must point at something other than the frontend itself (a public page, or the backend when it can be reached by an alternate representation).
- The IPv4-mapped loopback `[::ffff:7f00:1]` is a filter bypass on paper (PHP's `parse_url` keeps the brackets, so `inet_pton` and `filter_var` both fail), but it depends on IPv6 being usable in the container and on the backend binding. A plain public URL was the reliable choice here.
- PHP emits the header as lowercase `location`. Converting the response headers to a plain `dict` loses `HTTPMessage`'s case-insensitive lookup and the redirect is missed; keep the header object or match case-insensitively.
- Chrome normalizes URLs, so `check_equiv` compares `driver.current_url` with the requested URL after `unquote`. Percent-encoded braces are fine because both sides are unquoted, but anything Chrome rewrites into a different path or netloc fails the check and no PDF is written.

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
- A frontend that fetches URLs on the user's behalf can deadlock itself if the checked URL points back at the same single-worker server; always pick an out-of-band checksum target.

## Notes

- The `/pdfs/results-<time>.pdf` filename uses the user-controlled `time` parameter, but the `results-` prefix and `.pdf` suffix bound the traversal, so it was not useful.
- The keys and flag above come from a disposable instance; the sample output masks both.
