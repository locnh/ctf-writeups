---
title: web/nebula-network
platform: HTB
event: secfest26
category: web
tags: [ssrf, localhost-port-scan, fastapi, api-docs, jwt]
status: solved
difficulty: 2
---

# web/nebula-network

**Flag:** `HTB{un4ut0r1z3d_4cc3s5_t0_s3nt1n3l_pr1m3_l0g5_32b9dcd4360755d815f7307ea02de8c7}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`.

## Summary

Nebula Network is a FastAPI app. Its API docs are at `/docs/` and the OpenAPI schema is at `/openapi.json`. Any registered user can store a data source URL with `POST /api/data/sources`, then fetch that URL with `GET /api/data/sources/{id}/fetch`. The server requests the URL itself and returns the response body in the `data` field.

That fetch is a server-side request forgery. The server does not check the URL, so it can reach services bound to `127.0.0.1`. The hint says the interesting service is on localhost, between ports 1000 and 5000. A closed port returns `Connection refused` in the `data` field, and an open port returns its content. Scanning that range through the fetch endpoint finds the one service that holds the flag.

## Attack chain

1. **Read the API.** `/docs/` shows Swagger UI, and `/openapi.json` lists the routes. The data-source routes are the ones to look at.
2. **Register and log in.** A new account gets the `observer` role and a bearer token.
3. **Test the fetch.** Add a source with `http://127.0.0.1:1337/`. The fetch returns the page, which shows the flag.
4. **Scan the range.** For each port from 1000 to 5000, add a source with `http://127.0.0.1:<port>/`, fetch it, and check whether the response is a connection error. Print the open ports and any `HTB{...}` found.

## Steps

1. Run `solve.py`. It registers a random user, logs in, and scans localhost ports 1000 to 5000 through the fetch endpoint. It stops at the first flag. Progress is printed to stderr.
2. The solver reports port `1337` and prints the flag after `[+] Flag:`. The flag is `HTB{un4ut0r1z3d_4cc3s5_t0_s3nt1n3l_pr1m3_l0g5_32b9dcd4360755d815f7307ea02de8c7}`.

## Sample output

Output of `python3 solve.py <target_ip> <target_port>` against the live instance. Pasted from the run, not written by hand.

```
[+] Open localhost port: 1337
[+] Flag:
HTB{un4ut0r1z3d_4cc3s5_t0_s3nt1n3l_pr1m3_l0g5_32b9dcd4360755d815f7307ea02de8c7}
```

## Problems hit

- **Concurrent requests timed out.** With 8 workers the client hit read timeouts. Dropping to 4 workers, catching errors per port, and printing progress made the scan finish.
- **A closed port is not an HTTP error.** The fetch endpoint returns status 200, with `Connection refused` text in `data`. The solver checks the text, not the status.
- **Test sources stay in the account.** Each scan adds a source, so the list grows to thousands of rows. The solver does not clean them up, because the API has no delete route in the schema.

## Defense

- **Validate outbound URLs.** Allow only the expected hosts and schemes. Reject private, loopback and link-local addresses, including after DNS resolution and redirects.
- **Do not return raw response bodies.** The fetch endpoint sends the whole body of the internal service back to the user. Return a status and a summary, not the content.
- **Bind internal services to the right interface.** A service that holds sensitive data should not be reachable from the app's own host without authentication.
- **Limit who can add sources.** A low-privilege `observer` account should not be able to point the server at arbitrary URLs.

## Lessons

- A feature that fetches a user-supplied URL is an SSRF unless the URL is checked. The fetch here was the whole attack.
- The OpenAPI schema gives the full list of routes, which makes the attack surface easy to read.
- Port scanning through SSRF works best when the closed and open responses look different, as they do here.
