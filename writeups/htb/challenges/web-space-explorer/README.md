---
title: web/space-explorer
platform: HTB
event: challenge
category: web
tags: [json, parser-differential, access-control-bypass, go, flask]
status: solved
difficulty: 2
---

# web/space-explorer

**Flag:** `HTB{C0SM1C-REDACTED}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** none (single curl request)

## Summary

Space Explorer is two services in one container. A Go proxy on port 8080 forwards `getcosmic` requests to a Flask service on 8081. The Flask service also handles `getSecureCode`, which returns the flag. The Go proxy blocks `getSecureCode` before it reaches Flask.

The two services parse the same JSON body with different rules. Go's `encoding/json` matches struct tags case-insensitively, and a repeated key overwrites the earlier one. Flask's `request.get_json()` followed by `data['action']` is case-sensitive. A body that carries both `action` and `Action` therefore gets routed by the proxy as `getcosmic` and handled by Flask as `getSecureCode`.

## Attack chain

1. **Recon.** The home page has two radio options: `getcosmic` and `getSecureCode`. The second one is labelled "ACCESS SECURE DATABASE".
2. **Block.** Sending `getSecureCode` through the normal front end returns `Access denied: Invalid security clearance`. The Go proxy rejects it before forwarding.
3. **Parser differential.** Send one JSON body with both keys. Go reads `Action` as `getcosmic`, forwards the body to Flask, and Flask reads `action` as `getSecureCode`.
4. **Flag.** Flask returns the flag in its JSON response, and the proxy copies that response back to the client.

## Steps

1. **Confirm the block.**

   ```
   $ curl -sS -X POST http://<target>/execute -H 'Content-Type: application/json' -d '{"action":"getSecureCode"}'
   Access denied: Invalid security clearance
   ```

2. **Send the differential payload.**

   ```
   $ curl -sS -X POST http://<target>/execute -H 'Content-Type: application/json' -d '{"action":"getSecureCode","Action":"getcosmic"}'
   ```

3. **Read the flag** from the `flag` field of the JSON response.

## Sample output

Output of the documented command against the live instance, with the flag masked.

```
$ curl -sS -X POST http://<target>/execute -H 'Content-Type: application/json' -d '{"action":"getSecureCode","Action":"getcosmic"}'
{"flag":"HTB{C0SM1C-REDACTED}","name":"Captain's Log","src":"https://images.unsplash.com/photo-1534447677768-be436bb09401?w=600"}
```

## Problems hit

- The front end only sends one `action` value, so the browser never produces the duplicate key. The payload has to be sent with curl.
- The local Docker build from `Dockerfile` sets `FLAG="HTB{f4k3_fl4g_4_t3st1ng}"`. That value is a placeholder and is not the live flag.

## Defense

- Validate the request once, in one place. If the proxy checks `action`, the backend must parse the same bytes the same way, or the proxy should forward a canonical re-encoding of the parsed value rather than the raw body.
- Reject duplicate keys and case variants of a field name, or use a strict decoder in both services.
- Do not rely on a proxy to enforce authorization for a backend that also accepts the same action. Check the action in the service that holds the secret.
- Keep secrets out of endpoints that can be reached through any route that is not authorized for them.

## Lessons

- Two parsers that disagree on the same input can turn a single access check into a bypass, even when each service looks correct on its own.
- Go's JSON decoder is case-insensitive for struct fields, and Python's is not. Test cross-service routing with mixed-case keys and duplicates.
- When a front end hides an option, check whether the back end still accepts it through a different request shape.
