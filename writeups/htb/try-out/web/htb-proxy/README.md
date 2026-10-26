---
title: web/htb-proxy
platform: HTB
event: try-out
category: web
tags: [request-smuggling, pipelining, ssrf, command-injection, blind-oracle, nip-io]
status: solved
difficulty: 4
---

# web/htb-proxy

**Difficulty:** 🌶️🌶️🌶️🌶️ (4/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`. It takes about one minute.

## Summary

Two services run in one container. A Go proxy on port 1337 takes raw HTTP requests and forwards them to the host named in the `Host` header. A Node/Express backend on port 5000 is only meant to be reached through that proxy. The backend runs `ip address flush dev <interface>` through a shell, so its `interface` field is a command injection.

The proxy checks only the first request. It parses the first request line and body, then sends the whole buffer to the backend. Any second request pipelined on the same connection is never checked, so it reaches the Express route `/flushInterface`, which the proxy blocks by URL.

The backend returns no output, so the injection is blind. The exit status of `ip` decides the response code (200 on success, 401 on error), and that is enough to read the flag one bit at a time.

Relevant code:

The archive is password-protected with the standard HTB password, `hackthebox`.

- `proxy/main.go` checks requests in this order:
  - The URL must not contain `flushinterface` (case-insensitive). This blocks direct access to the route.
  - `Host` must be `host:port` with a numeric port.
  - The host must be an IPv4 address or a domain that passes the regex. The string blacklist blocks `localhost`, `0.0.0.0`, `127.`, `10.`, `172.`, `192.`.
  - `checkIfLocalhost` resolves the host and refuses loopback addresses.
  - `checkMaliciousBody` filters the first request's body for `` ` ; & | ``, `$( )`, newlines and similar.
  - It then forwards the raw request bytes to `Host`.
- `requestParser` reads `Content-Length` and takes the body as the text between the first and second `\r\n\r\n`. Only that text is checked. Anything after it is not.
- `proxy/main.go` also exposes `/server-status`, which returns the container's hostname and IPs. The pod IP is `10.244.14.223`.
- `backend/index.js` has `POST /getAddresses` (no input) and `POST /flushInterface`. `validateInput` only rejects an `interface` that is empty, not a string, or contains a space.
- `node_modules/ip-wrapper` 1.1.1 runs `exec("ip address flush dev " + interfaceName)` through `/bin/sh`. It rejects when stderr is non-empty and resolves otherwise.
- `flag.txt` is at `/flag.txt` on this instance. The entrypoint renames it on normal startup.

## Attack chain

Observations from testing:

- The backend is reached only through the pipelined request, not through a direct request. Sending the same `/flushInterface` request on its own gets `Not Allowed` from the proxy.
- `Connection: close` on R2 matters for speed. Without it, Node keeps the connection open for 5 seconds (its keep-alive timeout), and the proxy waits for that before it replies. Each oracle check then took about 5 seconds. With `Connection: close`, each check takes about 0.7 seconds.
- `ip` errors go to stderr, and `flush` treats any stderr as failure. The injected command must therefore keep stderr empty when it succeeds.
- The payloads only read files. Nothing on the target was changed.

Attack steps:

1. **Reach the backend.** The proxy blocks `10.` and `127.`, but `10-244-14-223.nip.io` contains neither `10.` nor a loopback address. It resolves to `10.244.14.223`, which is the backend container.
2. **Smuggle the route.** Send R1, a `POST /getAddresses` with a 1-byte body that passes the checks. End R1 with `\r\n\r\n`, then send R2, a `POST /flushInterface` with the injection in its body. The proxy checks only R1. Node processes both requests on the same connection.
3. **Inject.** The `interface` value is `x\t2>/dev/null;<cmd>||echo\tx>&2`:
   - `\t` (a JSON escape for a real tab) separates words. `${IFS}` cannot be used here, because `x${IFS}2` is parsed as one word and the `2>` redirect is lost.
   - `2>/dev/null` silences the `ip` error that would otherwise make the call fail.
   - `<cmd>` runs next. If it fails, `echo x>&2` writes to stderr and the response is 401. If it succeeds, the response is 200.
4. **Read the flag.** Use `[ $(head -cN /flag.txt | tail -c1 | od -An -tu1) -gt M ]` as `<cmd>`. A binary search over 0–127 gives each byte in about seven requests.

## Steps

1. Run `solve.py`. It reads the backend IP from `/server-status`, builds the nip.io hostname from it, then extracts up to 80 bytes of `/flag.txt` with eight parallel workers. Requests that time out are retried, so a timeout is never read as a false answer.
2. The flag is printed as `[+] Flag:`: `HTB{r3inv3nting_th3_wh331_c4n_cr34t3_h34dach35_REDACTED}`.

## Problems hit

- The first injection probes always returned `Error flushing interface`. The cause was `${IFS}`: in `x${IFS}2>/dev/null`, the shell parses `x${IFS}2` as one word, so the redirect did not apply. The fix was a JSON `\t`, which becomes a real tab and separates the words.
- A `sleep` probe confirmed that the shell runs the injected text. It also showed that the status code alone was not enough at first, because the proxy's first response was not separated from the second by a newline.
- The first full extraction took several minutes. It was slow because each request waited for the keep-alive timeout. Adding `Connection: close` fixed that.

## Defense

- **Check every request, not just the first.** A proxy that forwards the raw buffer must parse all pipelined requests or reject pipelining entirely.
- **Filter by the destination, not by string patterns.** Resolve the target, then check the resolved address against private and loopback ranges, and connect to that exact address. Do not rely on `strings.Contains` for IP ranges, and do not let `Host` pick the backend.
- **Do not build shell commands from input.** Use `execFile` with a fixed binary and an argument array, and validate the interface name against `^[a-zA-Z0-9_.:-]+$`.
- **Bind the backend to localhost or a private network that the proxy cannot reach by user-chosen names.** Otherwise any name that resolves to the pod IP reaches it.

## Lessons

- A check on the first request of a connection says nothing about the requests that follow it on that connection.
- Shell word splitting matters for payloads. `${IFS}` is expanded after the shell has parsed the words, so it cannot separate a redirect from the word before it.
- A blind command injection can still be read out. An exit-status oracle with binary search reads a byte in about seven requests.
- Connection handling affects a blind attack's runtime as much as the payload does.
