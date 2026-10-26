---
title: web/jailbreak
platform: HTB
event: try-out
category: web
tags: [xxe, xml, file-disclosure, werkzeug]
status: solved
difficulty: 2
---

# web/jailbreak

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`

## Summary

The target is a Pip-Boy themed Python web app served by Werkzeug 3.0.3 on Python 3.12. Most pages are static. The ROM page at `/rom` is a firmware update form. It takes an XML config and posts it to `POST /api/update` with `Content-Type: application/xml`. The server parses the XML and echoes the text of the `<Version>` element back in the `message` field.

The XML parser resolves external entities. Declaring an entity that points at a local file and referencing it inside `<Version>` returns that file's contents in the response. This is XML External Entity (XXE) file disclosure.

Relevant code: no source code was provided. The client side is in the page's JavaScript:

- `static/js/update.js` builds an XML config and posts it to `/api/update` with `Content-Type: application/xml`.
- The config is user-editable. The textarea is the whole input, so an arbitrary XML document (including a `DOCTYPE`) can be sent.
- The server response is JSON with a `message` field. The message contains the parsed value, which is the reflection channel for the file contents.

## Attack chain

1. Find the upload path. `/rom` posts XML to `/api/update`.
2. Confirm that the parser resolves entities. Send a `DOCTYPE` with `SYSTEM "file:///etc/passwd"` and reference it in `<Version>`. The `message` returns the contents of `/etc/passwd`.
3. Read the flag. `file:///flag.txt` is at the root of the filesystem and holds the flag.

Observations from testing:

- The response is status 200 with JSON. The file contents are in the `message` field, after the text `Firmware version`.
- The entity value is inserted as-is, so text containing newlines (like `/etc/passwd`) appears in the message.
- Reading `/root/flag.txt`, `/home/guest/flag.txt`, and `/app/flag.txt` returned `None`. The flag is at `/flag.txt`. Enumerating a few likely paths is quick.

## Steps

1. Load `/rom` and read `static/js/update.js` to find the endpoint and content type.
2. Send the XXE payload with `file:///etc/passwd` to confirm disclosure.
3. Send the same payload with `file:///flag.txt`. The flag appears in the `message` field: `HTB{b1om3tric_l0cks_4nd_fl1cker1ng_l1ghts_REDACTED}`.

The solve script does steps 2 and 3 with `requests` and prints both responses.

## Problems hit

- `file:///proc/self/environ` failed with `Char 0x0 out of allowed range`. The environment block is NUL-separated, and the XML parser rejects NUL characters. Reading regular text files works, but binary or NUL-delimited files do not.
- The first guesses for the flag location were wrong. The flag was at `/flag.txt`, not in a home or app directory.

## Defense

- **Disable external entities and DTDs.** Use a parser with entity resolution turned off. In Python, `defusedxml` rejects DTDs and entities by default. In Java, set `disallow-doctype-decl` to true. In libxml2-based code, do not pass `XML_PARSE_NOENT`.
- **Do not reflect parsed content to the client.** Returning the parsed value in `message` turns any entity resolution into a read primitive. Return a fixed status message.
- **Validate the schema before use.** A firmware update config should be parsed with a strict schema that allows only the known elements and rejects a `DOCTYPE`.
- **Run the service with least privilege.** Keep the flag and other secrets out of paths the app process can read unless the app needs them.

## Lessons

- An XML upload endpoint is an XXE candidate even when the feature looks like a config update. Check the content type and try a `DOCTYPE` early.
- Reflected output makes XXE easy. Without a reflection channel, blind XXE needs an out-of-band server.
- The page's JavaScript shows the request format, and the payload is built from there. Reading the front-end code before sending requests saved time.
