---
title: web/open-invitation
platform: HTB
event: secfest26
category: web
tags: [information-disclosure, hardcoded-credentials, view-source]
status: solved
difficulty: 1
---

# web/open-invitation

**Flag:** `HTB{op3n_REDACTED}`

**Difficulty:** 🌶️ (1/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`.

## Summary

The app is a static "Knowledge Base" FAQ served by nginx. It has no login, forms, or API. The FAQ entry "Need assistance managing employees through ADP?" links to an `ftp://` URL in its HTML. That URL carries credentials for user `dev`, and the password part is the flag. The flag is in the public page source, so nothing else on the server had to be reached.

The FTP host `open-invitation.htb` does not resolve, and ports 21 and 2121 on the target are closed from my side. So the FTP login could not be tested, and the flag was taken from the page itself.

## Attack chain

1. **Read the page source.** `GET /` returns the FAQ HTML.
2. **Find the credential link.** The "HR Guide for Managers" link is `ftp://dev:HTB{...}@open-invitation.htb/hr/hr_guide_for_managers.pdf`.
3. **Take the password.** The password is the flag.

### Trial and error

Steps tried before the flag was found, in order:

1. `GET /` returned the FAQ page. I read its full HTML before probing other paths.
2. Probed `/login`, `/register`, `/invite`, `/invitation`, `/invitations`, `/admin`, `/api`, `/health`, `/robots.txt`, `/app.js` and `/styles.css`. All returned `404`. `/static/` returned `403`, so directory listing is off.
3. Read `/static/main.js`, the search and accordion code. It has no secrets.
4. The FAQ entry "Need assistance managing employees through ADP?" links to `ftp://dev:HTB{...}@open-invitation.htb/hr/...`. The password part is the flag.
5. Checking the link did not work. `open-invitation.htb` does not resolve, ports 21 and 2121 on the target are closed (checked with `/dev/tcp`), and `curl` to `ftp://<target_ip>/` with those credentials returned nothing. The HR PDF path on the web server (`/hr/hr_guide_for_managers.pdf`, `/hr/`, `/ftp/`, `/static/hr_guide_for_managers.pdf`) returned `404`.

## Steps

1. Run `solve.py`. It fetches `/`, finds the first `HTB{...}` in the source, and prints it.
2. The flag is printed as `[+] Flag:`. The flag is `HTB{op3n_REDACTED}`.

## Sample output

Output of `python3 solve.py <target_ip> <target_port>` against the live instance, with the flag masked. Pasted from the run, not written by hand.

```
[+] Flag:
HTB{op3n_REDACTED}
```

## Problems hit

- **The FTP link does not resolve.** `open-invitation.htb` is not in public DNS, and ports 21 and 2121 on the target are closed from my side. The HR PDF path on the web server returns `404`. None of these were needed to get the flag.

## Defense

- **Do not put credentials in public pages.** Links in the HTML are visible to anyone who opens the source. Keep credentials out of content, and use a separate auth flow for file access.
- **Rotate credentials that have been exposed.** If a password was ever in published HTML, treat it as leaked.
- **Serve documents through a controlled download path.** An FTP link with embedded credentials is hard to audit. Use signed, authenticated links with expiry.

## Lessons

- View the page source of a static site before testing anything else. Links in the HTML can contain secrets, and here the flag was in an `href`.
- A flag that appears in a credential position is still a flag. Check the whole source, not only the visible text.
