---
title: forensics/an-unusual-sighting
platform: HTB
event: try-out
category: forensics
tags: [log-analysis, ssh, bash-history, timeline, sshd, incident-response]
status: solved
difficulty: 2
---

# forensics/an-unusual-sighting

**Flag:** `HTB{4n_unusual_s1ght1ng_1n_SSH_REDACTED}`

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** none (manual steps)

## Summary

The input is `bash_history.txt` and `sshd.log`, in a zip archive. There are no binaries and no network capture. The remote is `nc <ip> 40307`. It asks six questions in sequence. Each answer is checked exactly, and a wrong answer adds a wait before the next try.

The team's dev server, `korp`, had work disappear. The player gets two logs from that server: the SSH log and the bash history of the dev account. The job is to find the intrusion in those logs.

The attacker logged in to `root` over SSH from a public address, `2.67.182.119`, at 04:00:14. That is outside the company's operating hours of 09:00 to 19:00, and every other successful login in the logs falls inside them. The attacker then ran a short recon sequence, read `/etc/shadow`, downloaded a tarball from a lookalike domain, ran a `./setup` script, and deleted the archive with `shred`. The session ended at 04:38:17.

The six answers are all in the two logs. Nothing needs to be decrypted or cracked.

## Attack chain

1. Set up the server: `root` creates the `softdev` user and installs the dev tools.
2. Normal dev work: `softdev` logs in many times from different addresses, and each session has matching bash history.
3. Unusual access: `root` logs in from `2.67.182.119` at 04:00:14 on 2024-02-19, with no matching work in the history.
4. Recon and credential read: `whoami`, `uname -a`, `cat /etc/passwd`, `cat /etc/shadow`, `ps faux`.
5. Staging: `wget` a tarball from `gnu-packages.com`, `tar xvf`, then `./setup`.
6. Cleanup: `shred -zu latest.tar.gz`, then the session ends at 04:38:17.

## Steps

### 1. Map the logs

Both logs are `[YYYY-MM-DD HH:MM:SS] message`. The sshd log starts with two lines that show the listening socket:

```
Server listening on 0.0.0.0 port 2221.
```

Every later `Connection from ... on <ip> port <port>` line repeats the server's address. The first answer comes from that line.

### 2. Question 1: the SSH server address and port

Read the `Connection from` line and take the `on <ip> port <port>` part. It is `100.107.36.130 port 2221`, so the answer is `100.107.36.130:2221`. The remote asks for `IP:PORT`.

### 3. Question 2: the first successful login

Search for `Accepted ` lines. The first one is `Accepted password for root from 100.81.51.199` at `2024-02-13 11:29:50`. This is the admin's root login. It is followed by `useradd -mG sudo softdev` in the bash history at 11:31:01, which matches the admin session.

Answer: `2024-02-13 11:29:50`.

### 4. Question 3: the unusual login

Take every `Accepted` line and check its hour against the operating hours given in the challenge text, 09:00 to 19:00. Only one falls outside them: `Accepted password for root from 2.67.182.119` at `2024-02-19 04:00:14`.

The other successful logins are all from `softdev` or from the admin, and all fall inside the hours. This check is the key step, because there is no other obvious anomaly from the timestamps alone.

Answer: `2024-02-19 04:00:14`.

### 5. Question 4: the attacker's key fingerprint

At the same timestamp, sshd logs the key the client offered before falling back to password:

```
Failed publickey for root from 2.67.182.119 port 60071 ssh2: ECDSA SHA256:OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4
```

Use the connection's `ip port` pair to match the right line, since the same host may appear in several sessions. The remote takes the digest without the `SHA256:` prefix, so the answer is `OPkBSs6okUKraq8pYo4XwwBg55QSo210F09FCe1-yj4`.

### 6. Session window

The disconnect line for the same `ip port` pair gives the end of the session: `2024-02-19 04:38:17`. Every bash history entry between 04:00:14 and 04:38:17 belongs to this session.

### 7. Question 5: the first command after login

In the bash history, the first entry after 04:00:14 is `[2024-02-19 04:00:18] whoami`. Answer: `whoami`.

### 8. Question 6: the final command before logout

The last entry before 04:38:17 is `[2024-02-19 04:14:02] ./setup`. Nothing else is logged between 04:14:02 and the logout, so the answer is `./setup`.

Note what the history shows in between: the attacker read `/etc/passwd` and `/etc/shadow`, downloaded a `latest.tar.gz` from `gnu-packages.com`, and deleted it with `shred -zu` after extraction. The `./setup` script is the most likely payload.

**Flag:** `HTB{4n_unusual_s1ght1ng_1n_SSH_REDACTED}`

## Problems hit

- **Blank probes count as wrong answers.** I sent empty lines to the remote while trying to see the prompt, and each one counted as a wrong answer. The wait grew each time and blocked the next tries for minutes. To look at the prompt without answering, read it with a bare connection that sends nothing.
- **Fingerprint format.** The first answer for question 4 was the full string including `SHA256:`, and the remote rejected it. Removing the prefix made it pass. The sshd log always prints the prefix, so the prefix has to be dropped before submitting.
- **`2>1` in the history.** The attacker, or the operator, wrote `2>1` in several server commands. That redirects stderr to a file named `1`, not to stdout. It is not part of the intrusion, but it is worth knowing about when reading the logs.
- **Ambiguous "attacker".** The `softdev` account logs in from many addresses, several of them public. Only the `root` login at 04:00:14 is both outside office hours and followed by destructive commands, so that one is the attacker.

## Defense

- **Disable password login for `root`.** `PermitRootLogin prohibit-password` would have stopped the root login from `2.67.182.119` outright. The attacker had the password, so key-only login would also have stopped the session.
- **Restrict SSH by source address.** The admin logged in from a single internal range. Allowing only that range would have blocked the external login.
- **Alert on off-hours root logins.** The timestamp of the login was the strongest signal in these logs.
- **Protect `/etc/shadow`.** Root reading the shadow file is a clear indicator of compromise. Auditing reads of that file would have flagged it.
- **Verify downloads before running them.** The tarball came from a lookalike domain, and the attacker ran `./setup` right after extracting it. Checksum or signature checks on downloaded tools would have caught this.
- **Keep the bash history.** The attacker deleted the tarball, but the history still shows every command. Shipping history off the host would make cleanup harder.

## Lessons

- Start with the time window. In a timeline puzzle, the offset from normal working hours is often the clearest anomaly, and it narrows the search faster than any other field.
- Match events across logs by timestamp and by the `ip port` pair. Shared timestamps link the sshd log to the bash history, so a login can be tied to what was typed after it.
- A logged key fingerprint is a public identifier. It can be matched against other sessions to find repeat visits from the same client, even when the IP changes.
- Read the remote's format rules before submitting. The fingerprint and timestamp formats both mattered, and a wrong format looks the same as a wrong answer.
