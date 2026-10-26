---
title: forensics/phreaky
platform: HTB
event: try-out
category: forensics
tags: [pcap, smtp, mime, tcp-reassembly, zip, pdf, flate]
status: solved
difficulty: 2
---

# Phreaky

**Difficulty:** 🌶️🌶️ (2/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <phreaky.pcap> [output_dir]`. The pcap is the file from the challenge zip. It uses only the standard library.

## Summary

The input is one packet capture, `phreaky.pcap`, in a zip protected with the usual HTB forensics password. Most of the traffic is noise: DNS lookups and HTTP to Ubuntu mirrors, plus IGMP. The interesting part is SMTP traffic on port 25 from `192.168.68.108` (`caleb@thephreaks.com`) to `resources@thetalents.com`.

The sender emails 15 messages, all with the subject `Secure File Transfer`, two minutes apart. Each message has a text part with a password and a zip attachment. The zip holds one part of a PDF, `phreaks_plan.pdf.partN`. Each zip has its own password, so the parts must be unzipped one by one, then joined in order. The joined PDF is a document about an operation against "The Talents". Its last section, the appendix, contains the flag.

No cracking is needed. The passwords are in the mail bodies.

## Attack chain

1. Triage the capture. `tcpdump -nn -r phreaky.pcap` shows the conversations. Port 25 has the SMTP exchange, and the stream from `192.168.68.108` to the mail server carries `DATA` sections.
2. Reassemble the client-to-server SMTP streams in TCP sequence order. Each `DATA` block ends with `\r\n.\r\n`.
3. Parse each message as MIME. Read the `text/plain` part for the password, and decode the `application/zip` part. The attachment name is split across `filename*0` and `filename*1` (RFC 2231 continuation), so it must be joined before it is used.
4. Unzip each attachment with its password (`unzip -P <password>`). Each one contains `phreaks_plan.pdf.partN`, numbered 1 to 15.
5. Join the parts in numeric order: `cat part1 part2 ... part15 > phreaks_plan.pdf`. The result is a valid 2-page PDF.
6. The PDF content streams are FlateDecode-compressed. Inflate them with `zlib` and read the `Tj` text operators. The final line of the appendix reads "Key for secure communication: HTB{...}".

## Steps

1. Put `phreaky.pcap` in a folder, and run the solver. It uses only the standard library:

   ```
   python3 solve.py phreaky.pcap [output_dir]
   ```

   `output_dir` is optional. It defaults to `phreaky_out/` next to the pcap. The script writes each recovered zip part and the joined `phreaks_plan.pdf` there.

2. The script does these steps:
   - Parses the classic pcap format and reassembles the TCP streams to port 25, in sequence order.
   - Finds each SMTP `DATA` block and parses it as a MIME message.
   - Reads the password from the `text/plain` part and opens the `application/zip` attachment with it.
   - Joins the parts in numeric order, inflates the PDF streams, and searches the text for `HTB{...}`.

Sample output (flag masked):

```
$ python3 solve.py phreaky.pcap
[*] SMTP DATA messages: 15
[+] message 0: phreaks_plan.pdf.part1 (221 bytes), password S3W8yzixNoL8
[+] message 1: phreaks_plan.pdf.part2 (221 bytes), password r5Q6YQEcGWEF
[+] message 2: phreaks_plan.pdf.part3 (221 bytes), password TVm9aC1UycxF
[+] message 3: phreaks_plan.pdf.part4 (221 bytes), password jISlbC8145Ox
[+] message 4: phreaks_plan.pdf.part5 (221 bytes), password AdtJYhF4sFgv
[+] message 5: phreaks_plan.pdf.part6 (221 bytes), password j2SRRDraIvUZ
[+] message 6: phreaks_plan.pdf.part7 (221 bytes), password xh161WSXX7tB
[+] message 7: phreaks_plan.pdf.part8 (221 bytes), password yH5vqnkm7Ixa
[+] message 8: phreaks_plan.pdf.part9 (221 bytes), password tJPUTUfceO1P
[+] message 9: phreaks_plan.pdf.part10 (221 bytes), password 2qKlZHZlBPQz
[+] message 10: phreaks_plan.pdf.part11 (221 bytes), password mbkUvLZ1koxu
[+] message 11: phreaks_plan.pdf.part12 (221 bytes), password ZN4yKAYrtf8x
[+] message 12: phreaks_plan.pdf.part13 (221 bytes), password 0eA143t4432M
[+] message 13: phreaks_plan.pdf.part14 (221 bytes), password oea41WCJrWwN
[+] message 14: phreaks_plan.pdf.part15 (208 bytes), password gdOvbPtB0xCK
[*] parts recovered: 15
[*] joined PDF written to phreaky_out/phreaks_plan.pdf (3302 bytes)
[+] Flag: HTB{Th3Phr3aks_REDACTED}
```

Flag: `HTB{Th3Phr3aks_REDACTED}`

## Problems hit

- **Stream truncation.** My first SMTP reassembly cut each stream at 4000 bytes, which lost the attachments. The fix is to keep the full reassembled stream before parsing.
- **Zip password.** The zip is protected with the standard HTB forensics password, but each emailed zip has a separate password. Trying the one from the first mail on every zip fails.
- **Compressed PDF.** Plain `strings` shows only the object headers. The text is inside FlateDecode streams, so the file has to be inflated before the text can be read.

## Defense

- Do not send sensitive files as attachments over plain SMTP. Use an encrypted channel such as TLS (STARTTLS or SMTPS) and an authenticated submission port.
- Do not put the password for an attachment in the same message as the attachment. Send the password through a separate channel.
- Monitor and block mail flow that splits one file across many messages. Splitting is a common way to get past size and content limits.
- Alert on outbound SMTP from internal hosts to unknown domains, especially in a regular cadence.

## Lessons

- A capture with many unrelated conversations still has one thread that matters. Start with the protocol that carries the payload, here SMTP on port 25.
- MIME metadata matters. The RFC 2231 `filename*0` and `filename*1` pieces hold the real filename, and a naive parser would miss them.
- A passworded archive is not a barrier when the password is in the same data. Read every part of each message before attempting a crack.
- PDF text is often compressed. Parse the streams, not the raw bytes.
