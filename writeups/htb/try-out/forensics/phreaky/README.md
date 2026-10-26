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

1. Put `phreaky.pcap` in a fresh folder.
2. Reassemble the TCP streams on port 25, client to server, in sequence order. The stream is parsed with scapy, or with any tool that can reassemble TCP. Find each `DATA` block and parse it as a MIME message with `email.message_from_bytes` or an equivalent.
3. For each message, read the password from the `text/plain` part and save the `application/zip` attachment. Rebuild the filename from `filename*0` and `filename*1`.
4. Unzip each attachment with its password into a folder numbered by message, so each part keeps its `partN` name.
5. Join the parts in numeric order, then inflate the PDF content streams with `zlib` and read the `Tj` text.
6. The flag is in the appendix.

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
