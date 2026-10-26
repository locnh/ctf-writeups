#!/usr/bin/env python3
# Usage: python3 solve.py <phreaky.pcap> [output_dir]
# Standard library only.

import email
import io
import os
import re
import struct
import sys
import zipfile
import zlib


def read_pcap(path):
    """Yield (src, sport, dst, dport, seq, payload) for each IPv4/TCP packet."""
    with open(path, "rb") as f:
        data = f.read()

    magic = data[:4]
    if magic == b"\xd4\xc3\xb2\xa1":
        endian = "<"
    elif magic == b"\xa1\xb2\xc3\xd4":
        endian = ">"
    else:
        raise SystemExit("not a classic pcap file (pcapng is not supported)")

    linktype = struct.unpack(endian + "I", data[20:24])[0]
    if linktype != 1:
        raise SystemExit(f"unsupported link type {linktype}, expected Ethernet")

    off = 24
    while off + 16 <= len(data):
        _, _, incl_len, _ = struct.unpack(endian + "IIII", data[off:off + 16])
        off += 16
        pkt = data[off:off + incl_len]
        off += incl_len

        if len(pkt) < 14 or struct.unpack("!H", pkt[12:14])[0] != 0x0800:
            continue
        ip = pkt[14:]
        if len(ip) < 20 or ip[9] != 6:  # TCP only
            continue
        ihl = (ip[0] & 0x0F) * 4
        src = ".".join(str(b) for b in ip[12:16])
        dst = ".".join(str(b) for b in ip[16:20])
        tcp = ip[ihl:]
        if len(tcp) < 20:
            continue
        sport, dport, seq = struct.unpack("!HHI", tcp[:8])
        doff = (tcp[12] >> 4) * 4
        payload = tcp[doff:]
        if payload:
            yield src, sport, dst, dport, seq, payload


def smtp_messages(path):
    """Reassemble client -> server SMTP streams and return the DATA bodies."""
    streams = {}
    for src, sport, dst, dport, seq, payload in read_pcap(path):
        if dport != 25:
            continue
        # keep the first copy seen for each sequence number (drops retransmissions)
        streams.setdefault((src, sport, dst, dport), {}).setdefault(seq, payload)

    messages = []
    for segs in streams.values():
        stream = b"".join(segs[s] for s in sorted(segs))
        for m in re.finditer(rb"DATA\r\n(.*?)\r\n\.\r\n", stream, re.S):
            messages.append(m.group(1))
    return messages


def extract_parts(messages, out_dir):
    """Return {part_number: bytes} from each message's password-protected zip."""
    parts = {}
    for i, raw in enumerate(messages):
        msg = email.message_from_bytes(raw)
        password = None
        zip_data = None
        for part in msg.walk():
            if part.get_content_type() == "text/plain" and password is None:
                body = part.get_payload(decode=True).decode(errors="replace")
                m = re.search(r"Password:\s*(\S+)", body)
                if m:
                    password = m.group(1).encode()
            elif part.get_content_type() == "application/zip":
                zip_data = part.get_payload(decode=True)

        if password is None or zip_data is None:
            print(f"[!] message {i}: missing password or zip, skipped")
            continue

        with zipfile.ZipFile(io.BytesIO(zip_data)) as zf:
            for name in zf.namelist():
                m = re.search(r"part(\d+)$", name)
                if not m:
                    continue
                content = zf.read(name, pwd=password)
                parts[int(m.group(1))] = content
                with open(os.path.join(out_dir, name), "wb") as f:
                    f.write(content)
                print(f"[+] message {i}: {name} ({len(content)} bytes), password {password.decode()}")
    return parts


def pdf_text(pdf):
    """Inflate the FlateDecode streams of a PDF and return the text shown by Tj."""
    chunks = []
    for m in re.finditer(rb"stream\r?\n", pdf):
        start = m.end()
        end = pdf.find(b"endstream", start)
        if end < 0:
            continue
        try:
            inflated = zlib.decompressobj().decompress(pdf[start:end])
        except zlib.error:
            continue
        chunks += re.findall(rb"\((.*?)\)\s*Tj", inflated)
    return b" ".join(chunks).decode(errors="replace")


def main():
    if len(sys.argv) not in (2, 3):
        print(f"Usage: python3 {sys.argv[0]} <phreaky.pcap> [output_dir]")
        sys.exit(1)

    pcap = sys.argv[1]
    out_dir = sys.argv[2] if len(sys.argv) == 3 else os.path.splitext(pcap)[0] + "_out"
    os.makedirs(out_dir, exist_ok=True)

    messages = smtp_messages(pcap)
    print(f"[*] SMTP DATA messages: {len(messages)}")

    parts = extract_parts(messages, out_dir)
    print(f"[*] parts recovered: {len(parts)}")

    missing = [n for n in range(1, max(parts) + 1) if n not in parts] if parts else []
    if missing:
        sys.exit(f"[-] missing parts: {missing}")

    pdf = b"".join(parts[n] for n in sorted(parts))
    pdf_path = os.path.join(out_dir, "phreaks_plan.pdf")
    with open(pdf_path, "wb") as f:
        f.write(pdf)
    print(f"[*] joined PDF written to {pdf_path} ({len(pdf)} bytes)")

    flag = re.search(r"HTB\{[^}]*\}", pdf_text(pdf))
    if flag:
        print(f"[+] Flag: {flag.group(0)}")
    else:
        print("[-] flag not found in PDF text")


if __name__ == "__main__":
    main()
