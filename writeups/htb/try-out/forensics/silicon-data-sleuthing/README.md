---
title: forensics/silicon-data-sleuthing
platform: HTB
event: try-out
category: forensics
tags: [firmware, openwrt, squashfs, jffs2, overlayfs, zstd, sysupgrade, crc32, flash-dump]
status: solved
difficulty: 4
---

# forensics/silicon-data-sleuthing

**Flag:** `HTB{Y0u'v3_m4st3r3d_0p3nWRT_d4t4_3xtr4ct10n!!_REDACTED}`

**Difficulty:** 🌶️🌶️🌶️🌶️ (4/5)

**Input:** `chal_router_dump.bin`, a 16 MB raw flash dump of an OpenWrt router, in a zip archive.

**Remote:** `nc <ip> 31938`. It asks six questions in sequence. Each answer is checked exactly, and a wrong answer adds a wait before the next try.

## Summary

The challenge gives a raw dump of a router's SPI flash. The player has to turn the dump into a readable filesystem and pull six facts out of it: the OpenWrt release, the Linux kernel version, the root password hash, the PPPoE credentials, the WiFi SSID and key, and the WAN port forwards.

Most of the answers come from a backup archive stored in the overlay. The squashfs root filesystem is mostly defaults, and its `/etc/shadow` has no root hash. The overlay is a jffs2 partition on the same flash, and it holds the changes the device has made since it was installed, including a `sysupgrade.tgz` backup of its configuration. The backup has the shadow file, the network config, the wireless config and the firewall config.

The overlay's own nodes use a compression type that standard tools did not decode, so the solve works around that by reading the backup inside the gzip stream.

## Attack chain

1. Identify the dump as a raw SPI NOR flash image: the U-Boot banner, Ralink/MT7621 strings and `raspi_*` SPI routines are all visible in `strings`.
2. Find the OpenWrt squashfs root filesystem by its `hsqs` magic, carve it, and extract it.
3. Read `/etc/openwrt_release` from the squashfs. It says OpenWrt 23.05.0.
4. Find the kernel version from the banner string `MIPS OpenWrt Linux-5.15.134`.
5. Find the jffs2 overlay, which holds the device's changes.
6. Parse its nodes and build an inode-to-name map from the dirents. Inode 39 is `/etc/shadow`, inode 36 is `/etc/passwd`, and inode 2 is `sysupgrade.tgz`.
7. Stitch the `sysupgrade.tgz` nodes together by offset, gunzip the stream, and read the tar members `etc/shadow`, `etc/config/network`, `etc/config/wireless` and `etc/config/firewall`.

## Steps

### 1. Identify the flash image

The first bytes of the dump are a MIPS exception vector table, which is typical of a raw flash read. Searching the strings shows the boot loader and the SPI driver:

```
U-Boot 1.1.3 (Aug 18 2020 - 11:10:29)
raspi_read_devid
bbu_spic_trans
```

`raspi_*` and `bbu_spic_*` point to a SPI NOR controller. The `Ralink UBoot Version` string points to a MediaTek/Ralink MT7621 SoC.

```bash
strings -n 8 chal_router_dump.bin | grep -E 'U-Boot|raspi_|Ralink|OpenWrt'
```

### 2. Carve and extract the squashfs root filesystem

Searching the raw bytes for the squashfs magic `hsqs` finds one hit at offset `4375240`. Carve from that offset to the end of the dump, then extract it with `unsquashfs`. Install `squashfs` with Homebrew, since it is not on macOS by default.

```bash
grep -a -b -o hsqs chal_router_dump.bin          # 4375240:hsqs
tail -c +$((4375240 + 1)) chal_router_dump.bin > rootfs.sqsh
brew install squashfs
unsquashfs -d rootfs rootfs.sqsh
cat rootfs/etc/openwrt_release
```

### 3. Read the release and the kernel version

```
DISTRIB_RELEASE='23.05.0'
DISTRIB_REVISION='r23497-6637af95aa'
DISTRIB_TARGET='ramips/mt7621'
```

The kernel version comes from the string `MIPS OpenWrt Linux-5.15.134`, which `strings` finds in the dump.

Answers so far: OpenWrt `23.05.0`, kernel `5.15.134`.

### 4. Find the root password hash

The squashfs `etc/shadow` is 204 bytes, and its root line is `root:::0:99999:7:::`. That is the OpenWrt default, so the squashfs is not the answer.

The overlay holds changes made since flashing. The jffs2 nodes are identified by magic `0x1985` (`85 19`). Node type `0xE001` is a dirent (name and parent), and `0xE002` is an inode (file data). A dirent parser that reads `nsize` at byte 28 and the name at byte 40 gives the mapping:

- inode 39 is `shadow`, under parent inode 9 (`/etc`), and its size is 243 bytes
- inode 36 is `passwd`, with size 374 bytes
- inode 2 is `sysupgrade.tgz`

The shadow in the overlay is 243 bytes. The squashfs version is 204 bytes. That difference is about the size of a root line with an MD5-crypt hash, so the overlay probably has the root hash.

The inode data uses compression type 8, not zlib. Standard zstd tools do not read it, and the dump has no zstd frame magic at all, so a direct decode fails. Before giving up on that route, verify the data is intact: the `data_crc` field is CRC32 with initial value 0 and no inversion, and it matches all 39 inode nodes. The data is not corrupted, so the problem is the encoding, not damage to the flash.

The inode header layout used for the checks (offsets relative to the node start, `0x1985` magic):

| Offset | Field |
|---|---|
| 0 | magic `0x1985` (`85 19`) |
| 2 | nodetype (`0xE001` dirent, `0xE002` inode) |
| 4 | totlen |
| 8 | hdr_crc |
| 12 | ino |
| 16 | version |
| 44 | offset (position in the file) |
| 48 | csize (compressed size) |
| 52 | dsize (decompressed size) |
| 56 | compr |
| 60 | data_crc |
| 64 | node_crc |
| 68 | data (`csize` bytes) |

```python
T = []
for n in range(256):
    c = n
    for _ in range(8):
        c = (c >> 1) ^ 0xEDB88320 if c & 1 else c >> 1
    T.append(c)

def jffs2_crc(buf, crc=0):
    # init 0, no final inversion; differs from zlib.crc32
    for b in buf:
        crc = T[(crc ^ b) & 0xFF] ^ (crc >> 8)
    return crc

# node = inode node at position i in the dump
data = d[i + 68 : i + 68 + csize]
assert jffs2_crc(data) == struct.unpack_from('<I', d, i + 60)[0]
```

### 5. Read the backup tar

`sysupgrade.tgz` is a gzip stream spread across two inode nodes (offsets 0 and 4096, latest versions). Concatenate them by offset, then gunzip with `zlib.decompressobj(16 + zlib.MAX_WBITS)`.

```python
chunks = {}  # file offset -> (version, compressed bytes), for inode 2 only
for i in inode_positions:  # positions of 0xE002 nodes with ino == 2
    ver, = struct.unpack_from('<I', d, i + 16)
    off, = struct.unpack_from('<I', d, i + 44)
    csize, = struct.unpack_from('<I', d, i + 48)
    if off not in chunks or ver > chunks[off][0]:
        chunks[off] = (ver, d[i + 68 : i + 68 + csize])

blob = b''.join(chunks[o][1] for o in sorted(chunks))   # 4096 + 2824 bytes
tar = zlib.decompressobj(16 + zlib.MAX_WBITS).decompress(blob)

# ustar member header: name at 0, size (octal) at 124, magic "ustar" at 257
# match the header, not the bare name: the string also appears inside scripts
k = next(k for k in range(0, len(tar), 512)
         if tar[k:k + 10].startswith(b'etc/shadow') and tar[k + 257:k + 262] == b'ustar')
size = int(tar[k + 124 : k + 136].strip(b'\x00 '), 8)   # 243
print(tar[k + 512 : k + 512 + size].decode())
```

The tar entries include:

- `etc/shadow` (243 bytes, the same size as the overlay inode), containing `root:$1$…REDACTED:19804:0:99999:7:::`
- `etc/config/network`, with a `wan` interface set to `proto 'pppoe'`, a username and a password
- `etc/config/wireless`, with two `wifi-iface` sections and one SSID and key
- `etc/config/firewall`, with three `redirect` sections

### 6. Answer the remote

| Question | Source | Answer |
|---|---|---|
| OpenWrt version | squashfs `/etc/openwrt_release` | `23.05.0` |
| Kernel version | dump banner string | `5.15.134` |
| root shadow line | `sysupgrade.tgz` `etc/shadow` | `root:$1$YfuR…REDACTED` |
| PPPoE username | `etc/config/network`, `wan` | `yoh…REDACTED` |
| PPPoE password | `etc/config/network`, `wan` | `ae-h+i$i^…REDACTED` |
| WiFi SSID | `etc/config/wireless` | `VLT-…REDACTED` |
| WiFi password | `etc/config/wireless` | `french-halves-…REDACTED` |
| WAN → LAN ports | `etc/config/firewall`, `redirect` | `17XX,22XX,80XX` |

The three redirects are `DB` (17XX to 5881), `WEB` (22XX to 9889) and `NAS` (80XX to 4431), all with `src 'wan'` and `dest 'lan'`.

## Problems hit

- **Wrong-answer waits.** Sending empty lines to the remote while reading the prompt counted as wrong answers. Each one added a wait, which blocked later attempts for minutes. A bare connection with no input is the safe way to read a prompt, and `< /dev/null` is not safe, because EOF also counts as an answer.
- **The jffs2 zstd nodes do not decode with standard tools.** The `zstandard` library, both framed and magicless, failed. The dump has no zstd frame magic, and the first bytes of the data are not a standard zstd header. This was the main obstacle. The CRC check showed the data was intact, so the problem was the encoding.
- **Mounting the squashfs does not give the overlay.** OpenWrt uses overlayfs: the squashfs is the read-only base and the jffs2 overlay holds the changes on top. Mounting only the squashfs shows the default `/etc/shadow`. The Docker VM available here has no jffs2 or mtdram modules, so a kernel mount was not possible.
- **The backup was the way in.** The overlay's own inodes were not decodable, but the backup archive stored inside the overlay used gzip, which decodes with the standard library. Looking at the inode-to-name map and checking the archive's contents solved the problem.

## Defense

- **Keep credentials out of backups.** The `sysupgrade.tgz` backup stored the root hash, the PPPoE password and the WiFi key in clear. Backups should be encrypted, or secret fields removed before saving them.
- **Use a per-device PPPoE and WiFi password.** Storing the credentials on the flash in plain text means anyone with a flash dump gets them. Storing them in an encrypted keystore, or at least not in the backup, would help.
- **Change the default root password.** The squashfs default shows the root account has no password, and the overlay replaced that with a hash. Keep the root login locked to key-based access.
- **Protect the flash.** A raw SPI dump reveals the whole filesystem. Readout protection on the SPI controller, or encrypted flash, would make this kind of extraction much harder.
- **Limit the WAN port forwards.** Three forwards expose DB, web and NAS services to the internet. Only the services that need public access should be forwarded, and each should be restricted by source address.

## Lessons

- A firmware dump is a stack of layers. The squashfs is the base, and the jffs2 overlay on top is where the device's own changes live. Check both, and check whether a backup archive is stored inside the overlay.
- Check data integrity before blaming the decoder. A CRC match on the stored data shows the bytes are correct, so the failure is in the format or the algorithm, not in corruption.
- Compare sizes across copies. A shadow file that grows by about the length of a crypt hash between the base and the overlay is a strong hint, even before it is decoded.
- Read the remote's answer format before you submit. Penalty waits make wrong guesses expensive.
