---
title: forensics/leaked
platform: HTB
event: secfest26
category: forensics
tags: [memory-forensics, volatility, linux-memory, malware, reverse-shell, leaked-credentials]
status: solved
difficulty: 3
---

# forensics/leaked

**Flag:** `HTB{wh0_l34k3d_th3_cr3ds!!!!?}`

**Difficulty:** 🌶️🌶️🌶️ (3/5)

**Solve script:** none (manual steps)

## Summary

A Linux server's credentials were leaked, and a memory snapshot was taken before the machine was isolated. The dump is `memory.dmp` with a Volatility 2 profile for Ubuntu 4.15.0-184-generic. The attacker logged in over SSH as `developer` from `192.168.1.30`, then started an unknown binary, `./jN8ziHXGE`, from `/home/developer`. The binary connected out to `77.74.198.52:4444`.

The hint names `linux_psaux` and `linux_netstat`. Together they show the suspicious process and its connection. The rest of the answers come from the logs and the memory image.

## Attack chain

1. **Initial access.** `developer` logged in over SSH from `192.168.1.30`, which `auth.log` and `wtmp` both record on 2022-12-08.
2. **Execution.** A user process `jN8ziHXGE` (PID 1521) ran as uid 1000, a child of the bash session PID 1440.
3. **Command and control.** PID 1521 held an ESTABLISHED TCP connection from `192.168.1.5:39112` to `77.74.198.52:4444`.

## Steps

1. **Set up Volatility 2.** Clone the Volatility 2 source and run it under Python 2.7 in Docker. Copy the profile zip into `volatility/plugins/overlays/linux/` so Volatility loads it. Confirm the profile with `--info`, which lists `LinuxUbuntu_4_15_0-184-generic_profilex64`.
2. **List processes.** `linux_psaux` lists every process with its arguments. Ignore the kernel threads, which are in brackets. PID 1521 is the one running `./jN8ziHXGE` as uid 1000.
3. **Check connections.** `linux_netstat` shows PID 1521 with an ESTABLISHED connection to `77.74.198.52:4444`.
4. **Find the login.** `auth.log` shows `developer` accepted from `192.168.1.30` on 2022-12-08 at 15:21:07. `wtmp` matches it at 15:21:08 UTC.
5. **Find the interface.** `linux_ifconfig` gives `enp0s3` = `192.168.1.5`. The question wrote `en0s3`.
6. **Find the malware start time.** `linux_pslist` gave 15:22:29, which the server rejected. The correct value comes from the raw `real_start_time` of PID 1521 (105 942 316 172 ns) added to the boot time from `wall_to_monotonic`, which is 15:20:18 UTC. That gives 15:22:03.94, so the answer is `15:22:03`.
7. **Find the malware hash.** The on-disk binary was not in the file list, so the hash comes from memory. The ELF header of the mapping at `0x400000` has one PT_LOAD segment with `p_filesz = 250`, and every byte after 250 is zero. The MD5 of the first 250 bytes is `853bcc7d0867474ce3ab28ecb9756276`.
8. **Get the flag.** The server returned `HTB{wh0_l34k3d_th3_cr3ds!!!!?}` after all eight answers.

## Sample output

Output of `linux_psaux` and `linux_netstat` against the memory image, filtered to the suspicious process. Pasted from the run, not written by hand.

```
Pid    Uid    Gid    Arguments
1521   1000   1000   ./jN8ziHXGE
TCP      192.168.1.5     :39112 77.74.198.52    : 4444 ESTABLISHED             jN8ziHXGE/1521
```

## Problems hit

- **Volatility 2 needs Python 2.7.** The host has no Python 2, so the analysis runs in the `python:2.7-slim` Docker image, with the Volatility source mounted read-only.
- **`linux_psaux` in this build prints no start time.** The start time comes from `linux_pslist`, which uses a boot time computed from `timeo`. That boot time was 27 seconds later than the logs allow, so the value 15:22:29 was wrong. The raw `real_start_time` plus `wall_to_monotonic` gives the correct time.
- **The binary was removed from the host.** A 4096-byte procdump of the binary was written to the host, and Bitdefender deleted it. The hash was then taken inside the container, from the memory mapping, without writing an executable to the host.
- **The question wording.** The question asked about `en0s3`, but the interface in the dump is `enp0s3`. The answer `192.168.1.5` was accepted.

## Defense

- **Restrict SSH access.** Disable password logins and limit SSH to known source addresses or keys. The attacker logged in with a password.
- **Watch for unknown binaries running as users.** A binary in a home directory started by a login shell and connected to an external port is a strong signal.
- **Alert on outbound connections to uncommon ports.** An ESTABLISHED connection to port 4444 from a user process should raise an alert.
- **Rotate credentials that were exposed.** The leak came from a public forum, so the password for `developer` must be changed.

## Lessons

- Memory forensics gives the process list and open sockets, but timestamps need care. A plugin's computed start time can be off by tens of seconds, so check it against the logs and the raw kernel fields.
- When a file is deleted from disk, the memory image can still give its size and hash. Check the ELF headers to confirm the file length.
- Keep recovered malware inside the analysis container, and do not run it.
