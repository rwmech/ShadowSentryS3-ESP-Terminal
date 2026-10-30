"""Upload firmware to ShadowSentry over the admin panel's POST /api/ota.

Usage: python ota_upload.py <firmware.bin> <host>
Reads ADMIN_PORT from main/config.h. The password comes from tools/ota_password
(one line, git-ignored) when that file exists, otherwise ADMIN_PASSWORD in
main/config.h (git-ignored). Use tools/ota_password once the password has been
changed on the dashboard's Settings page, since config.h only holds the default.
The password is never on a command line, in an environment variable or committed.
Called by `pio run -e crowpanel35_ota -t upload` (see platformio.ini).
"""
import base64
import pathlib
import re
import sys
import urllib.request

ROOT = pathlib.Path(__file__).resolve().parent.parent


def config_value(name):
    text = (ROOT / "main" / "config.h").read_text(encoding="utf-8")
    m = re.search(r'^\s*#define\s+' + name + r'\s+("([^"]*)"|(\d+))', text, re.M)
    if not m:
        sys.exit(f"ota_upload: {name} not found in main/config.h")
    return m.group(2) if m.group(2) is not None else m.group(3)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    image = pathlib.Path(sys.argv[1]).read_bytes()
    host = sys.argv[2]
    port = config_value("ADMIN_PORT")
    override = ROOT / "tools" / "ota_password"
    password = ((override.read_text(encoding="utf-8-sig").splitlines() or [""])[0] if override.exists()
                else config_value("ADMIN_PASSWORD"))
    auth = base64.b64encode(f"admin:{password}".encode()).decode()

    url = f"http://{host}:{port}/api/ota"
    req = urllib.request.Request(url, data=image, method="POST", headers={
        "Authorization": f"Basic {auth}",
        "Content-Type": "application/octet-stream",
        "X-ShadowSentry": "1",      # firmware from this change on refuses POSTs without it
    })
    print(f"ota_upload: sending {len(image)} bytes to {url}")
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            print("ota_upload:", r.status, r.read().decode().strip())
    except urllib.error.HTTPError as e:
        sys.exit(f"ota_upload: {e.code} {e.read().decode().strip()}")


if __name__ == "__main__":
    main()
