"""Upload the MAC vendor database to ShadowSentry over POST /api/oui.

Usage: python tools/oui_upload.py <oui.bin> <host>
Build oui.bin first with tools/make_oui.py. The admin port and password are
read the way tools/ota_upload.py reads them (tools/ota_password, else
main/config.h, both git-ignored); the password is never on a command line.
The board checks the header, writes /sd/oui.bin.tmp and renames it.
"""
import base64
import pathlib
import sys
import urllib.request

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import ota_upload  # noqa: E402  (config_value, ROOT)


def main():
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    blob = pathlib.Path(sys.argv[1]).read_bytes()
    if blob[:4] != b"SSOU":
        sys.exit("oui_upload: not a make_oui.py file")
    host = sys.argv[2]
    port = ota_upload.config_value("ADMIN_PORT")
    override = ota_upload.ROOT / "tools" / "ota_password"
    password = ((override.read_text(encoding="utf-8-sig").splitlines() or [""])[0] if override.exists()
                else ota_upload.config_value("ADMIN_PASSWORD"))
    auth = base64.b64encode(f"admin:{password}".encode()).decode()
    url = f"http://{host}:{port}/api/oui"
    req = urllib.request.Request(url, data=blob, method="POST", headers={
        "Authorization": f"Basic {auth}",
        "Content-Type": "application/octet-stream",
        "X-ShadowSentry": "1",
    })
    print(f"oui_upload: sending {len(blob)} bytes to {url}")
    try:
        with urllib.request.urlopen(req, timeout=180) as r:
            print("oui_upload:", r.status, r.read().decode().strip())
    except urllib.error.HTTPError as e:
        sys.exit(f"oui_upload: {e.code} {e.read().decode().strip()}")


if __name__ == "__main__":
    main()
