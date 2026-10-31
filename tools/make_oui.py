"""Build the board's MAC vendor database (/sd/oui.bin) from the IEEE registry.

Usage:
  python tools/make_oui.py --download [-o oui.bin]
  python tools/make_oui.py oui.csv [mam.csv oui36.csv iab.csv] [-o oui.bin]

The IEEE Registration Authority publishes its assignments as CSV files:
  MA-L (24-bit)  https://standards-oui.ieee.org/oui/oui.csv
  MA-M (28-bit)  https://standards-oui.ieee.org/oui28/mam.csv
  MA-S (36-bit)  https://standards-oui.ieee.org/oui36/oui36.csv
  IAB  (36-bit)  https://standards-oui.ieee.org/iab/iab.csv
--download fetches them (TLS verified, standard library only). Or download
them with a browser and give their paths; the registry type is read from each
file. MA-L blocks the IEEE assigned onward as MA-M, MA-S or IAB are named
"IEEE Registration Authority" and are left out, so a lookup falls through to
the specific block or to nothing.

Output, little-endian (main/storage/oui.h has the reader):
  header 24 B   "SSOU", u16 version 1, u16 record size 12, u32 count,
                u32 build time (unix), u32 string table offset, u32 its length
  records       count x { u8 prefix[6], u8 bits (24/28/36), u8 0, u32 name offset },
                sorted by (prefix, bits)
  strings       NUL-terminated names, deduplicated, ASCII, at most 40 characters

Then upload it: python tools/oui_upload.py oui.bin <host>, or the Settings
page's "Update vendor database".
"""
import argparse
import csv
import io
import pathlib
import re
import ssl
import struct
import sys
import time
import unicodedata
import urllib.request

URLS = [
    "https://standards-oui.ieee.org/oui/oui.csv",
    "https://standards-oui.ieee.org/oui28/mam.csv",
    "https://standards-oui.ieee.org/oui36/oui36.csv",
    "https://standards-oui.ieee.org/iab/iab.csv",
]
BITS = {"MA-L": 24, "MA-M": 28, "MA-S": 36, "IAB": 36}
HEX_LEN = {24: 6, 28: 7, 36: 9}
NAME_MAX = 40
MAX_BYTES = 4 * 1024 * 1024
SUFFIX = re.compile(
    r"[\s,.]*\b(inc|incorporated|corp|corporation|co|company|ltd|limited|llc|l\.l\.c|gmbh|ag|s\.?a|"
    r"b\.?v|n\.?v|s\.?r\.?l|s\.?p\.?a|oy|ab|as|a/s|pty|plc|k\.?k|kk|pte|bhd|sdn|srl)\b[.,\s]*$",
    re.I)


def clean_name(raw):
    s = unicodedata.normalize("NFKD", raw)
    s = s.encode("ascii", "ignore").decode("ascii")
    s = re.sub(r"\s+", " ", s).strip(" ,.")
    for _ in range(4):                       # "Foo Co., Ltd." -> "Foo"
        t = SUFFIX.sub("", s).strip(" ,.")
        if t == s or not t:
            break
        s = t
    if len(s) > NAME_MAX:                    # at a word boundary
        cut = s.rfind(" ", 0, NAME_MAX + 1)
        s = s[:cut if cut > NAME_MAX // 2 else NAME_MAX].rstrip(" ,.")
    return s


def read_csv(text):
    rows = []
    for r in csv.DictReader(io.StringIO(text)):
        reg = (r.get("Registry") or "").strip()
        bits = BITS.get(reg)
        hx = (r.get("Assignment") or "").strip().upper()
        org = (r.get("Organization Name") or "").strip()
        if not bits or not re.fullmatch(r"[0-9A-F]{%d}" % HEX_LEN[bits], hx) or not org:
            continue
        if bits == 24 and org.lower().startswith("ieee registration authority"):
            continue
        val = int(hx, 16) << (48 - len(hx) * 4)
        rows.append((val.to_bytes(6, "big"), bits, clean_name(org)))
    return rows


def fetch(url):
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": "ShadowSentry make_oui.py"})
    with urllib.request.urlopen(req, context=ctx, timeout=180) as r:
        return r.read().decode("utf-8", "replace")


def build(rows):
    best = {}
    for pfx, bits, name in rows:
        if name:
            best[(pfx, bits)] = name
    keys = sorted(best)
    names, offs, table = {}, [], bytearray()
    for k in keys:
        n = best[k]
        if n not in names:
            names[n] = len(table)
            table += n.encode("ascii") + b"\0"
        offs.append(names[n])
    count = len(keys)
    str_off = 24 + 12 * count
    out = bytearray(b"SSOU" + struct.pack("<HHIIII", 1, 12, count, int(time.time()), str_off, len(table)))
    for (pfx, bits), off in zip(keys, offs):
        out += pfx + bytes([bits, 0]) + struct.pack("<I", off)
    out += table
    return bytes(out), count, len(names)


def lookup(blob, mac):
    """Reference lookup, the same search the board does (for a quick check)."""
    count, str_off = struct.unpack_from("<I", blob, 8)[0], struct.unpack_from("<I", blob, 16)[0]
    m = bytes.fromhex(mac.replace(":", "").replace("-", ""))
    if m[0] & 2:
        return "randomized (private)"
    for bits in (36, 28, 24):
        key = bytearray(m)
        key[5] = 0
        if bits == 36:
            key[4] &= 0xF0
        else:
            key[4] = 0
            key[3] = key[3] & 0xF0 if bits == 28 else 0
        lo, hi = 0, count
        while lo < hi:
            mid = (lo + hi) // 2
            rec = blob[24 + mid * 12: 36 + mid * 12]
            c = (rec[:6] > bytes(key)) - (rec[:6] < bytes(key)) or rec[6] - bits
            if c == 0:
                off = struct.unpack_from("<I", rec, 8)[0]
                end = blob.index(b"\0", str_off + off)
                return blob[str_off + off:end].decode("ascii")
            if c < 0:
                lo = mid + 1
            else:
                hi = mid
    return ""


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("csv", nargs="*", help="IEEE registry CSV files (oui.csv, mam.csv, oui36.csv, iab.csv)")
    ap.add_argument("--download", action="store_true", help="fetch the four CSVs from standards-oui.ieee.org")
    ap.add_argument("-o", "--out", default="oui.bin")
    ap.add_argument("--lookup", action="append", default=[], help="print the vendor of this MAC from the result")
    a = ap.parse_args()
    if not a.csv and not a.download:
        ap.error("give CSV files or --download")
    rows = []
    for p in a.csv:
        rows += read_csv(pathlib.Path(p).read_text(encoding="utf-8", errors="replace"))
    if a.download:
        for u in URLS:
            print(f"make_oui: fetching {u}")
            rows += read_csv(fetch(u))
    blob, count, distinct = build(rows)
    if len(blob) > MAX_BYTES:
        sys.exit(f"make_oui: {len(blob)} B is over the board's {MAX_BYTES} B limit")
    pathlib.Path(a.out).write_bytes(blob)
    print(f"make_oui: {a.out}: {count} prefixes, {distinct} vendor names, {len(blob)} B")
    for mac in a.lookup:
        print(f"make_oui: {mac} -> {lookup(blob, mac) or '(not found)'}")


if __name__ == "__main__":
    main()
