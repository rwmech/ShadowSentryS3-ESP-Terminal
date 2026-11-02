"""Width of panel strings in the board's own LVGL Montserrat fonts.

Reads adv_w (1/16 px) per glyph from managed_components' lv_font_montserrat_NN.c
and the ASCII cmap (glyph id = code - 0x20 + 1), adds letter spacing, ignores
kerning (a few px at most). Usage: python -I fitcheck.py  (prints every check)
"""
import re
import sys

FONTDIR = r"C:\Users\rwmec\Documents\Development\Honeypot\ShadowSentryS3\managed_components\lvgl__lvgl\src\font"
_cache = {}


def adv(size):
    if size not in _cache:
        src = open(rf"{FONTDIR}\lv_font_montserrat_{size}.c", encoding="utf-8").read()
        body = src.split("glyph_dsc[] = {", 1)[1].split("};", 1)[0]
        _cache[size] = [int(x) for x in re.findall(r"\.adv_w\s*=\s*(\d+)", body)]
    return _cache[size]


def width(text, size, ls=0):
    a = adv(size)
    w = 0
    for ch in text:
        c = ord(ch)
        if c == 0xB7:          # middle dot, not in the ASCII range: count it as '.'
            c = ord(".")
        if c < 0x20 or c > 0x7E:
            raise ValueError(f"no glyph for {ch!r}")
        w += a[c - 0x20 + 1] / 16 + ls
    return round(w - ls) if text else 0


# (where, text, font size, box width px, letter spacing): mockup v3, lcars-panel.html
CHECKS = [
    ("title", "SHADOWSENTRY | 03 TRIPWIRES", 14, 258, 0), ("title", "SHADOWSENTRY | YELLOW ALERT", 14, 258, 0),
    ("rail", "WIRES", 12, 48, 0), ("rail", "TRAPS", 12, 48, 0), ("clock", "10:44 PM", 12, 60, 0), ("auto", "AUTO", 12, 36, 0),
    ("cond", "CONDITION GREEN | 35 PORTS WATCHED", 12, 380, 0), ("pill", "DEVICES", 12, 60, 0),
    ("tile sub", "41 TOTAL", 12, 72, 0), ("tile value", "999", 28, 72, 0), ("port", "56700", 12, 45, 0),
    ("chart", "EVENTS PER HOUR, 24 H", 12, 300, 0),
    ("focus", "40-02 RDP TRIPWIRE | 192.168.0.75 | 12:58 PM", 12, 288, 0),
    ("focus", "MOST BLOCKED | SHIELD | CONVIVA.COM", 12, 288, 0), ("focus", "BUSIEST | DELL LAPTOP | 1.2 GB DOWN", 12, 288, 0),
    ("trap tag", "WEB 8080 +2", 12, 126, 0), ("trap tag", "CAMERA RTSP 554", 12, 126, 0), ("trap tag", "SHELL SESSIONS", 12, 126, 0),
    ("trap n", "26", 14, 30, 0), ("trap last", "12:58 PM", 12, 56, 0),
    ("trap detail", "192.168.0.78 | POST /DOC/PAGE/LOGIN.ASP | GG / GY", 12, 388, 0),
    ("wire", "ROUTEROS API 8728", 12, 150, 0), ("wire", "ROUTER LOGIN FAIL", 12, 150, 0), ("wire", "MAC-TELNET 20561", 12, 150, 0),
    ("wire detail", "192.168.0.75 | SOLICITATION (WINBOX NEIGHBORS)", 12, 388, 0),
    ("gauge value", "-48 DBM", 14, 76, 0), ("gauge label", "FREE RAM", 12, 76, 0),
    ("net", "B0:A7:B9:40:AC:A2", 12, 128, 0), ("net", "POSTED 14 MIN AGO", 12, 128, 0),
    ("dev name", "GOOGLE NEST HUB", 14, 190, 0), ("dev sub", "192.168.0.150 | SILICONDUST", 12, 190, 0), ("dev q", "70 % BLOCKED", 12, 96, 0),
    ("dev detail", "CONVIVA.COM (VIDEO ANALYTICS)", 12, 400, 0), ("dev button", "BLOCK DEVICE", 14, 150, 0),
    ("log", "11:11 AM | 30-01 WEB LOGIN | HIKVISION 80 | 192.168.0.78", 12, 400, 0),
    ("emblem", "ALERT", 28, 146, 2), ("emblem", "CONDITION: YELLOW", 14, 200, 0),
    ("alert code", "CODE 30-01 WEB LOGIN ATTEMPT", 20, 400, 0), ("alert src", "192.168.0.75 | DELL INC. | DELL LAPTOP", 14, 400, 0),
    ("alert stat", "17-03 PROBE", 14, 129, 0),
    ("alert btn", "ACKNOWLEDGE", 14, 124, 0), ("alert btn", "IGNORE ERROR", 14, 118, 0), ("alert btn", "IGNORE DEVICE", 14, 122, 0),
]

if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    bad = 0
    for where, text, size, box, ls in CHECKS:
        w = width(text, size, ls)
        ok = w <= box
        bad += not ok
        print(f"{'ok ' if ok else 'OVER'} {where:12} {size:2}px {w:4}/{box:<4} {text}")
    print(f"{bad} over")
