"""Width of panel strings in the board's own LVGL Montserrat fonts.

Reads adv_w (1/16 px) per glyph from managed_components' lv_font_montserrat_NN.c
and the ASCII cmap (glyph id = code - 0x20 + 1), adds letter spacing, ignores
kerning (a few px at most). Usage: python -I fitcheck.py  (prints every check)
For the Waveshare 4.3B's scaled layout: python -I fitcheck.py --board waveshare43
(the board's fonts and the boxes at its width scale; see parse_args).
"""
import os
import re
import sys

FONTDIR = os.environ.get("SS_LVGL_FONTDIR") or \
    r"C:\Users\rwmec\Documents\Development\Honeypot\ShadowSentryS3\managed_components\lvgl__lvgl\src\font"
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
    # 07 SUBSYS and the about screen, about-boot.html (the terminal lines: key and
    # value together against the 452 px line, values cut with "..." past it)
    ("subsys btn", "SUBSYS", 12, 50, 0), ("subsys btn", "07", 12, 50, 0),
    ("ab bar", "SHADOWSENTRY | LOCAL SUBSYSTEM CTL", 12, 464, 1),
    ("ab title", "SUBSYSTEM INFO", 28, 356, 2), ("ab sub", "LOCAL ACCESS GRANTED", 14, 356, 0),
    ("ab sub", "SUBSYS ID = SENTRY S3 / 1BF46C5-DIRTY", 14, 356, 0),
    ("ab line", "UNIT = ELECROW CROWPANEL ESP32-S3 3.5 IN", 12, 452, 1),
    ("ab line", "BASE = SHADOWSENTRY S3 BY RDX1S (MIT)", 12, 452, 1),
    ("ab line", "FORK = ROBERT MECH | SHADOWSENTRYS3-ESP-TERMINAL", 12, 452, 1),
    ("ab line", "BUILD = 1BF46C5-DIRTY | 2026-11-03 | IDF 5.4.0", 12, 452, 1),
    ("ab line", "NODE = 192.168.100.118:9999 | UP 99 D 23 H", 12, 452, 1),
    ("ab line", "ACCESS CODE = 03-11-2026-0118-9999_", 12, 452, 1),
    ("ab btn", "RETURN", 12, 92, 0), ("ab btn", "55-21", 12, 58, 0), ("ab btn", "00-00", 12, 58, 0),
    ("splash", "SHADOWSENTRY S3", 12, 480, 4),
    # The clan skin, clan-panel.html (main/ui/ui_clan.c): header and nav
    ("cl title", "YAIM VIRD", 28, 242, 3), ("cl title 9", "IRON WARD", 28, 242, 3), ("cl title 16", "NORTH WATCH 0712", 20, 242, 2),
    ("cl sub", "SENTRY | 03 PERIMETER", 12, 242, 2), ("cl sub", "SENTRY | YELLOW ALERT", 12, 242, 2),
    ("cl status", "STATUS", 12, 90, 0), ("cl pill", "NOMINAL", 12, 66, 0), ("cl pill", "CAUTION", 12, 66, 0),
    ("cl pill", "HOSTILE", 12, 66, 0),
    ("cl nav", "PERIMETER", 12, 76, 0), ("cl nav", "TACTICAL", 12, 76, 0), ("cl nav", "CONTACTS", 12, 76, 0),
    ("cl nav", "SYSTEMS", 12, 76, 0), ("cl nav", "AUTO", 12, 76, 0),
    # TACTICAL: the holo plate, the side plates (name x 7..73, value x 76..129), events
    ("cl tac", "TACTICAL HOLOMAP", 12, 208, 1), ("cl legend", "FRIENDLY", 12, 64, 0), ("cl legend", "HOSTILE", 12, 64, 0),
    ("cl legend n", "48", 14, 64, 0),
    ("cl side", "SENSORS", 12, 67, 1), ("cl side", "SHIELDS", 12, 67, 1), ("cl side", "POWER", 12, 67, 1),
    ("cl side v", "100 %", 14, 54, 0), ("cl side v", "128 KB", 14, 54, 0),
    ("cl side k", "PI-HOLE BLOCKED", 12, 124, 0), ("cl side k", "PORTS WATCHED", 12, 124, 0),
    ("cl events", "EVENTS / ALERTS", 12, 340, 1),
    ("cl event", "40-02 RDP TRIPWIRE | 192.168.100.118 | 12:58 PM", 12, 340, 0),
]

def parse_args(argv):
    """--fonts 12=18,14=20,... maps each grid size to the board's font;
    --sx scales the box widths, --ss the letter spacing (main/ui/ui_scale.h).
    --board waveshare43 is --fonts 12=18,14=20,20=30,28=42,48=48 --sx 800/480 --ss 480/320."""
    fonts, sx, ss = {}, 1.0, 1.0
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--board" and i + 1 < len(argv) and argv[i + 1] == "waveshare43":
            fonts = {12: 18, 14: 20, 20: 30, 28: 42, 48: 48}
            sx, ss = 800 / 480, 480 / 320
            i += 2
        elif a == "--fonts" and i + 1 < len(argv):
            fonts = {int(k): int(v) for k, v in (p.split("=") for p in argv[i + 1].split(","))}
            i += 2
        elif a == "--sx" and i + 1 < len(argv):
            n, _, d = argv[i + 1].partition("/")
            sx = float(n) / float(d or 1)
            i += 2
        elif a == "--ss" and i + 1 < len(argv):
            n, _, d = argv[i + 1].partition("/")
            ss = float(n) / float(d or 1)
            i += 2
        else:
            sys.exit(f"unknown argument {a!r}; usage: fitcheck.py [--board waveshare43] "
                     "[--fonts 12=18,...] [--sx 800/480] [--ss 480/320]")
    return fonts, sx, ss


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8")
    fonts, sx, ss = parse_args(sys.argv[1:])
    bad = 0
    for where, text, size, box, ls in CHECKS:
        f = fonts.get(size, size)
        b = int(box * sx + 0.5)
        w = width(text, f, round(ls * ss))
        ok = w <= b
        bad += not ok
        print(f"{'ok ' if ok else 'OVER'} {where:12} {f:2}px {w:4}/{b:<4} {text}")
    print(f"{bad} over")
