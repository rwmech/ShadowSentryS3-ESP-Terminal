#!/usr/bin/env python3
"""Precompress the dashboard's web assets for embedding (fork addition, alert-web).

main/index.html, main/device.html and main/analysis.js are written as
main/gz/<name>.gz (gzip level 9, mtime 0, so the output only changes when the
source does), and main/admin/web_assets.c serves them with
Content-Encoding: gzip. A .gz is rewritten only when its bytes change, so an
unchanged page does not trigger a rebuild.

Runs from three places:
  - main/CMakeLists.txt, at configure time (idf.py build); the sources are
    configure dependencies, so an edit re-runs it;
  - platformio.ini, as a pre: extra_script (every PlatformIO build);
  - by hand: python tools/gzip_assets.py
"""
import gzip
import io
import os
import sys

ASSETS = ("index.html", "device.html", "analysis.js")


def build(root):
    src_dir = os.path.join(root, "main")
    out_dir = os.path.join(src_dir, "gz")
    os.makedirs(out_dir, exist_ok=True)
    for name in ASSETS:
        with open(os.path.join(src_dir, name), "rb") as f:
            raw = f.read()
        buf = io.BytesIO()      # GzipFile, not gzip.compress(mtime=): Python 3.7 has no mtime there
        with gzip.GzipFile(filename="", mode="wb", compresslevel=9, fileobj=buf, mtime=0) as z:
            z.write(raw)
        gz = buf.getvalue()
        out = os.path.join(out_dir, name + ".gz")
        old = None
        if os.path.exists(out):
            with open(out, "rb") as f:
                old = f.read()
        if old != gz:
            with open(out, "wb") as f:
                f.write(gz)
        print("gzip_assets: %-12s %7d B -> %6d B (%d %%)%s"
              % (name, len(raw), len(gz), round(100 * len(gz) / max(1, len(raw))),
                 "" if old != gz else ", unchanged"))


try:
    Import("env")                                   # noqa: F821  PlatformIO (SCons) extra_script
    build(env.subst("$PROJECT_DIR"))                # noqa: F821
except NameError:
    if __name__ == "__main__":
        build(sys.argv[1] if len(sys.argv) > 1 else
              os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
