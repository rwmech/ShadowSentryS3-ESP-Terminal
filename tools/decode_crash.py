"""Decode the PCs of a ShadowSentry crash record to function, file and line.

Usage: python decode_crash.py <crash> <firmware.elf | builds folder> [--addr2line PATH]

<crash> is one of:
  - a report file from the card (/sd/crash/<date>.txt) or the "latest" text of
    GET /api/crashes saved to a file
  - a summary line from /spiffs/crash.log, or the whole GET /api/crashes JSON
    saved to a file (the newest summary is decoded)
  - a file or a quoted string holding addresses, e.g. "0x4200abcd 0x40378a10"

The second argument is the firmware.elf of the build that crashed. Given a
folder (for example the builds folder tools/archive_elf.py fills), every
firmware.elf under it is checked and the one whose SHA256 starts with the
record's "elf" prefix is used. A given ELF whose hash does not match the
record is used anyway, with a warning: its line numbers may be wrong.

addr2line is taken from --addr2line, else PATH, else the PlatformIO
toolchains (xtensa-esp32s3-elf-addr2line, then xtensa-esp-elf-addr2line).
"""
import hashlib
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys

PIO_PACKAGES = pathlib.Path.home() / ".platformio" / "packages"
TOOL_NAMES = ("xtensa-esp32s3-elf-addr2line", "xtensa-esp-elf-addr2line")
ADDR = re.compile(r"0x[0-9a-fA-F]{8}")


def code_pc(v):
    """A code address as the panic handler prints it, or None. A return
    address with the window-call bits set (A0) is mapped the way IDF's
    esp_cpu_process_stack_pc() does."""
    if v & 0x80000000:
        v = (v & 0x3FFFFFFF) | 0x40000000
    return v if 0x40000000 <= v < 0x44000000 else None


def from_summary(obj):
    pcs, elf = [], obj.get("elf", "")
    for key in ("pc",):
        if obj.get(key):
            pcs.append(("PC", obj[key]))
    for a in ADDR.findall(str(obj.get("detail", ""))):
        pcs.append(("abort caller", a))
    for i, a in enumerate(ADDR.findall(str(obj.get("bt", "")))):
        pcs.append((f"bt {i}", a))
    return pcs, elf


def from_report(text):
    pcs, elf = [], ""
    for line in text.splitlines():
        head, _, rest = line.partition(":")
        head = head.strip()
        if head == "Firmware":
            m = re.search(r"ELF SHA256 ([0-9a-fA-F]+)", rest)
            elf = m.group(1) if m else elf
        elif head == "PC":
            pcs += [("PC", a) for a in ADDR.findall(rest)]
        elif head == "Detail":
            pcs += [("abort caller", a) for a in ADDR.findall(rest)]
        elif head == "A0":
            pcs += [("A0", a) for a in ADDR.findall(rest)[:1]]
        elif head == "Backtrace":
            pcs += [(f"bt {i}", a) for i, a in enumerate(ADDR.findall(rest))]
    return pcs, elf


def parse(arg):
    p = pathlib.Path(arg)
    text = p.read_text(encoding="utf-8", errors="replace") if p.is_file() else arg
    s = text.strip()
    if s.startswith("{"):
        try:
            obj = json.loads(s)
            if isinstance(obj.get("crashes"), list):
                if not obj["crashes"]:
                    sys.exit("decode_crash: no crash in that JSON")
                obj = obj["crashes"][-1]
            return from_summary(obj)
        except (json.JSONDecodeError, AttributeError):
            # crash.log: one summary a line, the newest last
            lines = [l for l in s.splitlines() if l.strip().startswith("{")]
            if lines:
                return from_summary(json.loads(lines[-1]))
    if "Backtrace:" in text or "\nPC:" in text:
        return from_report(text)
    return [(f"addr {i}", a) for i, a in enumerate(ADDR.findall(text))], ""


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def pick_elf(arg, prefix):
    p = pathlib.Path(arg)
    if p.is_dir():
        found = sorted(p.rglob("*.elf"))
        if not found:
            sys.exit(f"decode_crash: no .elf under {p}")
        if not prefix:
            sys.exit("decode_crash: the record has no ELF hash; name the firmware.elf itself")
        for e in found:
            if sha256(e).startswith(prefix.lower()):
                return e
        sys.exit(f"decode_crash: no ELF under {p} has SHA256 {prefix}...")
    if not p.is_file():
        sys.exit(f"decode_crash: {p} not found")
    if prefix and not sha256(p).startswith(prefix.lower()):
        print(f"warning: {p} is not the build that crashed (ELF SHA256 {sha256(p)[:16]}, "
              f"record {prefix}); lines may be wrong\n", file=sys.stderr)
    return p


def find_addr2line(override):
    if override:
        return override
    for name in TOOL_NAMES:
        hit = shutil.which(name)
        if hit:
            return hit
    exe = ".exe" if os.name == "nt" else ""
    for name in TOOL_NAMES:
        for d in sorted(PIO_PACKAGES.glob("toolchain-xtensa-esp*"), reverse=True):
            cand = d / "bin" / (name + exe)
            if cand.is_file():
                return str(cand)
    sys.exit("decode_crash: addr2line not found; pass --addr2line PATH")


def main():
    args = sys.argv[1:]
    tool = None
    if "--addr2line" in args:
        i = args.index("--addr2line")
        if i + 1 >= len(args):
            sys.exit(__doc__)
        tool = args[i + 1]
        del args[i:i + 2]
    if len(args) != 2:
        sys.exit(__doc__)

    pcs, prefix = parse(args[0])
    addrs = []
    for label, a in pcs:
        v = code_pc(int(a, 16))
        if v is not None:
            addrs.append((label, v))
    if not addrs:
        sys.exit("decode_crash: no code address found")
    elf = pick_elf(args[1], prefix)
    tool = find_addr2line(tool)
    print(f"ELF: {elf}")
    out = subprocess.run([tool, "-e", str(elf), "-f", "-i", "-C", "-a"] + [f"0x{v:08x}" for _, v in addrs],
                         capture_output=True, text=True, check=False)
    if out.returncode != 0:
        sys.exit(f"decode_crash: addr2line failed: {out.stderr.strip()}")

    # -a -f -i: per address, the address line, then function and file:line
    # pairs (more than one pair when inlined).
    blocks, cur = [], None
    for line in out.stdout.splitlines():
        if re.fullmatch(r"0x[0-9a-fA-F]+", line.strip()):
            cur = []
            blocks.append(cur)
        elif cur is not None:
            cur.append(line.strip())
    for (label, v), b in zip(addrs, blocks):
        pairs = list(zip(b[0::2], b[1::2])) or [("??", "??:0")]
        for k, (fn, loc) in enumerate(pairs):
            lead = f"{label:>12}  0x{v:08x}" if k == 0 else f"{'':>12}  {'(inlined by)':>10}"
            print(f"{lead}  {fn}:{loc}")


if __name__ == "__main__":
    main()
