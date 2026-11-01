"""Keep the ELF of every OTA'd build, so a crash record can be decoded later.

Usage: python archive_elf.py [env] [dest]

Copies .pio/build/<env>/firmware.elf (env default crowpanel35_ota) to
<dest>/<git short hash>/firmware.elf, with elf_sha256.txt next to it (the
board's crash records carry the first 16 hex digits of that hash, and
tools/decode_crash.py <crash> <dest> picks the matching ELF by it).
With uncommitted changes the folder is <hash>-dirty. If the folder already
holds a different ELF, that one is kept as firmware-<its sha 8>.elf.

dest defaults to the "builds" folder beside the repository, or beside the
lanes folder for a lane worktree (lanes/<name>): for this project
Honeypot/builds either way.

Run it after each OTA build, before the upload.
"""
import hashlib
import pathlib
import shutil
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def git(*args):
    r = subprocess.run(["git", "-C", str(ROOT)] + list(args), capture_output=True, text=True, check=False)
    if r.returncode != 0:
        sys.exit(f"archive_elf: git {' '.join(args)} failed: {r.stderr.strip()}")
    return r.stdout.strip()


def main():
    args = sys.argv[1:]
    if len(args) > 2 or any(a in ("-h", "--help") for a in args):
        sys.exit(__doc__)
    env = args[0] if args else "crowpanel35_ota"
    if len(args) == 2:
        dest = pathlib.Path(args[1])
    else:
        base = ROOT.parent.parent if ROOT.parent.name == "lanes" else ROOT.parent
        dest = base / "builds"

    elf = ROOT / ".pio" / "build" / env / "firmware.elf"
    if not elf.is_file():
        sys.exit(f"archive_elf: {elf} not found; build {env} first")
    name = git("rev-parse", "--short", "HEAD")
    if git("status", "--porcelain", "--untracked-files=no"):
        name += "-dirty"
        print("archive_elf: uncommitted changes, archiving as " + name, file=sys.stderr)

    out = dest / name
    out.mkdir(parents=True, exist_ok=True)
    target = out / "firmware.elf"
    digest = sha256(elf)
    if target.is_file():
        old = sha256(target)
        if old == digest:
            print(f"{target} already holds this ELF (SHA256 {digest[:16]})")
            return
        keep = out / f"firmware-{old[:8]}.elf"
        target.replace(keep)
        print(f"kept the previous ELF as {keep}")
    shutil.copy2(elf, target)
    (out / "elf_sha256.txt").write_text(digest + "\n", encoding="ascii")
    print(f"{target}  (ELF SHA256 {digest[:16]})")


if __name__ == "__main__":
    main()
