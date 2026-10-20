"""Natives-stage helper: check a pinned download's SHA-256, then unpack the Ghidra zip keeping its exec bits.

    python3 -I -B unpack.py check <file> <sha256>
    python3 -I -B unpack.py ghidra <zip> <sha256> <destination>

Members must stay inside the destination; links and absolute or parent paths are refused.
"""

import hashlib
import os
from pathlib import Path
import shutil
import stat
import sys
import zipfile


def check(path, expected):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(1 << 20):
            digest.update(chunk)
    if digest.hexdigest() != expected:
        raise SystemExit("download does not match its pinned SHA-256")


def unpack(archive, destination):
    root = Path(destination).resolve()
    with zipfile.ZipFile(archive) as bundle:
        for info in bundle.infolist():
            mode = info.external_attr >> 16
            target = (root / info.filename).resolve()
            if stat.S_ISLNK(mode) or root not in target.parents:
                raise SystemExit("unsafe member in the archive")
            if info.is_dir():
                target.mkdir(parents=True, exist_ok=True)
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            with bundle.open(info) as source, open(target, "xb") as out:
                shutil.copyfileobj(source, out)
            os.chmod(target, 0o755 if mode & 0o111 else 0o644)


def main(argv):
    if len(argv) == 3 and argv[0] == "check":
        check(argv[1], argv[2])
    elif len(argv) == 4 and argv[0] == "ghidra":
        check(argv[1], argv[2])
        unpack(argv[1], argv[3])
    else:
        raise SystemExit("usage: unpack.py check FILE SHA256 | ghidra ZIP SHA256 DESTINATION")


if __name__ == "__main__":
    main(sys.argv[1:])
