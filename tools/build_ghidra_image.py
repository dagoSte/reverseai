"""Build the pinned Ghidra worker image and write containers/ghidra/image.lock.json.

Usage (from the repository root):
    python3 -B tools/build_ghidra_image.py --download-dir DIR [--download] [--tag TAG] [--lock PATH]

Ghidra 12.1.4 and the Temurin JDK 21.0.12.1+1 (aarch64) are fetched on the host
(decision owner-m3-downloads) from their fixed GitHub release URLs, following
redirects only to GitHub's release-asset hosts over HTTPS, with a size cap and the
SHA-256 checked before a file is kept. The image is built from the digest-pinned
python:3.12-slim base: one internal "natives" stage installs Debian's g++ and make
(signed archive, pinned versions) to build the arm64 decompiler and demangler from
the release's own sources, and the final stage copies only /opt/jdk and /opt/ghidra
from it. The Dockerfile check allows exactly that shape: network for the natives
stage's one package step only, every other RUN --network=none. Every docker call
is an argv list; nothing goes through a shell.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "containers" / "ghidra"
PLATFORM = "linux/arm64"
BASE_DIGEST = "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e"
BASE = "python:3.12-slim@" + BASE_DIGEST
STAGE = "natives"
ADAPTER_VERSION = "12.1.4-r4"
CONTEXT_FILES = ("Dockerfile", "worker.py", "unpack.py", "ghidra_scripts")
ASSETS = {
    "ghidra": {
        "name": "ghidra_12.1.4_PUBLIC_20260921.zip",
        "url": "https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_12.1.4_build/"
               "ghidra_12.1.4_PUBLIC_20260921.zip",
        "sha256": "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db",
        "limit": 640 * 1024 * 1024,
    },
    "jdk": {
        "name": "OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.12.1_1.tar.gz",
        "url": "https://github.com/adoptium/temurin21-binaries/releases/download/jdk-21.0.12.1%2B1/"
               "OpenJDK21U-jdk_aarch64_linux_hotspot_21.0.12.1_1.tar.gz",
        "sha256": "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223",
        "limit": 256 * 1024 * 1024,
    },
}
FIRST_HOST = "github.com"
REDIRECT_HOSTS = ("release-assets.githubusercontent.com", "objects.githubusercontent.com")
MAX_REDIRECTS = 2
CHUNK = 1024 * 1024


def logical_instructions(text):
    """Logical instructions as BuildKit reads them: a line ending in exactly one backslash (then only spaces or tabs)
    continues on the next one, comment and empty lines inside a continuation are skipped, and nothing is inserted at
    the join (A\\ then DD is ADD). A run of two or more trailing backslashes ends its instruction: measured natively
    with buildx v0.37.2 for runs of 1 to 5 (M3B-W). Lines are split on LF only: the caller has refused every other
    control byte."""
    joined, current = [], None
    for line in text.split("\n"):
        if current is None:
            line = line.lstrip(" \t")
            if not line or line.startswith("#"):
                continue
            current = ""
        elif not line.strip(" \t") or line.lstrip(" \t").startswith("#"):
            continue
        end = re.search(r"(\\+)[ \t]*$", line)
        if end and len(end.group(1)) == 1:
            current += line[:end.end(1) - 1]
        else:
            joined.append(current + line)
            current = None
    if current is not None:
        joined.append(current)
    return [words for words in (line.split() for line in joined) if words]


def check_dockerfile(path):
    """The lock records BASE_DIGEST, so the Dockerfile must build from exactly BASE and nothing else: ASCII without
    control bytes, FROM BASE AS natives then FROM BASE, COPY --from=natives of /opt/jdk and /opt/ghidra as the only
    cross-stage reads, no ADD, no RUN --mount from another image or stage, no parser directive, network for one
    natives RUN only (every other RUN starts --network=none) and exactly one line USER 65534:65534. Continuations
    are joined first and instructions are counted case-insensitively, so neither hides one."""
    raw = path.read_bytes()
    if not raw.isascii() or re.search(rb"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]|\r(?!\n)", raw):
        raise SystemExit("Dockerfile must be ASCII without control bytes (tab, LF and CRLF only)")
    text = raw.decode("ascii").replace("\r\n", "\n")
    lines = [line.strip(" \t") for line in text.split("\n") if line.strip(" \t")]
    instructions = logical_instructions(text)
    if [words for words in instructions if words[0].upper() == "FROM"] != [["FROM", BASE, "AS", STAGE], ["FROM", BASE]]:
        raise SystemExit("Dockerfile FROM differs from the pinned base " + BASE + " (one natives stage, then the image)")
    if any(re.match(r"#\s*\w+\s*=", line) for line in lines):
        raise SystemExit("Dockerfile parser directives are refused")
    if any(words[0].upper() == "ADD" for words in instructions):
        raise SystemExit("Dockerfile ADD is refused")
    for words in instructions:
        for flag in (word.lower() for word in words if word.startswith("--")):
            if flag.startswith("--from") and not (words[0].upper() == "COPY" and flag == "--from=" + STAGE):
                raise SystemExit("Dockerfile reads from another image or stage")
            if flag.startswith("--mount") and "from=" in flag:
                raise SystemExit("Dockerfile reads from another image or stage")
    copies = [words for words in instructions if any(word.lower().startswith("--from") for word in words)]
    if copies != [["COPY", "--from=" + STAGE, path, path] for path in ("/opt/jdk", "/opt/ghidra")]:
        raise SystemExit("Dockerfile may copy only /opt/jdk and /opt/ghidra from the natives stage")
    stage, networked = 0, []
    for words in instructions:
        if words[0].upper() == "FROM":
            stage += 1
        elif words[0].upper() == "RUN" and (len(words) < 2 or words[1].lower() != "--network=none"):
            networked.append(stage)
    if networked != [1]:
        raise SystemExit("Dockerfile may use the network in one natives RUN only")
    if [words for words in instructions if words[0].upper() == "USER"] != [["USER", "65534:65534"]]:
        raise SystemExit("Dockerfile must have exactly one USER 65534:65534")


class ReleaseAssetRedirects(urllib.request.HTTPRedirectHandler):
    """Follow at most MAX_REDIRECTS hops, each to an HTTPS GitHub release-asset host on the default port."""
    max_redirections = MAX_REDIRECTS

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        target = urllib.parse.urlsplit(newurl)
        if (target.scheme != "https" or target.hostname not in REDIRECT_HOSTS or target.port not in (None, 443)
                or target.username or target.password):
            raise SystemExit("a download redirected outside the GitHub release-asset hosts")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        while chunk := stream.read(CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def fetch(asset, folder):
    """Download one pinned asset into folder; nothing is kept unless its size and SHA-256 are the pinned ones."""
    first = urllib.parse.urlsplit(asset["url"])
    if first.scheme != "https" or first.hostname != FIRST_HOST or first.port is not None or not first.path.endswith("/" + asset["name"]):
        raise SystemExit("a download URL is not its pinned GitHub release URL")
    target = Path(folder) / asset["name"]
    partial = target.with_name(target.name + ".partial")
    digest, size = hashlib.sha256(), 0
    try:
        with urllib.request.build_opener(ReleaseAssetRedirects).open(asset["url"], timeout=60) as response, \
                open(partial, "xb") as stream:
            while chunk := response.read(CHUNK):
                size += len(chunk)
                if size > asset["limit"]:
                    raise SystemExit("a download is larger than its size cap")
                digest.update(chunk)
                stream.write(chunk)
        if digest.hexdigest() != asset["sha256"]:
            raise SystemExit("a download does not match its pinned SHA-256")
        os.replace(partial, target)
    finally:
        partial.unlink(missing_ok=True)
    return target


def docker(*args, capture=False):
    result = subprocess.run(["docker", *args], check=True, text=True, capture_output=capture)
    return result.stdout.strip() if capture else None


def place(source, target):
    """Hard-link a verified download into the build context, or copy it when the link is not possible."""
    try:
        os.link(source, target)
    except OSError:
        shutil.copy2(source, target)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--download-dir", type=Path, required=True, help="Private directory holding the pinned downloads")
    parser.add_argument("--download", action="store_true", help="Fetch a pinned file into --download-dir if it is missing")
    parser.add_argument("--tag", default="reverseai-ghidra:" + ADAPTER_VERSION)
    parser.add_argument("--lock", type=Path, default=SOURCE / "image.lock.json")
    args = parser.parse_args(argv)

    check_dockerfile(SOURCE / "Dockerfile")
    files = {}
    for key, asset in ASSETS.items():
        path = args.download_dir / asset["name"]
        if not path.is_file():
            if not args.download:
                raise SystemExit(f"missing {asset['name']} in --download-dir (or pass --download)")
            args.download_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
            fetch(asset, args.download_dir)
        if path.stat().st_size > asset["limit"] or file_sha256(path) != asset["sha256"]:
            raise SystemExit(f"{asset['name']} does not match its pinned SHA-256")
        files[key] = path

    docker("pull", "--platform", PLATFORM, BASE)
    with tempfile.TemporaryDirectory(prefix="reverseai-ghidra-build-") as temporary:
        context = Path(temporary)
        for name in CONTEXT_FILES:
            source = SOURCE / name
            (shutil.copytree if source.is_dir() else shutil.copy2)(source, context / name)
        (context / "downloads").mkdir()
        for path in files.values():
            place(path, context / "downloads" / path.name)
        iidfile = context / "image.id"
        docker("build", "--platform", PLATFORM, "--pull=false", "--iidfile", str(iidfile), "--tag", args.tag, str(context))
        image_id = iidfile.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise SystemExit("docker build returned no image ID")
    lock = {"adapter_version": ADAPTER_VERSION, "base_digest": BASE_DIGEST, "ghidra_sha256": ASSETS["ghidra"]["sha256"],
            "image_id": image_id, "jdk_sha256": ASSETS["jdk"]["sha256"], "platform": PLATFORM}
    text = json.dumps(lock, indent=2, sort_keys=True) + "\n"
    args.lock.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
