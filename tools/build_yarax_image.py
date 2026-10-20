"""Build the pinned YARA-X worker image and write containers/yarax/image.lock.json.

Usage (from the repository root):
    python3 -B tools/build_yarax_image.py --wheel-dir DIR [--download] [--tag TAG] [--lock PATH]

The base image is pulled by its linux/arm64 manifest digest (the same one as the LIEF
worker), and the Dockerfile must build FROM exactly that reference and nothing else.
The YARA-X wheel must be in DIR (or, with --download, is fetched from the single PyPI
URL below, refusing any redirect) and must match the SHA-256 in
containers/yarax/requirements.txt. The build itself runs with --network none and
installs only from that local wheel; the image compiles the reviewed ruleset once,
so a bad rule fails the build. The lock records the SHA-256 of the ruleset file
copied into the build. Every docker call is an argv list; nothing goes through a shell.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "containers" / "yarax"
PLATFORM = "linux/arm64"
BASE_DIGEST = "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e"
BASE = "python:3.12-slim@" + BASE_DIGEST
ADAPTER_VERSION = "1.21.0-r1"
RULESET = "m2_fixture_v1.json"
WHEEL = "yara_x-1.21.0-cp38-abi3-manylinux_2_28_aarch64.whl"
WHEEL_HOST = "https://files.pythonhosted.org/packages/"
WHEEL_URL = WHEEL_HOST + "9c/8e/63adf06593aff53180c7246f6b35c22ff9729705d1d31dd2e8a35a2e4643/" + WHEEL
WHEEL_BYTES_LIMIT = 16 * 1024 * 1024


def wheel_sha256():
    """The one hash pinned in requirements.txt."""
    pinned = re.findall(r"--hash=sha256:([0-9a-f]{64})", (SOURCE / "requirements.txt").read_text(encoding="utf-8"))
    if len(pinned) != 1:
        raise SystemExit("requirements.txt must pin exactly one SHA-256")
    return pinned[0]


def check_dockerfile(path):
    """The lock records BASE_DIGEST, so the Dockerfile must build from exactly BASE and nothing else: one FROM line,
    no COPY --from or RUN --mount ...from= (another image or stage), and no parser directive (# syntax=, # escape=)."""
    lines = [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
    instructions = [line.split() for line in lines if not line.startswith("#")]
    if [words for words in instructions if words[0].upper() == "FROM"] != [["FROM", BASE]]:
        raise SystemExit("Dockerfile FROM differs from the pinned base " + BASE)
    if any(re.match(r"#\s*\w+\s*=", line) for line in lines):
        raise SystemExit("Dockerfile parser directives are refused")
    flags = [word.lower() for words in instructions for word in words if word.startswith("--")]
    if any(flag.startswith("--from") or (flag.startswith("--mount") and "from=" in flag) for flag in flags):
        raise SystemExit("Dockerfile reads from another image or stage")


def file_sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


class RefuseRedirects(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise SystemExit("the wheel URL redirected; refusing to follow it")


def fetch_wheel(target, expected):
    # The one fixed HTTPS URL on PyPI's file host; any redirect is refused, so no other URL or host is ever requested.
    if not WHEEL_URL.startswith(WHEEL_HOST) or not WHEEL_URL.endswith("/" + WHEEL):
        raise SystemExit("the wheel URL is not the pinned PyPI file")
    with urllib.request.build_opener(RefuseRedirects).open(WHEEL_URL, timeout=60) as response:
        data = response.read(WHEEL_BYTES_LIMIT + 1)
    if len(data) > WHEEL_BYTES_LIMIT or hashlib.sha256(data).hexdigest() != expected:
        raise SystemExit("downloaded wheel does not match the pinned SHA-256")
    target.write_bytes(data)


def docker(*args, capture=False):
    result = subprocess.run(["docker", *args], check=True, text=True, capture_output=capture)
    return result.stdout.strip() if capture else None


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--wheel-dir", type=Path, required=True, help="Private directory holding the pinned YARA-X wheel")
    parser.add_argument("--download", action="store_true", help="Fetch the pinned wheel into --wheel-dir if it is missing")
    parser.add_argument("--tag", default="reverseai-yarax:" + ADAPTER_VERSION)
    parser.add_argument("--lock", type=Path, default=SOURCE / "image.lock.json")
    args = parser.parse_args(argv)

    check_dockerfile(SOURCE / "Dockerfile")
    expected = wheel_sha256()
    wheel = args.wheel_dir / WHEEL
    if not wheel.is_file():
        if not args.download:
            raise SystemExit(f"missing {WHEEL} in --wheel-dir (or pass --download)")
        args.wheel_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        fetch_wheel(wheel, expected)
    if file_sha256(wheel) != expected:
        raise SystemExit("wheel does not match the pinned SHA-256")

    docker("pull", "--platform", PLATFORM, BASE)
    with tempfile.TemporaryDirectory(prefix="reverseai-yarax-build-") as temporary:
        context = Path(temporary)
        for name in ("Dockerfile", "requirements.txt", "worker.py", RULESET):
            shutil.copy2(SOURCE / name, context / name)
        ruleset_sha256 = file_sha256(context / RULESET)  # the bytes the image copies
        (context / "wheels").mkdir()
        shutil.copy2(wheel, context / "wheels" / WHEEL)
        iidfile = context / "image.id"
        docker("build", "--platform", PLATFORM, "--network", "none", "--pull=false", "--iidfile", str(iidfile),
               "--tag", args.tag, str(context))
        image_id = iidfile.read_text(encoding="utf-8").strip()
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise SystemExit("docker build returned no image ID")
    lock = {"image_id": image_id, "platform": PLATFORM, "base_digest": BASE_DIGEST, "wheel_sha256": expected,
            "ruleset_sha256": ruleset_sha256, "adapter_version": ADAPTER_VERSION}
    text = json.dumps(lock, indent=2, sort_keys=True) + "\n"
    args.lock.write_text(text, encoding="utf-8")
    print(text, end="")
    return 0


if __name__ == "__main__":
    sys.exit(main())
