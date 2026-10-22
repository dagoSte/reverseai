"""Prove one commit on Linux arm64: the whole suite, then its wheel built, installed offline and run.

Usage (from the repository root, with docker-desktop reserved):
    python3 -B tools/linux_proof.py --commit REV --receipt NEW_FILE

Nothing is pulled or downloaded. The digest-pinned python:3.12-slim base must already be present locally. The
commit's Git-tracked files (git archive, no host mount) are added to a throwaway image FROM that base, with no RUN
step; the container runs as 65534:65534 with the network off, a read-only root, every capability dropped and a tmpfs
at /tmp. Inside, this file runs again with --inside from the archived copy: the whole suite on the read-only tree,
then pip builds the wheel from a copy in /tmp (pip wheel --no-index, no sdist), a fresh venv installs it with
--no-index, and the installed reverseai answers --version, doctor --json and one analyze of a code-built ELF. The
inside run prints one marker line of JSON; the host writes the receipt (Python version, platform, commit, counts,
base digest) and removes its image and container whatever the outcome. Every command is an argv list; nothing goes
through a shell.
"""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
PLATFORM = "linux/arm64"
BASE_DIGEST = "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e"
BASE = "python:3.12-slim@" + BASE_DIGEST
SOURCE = "/opt/src"
MARKER = "REVERSEAI-LINUX-PROOF "
DOCKERFILE = (f"FROM {BASE}\n"
              "ADD source.tar /opt/\n"
              "USER 65534:65534\n"
              f"WORKDIR {SOURCE}\n"
              f'ENTRYPOINT ["python3", "-B", "{SOURCE}/tools/linux_proof.py", "--inside"]\n')
DOCKER_SECONDS = 120
RUN_SECONDS = 1800
SUITE_SECONDS = 1200
STEP_SECONDS = 300
TAIL_LINES = 40
# Writes the code-built ELF with imports (tests/fixtures_structure.py) to the path in argv[1]; inert bytes, never run.
FIXTURE = ("import sys\nfrom tests import fixtures_structure as F\n"
           "open(sys.argv[1], 'xb').write(F.elf_imports()[0])\n")


def run(argv, *, timeout, cwd=None, env=None):
    """(exit code, stdout, stderr) of one argv; a timeout gives exit code None."""
    try:
        done = subprocess.run(argv, cwd=cwd, env=env, stdin=subprocess.DEVNULL, capture_output=True, text=True,
                              errors="replace", timeout=timeout, shell=False)
    except subprocess.TimeoutExpired as expired:
        return None, expired.stdout or "", expired.stderr or ""
    return done.returncode, done.stdout, done.stderr


def tail(text, lines=TAIL_LINES):
    return (text if isinstance(text, str) else text.decode("utf-8", "replace")).splitlines()[-lines:]


def suite_counts(stderr):
    """Counts from unittest's closing lines: {"ran", "skipped", "failures", "errors", "ok"}, or None."""
    ran = re.findall(r"^Ran (\d+) tests? in ", stderr, re.M)
    last = stderr.rstrip().splitlines()[-1] if stderr.strip() else ""
    status = re.fullmatch(r"(OK|FAILED)(?: \(([^)]*)\))?", last)
    if not ran or status is None:
        return None
    counts = {"ran": int(ran[-1]), "skipped": 0, "failures": 0, "errors": 0, "expected_failures": 0,
              "unexpected_successes": 0}
    for item in filter(None, (status.group(2) or "").split(", ")):
        key, _, value = item.partition("=")
        key = key.replace(" ", "_")
        if key not in counts or not value.isdigit():
            return None
        counts[key] = int(value)
    counts["ok"] = status.group(1) == "OK"
    return counts


# --- inside the container -------------------------------------------------------------------------------------------

def inside(runner=run, work=Path("/tmp"), source=Path(SOURCE)):
    """Run every step inside the container; return the facts the host writes into the receipt."""
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": str(work / "home"), "LANG": "C.UTF-8",
           "PIP_NO_CACHE_DIR": "1", "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_INPUT": "1",
           "PYTHONDONTWRITEBYTECODE": "1"}
    (work / "home").mkdir(exist_ok=True)
    facts = {"python": platform.python_version(), "platform": platform.platform(), "machine": platform.machine(),
             "uid": os.getuid(), "steps": {}}
    steps = facts["steps"]

    def step(name, argv, *, timeout=STEP_SECONDS, cwd=None):
        code, out, err = runner(argv, timeout=timeout, cwd=cwd, env=env)
        steps[name] = {"exit": code, "stdout": tail(out), "stderr": tail(err)}
        return code, out, err

    code, _, err = step("suite", [sys.executable, "-B", "-m", "unittest", "discover", "-s", "tests", "-t", "."],
                        timeout=SUITE_SECONDS, cwd=source)
    facts["suite"] = suite_counts(err)
    steps["suite"]["failed_tests"] = [line for line in err.splitlines() if line.startswith(("FAIL: ", "ERROR: "))][:50]
    build, dist, venv, scratch = work / "build", work / "dist", work / "venv", work / "run"
    shutil.copytree(source, build, symlinks=True)
    scratch.mkdir()
    code, _, _ = step("wheel", [sys.executable, "-m", "pip", "wheel", "--no-index", "--no-deps", "--wheel-dir",
                                str(dist), str(build)])
    wheels = sorted(dist.glob("reverseai-*-py3-none-any.whl")) if code == 0 else []
    if len(wheels) != 1:
        facts["wheel"] = None
        return facts
    data = wheels[0].read_bytes()
    facts["wheel"] = {"name": wheels[0].name, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()}
    if step("venv", [sys.executable, "-m", "venv", str(venv)])[0] != 0:
        return facts
    if step("install", [str(venv / "bin/python"), "-m", "pip", "install", "--no-index", "--no-deps",
                        str(wheels[0])])[0] != 0:
        return facts
    reverseai = str(venv / "bin/reverseai")
    code, out, _ = step("version", [reverseai, "--version"], cwd=scratch)
    facts["version"] = out.strip() if code == 0 else None
    code, out, _ = step("imported_from", [str(venv / "bin/python"), "-I", "-c",
                                          "import reverseai; print(reverseai.__file__)"], cwd=scratch)
    facts["imported_from"] = out.strip() if code == 0 else None
    code, out, _ = step("doctor", [reverseai, "doctor", "--json"], cwd=scratch)
    try:
        facts["doctor"] = json.loads(out) if code == 0 else None
    except ValueError:
        facts["doctor"] = None
    sample, report = scratch / "input.elf", scratch / "report"
    if step("fixture", [sys.executable, "-B", "-c", FIXTURE, str(sample)], cwd=source)[0] != 0:
        return facts
    code, out, _ = step("analyze", [reverseai, "analyze", str(sample), "--out", str(report)], cwd=scratch)
    if code == 0:
        document = json.loads((report / "report.json").read_text(encoding="utf-8"))
        facts["analyze"] = {"input_sha256": document["input"]["sha256"], "summary": document["summary"],
                            "reports": sorted(path.name for path in report.iterdir())}
    return facts


# --- on the host ----------------------------------------------------------------------------------------------------

def build_argv(context, iidfile, tag):
    return ["docker", "build", "--platform", PLATFORM, "--pull=false", "--network=none", "--iidfile", str(iidfile),
            "--tag", tag, str(context)]


def run_argv(image_id, name):
    return ["docker", "run", "--rm", "--init", "--pull", "never", "--name", name, "--platform", PLATFORM,
            "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65534:65534", "--pids-limit", "1024", "--memory", "4g", "--memory-swap", "4g",
            "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=2g", image_id]


def remove_argv(image_id):
    return ["docker", "image", "rm", "--no-prune", image_id]


def marker_facts(stdout):
    lines = [line for line in stdout.splitlines() if line.startswith(MARKER)]
    if len(lines) != 1:
        raise ValueError("the container printed no single proof marker")
    facts = json.loads(lines[0][len(MARKER):])
    if not isinstance(facts, dict):
        raise ValueError("the proof marker is not an object")
    return facts


def passed(facts, version):
    suite, doctor, analyze = facts.get("suite"), facts.get("doctor"), facts.get("analyze")
    return bool(suite and suite["ok"] and suite["failures"] == suite["errors"] == 0
                and facts.get("wheel") and facts.get("version") == "reverseai " + version
                and str(facts.get("imported_from", "")).startswith("/tmp/venv/")
                and doctor and doctor.get("host_ok") is True and doctor.get("reverseai") == version
                and len(doctor.get("tools", ())) == 5
                and all(tool["lock_loads"] and tool["lock"].startswith("/tmp/venv/") for tool in doctor["tools"])
                and analyze and analyze["reports"] == ["report.json", "report.md"])


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def prove(commit, receipt, runner=run):
    """Build, run and remove the throwaway image; write the receipt; return 0 only when every step passed."""
    code, out, _ = runner(["git", "-C", str(ROOT), "rev-parse", "--verify", commit + "^{commit}"], timeout=30)
    if code != 0 or not re.fullmatch(r"[0-9a-f]{40}", out.strip()):
        raise SystemExit("the commit does not resolve in this repository")
    commit = out.strip()
    if runner(["docker", "image", "inspect", "--format", "{{.Id}}", BASE], timeout=30)[0] != 0:
        raise SystemExit("the pinned base " + BASE + " is not present locally; this tool never pulls")
    started, image_id, facts, error = utc(), None, None, None
    name = "reverseai-linux-proof-" + uuid.uuid4().hex[:16]
    try:
        with tempfile.TemporaryDirectory(prefix="reverseai-linux-proof-") as temporary:
            context = Path(temporary)
            archive = context / "source.tar"
            if runner(["git", "-C", str(ROOT), "archive", "--format=tar", "--prefix=src/", "-o", str(archive),
                       commit], timeout=120)[0] != 0:
                raise SystemExit("git archive failed")
            code, out, _ = runner(["git", "-C", str(ROOT), "show", commit + ":reverseai/__init__.py"], timeout=30)
            version = re.search(r'^__version__ = "([^"]+)"$', out, re.M) if code == 0 else None
            if version is None:
                raise SystemExit("the commit names no reverseai.__version__")
            version = version.group(1)
            (context / "Dockerfile").write_text(DOCKERFILE, encoding="ascii")
            iidfile = context / "image.id"
            code, _, err = runner(build_argv(context, iidfile, "reverseai-linux-proof:" + commit[:12]),
                                  timeout=DOCKER_SECONDS)
            if code == 0 and iidfile.exists():
                image_id = iidfile.read_text(encoding="ascii").strip()
            if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id or ""):
                raise SystemExit("docker build failed: " + " | ".join(tail(err, 5)))
        code, out, err = runner(run_argv(image_id, name), timeout=RUN_SECONDS)
        if code is None:
            runner(["docker", "kill", name], timeout=30)
            error = "the container did not finish within the time limit"
        else:
            try:
                facts = marker_facts(out)
            except ValueError as problem:
                error = f"{problem}; exit {code}: " + " | ".join(tail(err, 5))
    finally:
        removed = image_id is None or runner(remove_argv(image_id), timeout=DOCKER_SECONDS)[0] == 0
        gone = image_id is None or runner(["docker", "image", "inspect", "--format", "{{.Id}}", image_id],
                                          timeout=30)[0] != 0
    ok = error is None and facts is not None and passed(facts, version) and removed and gone
    document = {"commit": commit, "platform": PLATFORM, "base": BASE, "base_digest": BASE_DIGEST,
                "expected_version": version, "image_id": image_id, "image_removed": removed and gone,
                "container": name, "started": started, "ended": utc(), "passed": ok, "error": error,
                "inside": facts}
    with open(receipt, "x", encoding="utf-8") as stream:
        stream.write(json.dumps(document, indent=2, sort_keys=True) + "\n")
    suite = (facts or {}).get("suite") or {}
    print(f"{'passed' if ok else 'FAILED'}: {commit[:12]} on {PLATFORM}, Python {(facts or {}).get('python')}, "
          f"{suite.get('ran')} tests ({suite.get('skipped')} skipped), image removed: {removed and gone}")
    return 0 if ok else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--inside", action="store_true", help=argparse.SUPPRESS)
    parser.add_argument("--commit", help="The candidate commit or tag")
    parser.add_argument("--receipt", type=Path, help="A new file for the JSON receipt")
    args = parser.parse_args(argv)
    if args.inside:
        print(MARKER + json.dumps(inside(), sort_keys=True))
        return 0
    if not args.commit or args.receipt is None:
        parser.error("--commit and --receipt are required")
    if args.receipt.exists() or args.receipt.is_symlink():
        parser.error("--receipt must name a new file")
    return prove(args.commit, args.receipt)


if __name__ == "__main__":
    sys.exit(main())
