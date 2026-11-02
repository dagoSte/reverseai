"""Run an explicitly approved project suite against two programs in separate workspaces.

A JSON description contains folder, argv, timeout, format (tap or curl), and optional
tests. Paths in folder are relative to the description. argv substitutes {program}
and {workdir}; selected test IDs are appended as individual arguments. Suite code is
trusted executable code: a fresh copy and a minimal environment are not a sandbox.
"""

import json
import math
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time

OUTPUT_LIMIT = 1024 * 1024  # per stream, per side; exceeding it makes the run incomplete
MAX_TESTS = 100_000
STATES = frozenset({"pass", "fail", "skip", "missing"})


class SuiteError(ValueError):
    pass


def load(path):
    """Read and validate a suite description without starting anything."""
    path = Path(path).resolve()
    try:
        with path.open("rb") as handle:
            data = handle.read(64 * 1024 + 1)
        if len(data) > 64 * 1024:
            raise SuiteError("suite description is too large")
        spec = json.loads(data)
    except (OSError, UnicodeError, ValueError) as error:
        raise SuiteError(f"cannot read suite description: {error}") from error
    return _spec(spec, path.parent)


def _spec(spec, base=None):
    required = {"folder", "argv", "timeout", "format"}
    if not isinstance(spec, dict) or not required <= spec.keys() or spec.keys() - required - {"tests"}:
        raise SuiteError("suite needs folder, argv, timeout, format, and optional tests")
    folder, argv, timeout, format = (spec[key] for key in ("folder", "argv", "timeout", "format"))
    if not isinstance(folder, (str, Path)) or not str(folder):
        raise SuiteError("suite folder must name a directory")
    folder = ((Path.cwd() if base is None else base) / folder).resolve()
    if not folder.is_dir():
        raise SuiteError("suite folder does not exist")
    if (not isinstance(argv, list) or not argv or
            any(not isinstance(arg, str) or not arg or "\x00" in arg for arg in argv) or
            not any("{program}" in arg for arg in argv)):
        raise SuiteError("suite argv must be a list of arguments containing {program}")
    if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
        raise SuiteError("suite timeout must be a positive finite number")
    try:
        timeout = float(timeout)
    except OverflowError as error:
        raise SuiteError("suite timeout must be a positive finite number") from error
    if not math.isfinite(timeout) or timeout <= 0:
        raise SuiteError("suite timeout must be a positive finite number")
    if format not in ("tap", "curl"):
        raise SuiteError("unknown suite result format")
    tests = spec.get("tests", [])
    if (not isinstance(tests, list) or len(tests) > MAX_TESTS or
            any(not isinstance(test, str) or not re.fullmatch(r"[1-9][0-9]{0,8}", test) for test in tests) or
            len(set(tests)) != len(tests)):
        raise SuiteError("suite tests must be unique positive numeric IDs")
    return {"folder": str(folder), "argv": list(argv), "timeout": timeout, "format": format, "tests": list(tests)}


def _results(tests, expected, problems):
    for test in expected:
        if test not in tests:
            tests[test] = "missing"
            problems.append(f"missing result for test {test}")
    return {"tests": tests, "complete": not problems and bool(tests),
            "reason": "; ".join(dict.fromkeys(problems)) or ("" if tests else "no test results")}


def parse_tap(text, expected=()):
    """Parse flat TAP with a complete plan; diagnostics and YAML blocks carry no verdict."""
    tests, problems, plan, yaml, trailing_plan = {}, [], None, False, False
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "---":
            yaml = True
            continue
        if yaml:
            if stripped == "...":
                yaml = False
            continue
        if not stripped or stripped.startswith("#") or stripped == "TAP version 13":
            continue
        planned = re.fullmatch(r"1\.\.([0-9]{1,9})(?:\s+#.*)?", stripped)
        if planned:
            count = int(planned.group(1))
            if plan is not None or count > MAX_TESTS:
                problems.append("invalid or repeated TAP plan")
            else:
                plan = count
                trailing_plan = bool(tests)
            continue
        result = re.fullmatch(r"(not ok|ok)\b(?:\s+(.*))?", stripped)
        if result and not line[:1].isspace():
            tail = result.group(2) or ""
            numbered = re.match(r"([0-9]+)(?:\s|$)", tail)
            ident = numbered.group(1) if numbered else str(len(tests) + 1)
            if len(ident) > 9 or (tail[:1].isdigit() and not numbered):
                problems.append("invalid TAP test ID")
                continue
            if ident in tests or int(ident) != len(tests) + 1 or len(tests) >= MAX_TESTS or trailing_plan:
                problems.append("invalid or repeated TAP test ID")
                continue
            skipped = re.search(r"#\s*SKIP\b", stripped, re.I)
            tests[ident] = "skip" if skipped else "pass" if result.group(1) == "ok" else "fail"
        else:
            problems.append("unrecognised or nested TAP output")
    if yaml:
        problems.append("unterminated TAP diagnostics")
    if plan is None:
        problems.append("missing TAP plan")
    elif set(tests) != {str(i) for i in range(1, plan + 1)}:
        problems.append("TAP results do not match the plan")
        for ident in map(str, range(1, plan + 1)):
            tests.setdefault(ident, "missing")
    return _results(tests, expected, problems)


def parse_curl(text, expected=()):
    """Keep both sides' missing results until the official output grammar is available."""
    return _results({}, expected, ["missing or unrecognised curl test results"])


def compare(original, rebuilt):
    """Keep observed differences even when another test makes the run incomplete."""
    before, after = original["tests"], rebuilt["tests"]
    identifiers = sorted(before.keys() | after.keys(), key=lambda value: (int(value), value))
    if any(state not in STATES for state in [*before.values(), *after.values()]):
        raise SuiteError("unknown suite test state")
    regressions = [i for i in identifiers if before.get(i) == "pass" and after.get(i) != "pass"]
    improvements = [i for i in identifiers if before.get(i) == "fail" and after.get(i) == "pass"]
    both_fail = [i for i in identifiers if before.get(i) == after.get(i) == "fail"]
    missing = {"original": [i for i in identifiers if before.get(i, "missing") == "missing"],
               "rebuilt": [i for i in identifiers if after.get(i, "missing") == "missing"]}
    skips = {"original": [i for i in identifiers if before.get(i) == "skip"],
             "rebuilt": [i for i in identifiers if after.get(i) == "skip"]}
    checked = sum(state == "pass" for state in before.values())
    complete = bool(original["complete"] and rebuilt["complete"] and checked and not any(missing.values()))
    reason = ("; ".join(f"{side}: {result['reason']}" for side, result in
                        (("original", original), ("rebuilt", rebuilt)) if not result["complete"]) or
              ("missing results" if any(missing.values()) else "no passing baseline tests" if not checked else ""))
    return {"complete": complete, "passed": complete and not regressions, "reason": reason,
            "checked": checked, "regressions": regressions, "improvements": improvements,
            "both_fail": both_fail, "skips": skips, "missing": missing}


def _execute(argv, cwd, home, timeout):
    """Bound both streams; kill the owned process group on a deadline or output overflow."""
    buffers = [bytearray(), bytearray()]
    process, reason, code = None, "", None
    deadline = time.monotonic() + timeout
    try:
        process = subprocess.Popen(argv, cwd=cwd, env={"PATH": os.environ.get("PATH", os.defpath),
                                   "HOME": str(home), "LC_ALL": "C"}, stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=False,
                                   start_new_session=os.name == "posix")
        with selectors.DefaultSelector() as selector:
            for index, stream in enumerate((process.stdout, process.stderr)):
                selector.register(stream, selectors.EVENT_READ, index)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                ready = selector.select(max(0, remaining))
                if remaining <= 0 or not ready:
                    reason = "suite timed out"
                    break
                for key, _ in ready:
                    buffer = buffers[key.data]
                    chunk = os.read(key.fileobj.fileno(), min(65536, OUTPUT_LIMIT + 1 - len(buffer)))
                    if not chunk:
                        selector.unregister(key.fileobj)
                    elif len(buffer) + len(chunk) > OUTPUT_LIMIT:
                        buffer.extend(chunk[:OUTPUT_LIMIT - len(buffer)])
                        reason = "suite output limit exceeded"
                        break
                    else:
                        buffer.extend(chunk)
                if reason:
                    break
        if not reason:
            code = process.wait(timeout=max(0, deadline - time.monotonic()))
            if code not in (0, 1):
                reason = f"suite process exited with {code}"
    except subprocess.TimeoutExpired:
        reason = "suite timed out"
    except OSError as error:
        reason = f"suite could not run: {error}"
    finally:
        if process is not None:
            if code is None:
                try:
                    if os.name == "posix":
                        os.killpg(process.pid, signal.SIGKILL)
                    else:
                        process.kill()
                except ProcessLookupError:
                    pass
                code = process.wait()
            process.stdout.close()
            process.stderr.close()
    return buffers, code, reason


def run(spec, original, rebuilt, out, *, allowed=False):
    """Compare both sides only when the caller explicitly authorises execution."""
    if allowed is not True:
        raise SuiteError("suite execution requires explicit permission to run the original")
    spec = load(spec) if isinstance(spec, (str, Path)) else _spec(spec)
    programs = {side: Path(program).resolve() for side, program in (("original", original), ("rebuilt", rebuilt))}
    if any(not path.is_file() for path in programs.values()):
        raise SuiteError("both programs must exist")
    out = Path(out).resolve()
    if out.exists() and (not out.is_dir() or any(out.iterdir())):
        raise SuiteError("suite output directory must be new or empty")
    if Path(spec["folder"]) == out or Path(spec["folder"]) in out.parents:
        raise SuiteError("suite output must be outside the source suite")
    out.mkdir(parents=True, exist_ok=True)
    parser = parse_tap if spec["format"] == "tap" else parse_curl
    sides = {}
    for side, program in programs.items():
        with tempfile.TemporaryDirectory(prefix=f"hive-suite-{side}-") as temporary:
            root = Path(temporary).resolve()
            work = root / "work"
            shutil.copytree(spec["folder"], work)
            home = root / "home"
            home.mkdir()
            replacements = {"program": str(program), "workdir": str(work)}
            argv = [re.sub(r"\{(program|workdir)\}", lambda match: replacements[match.group(1)], arg)
                    for arg in spec["argv"]]
            argv += spec["tests"]
            buffers, code, error = _execute(argv, work, home, spec["timeout"])
            logs = {}
            for stream, data in zip(("stdout", "stderr"), buffers):
                path = out / f"{side}.{stream}.log"
                path.write_bytes(data)
                logs[stream] = str(path)
            result = parser(bytes(buffers[0]).decode("utf-8", errors="replace"), spec["tests"])
            if not error and code == 1 and "fail" not in result["tests"].values():
                error = "suite process exited with 1 without a reported failed test"
            if error:
                result["complete"] = False
                result["reason"] = "; ".join(filter(None, (error, result["reason"])))
            sides[side] = {**result, "returncode": code, "argv": argv, "logs": logs}
    result = {"ran": True, **compare(sides["original"], sides["rebuilt"]), **sides}
    (out / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    return result
