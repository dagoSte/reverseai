"""tools/linux_proof.py with stand-in git, Docker and pip; nothing here builds, runs or pulls an image."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("linux_proof", ROOT / "tools/linux_proof.py")
P = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(P)

COMMIT = "c" * 40
IMAGE = "sha256:" + "e" * 64
WHEEL = "reverseai-0.6.0-py3-none-any.whl"


def doctor_facts(version="0.6.0"):
    return {"reverseai": version, "host_ok": True, "docker": {"answered": False},
            "tools": [{"tool": name, "lock_loads": True,
                       "lock": f"/tmp/venv/lib/python3.12/site-packages/reverseai/_locks/{name}.json"}
                      for name in ("lief", "yarax", "ghidra", "jadx", "jsparser")]}


def inside_facts(**changes):
    facts = {"python": "3.12.9", "platform": "Linux-6.10-aarch64-with-glibc2.36", "machine": "aarch64", "uid": 65534,
             "suite": {"ran": 1750, "skipped": 1, "failures": 0, "errors": 0, "expected_failures": 0,
                       "unexpected_successes": 0, "ok": True},
             "wheel": {"name": WHEEL, "size": 1, "sha256": "0" * 64}, "version": "reverseai 0.6.0",
             "imported_from": "/tmp/venv/lib/python3.12/site-packages/reverseai/__init__.py",
             "doctor": doctor_facts(), "analyze": {"reports": ["report.json", "report.md"]}, "steps": {}}
    facts.update(changes)
    return facts


class HostDocker:
    """Stand-in for git and docker on the host; records every argv."""
    def __init__(self, base=True, run=None, removed=True):
        self.calls, self.base, self.removed = [], base, removed
        self.run = (0, "noise\n" + P.MARKER + json.dumps(inside_facts()) + "\n", "") if run is None else run

    def __call__(self, argv, *, timeout, cwd=None, env=None):
        self.calls.append(list(argv))
        if argv[:4] == ["git", "-C", str(P.ROOT), "rev-parse"]:
            return 0, COMMIT + "\n", ""
        if argv[:4] == ["git", "-C", str(P.ROOT), "archive"]:
            Path(argv[argv.index("-o") + 1]).write_bytes(b"tar")
            return 0, "", ""
        if argv[:4] == ["git", "-C", str(P.ROOT), "show"]:
            return 0, '"""ReverseAI."""\n\n__version__ = "0.6.0"\n', ""
        if argv[:5] == ["docker", "image", "inspect", "--format", "{{.Id}}"]:
            if argv[5] == P.BASE:
                return (0, "sha256:base\n", "") if self.base else (1, "", "No such image")
            return (1, "", "No such image") if self.removed else (0, IMAGE, "")
        if argv[:2] == ["docker", "build"]:
            Path(argv[argv.index("--iidfile") + 1]).write_text(IMAGE)
            return 0, "", ""
        if argv[:2] == ["docker", "run"]:
            return self.run
        if argv[:3] == ["docker", "image", "rm"] or argv[:2] == ["docker", "kill"]:
            return 0, "", ""
        raise AssertionError(f"unexpected argv {argv}")


class DockerfileAndArgvTests(unittest.TestCase):
    def test_the_image_is_the_pinned_base_plus_the_archive_with_no_run_step(self):
        lines = P.DOCKERFILE.splitlines()
        self.assertEqual(lines[0], "FROM " + P.BASE)
        self.assertEqual(lines[1:3], ["ADD source.tar /opt/", "USER 65534:65534"])
        self.assertFalse(any(line.split()[0] in ("RUN", "COPY", "VOLUME", "EXPOSE") for line in lines))
        for tool in ("lief", "yarax", "ghidra", "jadx", "jsparser"):
            lock = json.loads((ROOT / f"containers/{tool}/image.lock.json").read_text())
            self.assertEqual(lock["base_digest"], P.BASE_DIGEST)
        self.assertTrue(P.DOCKERFILE.isascii())

    def test_docker_calls_never_pull_mount_or_open_the_network(self):
        build = P.build_argv(Path("/ctx"), Path("/ctx/image.id"), "reverseai-linux-proof:" + COMMIT[:12])
        self.assertEqual(build[:2], ["docker", "build"])
        self.assertIn("--pull=false", build)
        self.assertIn("--network=none", build)
        run = P.run_argv(IMAGE, "reverseai-linux-proof-0123")
        for flag in (["--pull", "never"], ["--network", "none"], ["--user", "65534:65534"], ["--cap-drop", "ALL"],
                     ["--security-opt", "no-new-privileges"], ["--platform", "linux/arm64"]):
            self.assertIn(flag, [run[i:i + 2] for i in range(len(run) - 1)])
        self.assertIn("--read-only", run)
        self.assertEqual(run[-1], IMAGE)
        self.assertFalse({"-v", "--volume", "--mount", "--privileged", "--network=host"} & set(run))
        self.assertEqual(P.remove_argv(IMAGE), ["docker", "image", "rm", "--no-prune", IMAGE])


class SuiteCountTests(unittest.TestCase):
    def test_closing_lines_give_exact_counts_or_none(self):
        self.assertEqual(P.suite_counts("....\nRan 1748 tests in 41.453s\n\nOK (skipped=1)\n"),
                         {"ran": 1748, "skipped": 1, "failures": 0, "errors": 0, "expected_failures": 0,
                          "unexpected_successes": 0, "ok": True})
        failed = P.suite_counts("Ran 9 tests in 1s\n\nFAILED (failures=2, errors=1, skipped=3, expected failures=1)")
        self.assertEqual((failed["ok"], failed["failures"], failed["errors"], failed["skipped"],
                          failed["expected_failures"]), (False, 2, 1, 3, 1))
        self.assertEqual(P.suite_counts("Ran 1 test in 0.1s\n\nOK")["ran"], 1)
        for text in ("", "OK", "Ran 3 tests in 1s\n\nOK (mystery=1)", "Ran 3 tests in 1s\n\nInterrupted"):
            with self.subTest(text=text):
                self.assertIsNone(P.suite_counts(text))


class ProveTests(unittest.TestCase):
    def prove(self, docker):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stdout(io.StringIO()) as stdout:
            receipt = Path(folder, "platform-linux-arm64.json")
            code = P.prove("m6-rc1", receipt, runner=docker)
            return code, json.loads(receipt.read_text()), stdout.getvalue()

    def test_a_passing_run_writes_the_receipt_and_removes_its_image(self):
        docker = HostDocker()
        code, receipt, printed = self.prove(docker)
        self.assertEqual(code, 0, receipt)
        self.assertEqual((receipt["commit"], receipt["base_digest"], receipt["platform"], receipt["image_id"]),
                         (COMMIT, P.BASE_DIGEST, "linux/arm64", IMAGE))
        self.assertEqual((receipt["passed"], receipt["image_removed"], receipt["error"]), (True, True, None))
        self.assertEqual(receipt["inside"]["suite"]["ran"], 1750)
        self.assertIn("passed: " + COMMIT[:12], printed)
        kinds = [" ".join(argv[:3]) for argv in docker.calls]
        self.assertEqual(kinds, ["git -C " + str(P.ROOT), "docker image inspect", "git -C " + str(P.ROOT),
                                 "git -C " + str(P.ROOT), "docker build --platform", "docker run --rm",
                                 "docker image rm", "docker image inspect"])
        self.assertIn(["docker", "image", "rm", "--no-prune", IMAGE], docker.calls)
        archive = next(argv for argv in docker.calls if "archive" in argv)
        self.assertEqual(archive[-1], COMMIT)
        self.assertIn("--prefix=src/", archive)

    def test_failures_still_remove_the_image_and_fail_the_receipt(self):
        cases = {"timeout": (None, "", ""), "no marker": (1, "Traceback", "boom"),
                 "suite failed": (0, P.MARKER + json.dumps(inside_facts(suite={
                     "ran": 3, "skipped": 0, "failures": 1, "errors": 0, "expected_failures": 0,
                     "unexpected_successes": 0, "ok": False})), ""),
                 "source tree imported": (0, P.MARKER + json.dumps(inside_facts(
                     imported_from="/opt/src/reverseai/__init__.py")), ""),
                 "lock from the checkout": (0, P.MARKER + json.dumps(inside_facts(doctor={
                     **doctor_facts(), "tools": [{**doctor_facts()["tools"][0], "lock": "/opt/src/containers/x"}]})), ""),
                 "two markers": (0, (P.MARKER + json.dumps(inside_facts()) + "\n") * 2, "")}
        for label, outcome in cases.items():
            with self.subTest(label=label):
                docker = HostDocker(run=outcome)
                code, receipt, printed = self.prove(docker)
                self.assertEqual((code, receipt["passed"], receipt["image_removed"]), (1, False, True))
                self.assertIn(["docker", "image", "rm", "--no-prune", IMAGE], docker.calls)
                self.assertTrue(printed.startswith("FAILED"))
                self.assertEqual(any(argv[:2] == ["docker", "kill"] for argv in docker.calls), label == "timeout")
        code, receipt, _ = self.prove(HostDocker(removed=False))
        self.assertEqual((code, receipt["image_removed"]), (1, False))

    def test_a_missing_base_refuses_before_any_build(self):
        docker = HostDocker(base=False)
        with tempfile.TemporaryDirectory() as folder, self.assertRaisesRegex(SystemExit, "never pulls"):
            P.prove("m6-rc1", Path(folder, "receipt.json"), runner=docker)
        self.assertFalse(any(argv[:2] in (["docker", "build"], ["docker", "run"]) for argv in docker.calls))

    def test_the_receipt_must_be_a_new_file(self):
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stderr(io.StringIO()):
            existing = Path(folder, "receipt.json")
            existing.write_text("{}")
            with self.assertRaises(SystemExit) as raised:
                P.main(["--commit", "m6-rc1", "--receipt", str(existing)])
            self.assertEqual(raised.exception.code, 2)
            self.assertEqual(existing.read_text(), "{}")


class InsideTests(unittest.TestCase):
    """The in-container sequence with stand-in commands: offline pip, a fresh venv, the installed entry point."""

    def runner(self, work, *, wheel_ok=True):
        calls = []

        def run(argv, *, timeout, cwd=None, env=None):
            calls.append((list(argv), cwd, env))
            if argv[1:4] == ["-B", "-m", "unittest"]:
                return 0, "", "......\nRan 6 tests in 0.1s\n\nOK (skipped=1)\n"
            if argv[1:4] == ["-m", "pip", "wheel"]:
                if wheel_ok:
                    Path(argv[argv.index("--wheel-dir") + 1]).mkdir()
                    Path(argv[argv.index("--wheel-dir") + 1], WHEEL).write_bytes(b"PK")
                return (0 if wheel_ok else 1), "", ""
            if argv[1:3] == ["-m", "venv"] or argv[1:4] == ["-m", "pip", "install"]:
                return 0, "", ""
            if argv[1:] == ["--version"]:
                return 0, "reverseai 0.6.0\n", ""
            if argv[1:3] == ["-I", "-c"]:
                return 0, "/tmp/venv/lib/python3.12/site-packages/reverseai/__init__.py\n", ""
            if argv[1:] == ["doctor", "--json"]:
                return 0, json.dumps(doctor_facts()), ""
            if argv[1:3] == ["-B", "-c"]:
                return 0, "", ""
            if argv[1] == "analyze":
                out = Path(argv[argv.index("--out") + 1])
                out.mkdir()
                (out / "report.json").write_text(json.dumps({"input": {"sha256": "1" * 64}, "summary": {"supported": 3}}))
                (out / "report.md").write_text("# report\n")
                return 0, "", ""
            raise AssertionError(f"unexpected argv {argv}")
        return run, calls

    def test_every_step_runs_offline_in_order_and_the_facts_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            work, source = Path(folder, "tmp"), Path(folder, "src")
            work.mkdir()
            source.mkdir()
            (source / "pyproject.toml").write_text("[project]\n")
            run, calls = self.runner(work)
            facts = P.inside(runner=run, work=work, source=source)
        names = list(facts["steps"])
        self.assertEqual(names, ["suite", "wheel", "venv", "install", "version", "imported_from", "doctor", "fixture",
                                 "analyze"])
        argvs = [argv for argv, _, _ in calls]
        self.assertIn("--no-index", argvs[1])
        self.assertEqual(argvs[1][-1], str(work / "build"))
        self.assertIn("--no-index", argvs[3])
        self.assertEqual(argvs[3][-1], str(work / "dist" / WHEEL))
        self.assertEqual(argvs[4], [str(work / "venv/bin/reverseai"), "--version"])
        self.assertFalse(any("sdist" in part or part.startswith("http") for argv in argvs for part in argv))
        self.assertEqual(calls[0][1], source)
        self.assertTrue(all(env["HOME"] == str(work / "home") and env["PIP_NO_CACHE_DIR"] == "1"
                            and not {"HTTP_PROXY", "HTTPS_PROXY"} & set(env) for _, _, env in calls))
        self.assertEqual(facts["suite"]["ran"], 6)
        self.assertEqual(facts["wheel"]["name"], WHEEL)
        self.assertEqual(facts["analyze"]["reports"], ["report.json", "report.md"])
        self.assertTrue(P.passed({**facts, "imported_from": facts["imported_from"]}, "0.6.0"))
        self.assertFalse(P.passed(facts, "0.6.1"))

    def test_a_failed_wheel_build_stops_before_any_install(self):
        with tempfile.TemporaryDirectory() as folder:
            work, source = Path(folder, "tmp"), Path(folder, "src")
            work.mkdir()
            source.mkdir()
            run, calls = self.runner(work, wheel_ok=False)
            facts = P.inside(runner=run, work=work, source=source)
        self.assertEqual(list(facts["steps"]), ["suite", "wheel"])
        self.assertIsNone(facts["wheel"])
        self.assertFalse(P.passed(facts, "0.6.0"))


if __name__ == "__main__":
    unittest.main()
