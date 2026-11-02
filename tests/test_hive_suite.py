import importlib.util
import contextlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import time
import unittest
from types import SimpleNamespace
from unittest.mock import patch

from hive import queen

if importlib.util.find_spec("hive.suite") is None:
    suite = None
else:
    from hive import suite


class SuiteCase(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(suite, "the project-suite behaviour runner is not available")
        temporary = tempfile.TemporaryDirectory(prefix="hive-suite-test-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        self.folder = self.root / "suite"
        self.folder.mkdir()

    def program(self, name, source):
        path = self.root / name
        path.write_text(source, encoding="utf-8")
        return path

    def spec(self, **changes):
        return {"folder": str(self.folder), "argv": [sys.executable, "{program}", "{workdir}"],
                "timeout": 3, "format": "tap", **changes}

    def run_outputs(self, original, rebuilt, **changes):
        before = self.program("original program.py", f"import sys\nsys.stdout.write({original!r})\n")
        after = self.program("rebuilt program.py", f"import sys\nsys.stdout.write({rebuilt!r})\n")
        return suite.run(self.spec(**changes), before, after, self.root / "out", allowed=True)


class TapTests(SuiteCase):
    def test_flat_tap_keeps_failures_and_skips(self):
        result = suite.parse_tap("TAP version 13\n1..3\nok 1 - alpha\nnot ok 2 - beta\nok 3 # SKIP unavailable\n")
        self.assertTrue(result["complete"], result)
        self.assertEqual(result["tests"], {"1": "pass", "2": "fail", "3": "skip"})

    def test_trailing_plan_implicit_numbers_and_yaml_diagnostics(self):
        result = suite.parse_tap("ok - first\nnot ok - second\n  ---\n  message: failure\n  ...\n1..2\n")
        self.assertTrue(result["complete"], result)
        self.assertEqual(result["tests"], {"1": "pass", "2": "fail"})

    def test_missing_and_unparsable_output_are_incomplete(self):
        for text in ("", "ok 1\n", "1..2\nok 1\n", "1..1\nok 1\nnot TAP\n",
                     "1..1\nok 1\nok 1\n", "1..1\nBail out! unavailable\n", "1..0 # SKIP all\n",
                     "1..1\n    ok 1 - nested\n", "1..1\nok 1\n  ---\n",
                     "1..1\nok 12345678901234567890\n", "1..1\nok 1invalid\n",
                     "ok 1\n1..2\nok 2\n", "1..2\nok 2\nok 1\n"):
            with self.subTest(text=text):
                self.assertFalse(suite.parse_tap(text)["complete"])
        result = suite.parse_tap("1..2\nok 1\n")
        self.assertEqual(result["tests"]["2"], "missing")

    def test_expected_tests_cannot_disappear(self):
        result = suite.parse_tap("1..1\nok 1\n", expected=["1", "2"])
        self.assertFalse(result["complete"])
        self.assertEqual(result["tests"]["2"], "missing")


class CurlTests(SuiteCase):
    def test_missing_or_unknown_output_is_incomplete_with_expected_ids(self):
        for text in ("", "not a curl test result\n"):
            with self.subTest(text=text):
                result = suite.parse_curl(text, expected=["1", "7"])
                self.assertFalse(result["complete"])
                self.assertEqual(result["tests"], {"1": "missing", "7": "missing"})
                self.assertTrue(result["reason"])

    def test_unparseable_curl_run_keeps_both_sides_and_their_raw_logs(self):
        result = self.run_outputs("unknown original output\n", "unknown rebuilt output\n", format="curl")
        self.assertTrue(result["ran"])
        self.assertFalse(result["complete"])
        self.assertFalse(result["passed"])
        for side in ("original", "rebuilt"):
            self.assertIn("unknown " + side + " output", Path(result[side]["logs"]["stdout"]).read_text())


class ComparisonTests(SuiteCase):
    def test_regressions_improvements_both_fail_and_skips_stay_distinct(self):
        before = suite.parse_tap("1..5\nok 1\nnot ok 2\nnot ok 3\nok 4 # SKIP\nok 5\n")
        after = suite.parse_tap("1..5\nnot ok 1\nok 2\nnot ok 3\nok 4 # SKIP\nok 5 # SKIP\n")
        result = suite.compare(before, after)
        self.assertTrue(result["complete"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["checked"], 2)
        self.assertEqual(result["regressions"], ["1", "5"])
        self.assertEqual(result["improvements"], ["2"])
        self.assertEqual(result["both_fail"], ["3"])
        self.assertEqual(result["skips"], {"original": ["4"], "rebuilt": ["4", "5"]})

    def test_same_failures_do_not_count_as_regressions(self):
        result = self.run_outputs("1..2\nok 1\nnot ok 2\n", "1..2\nok 1\nnot ok 2\n")
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["checked"], 1)
        self.assertEqual(result["both_fail"], ["2"])

    def test_incomplete_results_keep_observed_regressions(self):
        result = self.run_outputs("1..3\nok 1\nok 2\nok 3\n", "1..3\nnot ok 1\nok 2\n")
        self.assertFalse(result["complete"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["regressions"], ["1", "3"])
        self.assertEqual(result["missing"]["rebuilt"], ["3"])

    def test_no_passing_baseline_is_not_a_behaviour_proof(self):
        result = self.run_outputs("1..2\nnot ok 1\nok 2 # SKIP\n", "1..2\nnot ok 1\nok 2 # SKIP\n")
        self.assertFalse(result["complete"])
        self.assertFalse(result["passed"])
        self.assertEqual(result["checked"], 0)


class ExecutionTests(SuiteCase):
    def test_permission_is_required_before_any_execution_or_output(self):
        program = self.program("inert.py", "raise AssertionError('must never execute')\n")
        for allowed in (False, None, 1):
            with self.subTest(allowed=allowed), self.assertRaises(suite.SuiteError):
                suite.run(self.spec(), program, program, self.root / "out", allowed=allowed)
        self.assertFalse((self.root / "out").exists())

    def test_each_side_gets_a_fresh_copy_home_and_minimal_environment(self):
        (self.folder / "seed").write_text("original suite data")
        source = '''import json, os, sys
from pathlib import Path
cwd = Path.cwd()
assert not (cwd / "marker").exists()
assert Path(sys.argv[1]) == cwd
assert (cwd / "seed").read_text() == "original suite data"
(cwd / "marker").write_text("owned marker")
assert os.environ["LC_ALL"] == "C"
assert "HIVE_SUITE_TEST_SECRET" not in os.environ
assert Path(os.environ["HOME"]).is_dir()
print(json.dumps({"cwd": str(cwd), "home": os.environ["HOME"]}), file=sys.stderr)
print("1..1\\nok 1")
'''
        program = self.program("owned fixture.py", source)
        with patch.dict(os.environ, {"HIVE_SUITE_TEST_SECRET": "must not reach the suite"}):
            result = suite.run(self.spec(), program, program, self.root / "out", allowed=True)
        self.assertTrue(result["passed"], result)
        before = json.loads(Path(result["original"]["logs"]["stderr"]).read_text())
        after = json.loads(Path(result["rebuilt"]["logs"]["stderr"]).read_text())
        self.assertNotEqual(before, after)
        self.assertFalse((self.folder / "marker").exists())
        self.assertEqual((self.folder / "seed").read_text(), "original suite data")

    def test_argv_templates_keep_spaces_and_shell_metacharacters_literal(self):
        marker = self.root / "shell-marker"
        argument = f"literal; touch {marker}"
        source = 'import sys\nassert sys.argv[2] == '+repr(argument)+'\nprint("1..1\\nok 1")\n'
        program = self.program("a program {workdir} with spaces.py", source)
        spec = self.spec(argv=[sys.executable, "{program}", "{workdir}", argument])
        result = suite.run(spec, program, program, self.root / "out", allowed=True)
        self.assertTrue(result["passed"], result)
        self.assertFalse(marker.exists())
        self.assertEqual(result["original"]["argv"][-1], argument)

    def test_selected_ids_are_arguments_and_required_results(self):
        program = self.program("selected.py", 'import sys\nassert sys.argv[2:] == ["1", "2"]\nprint("1..2\\nok 1\\nok 2")\n')
        result = suite.run(self.spec(tests=["1", "2"]), program, program, self.root / "out", allowed=True)
        self.assertTrue(result["passed"], result)

    def test_timeout_and_partial_logs_never_pass(self):
        program = self.program("slow.py", 'import time\nprint("1..2\\nok 1", flush=True)\ntime.sleep(10)\n')
        result = suite.run(self.spec(timeout=0.3), program, program, self.root / "out", allowed=True)
        self.assertFalse(result["passed"])
        self.assertFalse(result["complete"])
        self.assertIn("timed out", result["reason"])
        self.assertIn(b"ok 1", Path(result["original"]["logs"]["stdout"]).read_bytes())

    @unittest.skipUnless(os.name == "posix", "requires POSIX process groups")
    def test_timeout_disposes_of_descendants_holding_output_pipes(self):
        marker = self.root / "late-child-marker"
        child = f'import time; from pathlib import Path; time.sleep(0.9); Path({str(marker)!r}).write_text("late")'
        source = 'import subprocess, sys\nsubprocess.Popen([sys.executable, "-c", '+repr(child)+'])\n'
        program = self.program("spawn.py", source)
        started = time.monotonic()
        result = suite.run(self.spec(timeout=0.2), program, program, self.root / "out", allowed=True)
        self.assertFalse(result["passed"])
        self.assertLess(time.monotonic() - started, 2)
        time.sleep(1)
        self.assertFalse(marker.exists())

    def test_both_output_streams_are_bounded_and_truncation_is_incomplete(self):
        for stream in ("stdout", "stderr"):
            with self.subTest(stream=stream):
                program = self.program(stream+".py", 'import sys\nprint("1..1\\nok 1", flush=True)\nsys.'+stream+'.write("x" * 100000)\nsys.'+stream+'.flush()\n')
                with patch.object(suite, "OUTPUT_LIMIT", 1024):
                    result = suite.run(self.spec(), program, program, self.root / stream, allowed=True)
                self.assertFalse(result["passed"])
                self.assertFalse(result["complete"])
                self.assertIn("output limit", result["reason"])
                for side in ("original", "rebuilt"):
                    for path in result[side]["logs"].values():
                        self.assertLessEqual(Path(path).stat().st_size, 1024)

    def test_exit_one_with_complete_test_results_is_a_test_failure_not_missing_output(self):
        program = self.program("fail.py", 'import sys\nprint("1..2\\nok 1\\nnot ok 2")\nsys.exit(1)\n')
        result = suite.run(self.spec(), program, program, self.root / "out", allowed=True)
        self.assertTrue(result["passed"], result)
        self.assertEqual(result["both_fail"], ["2"])

    def test_exit_one_without_a_reported_failed_test_is_incomplete(self):
        program = self.program("broken-harness.py", 'import sys\nprint("1..1\\nok 1")\nsys.exit(1)\n')
        result = suite.run(self.spec(), program, program, self.root / "out", allowed=True)
        self.assertFalse(result["complete"], result)
        self.assertFalse(result["passed"], result)
        self.assertIn("exited with 1", result["reason"])

    def test_start_errors_and_abnormal_exit_are_incomplete(self):
        program = self.program("error.py", 'import sys\nprint("1..1\\nok 1")\nsys.exit(9)\n')
        result = suite.run(self.spec(), program, program, self.root / "out", allowed=True)
        self.assertFalse(result["passed"])
        self.assertIn("exited with 9", result["reason"])
        result = suite.run(self.spec(argv=[str(self.root / "missing-command"), "{program}"]), program, program,
                           self.root / "missing-out", allowed=True)
        self.assertFalse(result["complete"])
        self.assertIn("could not run", result["reason"])


class DescriptionTests(SuiteCase):
    def test_description_resolves_folder_from_its_own_location(self):
        spec = self.spec(folder="suite")
        path = self.root / "spec.json"
        path.write_text(json.dumps(spec))
        loaded = suite.load(path)
        self.assertEqual(loaded["folder"], str(self.folder))

    def test_invalid_descriptions_are_rejected(self):
        for changes in ({"argv": "python suite.py"}, {"argv": ["echo", "ok"]}, {"argv": []},
                        {"timeout": 0}, {"timeout": True}, {"timeout": float("inf")}, {"timeout": 10 ** 1000},
                        {"format": "guess"}, {"tests": ["1", "1"]}, {"tests": ["1; echo unsafe"]},
                        {"shell": True}, {"folder": "missing"}):
            with self.subTest(changes=changes), self.assertRaises(suite.SuiteError):
                path = self.root / "bad.json"
                path.write_text(json.dumps(self.spec(**changes)))
                suite.load(path)

    def test_results_directory_cannot_reuse_stale_output_or_enter_the_suite(self):
        program = self.program("ok.py", 'print("1..1\\nok 1")\n')
        out = self.root / "out"
        out.mkdir()
        (out / "old-result").write_text("accepted")
        for destination in (out, self.folder / "inside"):
            with self.subTest(destination=destination), self.assertRaises(suite.SuiteError):
                suite.run(self.spec(), program, program, destination, allowed=True)


class QueenSuiteTests(SuiteCase):
    def fake_program(self, name, verdict="pass", normal="same"):
        program = self.program(name, f"#!{sys.executable}\nimport sys\n"
                               f"print({verdict!r} if '--suite' in sys.argv else {normal!r})\n")
        program.chmod(0o700)
        return program

    def make(self, verdict="pass", normal="same", **kwargs):
        before = self.fake_program("original.py")
        after = self.fake_program("rebuilt.py", verdict, normal)
        self.folder.joinpath("runner.py").write_text('''import subprocess, sys
done = subprocess.run([sys.argv[1], "--suite"], capture_output=True, text=True)
answer = done.stdout.strip()
if answer == "missing":
    print("no parseable results")
else:
    print("1..1")
    print("not ok 1" if done.returncode or answer == "fail" else "ok 1")
''')
        cases = [{"id": "first", "files": [{"name": "input", "text": "seed"}], "steps": [{"args": []}]},
                 {"id": "second", "steps": [{"args": ["other"]}]}]

        def bees(role, name, task, folder):
            self.assertEqual(role, "tester")
            return {"ok": True, "output": {"cases": cases}}

        def checker(claims, out):
            return {"claims": 1, "confirmed": 1, "rejected": 0, "questions": 1,
                    "input_sha256": ["ab" * 32]}, []

        spec = self.spec(argv=[sys.executable, "runner.py", "{program}"])
        out = self.root / "run"
        q = queen.Queen(engine=SimpleNamespace(file=before.name, path=before), out=out, bees=bees,
                        check=checker, behaviour_rounds=0, suite=spec,
                        run_original=kwargs.pop("run_original", True), **kwargs)
        (out / "survey").mkdir(parents=True)
        (out / "survey/map.json").write_text(json.dumps({"functions": [], "imports": [], "calls": [],
                                                        "strings": [], "references": [], "input_sha256": "ab" * 32}))
        contract = self.root / "contract.h"
        contract.write_text("int main(int argc, char **argv); /* 0x1000 */\n")
        claims = self.root / "claims.json"
        claims.write_text('{"claims": [{"id": "fixture"}]}')
        self.enterContext(patch.object(q.build, "ensure_confinement"))
        self.enterContext(patch.object(q, "plan", return_value=([], {}, contract)))
        self.enterContext(patch.object(q, "integrate", return_value={"ok": True, "binary": str(after)}))
        self.enterContext(patch.object(q, "claims", return_value=(claims, 1)))
        return q, before, after

    def execute(self, q):
        with contextlib.redirect_stdout(io.StringIO()):
            return q.run()

    def test_project_suite_runs_after_normal_cases_and_is_reported(self):
        q, _, _ = self.make()
        result = self.execute(q)
        self.assertEqual(result["verdict"], "accepted", result["reason"])
        self.assertEqual(result["conformance"]["plain"]["identical"], 2)
        self.assertEqual((result["conformance"]["identical"], result["conformance"]["cases"]), (3, 3))
        self.assertTrue(result["conformance"]["suite"]["passed"])
        self.assertEqual(result["conformance"]["suite"]["checked"], 1)
        self.assertIn("Project suite: 1 passing baseline tests; 0 regressions", (q.out / "REPORT.md").read_text())

    def test_suite_regression_blocks_an_otherwise_matching_program(self):
        q, _, _ = self.make(verdict="fail")
        result = self.execute(q)
        self.assertEqual(result["conformance"]["identical"], 2)
        self.assertEqual(result["conformance"]["suite"]["regressions"], ["1"])
        self.assertEqual(result["verdict"], "not accepted")
        self.assertEqual(result["conformance"]["different"], ["suite:1"])

    def test_suite_uses_the_final_binary_after_behaviour_repairs(self):
        q, _, _ = self.make(normal="different")
        q.behaviour_rounds = 1
        final = self.fake_program("final.py", verdict="fail")
        with patch.object(q, "behaviour_fix", return_value={"ok": True, "binary": str(final)}):
            result = self.execute(q)
        self.assertEqual(result["binary"], str(final))
        self.assertEqual(result["conformance"]["identical"], 2)
        self.assertEqual(result["conformance"]["suite"]["rebuilt"]["argv"][-1], str(final))
        self.assertEqual(result["verdict"], "not accepted")

    def test_no_passing_suite_baseline_cannot_prove_the_program(self):
        q, before, _ = self.make(verdict="fail")
        self.fake_program(before.name, verdict="fail")
        result = self.execute(q)
        self.assertEqual(result["conformance"]["suite"]["checked"], 0)
        self.assertEqual(result["conformance"]["suite"]["both_fail"], ["1"])
        self.assertEqual(result["verdict"], "not accepted")

    def test_invalid_suite_description_is_reported_without_running_the_suite(self):
        q, _, _ = self.make()
        description = self.root / "bad-description.json"
        description.write_text("not JSON")
        q.suite = description
        with patch.object(suite, "_execute", side_effect=AssertionError("invalid suite was executed")):
            result = self.execute(q)
        self.assertFalse(result["conformance"]["suite"]["ran"])
        self.assertIn("cannot read suite description", result["reason"])
        self.assertEqual(result["verdict"], "not accepted")

    def test_unparseable_suite_blocks_acceptance_and_keeps_raw_output(self):
        q, _, _ = self.make(verdict="missing")
        result = self.execute(q)
        proof = result["conformance"]["suite"]
        self.assertFalse(proof["complete"])
        self.assertEqual(result["verdict"], "not accepted")
        self.assertIn("project suite incomplete", result["reason"])
        self.assertIn("no parseable results", Path(proof["rebuilt"]["logs"]["stdout"]).read_text())

    def test_default_without_suite_preserves_the_existing_verdict(self):
        q, _, _ = self.make()
        q.suite = None
        with patch.object(suite, "run", side_effect=AssertionError("unexpected suite execution")):
            result = self.execute(q)
        self.assertEqual(result["verdict"], "accepted")
        self.assertNotIn("suite", result["conformance"])
        self.assertNotIn("Project suite:", (q.out / "REPORT.md").read_text())

    def test_api_without_original_permission_starts_no_program(self):
        q, _, _ = self.make(run_original=False)
        with patch.object(queen, "run_cases", side_effect=AssertionError("unexpected original execution")), \
             patch.object(suite, "run", side_effect=AssertionError("unexpected suite execution")):
            result = self.execute(q)
        self.assertFalse(result["conformance"]["suite"]["ran"])
        self.assertEqual(result["verdict"], "accepted without behaviour proof")
        self.assertIn("not allowed", result["conformance"]["suite"]["reason"])

    def test_a_suite_never_overrules_plain_case_differences(self):
        q, _, _ = self.make(normal="different")
        result = self.execute(q)
        self.assertTrue(result["conformance"]["suite"]["passed"])
        self.assertEqual(result["verdict"], "not accepted")
        self.assertEqual(len(result["conformance"]["different"]), 2)

    def test_an_incomplete_fuzz_proof_keeps_the_suite_result_and_its_veto(self):
        q, _, _ = self.make(fuzz=1)
        real = queen.run_cases

        def incomplete(cases, *args, **kwargs):
            return {} if any(case["id"].startswith("fz-") for case in cases) else real(cases, *args, **kwargs)

        with patch.object(queen, "run_cases", side_effect=incomplete):
            result = self.execute(q)
        conformance = result["conformance"]
        self.assertFalse(conformance["ran"])
        self.assertTrue(conformance["fuzz"]["incomplete"])
        self.assertTrue(conformance["suite"]["passed"])
        self.assertEqual((conformance["cases"], conformance["completed"]), (4, 3))
        self.assertEqual(result["verdict"], "not accepted")
        rendered = (q.out / "REPORT.md").read_text()
        self.assertIn("plain cases identical", rendered)
        self.assertIn("Project suite:", rendered)

    def test_failed_normal_conformance_does_not_run_the_suite(self):
        q, _, _ = self.make()
        q.bees = lambda *args: {"ok": True, "output": {"cases": []}}
        with patch.object(suite, "run", side_effect=AssertionError("suite ran before ordinary conformance")):
            result = self.execute(q)
        self.assertFalse(result["conformance"]["suite"]["ran"])
        self.assertEqual(result["verdict"], "not accepted")

    def test_resume_uses_new_suite_logs_and_cannot_keep_an_old_pass(self):
        q, _, after = self.make()
        first = self.execute(q)
        first_log = first["conformance"]["suite"]["rebuilt"]["logs"]["stdout"]
        self.fake_program(after.name, "fail")
        second = self.execute(q)
        second_log = second["conformance"]["suite"]["rebuilt"]["logs"]["stdout"]
        self.assertEqual(first["verdict"], "accepted")
        self.assertEqual(second["verdict"], "not accepted")
        self.assertNotEqual(first_log, second_log)
        self.assertIn("ok 1", Path(first_log).read_text())
        self.assertIn("not ok 1", Path(second_log).read_text())

    def test_cli_requires_permission_and_forwards_the_validated_description(self):
        q, before, _ = self.make()
        description = self.root / "description.json"
        description.write_text(json.dumps(q.suite))
        args = ["run", "--inputs", str(self.root), "--file", before.name,
                "--out", str(self.root / "cli-run"), "--suite", str(description)]
        with patch.object(queen, "Queen") as factory, contextlib.redirect_stderr(io.StringIO()), \
             self.assertRaises(SystemExit) as caught:
            queen.main(args)
        self.assertEqual(caught.exception.code, 2)
        factory.assert_not_called()
        with patch.object(queen.bees_module, "environment_ok", return_value=True), patch.object(queen, "Queen") as factory:
            factory.return_value.run.return_value = {"verdict": "accepted"}
            self.assertEqual(queen.main([*args, "--run-original"]), 0)
        self.assertTrue(factory.call_args.kwargs["run_original"])
        self.assertEqual(factory.call_args.kwargs["suite"], suite.load(description))


if __name__ == "__main__":
    unittest.main()
