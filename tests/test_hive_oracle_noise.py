import contextlib
import io
import itertools
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hive import queen
from tests import test_hive_fuzz

CASE = [{"id": "a", "files": [{"name": "in.txt", "text": "hello"}], "steps": [{"args": ["in.txt"]}]}]


def script(path, body):
    path.write_text("#!/bin/sh\n" + body)
    os.chmod(path, 0o755)
    return str(path)


def row(code=0, out="o", err="", files=None):
    return {"steps": [{"code": code, "out": out, "out_head": out, "err": err}], "files": files or {}}


class SamePathTests(unittest.TestCase):
    """Both programs see the same path, argv[0] and working directory, so paths in their output cannot differ."""

    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        body = 'echo "$0"; pwd; echo "$0" >&2\n'
        self.original = script(self.root / "original-name", body)
        self.rebuilt = script(self.root / "rebuilt-elsewhere", body)

    def test_named_runs_make_the_two_programs_indistinguishable(self):
        first = queen.run_cases(CASE, self.original, self.root / "runs", name="tool")
        second = queen.run_cases(CASE, self.rebuilt, self.root / "runs", name="tool")
        self.assertEqual(first, second)

    def test_without_a_name_the_paths_still_tell_them_apart(self):
        (self.root / "runs").mkdir()
        first = queen.run_cases(CASE, self.original, self.root / "runs")
        second = queen.run_cases(CASE, self.rebuilt, self.root / "runs")
        self.assertNotEqual(first, second)  # the reason for the named, same-path runs


class StableCompareTests(unittest.TestCase):
    def test_noise_in_the_original_is_masked_and_reported(self):
        original = {"a": row(err="at 12:00:01")}
        again = {"a": row(err="at 12:00:02")}
        same, different, unstable, masked = queen.compare_stable(original, {"a": row(err="at 12:00:07")}, again)
        self.assertEqual((same, different, unstable), (["a"], [], []))
        self.assertEqual(masked, {"a": ["step0.err"]})

    def test_a_real_difference_is_still_found(self):
        original, again = {"a": row(err="t1")}, {"a": row(err="t2")}
        _, different, _, _ = queen.compare_stable(original, {"a": row(out="other", err="t9")}, again)
        self.assertEqual(different, ["a"])
        _, different, _, _ = queen.compare_stable(original, {"a": row(code=1, err="t9")}, again)
        self.assertEqual(different, ["a"])

    def test_temporary_file_names_are_noise_but_an_extra_stable_file_is_not(self):
        original = {"a": row(files={"out.txt": "h1", "tmp-123": "x"})}
        again = {"a": row(files={"out.txt": "h1", "tmp-456": "x"})}
        same, _, _, masked = queen.compare_stable(original, {"a": row(files={"out.txt": "h1", "tmp-789": "x"})},
                                                  again)
        self.assertEqual(same, ["a"])
        self.assertNotIn("a", masked)  # same contents under temporary names: nothing to mask
        _, different, _, _ = queen.compare_stable(original, {"a": row(files={"out.txt": "h2", "tmp-9": "x"})}, again)
        self.assertEqual(different, ["a"])

    def test_a_case_with_no_stable_field_proves_nothing(self):
        original, again = {"a": row(code=0, out="x", err="e")}, {"a": row(code=1, out="y", err="f")}
        same, different, unstable, _ = queen.compare_stable(original, {"a": row(code=0, out="x", err="e")}, again)
        self.assertEqual((same, different, unstable), ([], [], ["a"]))


class ConformanceTests(unittest.TestCase):
    """End to end through Queen.conformance with simulated executions (helpers from the fuzz tests)."""

    setUp = test_hive_fuzz.QueenFuzzTests.setUp
    make = test_hive_fuzz.QueenFuzzTests.make

    def run_with(self, q, execute):
        with patch.object(queen, "run_cases", side_effect=execute), contextlib.redirect_stdout(io.StringIO()):
            return q.conformance("first-rebuild", [], self.root / "unused")

    def test_the_original_runs_twice_and_its_noise_does_not_fail_the_rebuild(self):
        q, clock, calls = self.make(total=0), itertools.count(), []

        def execute(cases, binary, folder, **kwargs):
            calls.append((str(binary), kwargs.get("name")))
            stamp = f"t{next(clock)}"
            return {c["id"]: {"steps": [{"code": 0, "out": "same", "err": stamp} for _ in c["steps"]]} for c in cases}
        result = self.run_with(q, execute)
        original = str(self.out / "tests/original/owned-input")
        self.assertEqual([binary for binary, _ in calls], [original, "first-rebuild", original])
        self.assertEqual({name for _, name in calls}, {"owned-input"})  # same staged name for both programs
        self.assertTrue(result["ran"])
        self.assertEqual(result["identical"], result["cases"])
        self.assertTrue(result["masked"])
        report = queen.render({"file": "owned-input", "input_sha256": "cd" * 32, "functions": 1, "skipped": 0,
                               "modules": {}, "link": True, "check": None, "claims": 0, "conformance": result,
                               "preflight": None, "verdict": "x", "reason": "x"})
        self.assertIn("compared on their stable fields only", report)

    def test_cases_the_original_cannot_reproduce_stop_the_proof(self):
        q, clock = self.make(total=0), itertools.count()

        def execute(cases, binary, folder, **kwargs):
            tick = next(clock)
            return {c["id"]: {"steps": [{"code": tick, "out": f"o{tick}", "err": f"e{tick}"} for _ in c["steps"]]}
                    for c in cases}
        result = self.run_with(q, execute)
        self.assertFalse(result["ran"])
        self.assertIn("different result on every field when the original runs twice", result["reason"])


if __name__ == "__main__":
    unittest.main()
