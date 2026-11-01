import base64
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import random
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from types import SimpleNamespace

from hive import fuzz, queen

SHA = "ab" * 32
CASES = [{"id": "first", "files": [{"name": "input.bin", "text": "seed"}],
          "steps": [{"args": ["--read", "input.bin"], "stdin": "input.bin"}]},
         {"id": "second", "files": [{"name": "input.bin", "text": "more"}],
          "steps": [{"args": ["input.bin"]}]}]


class MutationTests(unittest.TestCase):
    def test_every_mutator_changes_only_bounded_bytes(self):
        data, donor = b"abcdefgh", b"XYZ"
        outputs = {operation: fuzz.mutate(data, operation, random.Random(7), 16, donor)
                   for operation in fuzz.MUTATORS}
        self.assertEqual(sum((a ^ b).bit_count() for a, b in zip(data, outputs["bitflip"])), 1)
        self.assertEqual(len(outputs["insert"]), len(data) + 1)
        self.assertEqual(len(outputs["delete"]), len(data) - 1)
        self.assertTrue(data.startswith(outputs["truncate"]))
        self.assertLess(len(outputs["truncate"]), len(data))
        changed = [(a, b) for a, b in zip(data, outputs["boundary"]) if a != b]
        self.assertEqual(len(changed), 1)
        self.assertIn(changed[0][1], fuzz.BOUNDARIES)
        self.assertTrue(any(value in outputs["splice"] for value in donor))
        for operation in fuzz.MUTATORS:
            with self.subTest(operation=operation):
                self.assertLessEqual(len(fuzz.mutate(data * 100, operation, random.Random(2), 8, donor * 100)), 8)
                self.assertLessEqual(len(fuzz.mutate(b"", operation, random.Random(2), 8, b"")), 8)

    def test_seed_is_repeatable_bound_to_input_and_source_id(self):
        before = copy.deepcopy(CASES)
        first = fuzz.generate(CASES, SHA, 36, queen.MAX_CASE_FILE)
        self.assertEqual(first, fuzz.generate(CASES, SHA, 36, queen.MAX_CASE_FILE))
        self.assertEqual(first, fuzz.generate(list(reversed(CASES)), SHA, 36, queen.MAX_CASE_FILE))
        self.assertNotEqual(first, fuzz.generate(CASES, "cd" * 32, 36, queen.MAX_CASE_FILE))
        renamed = copy.deepcopy(CASES)
        renamed[0]["id"] = "another"
        changed_seed = fuzz.generate(renamed, SHA, 36, queen.MAX_CASE_FILE)
        self.assertNotEqual([case["files"] for case in first], [case["files"] for case in changed_seed])
        self.assertEqual(CASES, before)
        for mutant in first:
            source = CASES[0] if mutant["id"].startswith("fz-first-") else CASES[1]
            self.assertEqual(mutant["steps"], source["steps"])
            self.assertEqual([f["name"] for f in mutant["files"]], [f["name"] for f in source["files"]])

    def test_total_cap_off_and_unique_normalised_ids(self):
        sources = copy.deepcopy(CASES)
        sources[0]["id"], sources[1]["id"] = "x" * 63 + "a", "x" * 63 + "b"
        sources.append({"id": "fz-" + "x" * 59 + "-1", "steps": [{"args": []}]})
        mutants = fuzz.generate(sources, SHA, 500, queen.MAX_CASE_FILE)
        names = [case["id"] for case in mutants]
        self.assertEqual(len(names), 500)
        self.assertEqual(len(set(names)), 500)
        self.assertFalse(set(names) & {case["id"] for case in sources})
        self.assertTrue(all(len(name) <= 64 for name in names))
        self.assertTrue(all(name.startswith("fz-") for name in names))
        self.assertEqual(fuzz.generate(CASES, SHA, 0, queen.MAX_CASE_FILE), [])
        self.assertEqual(fuzz.generate([{"id":"args-only","steps":[{"args":["x"]}]}], SHA, 5,
                                       queen.MAX_CASE_FILE), [])
        for value in (-1, 501, True, 1.5, "2.0"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                fuzz.generate(CASES, SHA, value, queen.MAX_CASE_FILE)

    def test_all_files_are_capped_and_stdin_is_mutatable(self):
        cases = [{"id":"stdin", "files":[{"name":"stdin.bin","base64":base64.b64encode(b"a"*100000).decode()},
                                          {"name":"other","text":"z"*100000}],
                  "steps":[{"args":["literal"],"stdin":"stdin.bin"}]}]
        mutants = fuzz.generate(cases, SHA, 24, queen.MAX_CASE_FILE)
        decoded = [[base64.b64decode(item["base64"]) for item in case["files"]] for case in mutants]
        self.assertTrue(all(len(data) <= queen.MAX_CASE_FILE for files in decoded for data in files))
        self.assertTrue(any(files[0] != b"a"*queen.MAX_CASE_FILE for files in decoded))
        self.assertTrue(all(case["steps"] == cases[0]["steps"] for case in mutants))


class DifferentialTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hive-fuzz-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()

    def test_a_mutant_finds_a_rebuild_bug_missing_from_the_plain_cases(self):
        runs = self.root / "runs"
        runs.mkdir()
        calls = []
        def fake_binary(argv, **kwargs):
            self.assertEqual(kwargs["env"], {"PATH":"/usr/bin:/bin","LC_ALL":"C"})
            self.assertEqual(kwargs["timeout"], 20)
            data = (Path(kwargs["cwd"]) / "input.bin").read_bytes()
            value = len(data) + (argv[0] == "rebuilt" and b"\xff" in data)
            calls.append((argv[0], list(argv[1:])))
            return subprocess.CompletedProcess(argv, 0, str(value).encode(), b"")
        mutants = fuzz.generate(CASES, SHA, 100, queen.MAX_CASE_FILE)
        with patch.object(queen.subprocess, "run", side_effect=fake_binary):
            original = queen.run_cases(CASES, "original", runs)
            rebuilt = queen.run_cases(CASES, "rebuilt", runs)
            self.assertEqual(queen.compare(original, rebuilt)[1], [])
            original = queen.run_cases(mutants, "original", runs)
            rebuilt = queen.run_cases(mutants, "rebuilt", runs)
        summary = fuzz.summarise(mutants, original, rebuilt, SHA, queen.compare)
        self.assertTrue(summary["ran"])
        self.assertTrue(summary["different"])
        self.assertEqual(summary["cases"], 100)
        self.assertEqual(summary["identical"] + len(summary["different"]), 100)
        self.assertEqual(list(runs.iterdir()), [])  # the existing executor removes each fresh folder
        path = self.root / "fuzz.json"
        fuzz.write_report(path, summary, mutants)
        report = json.loads(path.read_text())
        self.assertEqual({case["id"] for case in report["inputs"]}, set(summary["different"]))
        self.assertTrue(all(b"\xff" in base64.b64decode(case["files"][0]["base64"]) for case in report["inputs"]))
        self.assertEqual(report["seed"], SHA)

    def test_incomplete_or_timed_out_results_never_count_as_a_fuzz_proof(self):
        mutants = fuzz.generate(CASES, SHA, 2, queen.MAX_CASE_FILE)
        good = {case["id"]:{"steps":[{"code":0}]} for case in mutants}
        for broken in ({}, {mutants[0]["id"]:good[mutants[0]["id"]]},
                       {case["id"]:{"steps":[{"code":"timeout"}]} for case in mutants},
                       {case["id"]:{"steps":[]} for case in mutants}):
            with self.subTest(broken=broken):
                result = fuzz.summarise(mutants, good, broken, SHA, queen.compare)
                self.assertFalse(result["ran"])
                self.assertEqual(result["identical"], 0)


class QueenFuzzTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hive-fuzz-queen-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.input = self.root / "owned-input"
        self.input.write_bytes(b"Owned inert input; every execution is simulated.\n")
        self.out = self.root / "run"
        (self.out / "survey").mkdir(parents=True)
        (self.out / "survey/map.json").write_text("{}")

    def make(self, *, permission=True, total=12, rounds=0):
        def tester(role, name, task, folder):
            self.assertEqual(role, "tester")
            return {"ok":True,"output":{"cases":copy.deepcopy(CASES)}}
        return queen.Queen(engine=SimpleNamespace(path=self.input,file="owned-input"), out=self.out, bees=tester,
                           run_original=permission, fuzz=total, behaviour_rounds=rounds)

    def execution(self, cases, binary, folder):
        return {case["id"]:{"steps":[{"code":0,"out":"same"} for _ in case["steps"]]} for case in cases}

    def conformance(self, q, execution):
        with patch.object(queen, "run_cases", side_effect=execution), contextlib.redirect_stdout(io.StringIO()):
            return q.conformance("first-rebuild", [], self.root / "unused-contract")

    def test_fuzz_runs_after_behaviour_repairs_on_the_final_binary(self):
        q = self.make(rounds=1)
        trace = []
        def execute(cases, binary, folder):
            trace.append((str(binary), [case["id"] for case in cases]))
            answer = self.execution(cases, binary, folder)
            if binary == "first-rebuild":
                for row in answer.values():row["steps"][0]["out"] = "wrong"
            return answer
        with patch.object(q, "behaviour_fix", return_value={"ok":True,"binary":"final-rebuild"}) as repair:
            result = self.conformance(q, execute)
        repair.assert_called_once()
        self.assertEqual([binary for binary, _ in trace][-2:],
                         [str(self.out / "tests/original/owned-input"), "final-rebuild"])
        self.assertEqual(result["cases"], len(CASES) + 12)
        self.assertEqual(result["identical"], result["cases"])
        self.assertEqual(result["different"], [])
        self.assertEqual(result["fuzz"]["cases"], 12)
        self.assertEqual(result["fuzz"]["seed"], hashlib.sha256(self.input.read_bytes()).hexdigest())
        self.assertTrue((self.out / "tests/fuzz.json").is_file())

    def test_fuzz_differences_are_reported_without_starting_a_repair_round(self):
        q = self.make(rounds=2)
        def execute(cases, binary, folder):
            answer = self.execution(cases, binary, folder)
            if binary == "first-rebuild" and cases[0]["id"].startswith("fz-"):
                answer[cases[0]["id"]]["steps"][0]["out"] = "fuzz-only difference"
            return answer
        with patch.object(q, "behaviour_fix", side_effect=AssertionError("no fuzz repair")):
            result = self.conformance(q, execute)
        self.assertEqual(len(result["different"]), 1)
        self.assertTrue(result["different"][0].startswith("fz-"))
        self.assertEqual(result["identical"], result["cases"] - 1)
        report = {"file":"owned-input","input_sha256":SHA,"functions":1,"skipped":0,"modules":{},
                  "link":True,"check":None,"claims":0,"conformance":result,"preflight":None,
                  "verdict":"not accepted","reason":"fuzz difference"}
        self.assertIn("(12 fuzz)",queen.render(report))
        details = json.loads((self.out / "tests/fuzz.json").read_text())
        self.assertEqual([case["id"] for case in details["inputs"]], result["different"])

    def test_missing_fuzz_execution_invalidates_conformance(self):
        q = self.make()
        def execute(cases, binary, folder):
            if binary == "first-rebuild" and cases[0]["id"].startswith("fz-"):
                return {}
            return self.execution(cases, binary, folder)
        result = self.conformance(q, execute)
        self.assertFalse(result["ran"])
        self.assertIn("incomplete", result["reason"])
        self.assertFalse(result["fuzz"]["ran"])

    def test_plain_incomplete_conformance_never_starts_fuzzing(self):
        q = self.make()
        with patch.object(fuzz, "generate", side_effect=AssertionError("plain proof incomplete")):
            result = self.conformance(q, lambda cases, binary, folder: {})
        self.assertFalse(result["ran"])
        self.assertNotIn("fuzz", result)

    def test_off_or_without_permission_never_adds_an_execution_path(self):
        for permission, total in ((True, 0), (False, 12)):
            with self.subTest(permission=permission,total=total), \
                 patch.object(fuzz,"generate",side_effect=AssertionError("fuzz is off")):
                q = self.make(permission=permission,total=total)
                result = self.conformance(q,self.execution)
                self.assertNotIn("fuzz", result)
                self.assertEqual(result["cases"], len(CASES))

    def test_cases_without_files_report_zero_mutants_and_do_not_mutate_arguments(self):
        q = self.make()
        plain = [{"id":"a","steps":[{"args":["literal"]}]}, {"id":"b","steps":[{"args":[]}]}]
        q.bees = lambda *args: {"ok":True,"output":{"cases":copy.deepcopy(plain)}}
        with patch.object(queen,"run_cases",side_effect=self.execution) as execute, \
             contextlib.redirect_stdout(io.StringIO()):
            result = q.conformance("first-rebuild",[],self.root/"unused")
        self.assertEqual(execute.call_count,2)
        self.assertTrue(result["ran"])
        self.assertEqual(result["cases"],2)
        self.assertEqual(result["fuzz"]["cases"],0)
        self.assertIn("no case files",result["fuzz"]["reason"])

    def test_cli_forwards_the_bound_and_original_permission(self):
        with patch.object(queen.bees_module,"environment_ok",return_value=True), \
             patch.object(queen,"Queen") as factory:
            factory.return_value.run.return_value={"verdict":"accepted"}
            self.assertEqual(queen.main(["run","--inputs",str(self.root),"--file",self.input.name,
                                         "--out",str(self.out),"--run-original","--fuzz","15"]),0)
        self.assertEqual(factory.call_args.kwargs["fuzz"],15)
        self.assertTrue(factory.call_args.kwargs["run_original"])
        for value in ("-1","501"):
            with self.subTest(value=value), contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as caught:
                queen.main(["run","--inputs",str(self.root),"--file",self.input.name,"--out",str(self.out),"--fuzz",value])
            self.assertEqual(caught.exception.code,2)


if __name__ == "__main__":
    unittest.main()
