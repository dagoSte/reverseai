"""Regression oracles for the first Hive queen fix round; all agents are stand-ins."""

import contextlib
import hashlib
import io
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hive import codex_bees, queen
from tests.test_hive_queen import CONTRACT, GOOD, WRONG_EXIT, FakeBees, FakeEngine


class RecordedBees(FakeBees):
    def __init__(self, **kwargs):
        super().__init__(kwargs.pop("sources", GOOD), **kwargs)
        self.trace = []
        self.reviewed = {}
        self.worker_override = None
        self.missing = set()

    def __call__(self, role, name, task, folder):
        folder = Path(folder)
        self.trace.append((role, name))
        if role == "councillor":
            source = next(folder.glob("unit-*"))
            self.reviewed.setdefault(name.split("-")[0], []).append(hashlib.sha256(source.read_bytes()).hexdigest())
            if name.rsplit("-", 1)[-1] in self.missing:
                return {"ok": False, "output": None, "error": "seat unavailable"}
        result = super().__call__(role, name, task, folder)
        if role in ("worker", "repair"):
            entries = {"m01": ["0x1040"], "m02": ["0x1000"]}
            mids = list(self.repaired) if folder.parent.name == "fixes" else [folder.name]
            result["output"] = {"status": "done", "functions": [
                {"entry": entry, "status": "rebuilt"} for mid in mids for entry in entries.get(mid, [])]}
            if role == "worker" and self.worker_override is not None:
                result["output"] = self.worker_override
        return result


@unittest.skipUnless(shutil.which("cc"), "requires a C compiler")
class QueenFixTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hive-queen-fixes-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.inputs = self.root / "inputs"
        self.inputs.mkdir()
        (self.inputs / "greet").write_text("Inert input: behaviour execution is simulated.\n")
        self.run_number = 0

    def make(self, bees=None, **kwargs):
        bees = bees or RecordedBees()
        def check(claims, out):
            bees.trace.append(("check", "check"))
            count = len(json.loads(Path(claims).read_text())["claims"])
            return {"claims": count, "confirmed": count, "rejected": 0, "questions": 1,
                    "input_sha256": ["cd" * 32]}, []
        self.run_number += 1
        q = queen.Queen(engine=FakeEngine(self.inputs), out=self.root / f"run{self.run_number}", bees=bees,
                        check=check, slots=2, compile_rounds=0, **kwargs)
        return q, bees

    def run_quietly(self, q):
        with contextlib.redirect_stdout(io.StringIO()):
            return q.run()

    def test_every_configured_seat_is_required(self):
        q, bees = self.make()
        bees.missing = {"io", "data"}
        result = self.run_quietly(q)
        self.assertEqual(set(result["modules"].values()), {"incomplete"})
        self.assertEqual(result["verdict"], "not accepted")

    def test_a_refused_non_author_majority_is_incomplete(self):
        q, bees = self.make()
        def refused(role, name, task, folder):
            if role == "councillor":
                return {"ok": False, "output": None, "error": codex_bees.NETWORK_REFUSAL}
            return bees(role, name, task, folder)
        q.bees = codex_bees.MixedBees(bees, refused)
        result = self.run_quietly(q)
        self.assertEqual(result["modules"]["m01"], "incomplete")
        self.assertEqual(result["verdict"], "not accepted")

    def test_link_repair_reviews_the_final_source(self):
        fake = RecordedBees(sources={"m01": '#include "contract.h"\n', "m02": GOOD["m02"]},
                            repaired={"m01": GOOD["m01"]})
        q, _ = self.make(fake)
        result = self.run_quietly(q)
        final = hashlib.sha256((q.out / "modules/m01/m01.c").read_bytes()).hexdigest()
        self.assertIn(final, fake.reviewed["m01"])
        self.assertEqual(result["verdict"], "accepted without behaviour proof")

    def test_a_late_council_veto_is_kept_in_the_final_result(self):
        class LateVeto(RecordedBees):
            def __call__(self, role, name, task, folder):
                result = super().__call__(role, name, task, folder)
                if role == "councillor" and name.startswith("m01-council-r2-"):
                    result["output"] = {"verdict": "refute", "defects": [
                        {"function": "greet_line", "problem": "synthetic late veto", "evidence": "0x1040"}]}
                return result
        fake = LateVeto(sources={"m01": '#include "contract.h"\n', "m02": GOOD["m02"]},
                        repaired={"m01": GOOD["m01"]})
        q, _ = self.make(fake)
        result = self.run_quietly(q)
        self.assertEqual(result["modules"]["m01"], "disputed")
        self.assertEqual(result["verdict"], "not accepted")

    def test_behaviour_repair_reviews_then_checks_final_source(self):
        cases = [{"id": "a", "steps": [{"args": []}]}, {"id": "b", "steps": [{"args": ["x"]}]}]
        fake = RecordedBees(sources={"m01": GOOD["m01"], "m02": WRONG_EXIT},
                            repaired={"m02": GOOD["m02"]}, cases=cases)
        q, _ = self.make(fake, run_original=True)
        def execute(cases, binary, folder, timeout=20):
            original = "/original/" in str(binary)
            correct = (q.out / "modules/m02/m02.c").read_text() == GOOD["m02"]
            return {c["id"]: {"steps": [{"code": 0 if original or correct else 1}], "files": {}} for c in cases}
        with patch.object(queen, "run_cases", side_effect=execute):
            result = self.run_quietly(q)
        final = hashlib.sha256((q.out / "modules/m02/m02.c").read_bytes()).hexdigest()
        self.assertIn(final, fake.reviewed["m02"])
        repair_at = fake.trace.index(("repair", "behaviour-fix-1"))
        after = [role for role, _ in fake.trace[repair_at + 1:]]
        self.assertIn("councillor", after)
        self.assertIn("check", after)
        self.assertEqual(result["verdict"], "accepted")

    def test_empty_or_colliding_cases_never_prove_behaviour(self):
        for cases in ([], [{"id": "only", "steps": [{"args": []}]}], [
            {"id": "same/name", "steps": [{"args": []}]},
            {"id": "same?name", "steps": [{"args": []}]}], [
            {"id": "x" * 64 + "a", "steps": [{"args": []}]},
            {"id": "x" * 64 + "b", "steps": [{"args": []}]}]):
            with self.subTest(cases=cases):
                q, _ = self.make(RecordedBees(cases=cases), run_original=True)
                with patch.object(queen, "run_cases", return_value={}) as execute:
                    result = self.run_quietly(q)
                self.assertEqual(result["verdict"], "not accepted")
                self.assertFalse(result["conformance"]["ran"])
                execute.assert_not_called()
                shutil.rmtree(q.out)

    def test_checker_must_report_only_the_target_hash(self):
        for hashes in (None, [], ["ab" * 32], ["cd" * 32, "ab" * 32]):
            with self.subTest(hashes=hashes):
                q, _ = self.make()
                q.check = lambda claims, out: ({"claims": 2, "confirmed": 2, "rejected": 0,
                                                "questions": 1, "input_sha256": hashes}, [])
                result = self.run_quietly(q)
                self.assertEqual(result["verdict"], "not accepted")
                shutil.rmtree(q.out)

    def test_missing_or_timed_out_executions_never_prove_behaviour(self):
        cases = [{"id": "a", "steps": [{"args": []}]}, {"id": "b", "steps": [{"args": []}]}]
        for results in ({}, {c["id"]: {"steps": [{"code": "timeout"}], "files": {}} for c in cases}):
            with self.subTest(results=results):
                q, _ = self.make(RecordedBees(cases=cases), run_original=True)
                with patch.object(queen, "run_cases", return_value=results):
                    result = self.run_quietly(q)
                self.assertEqual(result["verdict"], "not accepted")

    def test_resume_does_not_trust_a_builders_forged_status(self):
        q, bees = self.make()
        self.assertEqual(self.run_quietly(q)["verdict"], "accepted without behaviour proof")
        source = q.out / "modules/m01/m01.c"
        forged = json.loads((source.parent / "status.json").read_text())
        source.write_text(GOOD["m01"] + "\n/* synthetic unreviewed change */\n")
        changed_hash = hashlib.sha256(source.read_bytes()).hexdigest()
        forged.setdefault("compiled", {})["source_sha256"] = changed_hash
        forged.setdefault("reviewed", {})["source_sha256"] = changed_hash
        (source.parent / "status.json").write_text(json.dumps(forged))
        count = bees.calls.count(("worker", "m01-build"))
        try:
            result = self.run_quietly(q)
        except PermissionError as error:
            self.fail(f"resume cannot validate the modified module: {error}")
        self.assertEqual(result["verdict"], "accepted without behaviour proof")
        self.assertEqual(bees.calls.count(("worker", "m01-build")), count + 1)

    def test_citation_file_overrides_cannot_redirect_the_checker(self):
        q, _ = self.make()
        folder = q.out / "modules/m01"
        folder.mkdir(parents=True)
        (folder / "claims.json").write_text(json.dumps({"claims": [{"id": "x", "text": "x", "citations": [
            {"tool": "list_strings", "file": "decoy", "args": {"file": "other"}, "id": "fi-" + "a" * 16}]}]}))
        path, count = q.claims([{"id": "m01"}])
        citation = json.loads(path.read_text())["claims"][0]["citations"][0]
        self.assertNotIn(citation.get("file"), ("decoy", "other"))
        self.assertNotIn(citation.get("args", {}).get("file"), ("decoy", "other"))

    def test_blocked_partial_missing_or_wrong_worker_entries_are_incomplete(self):
        for report in ({"status": "blocked", "functions": []}, {"status": "done", "functions": []},
                       {"status": "partial", "functions": [{"entry": "0x1040", "status": "rebuilt"}]},
                       {"status": "done", "functions": [{"entry": "0xdead", "status": "rebuilt"}]}):
            with self.subTest(report=report):
                q, bees = self.make()
                bees.worker_override = report
                result = self.run_quietly(q)
                self.assertEqual(result["verdict"], "not accepted")
                self.assertIn("incomplete", result["modules"].values())
                shutil.rmtree(q.out)

    def test_frozen_contract_resume(self):
        q, _ = self.make()
        first = self.run_quietly(q)
        try:
            second = self.run_quietly(q)
        except PermissionError as error:
            self.fail(f"resume overwrites the frozen contract: {error}")
        self.assertEqual(first["verdict"], "accepted without behaviour proof")
        self.assertEqual(second["verdict"], first["verdict"])

    def test_relative_output_path(self):
        source, header = self.root / "m.c", self.root / "contract.h"
        source.write_text("int main(void) { return 0; }\n")
        header.write_text("int main(void);\n")
        previous = Path.cwd()
        os.chdir(self.root)
        try:
            result = queen.Build("relative-build").compile("m01", source, header)
        finally:
            os.chdir(previous)
        self.assertTrue(result["ok"], result)


@unittest.skipUnless(shutil.which("cc"), "requires a C compiler")
class CompilerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="hive-compiler-fixes-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name).resolve()
        self.source = self.root / "m01.c"
        self.header = self.root / "contract.h"
        self.secret = self.root / "outside.h"
        self.token = "SYNTHETIC_PRIVATE_HEADER_VALUE_482901"
        self.secret.write_text("#warning " + self.token + "\n")
        self.header.write_text("int main(void);\n")
        self.build = queen.Build(self.root / "build")

    def compile(self, text):
        self.source.write_text(text)
        return self.build.compile("m01", self.source, self.header)

    def test_external_absolute_relative_computed_and_include_next_are_unreadable(self):
        for directive in (f'#include "{self.secret}"', f'#define H "{self.secret}"\n#include H',
                          '#include "../../../outside.h"', f'#include_next "{self.secret}"'):
            with self.subTest(directive=directive):
                result = self.compile(directive + "\nint main(void) { return 0; }\n")
                self.assertNotIn(self.token, json.dumps(result))
                self.assertFalse(result["ok"], result)

    def test_has_include_cannot_observe_an_external_file(self):
        result = self.compile(f'#if __has_include("{self.secret}")\n#error EXTERNAL_EXISTS\n#endif\n'
                              'int main(void) { return 0; }\n')
        self.assertTrue(result["ok"], result)

    def test_macro_assembly_and_header_assembly_are_rejected(self):
        result = self.compile('#define JOIN(a,b) a ## b\nint main(void) { JOIN(__as,m__)("nop"); return 0; }\n')
        self.assertFalse(result["ok"], result)
        self.header.write_text('#define SAFE_NOP __asm__\nint main(void);\n')
        result = self.compile('#include "contract.h"\nint main(void) { SAFE_NOP("nop"); return 0; }\n')
        self.assertFalse(result["ok"], result)

    def test_planner_header_has_the_same_boundary(self):
        self.header.write_text(f'#include "{self.secret}"\n')
        ok, diagnostics = self.build.syntax(self.header)
        self.assertNotIn(self.token, diagnostics)
        self.assertFalse(ok)

    def test_external_diagnostics_are_not_forwarded_to_a_repair_bee(self):
        self.source.write_text(f'#include "{self.secret}"\nint main(void) {{ return 0; }}\n')
        prompts = []
        def repair(role, name, task, folder):
            prompts.append(task)
            return {"ok": False, "output": None}
        q = queen.Queen(engine=None, out=self.root / "repair-run", bees=repair, compile_rounds=1)
        with contextlib.redirect_stdout(io.StringIO()):
            result = q.compile_loop("m01", self.root, self.source, self.header, {})
        self.assertFalse(result["ok"])
        self.assertTrue(prompts)
        self.assertNotIn(self.token, "\n".join(prompts))

    def test_a_symlink_source_is_not_copied_into_the_stage(self):
        self.source.symlink_to(self.secret)
        result = self.build.compile("m01", self.source, self.header)
        self.assertFalse(result["ok"], result)
        self.assertNotIn(self.token, json.dumps(result))

    def test_standard_headers_and_frozen_contract_still_compile(self):
        self.header.write_text('#include <stdio.h>\nint main(void);\n')
        result = self.compile('#include "contract.h"\nint main(void) { return puts("safe"); }\n')
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["warnings"], "")


if __name__ == "__main__":
    unittest.main()
