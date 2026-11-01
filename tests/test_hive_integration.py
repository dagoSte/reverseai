import argparse
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from tests.hive_compiler import confined
from hive import codex_bees, preflight, queen
from tests.test_hive_queen import FakeBees, FakeEngine, GOOD

PACKED = {"verdict": "packed", "packers": ["UPX"], "signals": [
    {"strength": "strong", "signal": "packer section", "detail": "segment named 'UPX1' belongs to UPX"}],
    "advice": "Unpack it first.", "file_entropy": 7.9, "executable_bytes": 1}
CLEAN = {"verdict": "clean", "packers": [], "signals": [], "advice": "", "file_entropy": 5.0, "executable_bytes": 1}


class IntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "inputs").mkdir()
        (self.tmp / "inputs" / "greet").write_bytes(b"x")

    def queen(self, bees, verdict, **kwargs):
        def check(claims, out):
            return {"claims": 1, "confirmed": 1, "rejected": 0, "questions": 1,
                    "input_sha256": ["cd" * 32]}, []
        return queen.Queen(engine=FakeEngine(self.tmp / "inputs"), out=self.tmp / "run", bees=bees, slots=2,
                           check=check, preflight=lambda engine, program_map, folder: verdict, **kwargs)

    def test_a_packed_program_stops_before_any_bee(self):
        bees = FakeBees(GOOD)
        result = self.queen(bees, PACKED).run()
        self.assertEqual(result["verdict"], "not started")
        self.assertIn("UPX", result["reason"])
        self.assertEqual(bees.calls, [])
        report = (self.tmp / "run" / "REPORT.md").read_text()
        self.assertIn("Pre-flight: packed", report)
        self.assertIn("Language: not chosen", report)

    @unittest.skipUnless(confined("c"), "needs a Clang compiler the hive can confine")
    def test_the_operator_can_allow_a_packed_program(self):
        bees = FakeBees(GOOD)
        result = self.queen(bees, PACKED, allow_packed=True).run()
        self.assertTrue(bees.calls)
        self.assertEqual(result["preflight"]["verdict"], "packed")

    @unittest.skipUnless(confined("c"), "needs a Clang compiler the hive can confine")
    def test_a_clean_program_runs_and_reports_its_preflight(self):
        result = self.queen(FakeBees(GOOD), CLEAN).run()
        self.assertEqual(result["verdict"], "accepted without behaviour proof")
        self.assertIn("Pre-flight: clean", (self.tmp / "run" / "REPORT.md").read_text())

    def test_main_options_choose_the_bee_runner(self):
        parser = argparse.ArgumentParser()
        codex_bees.add_arguments(parser)
        claude = object()
        kwargs = {"engine": self.tmp, "inputs": self.tmp / "inputs", "config_dir": self.tmp / "codex"}
        self.assertIs(codex_bees.build(parser.parse_args([]), claude, **kwargs), claude)
        self.assertIsInstance(codex_bees.build(parser.parse_args(["--bee-policy", "codex"]), claude, **kwargs),
                              codex_bees.CodexBees)
        mixed = codex_bees.build(parser.parse_args(["--bee-policy", "mixed"]), claude, **kwargs)
        self.assertIsInstance(mixed, codex_bees.MixedBees)
        self.assertIs(mixed.claude, claude)

    def test_the_command_line_offers_language_preflight_and_policy(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            queen.main(["run", "--help"])
        for option in ("--language", "--allow-packed", "--bee-policy", "--codex-model", "--run-original"):
            self.assertIn(option, out.getvalue())

if __name__ == "__main__":
    unittest.main()
