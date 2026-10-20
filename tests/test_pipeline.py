import contextlib
import io
import json
import os
from pathlib import Path
import tempfile
import unittest

from reverseai import cli, pipeline, report
from reverseai.analysts import capability
from reverseai.contract import Budget, InputRef, make_finding, sha256_hex
from tests.fixtures_strings import KNOWN, clean_control, known_strings
from tests.fixtures_structure import elf, pe


def ref(data, name="sample.bin"):
    return InputRef(sha256_hex(data), len(data), name)


def findings(analysis):
    return {(r.role, f.claim_key): f for r in analysis.results for f in r.findings}


def verdicts(analysis):
    return {v.finding_id: v for v in analysis.verdicts}


def expected_capabilities():
    expected = {}
    for _, rule, category in KNOWN:
        expected.setdefault("capability." + category, set()).add(rule)
    expected = {key: sorted(rules) for key, rules in expected.items()}
    expected["strings.urls"] = sorted(match for match, rule, _ in KNOWN if rule == "url")
    return expected


class Fabricating:
    """An untrusted capability analyst that adds claims its evidence does not support."""

    plan = staticmethod(capability.plan)

    @staticmethod
    def conclude(task, evidence):
        return capability.conclude(task, evidence) + (
            make_finding("capability", "Invented: the input is an ELF file.", "format.container", "elf", []),
            make_finding("capability", "Invented: ransomware.", "capability.ransomware", ["encrypt_all"], ["ev-0000000000000000"]),
        )


class PipelineKnownAnswerTests(unittest.TestCase):
    def test_pe_with_indicator_strings(self):
        data = pe()[0] + known_strings()[0]
        analysis = pipeline.analyze_bytes(data, ref(data, "sample.exe"))
        self.assertEqual([(r.role, r.status, r.errors) for r in analysis.results], [("structural", "ok", ()), ("capability", "ok", ())])
        found = findings(analysis)
        expected = {
            ("structural", "format.container"): "pe",
            ("structural", "format.machine"): "x86_64",
            ("structural", "format.section_count"): 3,
            ("structural", "sections.writable_executable"): [".rwx"],
            **{("capability", key): value for key, value in expected_capabilities().items()},
        }
        self.assertEqual({key: f.value for key, f in found.items()}, expected)
        self.assertEqual({v.status for v in analysis.verdicts}, {"supported"})
        self.assertEqual(len(analysis.verdicts), len(expected))
        self.assertEqual(report.to_dict(analysis)["summary"], {"supported": len(expected), "unsupported": 0, "contradicted": 0, "unreviewed": 0})

    def test_clean_elf_control_has_no_capability_findings(self):
        data = elf()[0] + clean_control()
        analysis = pipeline.analyze_bytes(data, ref(data))
        found = findings(analysis)
        self.assertEqual(found[("structural", "format.container")].value, "elf")
        self.assertEqual(found[("structural", "format.machine")].value, "x86_64")
        self.assertFalse([key for key in found if key[0] == "capability"])
        self.assertEqual({v.status for v in analysis.verdicts}, {"supported"})

    def test_report_is_deterministic(self):
        data = pe()[0] + known_strings()[0]
        first = report.to_json(pipeline.analyze_bytes(data, ref(data)))
        self.assertEqual(first, report.to_json(pipeline.analyze_bytes(data, ref(data))))

    def test_fabricated_claims_are_rejected_and_cannot_cancel_verified_ones(self):
        data = pe()[0] + known_strings()[0]
        analysis = pipeline.analyze_bytes(data, ref(data), analysts=(pipeline.ANALYSTS[0], Fabricating))
        found, judged = findings(analysis), verdicts(analysis)
        self.assertEqual(judged[found[("capability", "format.container")].id].status, "unsupported")
        self.assertEqual(judged[found[("capability", "capability.ransomware")].id].status, "unsupported")
        self.assertEqual(judged[found[("structural", "format.container")].id].status, "supported")
        rendered = report.to_markdown(analysis).split("## Rejected or unreviewed claims")
        self.assertNotIn("Invented", rendered[0])
        self.assertIn("Invented: ransomware.", rendered[1])

    def test_budget_exhaustion_is_reported_not_raised(self):
        data = pe()[0] + known_strings()[0]
        analysis = pipeline.analyze_bytes(data, ref(data), budget=Budget(max_evidence=4))
        self.assertIn("budget_exceeded", {r.status for r in analysis.results})
        self.assertNotIn("contradicted", {v.status for v in analysis.verdicts})
        self.assertIn("budget_exceeded", report.to_markdown(analysis))


class CliTests(unittest.TestCase):
    def run_cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            try:
                code = cli.main(list(argv))
            except SystemExit as exit:
                code = exit.code
        return code, out.getvalue(), err.getvalue()

    def test_analyze_writes_both_reports_without_host_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.exe"), Path(temporary, "report")
            sample.write_bytes(pe()[0] + known_strings()[0])
            code, stdout, _ = self.run_cli("analyze", str(sample), "--out", str(out))
            self.assertEqual(code, 0)
            self.assertTrue(stdout.startswith(sha256_hex(sample.read_bytes())))
            data = json.loads((out / "report.json").read_text())
            self.assertEqual(data["input"]["name"], "sample.exe")
            self.assertEqual(data["summary"]["supported"], 10)
            for name in ("report.json", "report.md"):
                self.assertNotIn(temporary, (out / name).read_text())

    def test_refuses_used_output_and_unsafe_input(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.bin"), Path(temporary, "report")
            sample.write_bytes(elf()[0])
            self.assertEqual(self.run_cli("analyze", str(sample), "--out", str(out))[0], 0)
            code, _, err = self.run_cli("analyze", str(sample), "--out", str(out))
            self.assertEqual(code, 1)
            self.assertIn("new or empty directory", err)
            link = Path(temporary, "link.bin")
            os.symlink(sample, link)
            code, _, err = self.run_cli("analyze", str(link), "--out", str(Path(temporary, "other")))
            self.assertEqual(code, 1)
            self.assertIn("input refused", err)
            self.assertNotIn(temporary, err)
            self.assertFalse(Path(temporary, "other").exists())


if __name__ == "__main__":
    unittest.main()
