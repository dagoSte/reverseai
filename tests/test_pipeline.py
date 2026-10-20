import contextlib
import io
import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest import mock

from reverseai import cli, pipeline, report
from reverseai.analysts import capability
from reverseai.contract import Budget, ContractError, InputRef, evidence_intact, make_finding, sha256_hex
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

    def test_analyst_cannot_alter_the_gateway_evidence(self):
        class Tampering:
            plan = staticmethod(pipeline.ANALYSTS[0].plan)

            @staticmethod
            def conclude(task, evidence):
                for item in evidence:
                    if "format" in item.observation:
                        item.observation["format"] = "elf"
                return pipeline.ANALYSTS[0].conclude(task, evidence)

        data = pe()[0]
        analysis = pipeline.analyze_bytes(data, ref(data), analysts=(Tampering,))
        result = analysis.results[0]
        self.assertTrue(all(evidence_intact(item) for item in result.evidence))
        self.assertEqual({item.observation.get("format") for item in result.evidence} - {None}, {"pe"})
        claimed = findings(analysis)[("structural", "format.container")]
        self.assertEqual(claimed.value, "elf")
        self.assertEqual(verdicts(analysis)[claimed.id].status, "unsupported")

    def test_budget_exhaustion_is_reported_not_raised(self):
        data = pe()[0] + known_strings()[0]
        analysis = pipeline.analyze_bytes(data, ref(data), budget=Budget(max_evidence=4))
        self.assertIn("budget_exceeded", {r.status for r in analysis.results})
        self.assertNotIn("contradicted", {v.status for v in analysis.verdicts})
        self.assertIn("budget_exceeded", report.to_markdown(analysis))


class HostileTextTests(unittest.TestCase):
    NAMES = (b"<img src=x onerror=alert(1)>", b"[click](https://evil.example/x)", b"![p](http://e.invalid/p.png)")

    def test_sample_text_renders_only_inside_code_spans(self):
        data = elf(sections=tuple((name, 1, 0x7, 8) for name in self.NAMES))[0]
        analysis = pipeline.analyze_bytes(data, ref(data))
        names = findings(analysis)[("structural", "sections.writable_executable")].value
        self.assertEqual(sorted(names), sorted(name.decode() for name in self.NAMES))
        table = [line for line in report.to_markdown(analysis).splitlines() if line.startswith("|")]
        hostile = 0
        for line in table:
            for cell in re.split(r"(?<!\\)\|", line)[1:-1]:
                cell = cell.strip()
                if any(marker in cell for marker in ("<", "](", "://")):
                    hostile += 1
                    self.assertTrue(cell.startswith("`") and cell.endswith("`") and "`" not in cell[1:-1], cell)
        self.assertGreater(hostile, 0)


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

    def test_reports_are_private(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.bin"), Path(temporary, "report")
            sample.write_bytes(elf()[0])
            self.assertEqual(self.run_cli("analyze", str(sample), "--out", str(out))[0], 0)
            self.assertEqual(out.stat().st_mode & 0o777, 0o700)
            for name in ("report.json", "report.md"):
                self.assertEqual((out / name).stat().st_mode & 0o777, 0o600)

    def test_swapping_the_output_path_during_analysis_cannot_redirect_reports(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.bin"), Path(temporary, "report")
            moved, elsewhere = Path(temporary, "moved"), Path(temporary, "elsewhere")
            sample.write_bytes(elf()[0])
            elsewhere.mkdir()
            original = pipeline.analyze_bytes

            def swap_then_analyze(*args, **kwargs):
                os.rename(out, moved)
                os.symlink(elsewhere, out)
                return original(*args, **kwargs)

            with mock.patch.object(pipeline, "analyze_bytes", swap_then_analyze):
                code, _, _ = self.run_cli("analyze", str(sample), "--out", str(out))
            self.assertEqual(code, 0)
            self.assertEqual(list(elsewhere.iterdir()), [])
            self.assertEqual(sorted(p.name for p in moved.iterdir()), ["report.json", "report.md"])

    def test_output_failures_are_short_and_name_what_was_written(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.bin"), Path(temporary, "report")
            sample.write_bytes(elf()[0])
            out.mkdir()
            out.chmod(0o500)
            try:
                code, stdout, err = self.run_cli("analyze", str(sample), "--out", str(out))
            finally:
                out.chmod(0o700)
            self.assertEqual((code, stdout), (1, ""))
            self.assertEqual(err, "reverseai: output failed: PermissionError; written: nothing\n")
            other = Path(temporary, "other")
            with mock.patch.object(report, "to_markdown", side_effect=ValueError("secret /path")):
                code, _, err = self.run_cli("analyze", str(sample), "--out", str(other))
            self.assertEqual(code, 1)
            self.assertEqual(err, "reverseai: output failed: ValueError; written: report.json\n")
            self.assertNotIn(temporary, err)

    def test_unreadable_output_directory_is_refused_without_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.bin"), Path(temporary, "locked", "report")
            sample.write_bytes(elf()[0])
            out.parent.mkdir()
            out.parent.chmod(0)
            try:
                code, _, err = self.run_cli("analyze", str(sample), "--out", str(out))
            finally:
                out.parent.chmod(0o700)
            self.assertEqual(code, 1)
            self.assertTrue(err.startswith("reverseai: output refused:") or err.startswith("reverseai: --out must be"), err)
            self.assertNotIn(temporary, err)
            self.assertNotIn("Traceback", err)

    def test_an_unreadable_empty_output_directory_is_refused_without_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.bin"), Path(temporary, "report")
            sample.write_bytes(elf()[0])
            out.mkdir()
            out.chmod(0)
            try:
                code, _, err = self.run_cli("analyze", str(sample), "--out", str(out))
            finally:
                out.chmod(0o700)
            self.assertEqual((code, err), (1, "reverseai: --out must be a new or empty directory\n"))

    def test_analysis_errors_are_not_reported_as_output_errors(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample, out = Path(temporary, "sample.bin"), Path(temporary, "report")
            sample.write_bytes(elf()[0])
            with mock.patch.object(pipeline, "analyze_bytes", side_effect=ContractError("detail")):
                code, _, err = self.run_cli("analyze", str(sample), "--out", str(out))
            self.assertEqual((code, err), (1, "reverseai: analysis failed: ContractError\n"))

    def test_uncreatable_output_is_refused_without_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            sample = Path(temporary, "sample.bin")
            sample.write_bytes(elf()[0])
            code, _, err = self.run_cli("analyze", str(sample), "--out", str(Path(temporary, "missing", "report")))
            self.assertEqual(code, 1)
            self.assertEqual(err, "reverseai: output refused: --out cannot be created\n")


if __name__ == "__main__":
    unittest.main()
