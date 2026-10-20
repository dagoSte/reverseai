import json
import unittest

from reverseai import report
from reverseai.report import Analysis
from reverseai.contract import (
    AnalysisResult, InputRef, Location, Observation, ReviewVerdict, ToolRef, make_evidence, make_finding, sha256_hex,
)

DATA = b"MZ" + bytes(62) + b"http://example.invalid/a|b`c\x00"
TOOL = ToolRef("strings", "0.1.0")


def analysis(verdict_status="supported"):
    evidence = make_evidence(DATA, TOOL, "strings.extract", Observation(Location(64, 27), {"text": "http://example.invalid/a|b`c"}))
    finding = make_finding("capability", "The input contains a URL.", "strings.urls", ["http://example.invalid/a|b`c"], [evidence.id])
    orphan = make_finding("capability", "Claim with no evidence.", "capability.network", ["net"], [], "inferred")
    result = AnalysisResult("tk-0123456789abcdef", "capability", "ok", (evidence,), (finding, orphan))
    verdicts = (
        ReviewVerdict(finding.id, verdict_status, () if verdict_status == "supported" else ("cited evidence failed",)),
        ReviewVerdict(orphan.id, "unsupported", ("no evidence cited",)),
    )
    ref = InputRef(sha256_hex(DATA), len(DATA), "sample.exe")
    return Analysis(ref, (TOOL,), (result,), verdicts)


class ReportTests(unittest.TestCase):
    def test_json_is_deterministic_and_complete(self):
        first, second = report.to_json(analysis()), report.to_json(analysis())
        self.assertEqual(first, second)
        data = json.loads(first)
        self.assertEqual(data["contract"], "reverseai.contract/1")
        self.assertEqual(data["input"]["sha256"], sha256_hex(DATA))
        self.assertEqual(data["summary"], {"supported": 1, "unsupported": 1, "contradicted": 0, "unreviewed": 0})
        verdicts = {f["claim_key"]: f["verdict"] for f in data["results"][0]["findings"]}
        self.assertEqual(verdicts, {"strings.urls": "supported", "capability.network": "unsupported"})

    def test_unreviewed_findings_are_counted_not_hidden(self):
        partial = analysis()
        partial = Analysis(partial.input, partial.tools, partial.results, partial.verdicts[:1])
        data = report.to_dict(partial)
        self.assertEqual(data["summary"]["unreviewed"], 1)

    def test_markdown_separates_rejected_claims_and_escapes_cells(self):
        text = report.to_markdown(analysis())
        supported, rejected = text.split("## Rejected or unreviewed claims")
        self.assertIn("The input contains a URL.", supported)
        self.assertIn("strings.extract @ 64+27", supported)
        self.assertIn("Claim with no evidence.", rejected)
        self.assertNotIn("Claim with no evidence.", supported)
        self.assertIn("a\\|b'c", supported)
        self.assertIn("The sample was not executed.", text)

    def test_long_cells_are_visibly_truncated(self):
        self.assertEqual(report._cell("x" * 300), "x" * 199 + "…")
        self.assertEqual(report._cell("|" * 150), "\\|" * 99 + "…")

    def test_no_supported_findings(self):
        text = report.to_markdown(analysis("unsupported"))
        self.assertIn("No finding was supported by the evidence.", text)


if __name__ == "__main__":
    unittest.main()
