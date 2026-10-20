"""contract/2 derived evidence: anchored in the input, reviewed as "derived", never verified or contradicting."""

import unittest

from reverseai import report
from reverseai.contract import (
    AnalysisResult, ContractError, InputRef, Location, Observation, OperationSpec, ToolRef, ToolSpec,
    content_id, make_evidence, make_finding, sha256_hex,
)
from reverseai.review import review

DATA = bytes(range(256)) * 4
INPUT = InputRef(sha256_hex(DATA), len(DATA), "sample.bin")
GHIDRA = ToolRef("ghidra", "12.1.4-r1")
TASK = content_id("tk", {"test": "derived"})


def tool(derived=True):
    operation = OperationSpec("ghidra.analyze", {}, lambda data, args: [], max_observations=400, derived=derived)
    return {"ghidra": ToolSpec(GHIDRA, {"ghidra.analyze": operation})}


def observed(offset, **value):
    return make_evidence(DATA, GHIDRA, "ghidra.analyze", Observation(Location(offset, 16), value))


def verdicts(findings, evidence, tools=None):
    result = AnalysisResult(TASK, "code", "ok", tuple(evidence), tuple(findings))
    return {v.finding_id: v for v in review(DATA, INPUT, [result], tools or tool())}


FUNCTIONS = [observed(0, kind="function", index=0, name="entry", entry=0x1000, size=32),
             observed(64, kind="function", index=1, name="helper", entry=0x1040, size=16)]


class DerivedTests(unittest.TestCase):
    def test_a_derived_operation_yields_a_derived_verdict_with_a_reason(self):
        finding = make_finding("code", "Functions.", "code.functions", ["entry", "helper"], [e.id for e in FUNCTIONS], "inferred")
        verdict = verdicts([finding], FUNCTIONS)[finding.id]
        self.assertEqual(verdict.status, "derived")
        self.assertIn("not verified against the bytes", verdict.reasons[0])

    def test_the_same_evidence_from_a_non_derived_operation_is_supported(self):
        finding = make_finding("code", "Functions.", "code.functions", ["entry", "helper"], [e.id for e in FUNCTIONS], "inferred")
        self.assertEqual(verdicts([finding], FUNCTIONS, tool(derived=False))[finding.id].status, "supported")

    def test_derived_claims_still_need_their_rule_confidence_and_value(self):
        overstated = make_finding("code", "Functions.", "code.functions", ["entry", "helper"], [e.id for e in FUNCTIONS], "observed")
        wrong = make_finding("code", "Functions.", "code.functions", ["helper", "entry"], [e.id for e in FUNCTIONS], "inferred")
        judged = verdicts([overstated, wrong], FUNCTIONS)
        self.assertEqual({judged[f.id].status for f in (overstated, wrong)}, {"unsupported"})

    def test_derived_findings_neither_contradict_nor_are_contradicted(self):
        first = observed(0, kind="pseudocode", index=0, entry=0x1000, text="int entry(void) {}", truncated=False)
        second = observed(64, kind="pseudocode", index=1, entry=0x1040, text="void helper(void) {}", truncated=False)
        findings = [make_finding("code", "Code.", "code.pseudocode", {"entry": e.observation["entry"], "text": e.observation["text"],
                                                                     "truncated": False}, [e.id], "inferred") for e in (first, second)]
        self.assertEqual({v.status for v in verdicts(findings, [first, second]).values()}, {"derived"})

    def test_an_anchor_that_no_longer_matches_the_bytes_is_unsupported(self):
        evidence = observed(0, kind="function", index=0, name="entry", entry=0x1000, size=32)
        finding = make_finding("code", "Functions.", "code.functions", ["entry"], [evidence.id], "inferred")
        changed = bytes([DATA[0] ^ 1]) + DATA[1:]
        result = AnalysisResult(TASK, "code", "ok", (evidence,), (finding,))
        verdict = review(changed, InputRef(sha256_hex(changed), len(changed), "x"), [result], tool())[0]
        self.assertEqual(verdict.status, "unsupported")

    def test_reports_count_and_list_derived_findings_separately(self):
        finding = make_finding("code", "Functions.", "code.functions", ["entry", "helper"], [e.id for e in FUNCTIONS], "inferred")
        result = AnalysisResult(TASK, "code", "ok", tuple(FUNCTIONS), (finding,))
        analysis = report.Analysis(INPUT, (GHIDRA,), (result,), review(DATA, INPUT, [result], tool()))
        self.assertEqual(report.to_dict(analysis)["summary"]["derived"], 1)
        supported, derived = report.to_markdown(analysis).split("## Derived by analysis tools (not verified against the bytes)")
        self.assertIn("No finding was supported", supported)
        self.assertIn("Functions the analysis tool identified", derived.split("## Rejected")[0])

    def test_derived_must_be_a_bool(self):
        with self.assertRaises(ContractError):
            OperationSpec("ghidra.analyze", {}, lambda data, args: [], derived="yes")


if __name__ == "__main__":
    unittest.main()
