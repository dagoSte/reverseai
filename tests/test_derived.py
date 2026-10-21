"""contract/2 derived evidence: anchored in the input, reviewed as "derived", never verified or contradicting."""

import unittest

from reverseai import claims, report
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

    def test_code_claims_stay_derived_even_under_a_misregistered_spec(self):
        # Decision m3a-derived-claims-by-key: the claim key, not only the spec flag, makes a finding derived.
        # Decision m3c-contract adds assembly, references and referenced strings.
        self.assertEqual(claims.DERIVED_CLAIMS, {"code.functions", "code.pseudocode", "code.calls",
                                                 "code.assembly", "code.references", "code.strings"})
        finding = make_finding("code", "Functions.", "code.functions", ["entry", "helper"], [e.id for e in FUNCTIONS], "inferred")
        self.assertEqual(verdicts([finding], FUNCTIONS, tool(derived=False))[finding.id].status, "derived")

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

    def test_a_pseudocode_claim_cites_exactly_one_function(self):
        first = observed(0, kind="pseudocode", index=0, entry=0x1000, text="int entry(void) {}", truncated=False)
        second = observed(64, kind="pseudocode", index=1, entry=0x1040, text="int entry(void) {}", truncated=False)
        finding = make_finding("code", "Code.", "code.pseudocode", {"entry": 0x1000, "text": "int entry(void) {}", "truncated": False},
                               [first.id, second.id], "inferred")
        self.assertEqual(verdicts([finding], [first, second])[finding.id].status, "unsupported")
        # Two citations with equal values: only the one-observation rule refuses them, whatever the evidence ID order.
        twin = observed(128, kind="pseudocode", index=0, entry=0x1000, text="int entry(void) {}", truncated=False)
        same = make_finding("code", "Code.", "code.pseudocode", {"entry": 0x1000, "text": "int entry(void) {}", "truncated": False},
                            [first.id, twin.id], "inferred")
        self.assertEqual(verdicts([same], [first, twin])[same.id].status, "unsupported")

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

    def test_assembly_claims_cite_exactly_one_listing(self):
        rows = [[0, 1, "PUSH RBP"], [1, 3, "MOV RBP,RSP"]]
        listing = observed(0, kind="assembly", index=0, entry=0x1000, instructions=rows, truncated=False)
        twin = observed(64, kind="assembly", index=1, entry=0x1040, instructions=rows, truncated=False)
        value = {"entry": 0x1000, "instructions": rows, "truncated": False}
        good = make_finding("code", "Code.", "code.assembly", value, [listing.id], "inferred")
        two = make_finding("code", "Code.", "code.assembly", value, [listing.id, twin.id], "inferred")
        changed = make_finding("code", "Code.", "code.assembly", {**value, "truncated": True}, [listing.id], "inferred")
        mixed = make_finding("code", "Code.", "code.assembly", value, [listing.id, FUNCTIONS[0].id], "inferred")
        judged = verdicts([good, two, changed, mixed], [listing, twin, *FUNCTIONS])
        self.assertEqual(judged[good.id].status, "derived")
        self.assertEqual({judged[f.id].status for f in (two, changed, mixed)}, {"unsupported"})

    def test_reference_claims_are_the_sorted_unique_rows(self):
        refs = [observed(0, kind="ref", **{"from": 0x1000}, to=0x3000, type="read", to_name="counter"),
                observed(16, kind="ref", **{"from": 0x1000}, to=0x2000, type="data", to_name=""),
                observed(32, kind="ref", **{"from": 0x1000}, to=0x3000, type="read", to_name="counter")]
        rows = [[0x1000, "data", 0x2000, ""], [0x1000, "read", 0x3000, "counter"]]
        good = make_finding("code", "Refs.", "code.references", rows, [e.id for e in refs], "inferred")
        unsorted = make_finding("code", "Refs.", "code.references", rows[::-1], [e.id for e in refs], "inferred")
        odd = observed(48, kind="ref", **{"from": 0x1000}, to=0x2000, type="call", to_name="")
        typed = make_finding("code", "Refs.", "code.references", [[0x1000, "call", 0x2000, ""]], [odd.id], "inferred")
        judged = verdicts([good, unsorted, typed], [*refs, odd])
        self.assertEqual(judged[good.id].status, "derived")
        self.assertEqual({judged[f.id].status for f in (unsorted, typed)}, {"unsupported"})

    def test_string_claims_list_one_reading_per_address_in_address_order(self):
        def string(offset, address, text, sources=(0x1000,)):
            return observed(offset, kind="string", address=address, encoding="ascii", text=text, truncated=False,
                            **{"from": list(sources)})
        hello, world, again = string(0, 0x2010, "hello"), string(16, 0x2000, "world"), string(0, 0x2010, "hello")
        value = [{"address": 0x2000, "encoding": "ascii", "text": "world", "truncated": False, "from": [0x1000]},
                 {"address": 0x2010, "encoding": "ascii", "text": "hello", "truncated": False, "from": [0x1000]}]
        good = make_finding("code", "Strings.", "code.strings", value, [hello.id, world.id], "inferred")
        self.assertEqual(again.id, hello.id)  # equal content is one evidence record
        clash = string(32, 0x2010, "other")
        disagree = make_finding("code", "Strings.", "code.strings", value, [hello.id, world.id, clash.id], "inferred")
        reordered = make_finding("code", "Strings.", "code.strings", value[::-1], [hello.id, world.id], "inferred")
        judged = verdicts([good, disagree, reordered], [hello, world, clash])
        self.assertEqual(judged[good.id].status, "derived")
        self.assertEqual({judged[f.id].status for f in (disagree, reordered)}, {"unsupported"})

    def test_malformed_code_observations_yield_nothing_rather_than_fail(self):
        bad = [observed(0, kind="ref", **{"from": "x"}, to=1, type="read", to_name=""),
               observed(16, kind="ref", **{"from": 1}, to=None, type="read", to_name=""),
               observed(32, kind="string", address="0x10", text="hi"),
               observed(48, kind="assembly", index=0)]
        for item in bad:
            key = {"ref": "code.references", "string": "code.strings", "assembly": "code.assembly"}[item.observation["kind"]]
            finding = make_finding("code", "Code.", key, [], [item.id], "inferred")
            self.assertEqual(verdicts([finding], [item])[finding.id].status, "unsupported")

    def test_derived_must_be_a_bool(self):
        with self.assertRaises(ContractError):
            OperationSpec("ghidra.analyze", {}, lambda data, args: [], derived="yes")


if __name__ == "__main__":
    unittest.main()
