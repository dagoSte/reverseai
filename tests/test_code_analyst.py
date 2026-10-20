"""Inert code observations and reviewer checks; no Ghidra, Docker or input execution."""

import copy
from dataclasses import replace
from types import SimpleNamespace
import unittest

from reverseai.analysts import code
from reverseai.contract import (
    MAX_EVIDENCE_PER_FINDING, AnalysisResult, ArgSpec, ContractError, Evidence, InputRef, Location, Observation,
    OperationRequest, OperationSpec, ToolRef, ToolSpec, content_id, evidence_id, make_evidence, sha256_hex,
)
from reverseai.review import review


DATA = bytes(range(256)) * 32
INPUT = InputRef(sha256_hex(DATA), len(DATA), "inline.bin")
REF = ToolRef("ghidra", "12.1.4-r3")


def tool(*, ref=REF, derived=True, operation="ghidra.analyze"):
    args = {"max_functions": ArgSpec("int", 1, 128, default=64),
            "decompile": ArgSpec("int", 0, 16, default=8),
            "max_chars": ArgSpec("int", 64, 2048, default=1024),
            "max_calls": ArgSpec("int", 0, 256, default=128)}
    spec = OperationSpec(operation, args, lambda data, args: (), max_observations=400, derived=derived)
    return ToolSpec(ref, {operation: spec})


def observed(offset=0, *, data=DATA, ref=REF, operation="ghidra.analyze", length=16, **value):
    return make_evidence(data, ref, operation, Observation(Location(offset, length), value))


def function(index=0, *, name="entry", **options):
    return observed(index * 32, kind="function", index=index, name=name, entry=0x1000 + index * 32, size=32, **options)


def pseudocode(index=0, *, text="void entry(void) {}", truncated=False):
    return observed(index * 32, kind="pseudocode", index=index, entry=0x1000 + index * 32,
                    text=text, truncated=truncated)


def call(offset=4, *, source=0x1000, target=0x1020, name="helper"):
    return observed(offset, length=5, **{"kind": "call", "from": source, "to": target, "to_name": name})


class CodeAnalystTests(unittest.TestCase):
    def setUp(self):
        self.tool = tool()
        self.task = code.plan(INPUT, tools=(self.tool,))

    def verdicts(self, evidence, findings=None, *, data=DATA, input=INPUT):
        findings = code.conclude(self.task, evidence) if findings is None else findings
        result = AnalysisResult(self.task.id, "code", "ok", tuple(evidence), findings)
        return review(data, input, (result,), {"ghidra": self.tool})

    def test_plan_is_optional_and_requires_the_exact_derived_operation(self):
        self.assertIsNone(code.plan(INPUT))
        for other in (tool(ref=ToolRef("ghidra", "12.1.4-r1")), tool(ref=ToolRef("ghidra", "12.1.4-r2")),
                      tool(derived=False), tool(operation="ghidra.other")):
            with self.subTest(tool=other.ref, operations=tuple(other.operations)):
                self.assertIsNone(code.plan(INPUT, tools=(other,)))
        self.assertIsNone(code.plan(INPUT, tools=(ToolSpec(REF, {}),)))

    def test_plan_is_content_bound_deterministic_and_uses_only_defaults(self):
        self.assertEqual(self.task.role, "code")
        self.assertEqual(self.task.id, content_id("tk", {"input": INPUT.sha256, "role": "code"}))
        self.assertEqual(self.task.operations, (OperationRequest("ghidra.analyze"),))
        self.assertEqual(self.tool.operations["ghidra.analyze"].validate_args(self.task.operations[0].args),
                         {"decompile": 8, "max_calls": 128, "max_chars": 1024, "max_functions": 64})
        self.assertEqual(self.task, code.plan(INPUT, tools=(self.tool, self.tool)))
        self.assertEqual(self.task.id, code.plan(replace(INPUT, name="alias"), tools=(self.tool,)).id)
        self.assertNotEqual(self.task.id, code.plan(replace(INPUT, sha256="f" * 64), tools=(self.tool,)).id)
        self.assertEqual((self.task.budget.max_operations, self.task.budget.max_concurrency,
                          self.task.budget.max_wall_seconds), (1, 1, 300))

    def test_exact_values_and_citations_are_all_inferred_and_derived(self):
        evidence = (function(1, name="helper"), pseudocode(1, truncated=True), call(9), function(),
                    pseudocode(), call())
        findings = code.conclude(self.task, evidence)
        functions = next(f for f in findings if f.claim_key == "code.functions")
        calls = next(f for f in findings if f.claim_key == "code.calls")
        texts = [f for f in findings if f.claim_key == "code.pseudocode"]
        self.assertEqual(functions.value, ["entry", "helper"])
        self.assertEqual(set(functions.evidence_ids), {evidence[0].id, evidence[3].id})
        self.assertEqual(calls.value, [[0x1000, "helper"]])
        self.assertEqual(set(calls.evidence_ids), {evidence[2].id, evidence[5].id})
        self.assertEqual([f.value for f in texts], [
            {"entry": 0x1000, "text": "void entry(void) {}", "truncated": False},
            {"entry": 0x1020, "text": "void entry(void) {}", "truncated": True}])
        self.assertEqual([f.evidence_ids for f in texts], [(evidence[4].id,), (evidence[1].id,)])
        self.assertTrue(all(f.role == "code" and f.confidence == "inferred" for f in findings))
        self.assertEqual({v.status for v in self.verdicts(evidence, findings)}, {"derived"})
        self.assertEqual(findings, code.conclude(self.task, tuple(reversed(evidence))))
        self.assertEqual(findings, code.conclude(self.task, evidence + evidence))

    def test_empty_foreign_role_and_unplanned_operation_produce_no_findings(self):
        self.assertEqual(code.conclude(self.task, ()), ())
        self.assertEqual(code.conclude(replace(self.task, role="capability"), (function(),)), ())
        other = replace(self.task, operations=(OperationRequest("ghidra.other"),))
        self.assertEqual(code.conclude(other, (function(),)), ())

    def test_foreign_input_tool_version_and_operation_are_not_cited(self):
        value = dict(function().observation)
        foreign = (
            observed(data=DATA[:-1] + b"!", **value),
            observed(ref=ToolRef("ghidra", "12.1.4-r1"), **value),
            observed(ref=ToolRef("ghidra", "12.1.4-r2"), **value),
            observed(ref=ToolRef("other", "12.1.4-r1"), operation="other.analyze", **value),
            observed(operation="ghidra.other", **value),
        )
        self.assertEqual(code.conclude(self.task, foreign), ())
        self.assertEqual(self.verdicts(foreign), ())
        honest = function()
        self.assertEqual(code.conclude(self.task, (*foreign, honest)), code.conclude(self.task, (honest,)))

    def test_an_out_of_range_anchor_cannot_be_cited_even_with_an_intact_forged_record(self):
        value = dict(function().observation)
        observation = Observation(Location(len(DATA), 16), value)
        outside = make_evidence(DATA + bytes(32), REF, "ghidra.analyze", observation, input_sha256=INPUT.sha256)
        self.assertEqual(code.conclude(self.task, (outside,)), ())

    def test_mutated_evidence_ids_or_observations_are_ignored(self):
        for field in ("id", "observation"):
            item = copy.deepcopy(function())
            if field == "id":
                object.__setattr__(item, "id", "ev-0000000000000000")
            else:
                item.observation["name"] = "invented"
            with self.subTest(field=field):
                self.assertEqual(code.conclude(self.task, (item,)), ())
        self.assertEqual(code.conclude(self.task, (None, {}, "evidence")), ())

    def test_a_rebound_false_excerpt_is_rejected_by_the_reviewer(self):
        item = function()
        fields = dict(input_sha256=item.input_sha256, tool=item.tool, operation=item.operation,
                      location=item.location, excerpt_sha256="f" * 64, observation=item.observation)
        forged = Evidence(id=evidence_id(**fields), **fields)
        verdicts = self.verdicts((forged,))
        self.assertTrue(verdicts)
        self.assertEqual({v.status for v in verdicts}, {"unsupported"})
        self.assertIn("excerpt hash mismatch", verdicts[0].reasons[0])

    def test_changed_input_bytes_cannot_get_a_derived_or_supported_verdict(self):
        evidence = (function(), pseudocode(), call())
        changed = b"!" + DATA[1:]
        verdicts = self.verdicts(evidence, data=changed, input=InputRef(sha256_hex(changed), len(changed), "changed"))
        self.assertEqual({v.status for v in verdicts}, {"unsupported"})

    def test_unknown_or_malformed_observations_do_not_create_claims(self):
        values = [dict(function().observation), dict(pseudocode().observation), dict(call().observation)]
        invalid = [{"kind": "unrecognized"}, {"kind": []}]
        for value in values:
            for field in value:
                changed = dict(value)
                del changed[field]
                invalid.append(changed)
            invalid.append(dict(value, extra="unexpected"))
        invalid.extend((dict(values[0], index=True), dict(values[0], index=-1), dict(values[0], index=128),
                        dict(values[0], entry=-1),
                        dict(values[0], size=0), dict(values[0], name="x" * 129),
                        dict(values[0], name="line\nname"), dict(values[1], text=[]),
                        dict(values[1], text="x" * 2049), dict(values[1], truncated=1),
                        dict(values[2], **{"from": True}), dict(values[2], to_name="bad\x00name")))
        for value in invalid:
            with self.subTest(value=value):
                self.assertEqual(code.conclude(self.task, (observed(length=5, **value),)), ())
        self.assertTrue(code.conclude(self.task, (observed(length=16, **values[2]),)))
        self.assertEqual(code.conclude(self.task, (observed(length=17, **values[2]),)), ())
        overflow = dict(values[0], entry=2**64)
        self.assertFalse(code._valid(SimpleNamespace(observation=overflow, location=Location(0, 5))))
        with self.assertRaises(ContractError):
            observed(length=5, **overflow)

    def test_sixty_five_reverse_named_functions_keep_index_order_across_chunks(self):
        self.task = replace(self.task, operations=(OperationRequest("ghidra.analyze", {"max_functions": 65}),))
        names = [f"function_{64 - index:03d}" for index in range(65)]
        evidence = tuple(function(index, name=name) for index, name in enumerate(names))
        findings = code.conclude(self.task, tuple(reversed(evidence)))
        self.assertEqual([f.claim_key for f in findings], ["code.functions", "code.functions"])
        self.assertEqual([f.value for f in findings], [names[:64], names[64:]])
        self.assertEqual([set(f.evidence_ids) for f in findings],
                         [{item.id for item in evidence[:64]}, {evidence[64].id}])
        self.assertEqual({v.status for v in self.verdicts(evidence, findings)}, {"derived"})

    def test_pseudocode_alone_keeps_exact_text_and_truncation(self):
        item = pseudocode(text="`<img src=x>\nreturn user_input;", truncated=True)
        finding, = code.conclude(self.task, (item,))
        self.assertEqual(finding.value, {"entry": 0x1000, "text": item.observation["text"], "truncated": True})
        self.assertEqual(self.verdicts((item,))[0].status, "derived")

    def test_all_four_hundred_observations_fit_deterministic_citation_chunks(self):
        self.task = replace(self.task, operations=(OperationRequest("ghidra.analyze", {
            "max_functions": 128, "decompile": 16, "max_chars": 2048, "max_calls": 256}),))
        functions = [function(i, name=f"f{i:03d}") for i in range(128)]
        texts = [pseudocode(i) for i in range(16)]
        calls = [call(4096 + 5 * i, source=0x1000 + (i // 2) * 32, name=f"f{i // 2:03d}") for i in range(256)]
        evidence = (*functions, *texts, *calls)
        findings = code.conclude(self.task, tuple(reversed(evidence)))
        self.assertEqual(findings, code.conclude(self.task, evidence))
        grouped = {key: [f for f in findings if f.claim_key == key] for key in
                   ("code.functions", "code.pseudocode", "code.calls")}
        self.assertEqual([len(grouped[key]) for key in grouped], [2, 16, 4])
        self.assertEqual([name for f in grouped["code.functions"] for name in f.value], [f"f{i:03d}" for i in range(128)])
        citations = [i for f in findings for i in f.evidence_ids]
        self.assertEqual(len(citations), 400)
        self.assertEqual(set(citations), {e.id for e in evidence})
        self.assertTrue(all(len(f.evidence_ids) <= MAX_EVIDENCE_PER_FINDING for f in findings))
        ordered_calls = sorted(calls, key=lambda e: (e.observation["from"], e.observation["to_name"], e.id))
        for index, finding in enumerate(grouped["code.calls"]):
            self.assertEqual(set(finding.evidence_ids), {e.id for e in ordered_calls[index * 64:(index + 1) * 64]})
        self.assertEqual({v.status for v in self.verdicts(evidence, findings)}, {"derived"})


if __name__ == "__main__":
    unittest.main()
