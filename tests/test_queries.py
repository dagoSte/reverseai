"""Closed query routing, independent conclusions, paging and real reviewer wiring."""
import copy
from dataclasses import replace
import unittest
from unittest.mock import patch

from reverseai import pipeline, queries, report
from reverseai.analysts import query
from reverseai.contract import (
    AnalysisTask, ArgSpec, Budget, ContractError, InputRef, Location, Observation, OperationRequest, OperationSpec,
    ToolRef, ToolSpec, content_id, make_evidence, sha256_hex,
)
from reverseai.gateway import Gateway
from tests.test_cli_query import byte_tool

DATA = bytes(range(256)) * 8
REF = InputRef(sha256_hex(DATA), len(DATA), "inline")


def standin(operation, rows, schema):
    ref = query.REFS[operation.split(".")[0]]
    spec = OperationSpec(operation, schema, lambda data, args: rows, max_observations=643,
                         derived=operation.startswith("ghidra."))
    return ToolSpec(ref, {operation: spec})


class QueryTests(unittest.TestCase):
    def test_real_host_queries_flow_through_the_gateway_analyst_and_reviewer_on_three_formats(self):
        from tests.fixtures_code import elf_refs, pe_refs, macho_refs
        for builder in (elf_refs, pe_refs, macho_refs):
            data, _ = builder()
            ref = InputRef(sha256_hex(data), len(data), "inline")
            for name, args in (("binary_overview", {}), ("list_segments", {}), ("inspect_native_load_image", {}),
                               ("list_names", {}), ("read_bytes", {"length": 2000}), ("list_strings", {"min_length": 4}),
                               ("search_strings", {"query": "ReverseAI"})):
                with self.subTest(format=builder.__name__, query=name):
                    analysis = pipeline.query_bytes(data, ref, name, args)
                    self.assertEqual({result.status for result in analysis.results}, {"ok"})
                    self.assertLessEqual({verdict.status for verdict in analysis.verdicts}, {"supported"})
                    if not analysis.results[0].evidence:
                        self.assertEqual(analysis.results[0].findings, ())
                    self.assertEqual(report.to_json(analysis), report.to_json(pipeline.query_bytes(data, ref, name, args)))

    def test_the_table_has_exactly_the_sixteen_query_names_and_fixed_operations(self):
        expected = {
            "binary_overview": ("structure.identify", "structure.headers", "structure.sections", "structure.imports", "structure.entry"),
            "list_segments": ("structure.segments",), "inspect_native_load_image": ("structure.segments", "structure.entry"),
            "list_names": ("structure.symbols",), "read_bytes": ("structure.read_bytes",),
            "list_strings": ("strings.list",), "search_strings": ("strings.search",),
            "list_procedures": ("ghidra.functions",), "search_procedures": ("ghidra.functions",),
            **{name: ("ghidra.function",) for name in ("procedure_info", "procedure_pseudo_code", "procedure_assembly",
                                                     "procedure_callees", "procedure_callers", "analyze_function")},
            "xrefs": ("ghidra.xrefs",),
        }
        self.assertEqual(set(queries.TABLE), set(expected))
        for name, operations in expected.items():
            args = {"query": "hi"} if name == "search_strings" else {"address": 16} if name == "xrefs" else {}
            spec, checked = queries.resolve(name, args)
            self.assertEqual(tuple(request.operation for request in spec.requests(checked)), operations)
            self.assertEqual(spec.role, "code" if operations[0].startswith("ghidra.") else "structural")
        for name, part in (("procedure_info", "info"), ("procedure_assembly", "assembly"), ("analyze_function", "all")):
            spec, checked = queries.resolve(name, {})
            self.assertEqual(spec.requests(checked)[0].args["parts"], part)
        spec, args = queries.resolve("inspect_native_load_image", {"start": 3})
        self.assertEqual(spec.requests(args)[1].args, {})

    def test_argument_validation_separates_host_literal_text_from_contained_strings(self):
        self.assertEqual(queries.parse_args("list_names", ["query=-../a\\b"])["query"], "-../a\\b")
        self.assertEqual(queries.parse_args("search_strings", ["query=a=b"])["query"], "a=b")
        self.assertEqual(queries.parse_args("read_bytes", ["at=0XFF", "length=0004"])["at"], 255)
        for name, raw in (("procedure_info", {"name": "../x"}), ("list_procedures", {"query": "x"}),
                          ("procedure_info", {"parts": "all"}), ("read_bytes", {"at": True}),
                          ("xrefs", {"address": 2**64}), ("search_strings", {"query": "x\ny"}),
                          ("not_a_query", {})):
            with self.subTest(name=name, raw=raw), self.assertRaises(ContractError):
                queries.resolve(name, raw)

    def test_a_host_page_is_chunked_contiguously_with_all_citations_and_supported_values(self):
        rows = [Observation(Location(i, 1), {"kind": "segment", "index": 7+i, "total": 300, "name": "LOAD",
                                            "offset": i, "filesz": 1, "address": 0x1000+i, "memsz": 1,
                                            "readable": True, "writable": False, "executable": True}) for i in range(129)]
        tool = standin("structure.segments", rows, {"start": ArgSpec("int", 0, 65535, default=0),
                                                    "limit": ArgSpec("int", 1, 256, default=64)})
        result = pipeline.query_bytes(DATA, REF, "list_segments", {"start": 7, "limit": 129}, tools=(tool,))
        findings = result.results[0].findings
        self.assertEqual([(f.value["start"], len(f.value["rows"]), f.value["total"]) for f in findings],
                         [(7, 64, 300), (71, 64, 300), (135, 1, 300)])
        cited = [identifier for f in findings for identifier in f.evidence_ids]
        self.assertEqual(len(cited), len(set(cited)))
        self.assertEqual(set(cited), {e.id for e in result.results[0].evidence})
        self.assertEqual({v.status for v in result.verdicts}, {"supported"})
        text = report.to_markdown(result)
        self.assertIn("rows 7..70 of 300", text)
        self.assertIn("Next start: 71", text)
        self.assertIn("rows 135..135 of 300", text)
        self.assertIn("`0x1000`", text)
        self.assertIn('"query"', report.to_json(result))
        self.assertEqual(report.to_dict(result)["query"]["name"], "list_segments")

    def test_ghidra_query_uses_fixed_budget_and_stays_derived_even_if_spec_is_misregistered(self):
        row = Observation(Location(0, 16), {"kind": "function_row", "index": 0, "total": 1,
                                           "name": "entry", "entry": 0x1000, "size": 16})
        schema = {"query": ArgSpec("str", default=""), "start": ArgSpec("int", 0, 65535, default=0),
                  "limit": ArgSpec("int", 1, 128, default=64)}
        tool = standin("ghidra.functions", [row], schema)
        tool = replace(tool, operations={"ghidra.functions": replace(tool.operations["ghidra.functions"], derived=False)})
        with patch.object(pipeline, "Gateway", wraps=Gateway) as factory:
            result = pipeline.query_bytes(DATA, REF, "list_procedures", {}, tools=(tool,))
        self.assertEqual(factory.call_args.args[1], pipeline.GHIDRA_BUDGET)
        self.assertEqual({v.status for v in result.verdicts}, {"derived"})
        self.assertEqual(result.results[0].findings[0].value, {"start": 0, "total": 1, "rows": [["entry", 0x1000, 16]]})
        self.assertIn("0x1000", report.to_markdown(result))
        for tools in ((), (replace(tool, ref=ToolRef("ghidra", "12.1.4-r5")),)):
            with self.assertRaises(ContractError):
                pipeline.query_bytes(DATA, REF, "list_procedures", {}, tools=tools)

    def test_empty_page_makes_no_absence_claim_and_analyze_metadata_is_unchanged(self):
        tool = byte_tool()
        empty = replace(tool, operations={name: replace(spec, handler=lambda data, args: [])
                                          for name, spec in tool.operations.items()})
        analysis = pipeline.query_bytes(DATA, REF, "read_bytes", {}, tools=(empty,))
        self.assertEqual(analysis.results[0].findings, ())
        self.assertNotIn("query", report.to_dict(pipeline.analyze_bytes(DATA, REF)))
        self.assertNotIn("- Query:", report.to_markdown(pipeline.analyze_bytes(DATA, REF)))

    def test_query_analyst_refuses_foreign_input_undeclared_operation_and_mutated_evidence(self):
        obs = Observation(Location(0, 1), {"kind": "entry", "address": 0x1000, "offset": 0})
        item = make_evidence(DATA, query.REFS["structure"], "structure.entry", obs)
        task = AnalysisTask(content_id("tk", {"q": "test"}), "structural", REF, (OperationRequest("structure.entry"),))
        self.assertEqual(len(query.conclude(task, [item])), 1)
        altered = copy.deepcopy(item)
        altered.observation["address"] = 0
        foreign = replace(task, input=InputRef("0"*64, len(DATA), "other"))
        undeclared = replace(task, operations=(OperationRequest("structure.headers"),))
        for current, evidence in ((task, [altered]), (foreign, [item]), (undeclared, [item])):
            self.assertEqual(query.conclude(current, evidence), ())

    def test_xref_pages_preserve_target_and_nullable_sources(self):
        rows = [Observation(Location(i*5, 5), {"kind": "xref", "index": i, "total": 2, "at": 0x1000+i*5,
                                              "from": None if i == 0 else 0x1000, "to": 0x2000, "type": "read"}) for i in range(2)]
        schema = {"address": ArgSpec("int", 0, 2**64-1), "start": ArgSpec("int", 0, 65535, default=0),
                  "limit": ArgSpec("int", 1, 256, default=64)}
        result = pipeline.query_bytes(DATA, REF, "xrefs", {"address": 0x2000}, tools=(standin("ghidra.xrefs", rows, schema),))
        self.assertEqual(result.results[0].findings[0].value,
                         {"to": 0x2000, "start": 0, "total": 2, "rows": [[0x1000, None, "read"], [0x1005, 0x1000, "read"]]})
        self.assertEqual({v.status for v in result.verdicts}, {"derived"})
        self.assertNotIn("Next start:", report.to_markdown(result))

    def test_all_function_parts_are_cited_and_reviewed_as_derived(self):
        from reverseai.tools import ghidra_tool
        from tests.test_ghidra_tool import FakeExecutor, reply
        values = [
            (0, 32, {"kind": "target", "name": "entry", "entry": 0x1000, "size": 32, "matches": 1,
                     "callers_total": 1, "callees_total": 1}),
            (0, 32, {"kind": "pseudocode", "index": 0, "entry": 0x1000, "text": "return 1;", "truncated": False}),
            (16, 1, {"kind": "instructions", "entry": 0x1000, "start": 1, "total": 3,
                     "rows": [[16, 1, "RET"]], "truncated": True}),
            (1, 5, {"kind": "call", "from": 0x1000, "to": 0x2000, "to_name": "callee"}),
            (40, 5, {"kind": "caller", "at": 0x1028, "from": None, "to": 0x1000}),
            (8, 3, {"kind": "ref", "from": 0x1000, "to": 0x3000, "type": "read", "to_name": "counter"}),
        ]
        observations = [Observation(Location(at, size), value) for at, size, value in values]
        base = ghidra_tool.make_tool(FakeExecutor(reply(DATA, [])))
        spec = replace(base.operations["ghidra.function"], handler=lambda data, args: observations)
        tool = replace(base, operations={"ghidra.function": spec})
        result = pipeline.query_bytes(DATA, REF, "analyze_function", {"entry": 0x1000, "start": 1}, tools=(tool,))
        self.assertEqual({finding.claim_key for finding in result.results[0].findings},
                         {"code.function_info", "code.pseudocode", "code.instructions", "code.calls", "code.callers", "code.references"})
        self.assertEqual({verdict.status for verdict in result.verdicts}, {"derived"})
        all_ids = [identifier for finding in result.results[0].findings for identifier in finding.evidence_ids]
        self.assertEqual(set(all_ids), {e.id for e in result.results[0].evidence})
        self.assertEqual(len(all_ids), len(set(all_ids)))
        text = report.to_markdown(result)
        self.assertIn("rows 1..1 of 3", text)
        self.assertIn("| `0x1028` | `null` |", text)

    def test_overview_imports_use_one_bounded_supported_finding_per_claim(self):
        rows = [Observation(Location(i, 1), {"kind": "library", "name": f"lib{i:03}"}) for i in range(129)]
        operations = {name: OperationSpec(name, {}, lambda data, args: [], max_observations=256)
                      for name in ("structure.identify", "structure.headers", "structure.sections", "structure.entry")}
        operations["structure.imports"] = OperationSpec("structure.imports", {}, lambda data, args: rows, max_observations=256)
        tool = ToolSpec(query.REFS["structure"], operations)
        result = pipeline.query_bytes(DATA, REF, "binary_overview", {}, tools=(tool,))
        finding, = result.results[0].findings
        self.assertEqual(finding.claim_key, "imports.libraries")
        self.assertEqual(len(finding.evidence_ids), 64)
        self.assertEqual(finding.value, [f"lib{i:03}" for i in range(64)])
        self.assertEqual({v.status for v in result.verdicts}, {"supported"})
