"""analyze_javascript_application (M5a): arguments, routing by detail, page conclusions and review, with js operations
answering from the fixture layouts until codex-support-2's js tool lands."""

from dataclasses import replace
import unittest

from reverseai import claims, pipeline, queries
from reverseai.contract import (
    ArgSpec, ContractError, InputRef, Location, MAX_EVIDENCE_PER_FINDING, Observation, OperationSpec, ToolRef, ToolSpec,
    sha256_hex,
)
from reverseai.tools import structure
from tests import fixtures_js as J

NAME = "analyze_javascript_application"
JS = ToolRef("js", "0.1.0")
# Stand-in hints: the fixture's mark labels as jshints catalog names (decision m5a-seams-l)
STANDIN_HINTS = {
    "url_https": ("endpoint", "url"), "url_http": ("endpoint", "url"), "url_wss": ("endpoint", "url"),
    "eval_call": ("dynamic_code", "eval"), "new_function": ("dynamic_code", "new_function"),
    "dynamic_import": ("dynamic_code", "dynamic_import"), "require_child_process": ("shell", "child_process"),
    "exec_call": ("shell", "process_call"), "fetch_call": ("network", "fetch"), "websocket": ("network", "web_socket"),
    "xhr": ("network", "xml_http_request"), "aws_key_id": ("credential", "aws_access_key"),
    "private_key": ("credential", "private_key"), "atob_call": ("encoding", "atob"),
    "buffer_from": ("encoding", "buffer_decode"),
}
FILE = ArgSpec("literal", 0, 255, default="")
LIMIT = ArgSpec("int", 1, 256, default=128)


def standin(layout, *, skip=None):
    """js.files, js.package and js.hints with the contract's arguments, answering from a fixture layout; skip drops
    one row index from every page, as a faulty tool would."""
    def page(rows, args):
        return [Observation(location, {**value, "index": index, "total": len(rows)}, artifact)
                for index, (location, value, artifact) in enumerate(rows)
                if args["start"] <= index < args["start"] + args["limit"] and index != skip]

    def files(data, args):
        return page([(Location(**f["anchor"]), {"kind": "js_file", **f["row"]}, f["artifact"])
                     for f in layout["files"]], args)

    def package(data, args):
        chosen = layout["packages"].get(args["file"] or layout["default_package"])
        rows = chosen["rows"] if chosen is not None and (not args["file"] or chosen["member"] is not None) else []
        return page([(Location(row["offset"], row["length"]), {"kind": "package_field", **row["row"]},
                      chosen["artifact"]) for row in rows], args)

    def hints(data, args):
        rows = []
        for f in layout["files"]:
            if f["name"].rsplit("/", 1)[-1] == "package.json" or args["file"] not in ("", f["row"]["file"]):
                continue
            for mark in sorted(layout["marks"].get(f["name"], ()), key=lambda m: m["offset"]):
                category, hint = STANDIN_HINTS.get(mark["label"], (None, None))
                if hint and args["category"] in ("all", category):
                    text, truncated = J.cut(mark["text"])
                    rows.append((Location(mark["offset"], mark["length"]),
                                 {"kind": "js_hint", "file": f["row"]["file"], "category": category, "hint": hint,
                                  "text": text, "truncated": truncated}, f["artifact"]))
        return page(rows, args)

    return ToolSpec(JS, {
        "js.files": OperationSpec("js.files", {"start": ArgSpec("int", 0, 65535, default=0), "limit": LIMIT}, files,
                                  max_observations=256),
        "js.package": OperationSpec("js.package", {"file": FILE, "start": ArgSpec("int", 0, 65535, default=0),
                                                   "limit": LIMIT}, package, max_observations=256),
        "js.hints": OperationSpec("js.hints", {
            "file": FILE, "category": ArgSpec("enum", choices=queries.JS_CATEGORIES, default="all"),
            "start": ArgSpec("int", 0, 1048575, default=0), "limit": LIMIT}, hints, max_observations=256),
    })


def run(built, args=None, *, tools=None, name="app.zip"):
    data, layout = built
    ref = InputRef(sha256_hex(data), len(data), name)
    return pipeline.query_bytes(data, ref, NAME, args or {}, tools=tools or (standin(layout),))


def pages(analysis):
    """{claim key: [(verdict, value)]} of the query's findings."""
    verdicts = {verdict.finding_id: verdict.status for verdict in analysis.verdicts}
    found = {}
    for finding in analysis.results[0].findings:
        found.setdefault(finding.claim_key, []).append((verdicts[finding.id], finding.value))
    return found


def files_page(layout, start=0, stop=None):
    rows = layout["files"][start:stop]
    return {"start": start, "total": len(layout["files"]),
            "rows": [[f["row"][field] for field in ("file", "size", "sha256", "lines", "max_line")] for f in rows]}


class QueryTableTests(unittest.TestCase):
    def test_the_arguments_and_their_defaults(self):
        spec, args = queries.resolve(NAME, {})
        self.assertEqual(args, {"detail": "summary", "file": "", "category": "all", "start": 0, "limit": 128})
        self.assertEqual(spec.role, "structural")
        self.assertEqual(spec.operations, ("js.files", "js.package", "js.hints"))
        self.assertEqual(queries.JS_CATEGORIES, ("all", *claims.JS_CATEGORIES))

    def test_each_detail_routes_its_operations(self):
        def routed(raw):
            spec, args = queries.resolve(NAME, raw)
            return [(request.operation, request.args) for request in spec.requests(args)]
        self.assertEqual(routed({"limit": 5}), [
            ("js.files", {"start": 0, "limit": 5}), ("js.package", {"file": "", "start": 0, "limit": 5}),
            ("js.hints", {"file": "", "category": "all", "start": 0, "limit": 5})])
        self.assertEqual(routed({"detail": "files", "start": 3}), [("js.files", {"start": 3, "limit": 128})])
        self.assertEqual(routed({"detail": "package", "file": "a/package.json", "start": 1, "limit": 2}),
                         [("js.package", {"file": "a/package.json", "start": 1, "limit": 2})])
        self.assertEqual(routed({"detail": "hints", "file": "lib/index.js", "category": "shell", "start": 1048575}),
                         [("js.hints", {"file": "lib/index.js", "category": "shell", "start": 1048575, "limit": 128})])
        spec = queries.TABLE[NAME]  # every argument is passed on by some detail, or selects the detail
        used = {source for routes in spec.details.values() for taken, _ in routes.values() for source in taken.values()}
        self.assertEqual(used | {"detail"}, set(spec.args))

    def test_an_argument_the_detail_does_not_pass_on_is_refused(self):
        for raw in ({"file": "lib/index.js"}, {"category": "shell"}, {"start": 1},
                    {"detail": "files", "file": "a.js"}, {"detail": "files", "category": "network"},
                    {"detail": "package", "category": "credential"},
                    {"detail": "files", "start": 65536}, {"detail": "package", "start": 65536},
                    {"detail": "hints", "start": 1048576}, {"detail": "all"}, {"detail": "hints", "category": "behaviour"},
                    {"detail": "package", "file": "x" * 256}, {"detail": "hints", "file": "a\nb.js"},
                    {"limit": 0}, {"limit": 257}, {"query": "x"}):
            with self.subTest(raw=raw), self.assertRaises(ContractError):
                queries.resolve(NAME, raw)
        self.assertEqual(queries.resolve(NAME, {"detail": "package", "file": "x" * 255})[1]["file"], "x" * 255)

    def test_command_line_arguments(self):
        self.assertEqual(queries.parse_args(NAME, ["detail=hints", "category=credential", "start=0x10", "limit=5",
                                                   "file=lib/a b.js"]),
                         {"detail": "hints", "file": "lib/a b.js", "category": "credential", "start": 16, "limit": 5})
        for values in (["detail=files", "detail=hints"], ["mode=x"], ["limit=five"], ["detail"]):
            with self.subTest(values=values), self.assertRaises(ContractError):
                queries.parse_args(NAME, values)


class QueryRunTests(unittest.TestCase):
    def test_summary_reads_the_first_page_of_files_package_and_hints(self):
        built = J.app_zip()
        found = pages(run(built))
        self.assertEqual(set(found), {"javascript.files", "javascript.package", "javascript.hints"})
        self.assertEqual(found["javascript.files"], [("supported", files_page(built[1]))])
        package = built[1]["package"]["rows"]
        self.assertEqual(found["javascript.package"], [("supported", {"start": 0, "total": len(package), "rows": [
            [row["row"][field] for field in ("file", "path", "value", "truncated")] for row in package]})])
        (verdict, hints), = found["javascript.hints"]
        self.assertEqual(verdict, "supported")
        self.assertEqual(hints["rows"][0], ["lib/index.js", "shell", "child_process", "require('child_process')", False])
        self.assertEqual({row[0] for row in hints["rows"]},
                         {"lib/index.js", "lib/loader.mjs", "src/config.ts", "dist/app.min.js"})

    def test_files_pages_cite_each_child_from_its_first_byte(self):
        built = J.app_zip()
        analysis = run(built, {"detail": "files", "start": 2, "limit": 3})
        self.assertEqual(pages(analysis), {"javascript.files": [("supported", files_page(built[1], 2, 5))]})
        result = analysis.results[0]
        cited = [item for item in result.evidence if item.id in result.findings[0].evidence_ids]
        self.assertEqual([(item.location.offset, item.location.length, item.artifact["member"]) for item in cited],
                         [(0, f["row"]["size"], f["name"]) for f in built[1]["files"][2:5]])
        self.assertEqual([item.artifact for item in cited], [f["artifact"] for f in built[1]["files"][2:5]])

    def test_a_single_file_is_named_empty_and_cited_in_the_input(self):
        data, layout = J.package_only()
        analysis = run((data, layout), {"detail": "package", "limit": 4}, name="package.json")
        (verdict, value), = pages(analysis)["javascript.package"]
        self.assertEqual((verdict, value["start"], value["total"]), ("supported", 0, len(J.APP_PACKAGE_PATHS)))
        self.assertEqual([row[:2] for row in value["rows"]], [["", path] for path in J.APP_PACKAGE_PATHS[:4]])
        result = analysis.results[0]
        self.assertEqual([(item.artifact, item.location.offset) for item in result.evidence],
                         [(None, row["offset"]) for row in layout["package"]["rows"][:4]])
        bundle = J.bundle_js()
        found = pages(run(bundle, name="bundle.js"))
        self.assertEqual(found["javascript.files"], [("supported", files_page(bundle[1]))])
        self.assertEqual({row[0] for _, value in found["javascript.hints"] for row in value["rows"]}, {""})

    def test_an_explicit_package_selector_picks_that_member_and_one_naming_none_gives_no_rows(self):
        built = J.app_zip()
        found = pages(run(built, {"detail": "package", "file": "node_modules/left-pad/package.json"}))
        self.assertEqual([row[1] for row in found["javascript.package"][0][1]["rows"]],
                         ["/name", "/version", "/main", "/license"])
        analysis = run(built, {"detail": "package", "file": "lib/missing/package.json"})
        self.assertEqual((analysis.results[0].status, pages(analysis)), ("ok", {}))

    def test_hint_pages_filter_by_category_and_split_at_64_citations(self):
        built = J.app_zip()
        found = pages(run(built, {"detail": "hints", "category": "credential"}))
        self.assertEqual([row[1:3] for row in found["javascript.hints"][0][1]["rows"]],
                         [["credential", "aws_access_key"], ["credential", "private_key"]])
        data, marks = J.source(*(("fetch(", ("url_https", f"https://e{i}.example.com/"), ");") for i in range(100)))
        found = pages(run(J.single(data, marks=marks), {"detail": "hints", "limit": 100}, name="many.js"))
        self.assertEqual([(verdict, value["start"], len(value["rows"]), value["total"])
                          for verdict, value in found["javascript.hints"]],
                         [("supported", 0, MAX_EVIDENCE_PER_FINDING, 100), ("supported", 64, 36, 100)])

    def test_the_summary_limit_applies_to_every_page(self):
        found = pages(run(J.app_zip(), {"limit": 2}))
        self.assertEqual({key: [(value["start"], len(value["rows"])) for _, value in found[key]] for key in found},
                         {"javascript.files": [(0, 2)], "javascript.package": [(0, 2)], "javascript.hints": [(0, 2)]})

    def test_a_page_with_a_missing_row_concludes_nothing(self):
        built = J.app_zip()
        analysis = run(built, {"detail": "files"}, tools=(standin(built[1], skip=1),))
        self.assertEqual(len(analysis.results[0].evidence), len(built[1]["files"]) - 1)
        self.assertEqual(pages(analysis), {})

    def test_the_query_needs_the_js_operations(self):
        data, _ = J.app_zip()
        with self.assertRaisesRegex(ContractError, "Query operation unavailable"):
            pipeline.query_bytes(data, InputRef(sha256_hex(data), len(data), "app.zip"), NAME, {}, tools=(structure.TOOL,))
        built = J.app_zip()
        tool = standin(built[1])
        partial = replace(tool, operations={k: v for k, v in tool.operations.items() if k != "js.hints"})
        with self.assertRaisesRegex(ContractError, "Query operation unavailable"):
            run(built, tools=(partial,))
        self.assertEqual(set(pages(run(built, {"detail": "files"}, tools=(partial,)))), {"javascript.files"})


if __name__ == "__main__":
    unittest.main()
