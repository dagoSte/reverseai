"""M5a contract: JavaScript page claims and their row shapes (decision owner-next-m5a)."""

import unittest

from reverseai import claims
from reverseai.contract import (
    AnalysisResult, InputRef, Location, Observation, OperationSpec, ToolRef, ToolSpec, content_id, make_evidence,
    make_finding, sha256_hex,
)
from reverseai.review import review

DATA = bytes(range(256)) * 4
INPUT = InputRef(sha256_hex(DATA), len(DATA), "app.zip")
JS = ToolRef("js", "0.1.0")
TOOLS = {"js": ToolSpec(JS, {name: OperationSpec(name, {}, lambda d, a: []) for name in
                             ("js.files", "js.package", "js.hints")})}
CASES = {
    ("javascript.files", "js.files", "js_file"): (
        {"file": "app/index.js", "size": 120, "sha256": "ab" * 32, "lines": 4, "max_line": 60},
        [("file", "a\nb"), ("size", -1), ("sha256", "AB" * 32), ("sha256", "ab"), ("lines", 122),
         ("max_line", 121), ("max_line", None)]),
    ("javascript.package", "js.package", "package_field"): (
        {"file": "package.json", "path": "/scripts/postinstall", "value": "node setup.js", "truncated": False},
        [("path", "scripts/postinstall"), ("path", ""), ("value", "a\nb"), ("value", "x" * 257),
         ("truncated", True), ("truncated", 0)]),
    ("javascript.hints", "js.hints", "js_hint"): (
        {"file": "", "category": "dynamic_code", "hint": "eval", "text": "eval(", "truncated": False},
        [("category", "behaviour"), ("hint", ""), ("hint", "x" * 65), ("text", ""), ("text", "x" * 300),
         ("truncated", True), ("file", "a\tb")]),
}


def judge(key, operation, kind, row):
    item = make_evidence(DATA, JS, operation, Observation(Location(0, 8), {"kind": kind, "index": 0, "total": 1, **row}))
    fields = claims.PAGES[kind][0]
    finding = make_finding("structural", "Rows.", key, {"start": 0, "total": 1, "rows": [[row[f] for f in fields]]},
                           [item.id], "observed")
    result = AnalysisResult(content_id("tk", {"k": key}), "structural", "ok", (item,), (finding,))
    return review(DATA, INPUT, [result], TOOLS)[0].status


class JavaScriptClaimTests(unittest.TestCase):
    def test_each_page_kind_accepts_its_row_and_refuses_each_bad_field(self):
        for (key, operation, kind), (row, bad) in CASES.items():
            self.assertIn(key, claims.PAGE_CLAIMS)
            self.assertEqual(judge(key, operation, kind, row), "supported", key)
            for field, value in bad:
                self.assertEqual(judge(key, operation, kind, {**row, field: value}), "unsupported", (key, field, value))

    def test_a_cut_value_is_exactly_256_characters(self):
        row = {"file": "package.json", "path": "/description", "value": "d" * 256, "truncated": True}
        self.assertEqual(judge("javascript.package", "js.package", "package_field", row), "supported")


if __name__ == "__main__":
    unittest.main()
