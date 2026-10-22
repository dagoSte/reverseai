"""The JavaScript section of query reports (M5a): files, package.json declarations with install-time scripts marked,
hints grouped by category, a plain statement of what M5a reads, and sample text kept inert."""

import json
import re
import unittest

from reverseai import claims, report
from tests import fixtures_apk as F
from tests import fixtures_js as J
from tests.test_js_queries import run

SECTION = "## JavaScript application"
LEXICAL = ("Hints are lexical: occurrences of fixed patterns in the bytes, comments and strings included, not evidence "
           "that the code runs. M5a reads no JavaScript syntax and runs nothing.")


def section(markdown):
    """The lines of the JavaScript section, up to the next level-two heading."""
    lines = markdown.splitlines()
    start = lines.index(SECTION)
    end = next(i for i in range(start + 1, len(lines)) if lines[i].startswith("## "))
    return lines[start:end]


def outside_code(line):
    return re.sub(r"`[^`]*`", "", line)


class JavaScriptReportTests(unittest.TestCase):
    def test_the_summary_shows_files_declarations_and_hints_by_category(self):
        built = J.app_zip()
        lines = section(report.to_markdown(run(built)))
        self.assertEqual(lines[2], LEXICAL)
        headings = [line for line in lines if line.startswith("### ")]
        self.assertEqual(headings, [f"### {claims.statement(key)}" for key in
                                    ("javascript.files", "javascript.package", "javascript.hints")])
        self.assertIn("| Index | File | Size | SHA-256 | Lines | Longest line (bytes) |", lines)
        minified = next(f["row"] for f in built[1]["files"] if f["name"] == "dist/app.min.js")
        self.assertIn(f"| 6 | `dist/app.min.js` | `{minified['size']}` | `{minified['sha256']}` | `1` | "
                      f"`{minified['max_line']}` |", lines)
        self.assertIn("rows 0..8 of 9", lines)
        categories = [line[5:] for line in lines if line.startswith("#### ")]
        self.assertEqual(categories, ["`endpoint`", "`dynamic_code`", "`shell`", "`network`", "`credential`",
                                      "`encoding`"])
        credential = lines.index("#### `credential`")
        self.assertEqual(lines[credential + 2:credential + 6], [
            "| Index | File | Category | Hint | Text | Truncated |", "|---|---|---|---|---|---|",
            f"| 12 | `src/config.ts` | `credential` | `aws_access_key` | `{J.FAKE_AWS_KEY_ID}` | `false` |",
            f"| 13 | `src/config.ts` | `credential` | `private_key` | `{J.PRIVATE_KEY_BEGIN}` | `false` |"])

    def test_install_time_scripts_are_marked_and_nothing_else(self):
        package, strings = J.json_text({"name": "marks", "scripts": {
            "preinstall": "a", "install": "b", "postinstall": "c", "prepare": "d", "build": "e", "prepublish": "f"},
            "dependencies": {"postinstall": "1.0.0"}})
        built = J.archive([F.member("package.json", package)], strings={"package.json": strings})
        lines = section(report.to_markdown(run(built, {"detail": "package"})))
        marked = {line.split(" | ")[2]: line.endswith("| yes |") for line in lines if line.startswith("| ")
                  and line.split(" | ")[2].startswith("`/")}
        self.assertEqual(marked, {"`/name`": False, "`/scripts/preinstall`": True, "`/scripts/install`": True,
                                  "`/scripts/postinstall`": True, "`/scripts/prepare`": True, "`/scripts/build`": False,
                                  "`/scripts/prepublish`": False, "`/dependencies/postinstall`": False})
        self.assertTrue(any(line.startswith("Runs on install marks the scripts npm runs") for line in lines))

    def test_a_single_file_is_shown_as_the_input_and_the_next_page_is_named(self):
        lines = section(report.to_markdown(run(J.bundle_js(), {"detail": "files"}, name="bundle.js")))
        self.assertTrue(any(line.startswith("| 0 | (input) | ") for line in lines))
        lines = section(report.to_markdown(run(J.app_zip(), {"detail": "files", "limit": 3})))
        self.assertEqual(lines[lines.index("rows 0..2 of 9") + 1], "Next start: 3")
        self.assertNotIn("Next start", "\n".join(section(report.to_markdown(run(J.app_zip(), {"detail": "files"})))))

    def test_without_rows_the_section_says_so(self):
        analysis = run(J.app_zip(), {"detail": "package", "file": "none/package.json"})
        self.assertEqual(section(report.to_markdown(analysis)),
                         [SECTION, "", LEXICAL, "", "No JavaScript row was supported.", ""])
        analysis = run(J.app_zip(), {"detail": "files"})
        self.assertNotIn(SECTION, report.to_markdown(analysis).replace(SECTION, "", 1))  # one section only

    def test_sample_names_values_and_texts_stay_inert(self):
        # L0001: HTML, links and backticks from the sample never render
        hostile = "<img src=x onerror=alert(1)>[x](https://evil.example/)`b`"
        package, strings = J.json_text({"name": hostile, "scripts": {"postinstall": hostile}})
        script, marks = J.source(("fetch(", ("url_https", "https://evil.example/" + "<img src=x>"), ");"))
        built = J.archive([F.member("package.json", package), F.member(hostile + ".js", script)],
                          strings={"package.json": strings}, marks={hostile + ".js": marks})
        markdown = report.to_markdown(run(built))
        lines = section(markdown)
        self.assertTrue(any("<img src=x onerror=alert(1)>[x](https://evil.example/)'b'" in line for line in lines))
        for line in markdown.splitlines():
            self.assertNotIn("<img", outside_code(line), line)
            self.assertNotIn("](", outside_code(line), line)

    def test_the_json_report_keeps_the_query_and_page_findings(self):
        document = json.loads(report.to_json(run(J.app_zip(), {"limit": 2})))
        self.assertEqual(document["query"], {"name": "analyze_javascript_application", "args": {
            "detail": "summary", "file": "", "category": "all", "start": 0, "limit": 2}})
        self.assertEqual(sorted((f["claim_key"], f["verdict"]) for f in document["results"][0]["findings"]),
                         [("javascript.files", "supported"), ("javascript.hints", "supported"),
                          ("javascript.package", "supported")])


if __name__ == "__main__":
    unittest.main()
