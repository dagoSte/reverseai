import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from tests.hive_compiler import confined
from hive import bees, queen

CC = shutil.which("cc")

ORIGINAL = r'''
#include <stdio.h>
static int greet_line(const char *name) { return printf("hello %s\n", name); }
int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: greet NAME\n"); return 2; }
    greet_line(argv[1]);
    return 0;
}
'''
CONTRACT = '''#include <stdio.h>
int greet_line(const char *name); /* 0x1040 */
int main(int argc, char **argv); /* 0x1000 */
'''
GOOD = {
    "m01": '#include "contract.h"\nint greet_line(const char *name) { return printf("hello %s\\n", name); }\n',
    "m02": '#include "contract.h"\nint main(int argc, char **argv) {\n'
           '    if (argc < 2) { fprintf(stderr, "usage: greet NAME\\n"); return 2; }\n'
           '    greet_line(argv[1]);\n    return 0;\n}\n',
}
WRONG_EXIT = GOOD["m02"].replace("return 2;", "return 1;")
FI = "fi-" + "a" * 16


def page(claim_key, rows, total):
    return {"input": {"sha256": "cd" * 32},
            "results": [{"findings": [{"claim_key": claim_key, "verdict": "derived",
                                       "value": {"rows": rows, "total": total}}]}]}


class FakeEngine:
    file = "greet"

    def __init__(self, inputs):
        self.path = Path(inputs) / self.file
        self.questions = []

    def prepare(self):
        return {"status": "prepared"}

    def query(self, name, args, out):
        self.questions.append((name, dict(args)))
        functions = [{"index": 0, "entry": 0x1000, "name": "FUN_1000", "size": 64, "signature": None},
                     {"index": 1, "entry": 0x1040, "name": "FUN_1040", "size": 32, "signature": None},
                     {"index": 2, "entry": 0x1080, "name": "_printf", "size": 12, "signature": None}]
        tables = {"functions": ("code.export_functions", functions),
                  "calls": ("code.export_calls", [{"index": 0, "from": 0x1000, "to": 0x1040, "to_name": "FUN_1040"},
                                                  {"index": 1, "from": 0x1040, "to": 0x9000, "to_name": "_printf"}]),
                  "strings": ("code.export_strings", [{"index": 0, "from": 0x1000, "address": 0x2000,
                                                       "text": "usage: greet NAME\n"}]),
                  "references": ("code.export_references", [{"index": 0, "from": 0x1000, "at": 0x1008, "to": 0x2000,
                                                             "type": "data_read", "to_name": None}])}
        key, rows = tables[args["part"]]
        start = args["start"]
        return page(key, rows[start:start + 2], len(rows))  # two rows per page, to exercise paging


class FakeBees:
    """Writes canned module sources; council and repair behaviour is set per scenario."""

    def __init__(self, sources, *, refute_first=(), repaired=None, cases=None):
        self.sources, self.refute_first = dict(sources), set(refute_first)
        self.repaired, self.cases, self.calls = dict(repaired or {}), cases or [], []

    def __call__(self, role, name, task, folder):
        folder = Path(folder)
        self.calls.append((role, name))
        if role == "planner":
            (folder / "contract.h").write_text(CONTRACT)
            return {"ok": True, "seconds": 1, "output": {
                "modules": [{"id": "x", "title": "greeting", "functions": ["0x1040"]},
                            {"id": "y", "title": "main", "functions": ["0x1000", "0x1000", "0xdead"]}],
                "skipped": [{"entry": "0x1080", "reason": "import stub"}]}}
        if role in ("worker", "repair"):
            mid = folder.name
            if role == "worker":
                (folder / f"{mid}.c").write_text(self.sources[mid])
            elif mid in self.repaired:
                (folder / f"{mid}.c").write_text(self.repaired[mid])
            elif folder.parent.name == "fixes":
                for name_, text in self.repaired.items():
                    (folder / f"{name_}.c").write_text(text)
            (folder / "claims.json").write_text(json.dumps({"file": "greet", "claims": [
                {"id": "c1", "text": "t", "citations": [{"tool": "export_function", "args": {"entry": 1}, "id": FI}]}]}))
            entries = {"m01": ["0x1040"], "m02": ["0x1000"]}
            mids = list(self.repaired) if folder.parent.name == "fixes" else [mid]
            return {"ok": True, "seconds": 1, "output": {"status": "done", "functions": [
                {"entry": entry, "status": "rebuilt"} for unit in mids for entry in entries.get(unit, [])]}}
        if role == "councillor":
            mid = name.split("-")[0]
            if mid in self.refute_first and "-r1-" in name and name.endswith("-io"):
                return {"ok": True, "seconds": 1, "output": {"verdict": "refute", "defects": [
                    {"function": "main", "problem": "wrong exit code", "evidence": "0x1010 mov w0, #2"},
                    {"function": "main", "problem": "unevidenced opinion", "evidence": "trust me"}]}}
            return {"ok": True, "seconds": 1, "output": {"verdict": "accept", "defects": []}}
        if role == "tester":
            return {"ok": True, "seconds": 1, "output": {"cases": self.cases}}
        raise AssertionError(role)


CASES = [{"id": "no-args", "steps": [{"args": []}]},
         {"id": "name", "steps": [{"args": ["ada"]}]},
         {"id": "file-escape", "files": [{"name": "../outside", "text": "x"}], "steps": [{"args": ["x"]}]}]


@unittest.skipUnless(confined("c"), "needs a Clang compiler the hive can confine")
class QueenRunTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.inputs = self.tmp / "inputs"
        self.inputs.mkdir()
        source = self.tmp / "greet.c"
        source.write_text(ORIGINAL)
        subprocess.run([CC, str(source), "-o", str(self.inputs / "greet")], check=True)

    def queen(self, fake, *, rejected=0, **kwargs):
        def check(claims, out):
            count = len(json.loads(Path(claims).read_text())["claims"])
            return {"claims": count, "confirmed": count - rejected, "rejected": rejected, "questions": 1,
                    "input_sha256": ["cd" * 32]}, []
        return queen.Queen(engine=FakeEngine(self.inputs), out=self.tmp / "run", bees=fake, slots=2,
                           check=check, **kwargs)

    def test_accepted_only_when_every_check_passes(self):
        fake = FakeBees(GOOD, cases=CASES)
        result = self.queen(fake, run_original=True).run()
        self.assertEqual(result["verdict"], "accepted", result["reason"])
        self.assertEqual(result["modules"], {"m01": "accepted", "m02": "accepted"})
        self.assertEqual(result["conformance"]["identical"], 3)
        self.assertFalse((self.tmp / "outside").exists())
        self.assertEqual(result["skipped"], 1)
        self.assertTrue((self.tmp / "run" / "REPORT.md").is_file())
        frozen = self.tmp / "run" / "src" / "contract.h"
        self.assertEqual(frozen.stat().st_mode & 0o777, 0o444)
        self.assertEqual(sum(1 for role, _ in fake.calls if role == "councillor"), 6)  # 3 lenses x 2 modules

    def test_without_permission_the_original_never_runs(self):
        result = self.queen(FakeBees(GOOD, cases=CASES)).run()
        self.assertEqual(result["verdict"], "accepted without behaviour proof")
        self.assertFalse(result["conformance"]["ran"])
        self.assertFalse((self.tmp / "run" / "tests").exists())

    def test_council_defect_with_evidence_goes_back_for_repair(self):
        fake = FakeBees({"m01": GOOD["m01"], "m02": WRONG_EXIT}, refute_first={"m02"}, repaired={"m02": GOOD["m02"]})
        result = self.queen(fake).run()
        self.assertEqual(result["modules"]["m02"], "accepted")
        status = json.loads((self.tmp / "run" / "modules" / "m02" / "status.json").read_text())
        self.assertEqual([d["problem"] for d in status["rounds"][0]["defects"]], ["wrong exit code"])
        self.assertIn(("repair", "m02-repair-c1"), fake.calls)
        council_seats = list((self.tmp / "run" / "council").iterdir())
        self.assertTrue(all(not list(seat.glob("m0*.c")) for seat in council_seats))  # authorship hidden
        self.assertTrue(all(not (seat / "NOTES.md").exists() for seat in council_seats))

    def test_compile_errors_are_repaired_and_cheats_fail(self):
        fake = FakeBees({"m01": "#include \"contract.h\"\nint greet_line(const char *name) { return nope; }\n",
                         "m02": GOOD["m02"].replace("return 0;", "__asm__(\"nop\"); return 0;")},
                        repaired={"m01": GOOD["m01"]})
        result = self.queen(fake).run()
        self.assertEqual(result["modules"], {"m01": "accepted", "m02": "failed"})
        self.assertEqual(result["verdict"], "not accepted")
        status = json.loads((self.tmp / "run" / "modules" / "m02" / "status.json").read_text())
        self.assertIn("forbidden constructs", status["errors"])

    def test_checker_rejection_cannot_be_overridden(self):
        result = self.queen(FakeBees(GOOD), rejected=1).run()
        self.assertEqual(result["verdict"], "not accepted")
        self.assertIn("rejected by the evidence checker", result["reason"])

    def test_behaviour_difference_triggers_a_fix_round(self):
        unfixed = FakeBees({"m01": GOOD["m01"], "m02": WRONG_EXIT}, cases=CASES)
        result = self.queen(unfixed, run_original=True).run()
        self.assertEqual(result["conformance"]["different"], ["no-args"])
        self.assertEqual(result["verdict"], "not accepted")
        shutil.rmtree(self.tmp / "run")
        fixed = FakeBees({"m01": GOOD["m01"], "m02": WRONG_EXIT}, cases=CASES, repaired={"m02": GOOD["m02"]})
        result = self.queen(fixed, run_original=True).run()
        self.assertIn(("repair", "behaviour-fix-1"), fixed.calls)
        self.assertEqual(result["conformance"]["identical"], 3)
        self.assertEqual(result["verdict"], "accepted")

    def test_bee_budget_is_enforced_and_logged(self):
        result = self.queen(FakeBees(GOOD), max_bees=1).run()
        self.assertEqual(result["verdict"], "not accepted")
        self.assertIn("not started", (self.tmp / "run" / "hive.log").read_text())


class PlanAndLinkTests(unittest.TestCase):
    MAP = {"functions": [{"hex": hex(e), "entry": e} for e in (0x10, 0x20, 0x30, 0x40, 0x50)]}

    def test_every_function_lands_in_exactly_one_bounded_module(self):
        plan = {"modules": [{"title": "a", "functions": ["0x10", "0x20", "0x30", "0x10", "0x999"]},
                            {"title": "b", "functions": ["0x20"]}],
                "skipped": [{"entry": "0x50", "reason": "stub"}, {"entry": "0x777", "reason": "?"}]}
        modules, skipped = queen.normalise_plan(plan, self.MAP, max_functions=2)
        assigned = [e for m in modules for e in m["functions"]]
        self.assertEqual(sorted(assigned), ["0x10", "0x20", "0x30", "0x40"])
        self.assertEqual(len(assigned), len(set(assigned)))
        self.assertTrue(all(len(m["functions"]) <= 2 for m in modules))
        self.assertEqual(skipped, {"0x50": "stub"})
        self.assertEqual([m["id"] for m in modules], ["m01", "m02", "m03"])

    def test_link_errors_are_routed_to_their_modules(self):
        mac = ('Undefined symbols for architecture arm64:\n  "_greet_line", referenced from:\n      _main in m02.o\n'
               "duplicate symbol '_helper' in:\n    build/obj/m01.o\n    build/obj/m03.o\n")
        blamed = queen.link_blame(mac, {"greet_line": "m01", "helper": "m01"}, ["m01", "m02", "m03"])
        self.assertIn("undefined symbol greet_line", blamed["m01"][0])
        self.assertIn("duplicate symbol helper", blamed["m03"][0])
        gnu = "m02.o: in function `main':\nx.c:(.text+0x1): undefined reference to `greet_line'\n"
        self.assertIn("m01", queen.link_blame(gnu, {"greet_line": "m01"}, ["m01", "m02"]))

    def test_contract_names_read_the_entry_comments(self):
        self.assertEqual(queen.contract_names(CONTRACT), {0x1040: "greet_line", 0x1000: "main"})


class BeeCommandTests(unittest.TestCase):
    def test_no_role_gets_a_shell_or_the_web_and_each_bee_has_its_own_server(self):
        tmp = Path(tempfile.mkdtemp())
        runner = bees.ClaudeBees(engine="/engine", inputs="/inputs", config_dir=tmp)
        for role in bees.TOOLSETS:
            argv = runner.argv(role, f"bee-{role}")
            tools = argv[argv.index("--tools") + 1].split(",")
            self.assertFalse({"Bash", "WebFetch", "WebSearch", "Agent"} & set(tools))
            self.assertIn("--strict-mcp-config", argv)
            allowed = argv[argv.index("--allowedTools") + 1:]
            self.assertEqual(allowed[0], "mcp__reverseai__*")
            self.assertEqual(allowed[1:], [f"{tool}(./**)" for tool in tools])  # file tools fenced to the bee's folder
            if "Write" in tools:
                self.assertIn("Edit(./**)", allowed)  # Claude Code checks file writes against Edit rules
            self.assertEqual(argv[argv.index("--permission-mode") + 1], "dontAsk")
            config = json.loads(Path(argv[argv.index("--mcp-config") + 1]).read_text())
            server = config["mcpServers"]["reverseai"]
            self.assertEqual(server["args"][:5], ["-B", "-m", "reverseai", "mcp", "--inputs"])
            self.assertEqual(server["env"]["PYTHONPATH"], "/engine")
        self.assertEqual(runner.argv("councillor", "c")[runner.argv("councillor", "c").index("--tools") + 1], "Read")
        self.assertEqual(len(list(tmp.glob("*.json"))), len(bees.TOOLSETS) + 1)

    def test_every_role_has_a_card_and_a_schema(self):
        for role in bees.TOOLSETS:
            text = bees.brief(role, "TASK")
            self.assertTrue(text.startswith("# ReverseAI hive: rules for every bee"))
            self.assertTrue(text.rstrip().endswith("TASK"))
            self.assertEqual(bees.SCHEMAS[role]["type"], "object")


if __name__ == "__main__":
    unittest.main()
