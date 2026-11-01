import json
import tempfile
import unittest
from pathlib import Path

from hive import queen
from tests.hive_compiler import confined
from tests.test_hive_queen import FakeBees, FakeEngine, GOOD

CONTRACT = """#include <stdio.h>
#include <stdint.h>
extern const uint32_t dec64table[8]; /* 0x5000 */
extern int g_display_level; /* 0x6000 */
extern const char *g_unused_name; /* 0x7000 */
extern int no_address_comment;
int decode_block(const uint8_t *src, int size); /* 0x1000 */
void set_level(int level); /* 0x1100 */
int main(int argc, char **argv); /* 0x1200 */
"""
MODULES = [{"id": "m01", "title": "decoder", "functions": ["0x1000"]},
           {"id": "m02", "title": "settings", "functions": ["0x1100"]},
           {"id": "m03", "title": "main", "functions": ["0x1200"]}]


def ref(source, target):
    return {"from": source, "to": hex(target), "type": "read"}


class ParseAndAssignTests(unittest.TestCase):
    def test_contract_globals_need_an_address_comment(self):
        found = queen.contract_globals(CONTRACT)
        self.assertEqual(found, {0x5000: "dec64table", 0x6000: "g_display_level", 0x7000: "g_unused_name"})
        self.assertNotIn("decode_block", found.values())  # functions are not globals

    def test_each_global_goes_to_the_module_that_uses_it_most(self):
        program_map = {"references": [
            ref("0x1000", 0x5000), ref("0x1000", 0x5010), ref("0x1200", 0x5004),  # table: m01 twice, m03 once
            ref("0x1100", 0x6000), ref("0x1200", 0x6000),                       # tie m02/m03 -> lowest id m02
            ref("0x9999", 0x6000),                                               # unknown function: ignored
        ]}
        owners = queen.assign_globals(queen.contract_globals(CONTRACT), MODULES, program_map)
        self.assertEqual(owners, {"dec64table": "m01", "g_display_level": "m02", "g_unused_name": "m01"})

    def test_a_reference_counts_only_for_the_global_it_falls_in(self):
        globals_ = {0x5000: "a", 0x5020: "b"}
        program_map = {"references": [ref("0x1100", 0x5024), ref("0x1100", 0x5000 + queen.GLOBAL_SPAN + 0x40000)]}
        owners = queen.assign_globals(globals_, MODULES, program_map)
        self.assertEqual(owners, {"a": "m01", "b": "m02"})

    def test_link_errors_on_data_go_to_the_owner(self):
        log = ('Undefined symbols for architecture arm64:\n  "_dec64table", referenced from:\n      _main in m03.o\n'
               "duplicate symbol '_g_display_level' in:\n    build/obj/m02.o\n    build/obj/m03.o\n")
        owners = {"decode_block": "m01", "dec64table": "m01", "g_display_level": "m02"}
        blamed = queen.link_blame(log, owners, ["m01", "m02", "m03"])
        self.assertIn("undefined symbol dec64table", blamed["m01"][0])
        self.assertIn("duplicate symbol g_display_level", blamed["m03"][0])
        self.assertNotIn("m02", [m for m, problems in blamed.items() if any("duplicate" in p for p in problems)])


class BriefTests(unittest.TestCase):
    def test_briefs_say_who_defines_each_global(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "inputs").mkdir()
        (tmp / "inputs" / "greet").write_bytes(b"x")
        hive = queen.Queen(engine=FakeEngine(tmp / "inputs"), out=tmp / "run", bees=FakeBees(GOOD))
        hive.global_addresses = queen.contract_globals(CONTRACT)
        hive.global_owners = {"dec64table": "m01", "g_display_level": "m02", "g_unused_name": "m01"}
        program_map = {"functions": [{"hex": "0x1000", "entry": 0x1000, "name": "FUN_1000", "size": 64}],
                       "calls": [], "strings": []}
        text = hive.brief(MODULES[0], program_map, {0x1000: "decode_block"})
        self.assertIn("must define", text)
        self.assertIn("`dec64table` at 0x5000", text)
        self.assertIn("`g_unused_name` at 0x7000", text)
        self.assertIn("never define them here): `g_display_level`", text)


@unittest.skipUnless(confined("c"), "needs a Clang compiler the hive can confine")
class RunTests(unittest.TestCase):
    def test_a_run_assigns_owners_and_routes_them(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "inputs").mkdir()
        (tmp / "inputs" / "greet").write_bytes(b"x")

        def check(claims, out):
            return {"claims": 1, "confirmed": 1, "rejected": 0, "questions": 1, "input_sha256": ["cd" * 32]}, []
        hive = queen.Queen(engine=FakeEngine(tmp / "inputs"), out=tmp / "run", bees=FakeBees(GOOD), slots=2, check=check)
        hive.run()
        program_map = json.loads((tmp / "run" / "survey" / "map.json").read_text())
        self.assertEqual(program_map["references"], [{"from": "0x1000", "to": "0x2000", "type": "read"}])
        self.assertEqual(hive.global_owners, {})  # the fake contract declares no globals; nothing is invented


if __name__ == "__main__":
    unittest.main()


class DeclarationFormTests(unittest.TestCase):
    """No declared global may be lost: pointer declarators are read, shared addresses and unreadable forms are refused."""

    def test_pointer_declarators_are_globals_and_extern_functions_are_not(self):
        text = ("extern int (*callback)(int); /* 0x5000 */\nextern int (*handlers[4])(void); /* 0x5100 */\n"
                "extern int (*matrix)[8]; /* 0x5200 */\nextern int helper(void); /* 0x1000 */\n")
        self.assertEqual(queen.contract_globals(text), {0x5000: "callback", 0x5100: "handlers", 0x5200: "matrix"})
        self.assertEqual(queen.contract_global_problems(text), [])

    def test_two_names_at_one_address_are_refused_before_the_builders(self):
        problems = queen.contract_global_problems("extern int original; /* 0x5000 */\nextern int alias; /* 0x5000 */\n")
        self.assertEqual(len(problems), 1)
        self.assertIn("original, alias share the address 0x5000", problems[0])

    def test_an_unreadable_pointer_declaration_is_refused(self):
        problems = queen.contract_global_problems("extern int (* const)(void); /* 0x5000 */\n")
        self.assertEqual(len(problems), 1)
        self.assertIn("cannot read the name", problems[0])

    def test_jumps_do_not_count_as_data_use(self):
        program_map = {"references": [{"from": "0x1000", "to": "0x5000", "type": "read"},
                                      {"from": "0x1100", "to": "0x5008", "type": "jump"},
                                      {"from": "0x1100", "to": "0x5010", "type": "jump"}]}
        owners = queen.assign_globals({0x5000: "table"}, MODULES, program_map)
        self.assertEqual(owners, {"table": "m01"})


@unittest.skipUnless(confined("c"), "needs a Clang compiler the hive can confine")
class PlanRefusalTests(unittest.TestCase):
    """A contract whose globals cannot all get an owner goes back to the planner, and is refused if never fixed."""

    def plan_with(self, contracts):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "inputs").mkdir()
        (tmp / "inputs" / "greet").write_bytes(b"x")
        (tmp / "run" / "survey").mkdir(parents=True)
        program_map = {"functions": [{"hex": "0x1000", "entry": 0x1000, "name": "f", "size": 8}], "imports": [],
                       "calls": [], "strings": [], "references": [], "input_sha256": "cd" * 32}
        (tmp / "run" / "survey" / "map.json").write_text(json.dumps(program_map))
        written = []

        def bees(role, name, task, folder):
            text = contracts[min(len(written), len(contracts) - 1)]
            written.append(name)
            (Path(folder) / "contract.h").write_text(text)
            return {"ok": True, "output": {"modules": [{"id": "a", "title": "t", "functions": ["0x1000"]}], "skipped": []}}
        hive = queen.Queen(engine=FakeEngine(tmp / "inputs"), out=tmp / "run", bees=bees)
        return hive, program_map, written

    def test_the_planner_fixes_a_shared_address(self):
        bad = "extern int original; /* 0x5000 */\nextern int alias; /* 0x5000 */\nint f(void); /* 0x1000 */\n"
        good = "extern int original; /* 0x5000 */\nint f(void); /* 0x1000 */\n"
        hive, program_map, written = self.plan_with([bad, good])
        modules, _, contract = hive.plan(program_map)
        self.assertEqual(written, ["planner", "planner-fix1"])
        self.assertEqual(queen.contract_globals(contract.read_text()), {0x5000: "original"})

    def test_a_contract_that_stays_unusable_is_refused(self):
        bad = "extern int original; /* 0x5000 */\nextern int alias; /* 0x5000 */\nint f(void); /* 0x1000 */\n"
        hive, program_map, written = self.plan_with([bad])
        with self.assertRaises(queen.HiveError) as raised:
            hive.plan(program_map)
        self.assertIn("share the address", str(raised.exception))
