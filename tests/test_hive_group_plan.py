import json
import re
import sys
import tempfile
import threading
import types
import unittest
from pathlib import Path
from unittest import mock

from hive import queen
from tests.test_hive_queen import FakeEngine

PROTOTYPE = re.compile(r"/\* (0x[0-9a-f]+) \*/")


def fake_fragments(merge_problems=()):
    """A stand-in for hive.fragments (HIVE-FRAGMENTS) with its agreed API."""
    module = types.ModuleType("hive.fragments")

    def fragment_problems(text, group_id, functions):
        declared = set(PROTOTYPE.findall(text))
        missing = sorted(set(functions) - declared)
        return (["struct bodies are not allowed"] if "{" in text else []) + [f"no prototype for {e}" for e in missing]

    def merge_fragments(fragments):
        return "".join(fragments[g] for g in sorted(fragments)), list(merge_problems)

    module.fragment_problems, module.merge_fragments = fragment_problems, merge_fragments
    return module


def big_map(count):
    functions = [{"entry": 0x10000 + i * 0x40, "hex": hex(0x10000 + i * 0x40), "name": f"_f{i}", "size": 32,
                  "signature": f"undefined _f{i}()"} for i in range(count)]
    calls = [{"from": functions[i]["hex"], "to": functions[i + 1]["hex"], "to_name": functions[i + 1]["name"]}
             for i in range(count - 1)]
    return {"file": "greet", "input_sha256": "cd" * 32, "functions": functions, "calls": calls, "imports": [],
            "strings": [], "references": []}


class GroupPlanTests(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        (self.tmp / "inputs").mkdir()
        (self.tmp / "inputs" / "greet").write_bytes(b"x")
        (self.tmp / "run" / "survey").mkdir(parents=True)
        self.names, self.lock = [], threading.Lock()
        for patch in (mock.patch.object(queen.Build, "ensure_confinement", return_value=None),
                      mock.patch.object(queen.Build, "syntax", return_value=(True, ""))):
            patch.start()
            self.addCleanup(patch.stop)

    def hive(self, program_map, fragments_module, bad_once=(), bad_always=()):
        (self.tmp / "run" / "survey" / "map.json").write_text(json.dumps(program_map))
        sys.modules["hive.fragments"] = fragments_module
        self.addCleanup(sys.modules.pop, "hive.fragments", None)
        seen = set()

        def bees(role, name, task, folder):
            with self.lock:
                self.names.append(name)
            folder = Path(folder)
            if name.startswith("contract-fix"):
                return {"ok": True, "output": {"modules": [], "skipped": []}}
            if name == "planner":
                (folder / "contract.h").write_text("int f(void); /* 0x10000 */\n")
                own = [f["hex"] for f in json.loads((folder / "map.json").read_text())["functions"]]
                return {"ok": True, "output": {"modules": [{"id": "a", "title": "all", "functions": own}], "skipped": []}}
            gid = re.match(r"planner-(g\d+)", name).group(1)
            own = [f["hex"] for f in json.loads((folder / "map.json").read_text())["functions"]]
            broken = gid in bad_always or (gid in bad_once and gid not in seen)
            seen.add(gid)
            text = "struct broken { int a; };\n" if broken else "".join(
                f"int {gid}_{i}(void); /* {e} */\n" for i, e in enumerate(own))
            (folder / "fragment.h").write_text(text)
            modules = [{"id": f"x{i}", "title": "part", "functions": own[i:i + 12]} for i in range(0, len(own), 12)]
            return {"ok": True, "output": {"modules": modules, "skipped": []}}
        return queen.Queen(engine=FakeEngine(self.tmp / "inputs"), out=self.tmp / "run", bees=bees, slots=4)

    def test_a_large_program_is_planned_group_by_group(self):
        program_map = big_map(600)
        hive = self.hive(program_map, fake_fragments())
        modules, skipped, contract = hive.plan(program_map)
        group_planners = [n for n in self.names if re.fullmatch(r"planner-g\d+", n)]
        self.assertGreater(len(group_planners), 1)
        self.assertNotIn("planner", self.names)  # no single whole-program planner
        covered = [e for m in modules for e in m["functions"]]
        self.assertEqual(sorted(covered), sorted(f["hex"] for f in program_map["functions"]))  # each exactly once
        self.assertEqual(len({m["id"] for m in modules}), len(modules))
        self.assertTrue(all(re.fullmatch(r"m\d{3}", m["id"]) and len(m["functions"]) <= hive.max_functions
                            for m in modules))
        self.assertEqual(len(PROTOTYPE.findall(contract.read_text())), 600)
        self.assertTrue(hive.opaque)
        brief = hive.brief(modules[0], program_map, {})
        self.assertIn("opaque in the contract", brief)

    def test_a_small_program_keeps_the_single_planner(self):
        program_map = big_map(queen.GROUP_THRESHOLD)
        hive = self.hive(program_map, fake_fragments())
        hive.plan(program_map)
        self.assertEqual(self.names[0], "planner")
        self.assertFalse(getattr(hive, "opaque", False))

    def test_an_unusable_fragment_goes_back_to_its_group_planner(self):
        program_map = big_map(600)
        hive = self.hive(program_map, fake_fragments(), bad_once={"g0001"})
        hive.plan(program_map)
        self.assertIn("planner-g0001-fix1", self.names)
        self.assertFalse([n for n in self.names if re.fullmatch(r"planner-g0002-fix\d", n)])

    def test_a_fragment_that_stays_unusable_stops_the_plan(self):
        program_map = big_map(600)
        hive = self.hive(program_map, fake_fragments(), bad_always={"g0002"})
        with self.assertRaises(queen.HiveError) as raised:
            hive.plan(program_map)
        self.assertIn("the fragment of g0002 is not usable", str(raised.exception))

    def test_merge_problems_go_to_the_contract_fixer(self):
        program_map = big_map(600)
        hive = self.hive(program_map, fake_fragments(merge_problems=["0x10040 declared twice by g0001 and g0002"]))
        hive.plan(program_map)
        self.assertIn("contract-fix1", self.names)


if __name__ == "__main__":
    unittest.main()
