"""Contract tests for the model-free first stage of planning."""

import copy
import hashlib
import importlib
import json
import os
import subprocess
import sys
import unittest
from pathlib import Path

try:
    partition = importlib.import_module("hive.partition")
except ModuleNotFoundError as error:
    if error.name != "hive.partition":
        raise
    partition = None


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False).encode("utf-8")


def program(count):
    return {"file": "fixture", "input_sha256": "ab" * 32,
            "functions": [{"entry": 0x1000 + 16 * i, "hex": hex(0x1000 + 16 * i),
                           "name": f"fn_{i}", "size": 16, "signature": "int f(void)"}
                          for i in range(count)],
            "calls": [], "strings": [], "imports": []}


def owner(result):
    return {entry: group["id"] for group in result["groups"] for entry in group["functions"]}


class PartitionTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(partition, "Phase A partitioner is not implemented on the original base")

    def check_bounds(self, source, result, count, size, summary):
        entries = [entry for group in result["groups"] for entry in group["functions"]]
        self.assertEqual(sorted(entries), sorted(row["hex"] for row in source["functions"]))
        self.assertEqual(len(entries), len(set(entries)))
        self.assertEqual(len({g["id"] for g in result["groups"]}), len(result["groups"]))
        for group in result["groups"]:
            self.assertGreater(len(group["functions"]), 0)
            self.assertLessEqual(len(group["functions"]), count)
            self.assertEqual(group["bytes"], len(encoded(group["map"])))
            self.assertLessEqual(group["bytes"], size)
            self.assertEqual(set(group["map"]), set(source))
            self.assertEqual({f["hex"] for f in group["map"]["functions"]}, set(group["functions"]))
        self.assertEqual(result["summary_bytes"], len(encoded(result["summary"])))
        self.assertLessEqual(result["summary_bytes"], summary)
        self.assertEqual(result["summary"]["totals"]["functions"], len(entries))
        self.assertEqual(result["summary"]["totals"]["groups"], len(result["groups"]))
        self.assertEqual(result["summary"]["totals"]["cut_edges"], len(result["cut_edges"]))

    def test_empty_map(self):
        source = program(0)
        result = partition.partition(source)
        self.assertEqual(result["groups"], [])
        self.assertEqual(result["cut_edges"], [])
        self.check_bounds(source, result, 128, 65536, 8192)

    def test_every_function_is_assigned_once_even_without_relations(self):
        source = program(173)
        result = partition.partition(source, max_functions=7, max_bytes=5000)
        self.check_bounds(source, result, 7, 5000, 8192)
        self.assertEqual(len(result["groups"]), 25)

    def test_mutually_calling_pairs_stay_together(self):
        source = program(6)
        entries = [f["hex"] for f in source["functions"]]
        pairs = [(entries[i], entries[i + 3]) for i in range(3)]
        source["calls"] = [{"from": a, "to": b, "to_name": "callee"}
                           for a, b in pairs + [(b, a) for a, b in pairs]]
        result = partition.partition(source, max_functions=2)
        owners = owner(result)
        self.assertTrue(all(owners[a] == owners[b] for a, b in pairs))
        self.assertEqual(result["cut_edges"], [])

    def test_shared_string_bytes_join_functions_at_different_addresses(self):
        source = program(4)
        source["strings"] = [{"from": f["hex"], "address": hex(0x8000 + i * 32),
                              "text": "even" if i % 2 == 0 else "odd"}
                             for i, f in enumerate(source["functions"])]
        result = partition.partition(source, max_functions=2)
        owners = owner(result)
        self.assertEqual(owners["0x1000"], owners["0x1020"])
        self.assertEqual(owners["0x1010"], owners["0x1030"])

    def test_shared_data_references_join_functions_and_preserve_rows(self):
        for table in ("references", "data_refs"):
            with self.subTest(table=table):
                source = program(4)
                source[table] = [{"from": f["hex"], "to": "0x9000" if i % 2 == 0 else "0xa000",
                                  "type": "READ" if i < 2 else "WRITE", "at": f["entry"] + 1}
                                 for i, f in enumerate(source["functions"])]
                result = partition.partition(source, max_functions=2)
                owners = owner(result)
                self.assertEqual(owners["0x1000"], owners["0x1020"])
                self.assertEqual(owners["0x1010"], owners["0x1030"])
                actual = [r for g in result["groups"] for r in g["map"][table]]
                self.assertEqual(sorted(map(encoded, actual)), sorted(map(encoded, source[table])))

    def test_utf8_slice_limit_includes_metadata_and_all_rows(self):
        source = program(12)
        for function in source["functions"]:
            function["signature"] = "é漢" * 80
        result = partition.partition(source, max_functions=12, max_bytes=900)
        self.check_bounds(source, result, 12, 900, 8192)
        self.assertEqual(len(result["groups"]), 12)
        self.assertTrue(all(g["map"]["functions"][0]["signature"] == "é漢" * 80 for g in result["groups"]))

    def test_impossible_singleton_is_explicit_instead_of_losing_evidence(self):
        source = program(1)
        source["strings"] = [{"from": "0x1000", "address": "0x8000", "text": "x" * 5000}]
        with self.assertRaisesRegex(ValueError, r"0x1000.*[Bb]ytes"):
            partition.partition(source, max_bytes=1000)
        source = program(1)
        source["file"] = "x" * 2000
        with self.assertRaises(ValueError):
            partition.partition(source, max_bytes=1000)

    def test_exact_limit_is_allowed(self):
        source = program(1)
        limit = len(encoded(source))
        result = partition.partition(source, max_bytes=limit)
        self.assertEqual(result["groups"][0]["bytes"], limit)
        with self.assertRaises(ValueError):
            partition.partition(source, max_bytes=limit - 1)

    def test_all_directed_cut_calls_are_listed_including_distinct_callsites(self):
        source = program(3)
        source["calls"] = [
            {"from": "0x1000", "to": "0x1010", "at": "0x1001", "to_name": "first"},
            {"from": "0x1000", "to": "0x1010", "at": "0x1002", "to_name": "first"},
            {"from": "0x1010", "to": "0x1000", "at": "0x1011"},
            {"from": "0x1020", "to": "0x1020"},
            {"from": "0x1020", "to": "0x9999", "to_name": "puts"}]
        source["imports"] = ["unused", "puts"]
        result = partition.partition(source, max_functions=1)
        owners = owner(result)
        expected = [{**row, "from_group": owners[row["from"]], "to_group": owners[row["to"]]}
                    for row in source["calls"] if row["to"] in owners and owners[row["from"]] != owners[row["to"]]]
        self.assertEqual(sorted(map(encoded, result["cut_edges"])), sorted(map(encoded, expected)))
        self.assertEqual(len(result["cut_edges"]), 3)
        for group in result["groups"]:
            mine = set(group["functions"])
            touched = [r for r in source["calls"] if r["from"] in mine or r["to"] in mine]
            self.assertEqual(sorted(map(encoded, group["map"]["calls"])), sorted(map(encoded, touched)))
            self.assertEqual(group["map"]["imports"], ["puts"] if "0x1020" in mine else [])

    def test_table_order_and_json_key_order_do_not_change_partition(self):
        source = program(31)
        source["calls"] = [{"from": f["hex"], "to": source["functions"][(i + 3) % 31]["hex"]}
                           for i, f in enumerate(source["functions"])]
        shuffled = {key: list(reversed(value)) if isinstance(value, list) else value
                    for key, value in reversed(list(source.items()))}
        self.assertEqual(encoded(partition.partition(source, max_functions=5)),
                         encoded(partition.partition(shuffled, max_functions=5)))

    def test_hash_seed_does_not_change_serialized_result(self):
        source = program(24)
        source["strings"] = [{"from": f["hex"], "address": "0x8000", "text": "common"}
                             for f in source["functions"]]
        script = ("import json,sys,hashlib; from hive.partition import partition,encode; "
                  "print(hashlib.sha256(encode(partition(json.load(sys.stdin),max_functions=5))).hexdigest())")
        digests = []
        for seed in ("1", "917"):
            env = dict(os.environ, PYTHONHASHSEED=seed)
            done = subprocess.run([sys.executable, "-B", "-c", script], env=env,
                                  cwd=Path(__file__).resolve().parents[1], input=json.dumps(source),
                                  text=True, capture_output=True, timeout=20, check=True)
            digests.append(done.stdout.strip())
        self.assertEqual(digests[0], digests[1])
        self.assertEqual(len(digests[0]), hashlib.sha256().digest_size * 2)

    def test_summary_omissions_are_explicit_and_complete_edges_stay_available(self):
        source = program(350)
        source["entry_points"] = [f["hex"] for f in source["functions"]]
        source["calls"] = [{"from": source["functions"][i]["hex"], "to": source["functions"][i + 1]["hex"]}
                           for i in range(349)]
        result = partition.partition(source, max_functions=1, max_bytes=30000, summary_bytes=512)
        self.check_bounds(source, result, 1, 30000, 512)
        self.assertEqual(len(result["cut_edges"]), 349)
        summary = result["summary"]
        for key in ("groups", "cut_edges", "entry_points", "entry_hints"):
            self.assertEqual(len(summary[key]) + summary["omitted"][key], summary["totals"][key])
        self.assertGreater(summary["omitted"]["groups"], 0)
        self.assertGreater(summary["omitted"]["cut_edges"], 0)
        with self.assertRaisesRegex(ValueError, "summary"):
            partition.partition(source, summary_bytes=1)

    def test_runtime_hints_and_declared_entries_are_preserved_without_skipping(self):
        source = program(4)
        source["functions"][0].update(name="main")
        source["functions"][1].update(library_hint="libc", is_thunk=True)
        source["functions"][2].update(runtime=True, is_entry=True)
        source["entry_points"] = ["0x1030"]
        before = copy.deepcopy(source)
        result = partition.partition(source, max_functions=2)
        self.check_bounds(source, result, 2, 65536, 8192)
        actual = {f["hex"]: f for g in result["groups"] for f in g["map"]["functions"]}
        self.assertEqual(actual, {f["hex"]: f for f in source["functions"]})
        self.assertEqual(result["summary"]["entry_points"], ["0x1020", "0x1030"])
        self.assertEqual(result["summary"]["entry_hints"], ["0x1000"])
        result["groups"][0]["map"]["functions"][0]["name"] = "changed"
        self.assertEqual(source, before)

    def test_invalid_limits_addresses_or_duplicate_functions_fail(self):
        for limits in ({"max_functions": 0}, {"max_functions": True}, {"max_bytes": -1},
                       {"summary_bytes": 0}, {"max_bytes": 2.5}):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                partition.partition(program(1), **limits)
        for update in (lambda m: m["functions"].append(dict(m["functions"][0])),
                       lambda m: m["functions"][0].update(hex="0xffff"),
                       lambda m: m["calls"].append({"from": "bad", "to": "0x1000"})):
            source = program(2)
            update(source)
            with self.assertRaises(ValueError):
                partition.partition(source)

    def test_three_thousand_functions_have_bounded_lossless_slices(self):
        source = program(3000)
        for i, function in enumerate(source["functions"]):
            source["calls"].append({"from": function["hex"],
                                    "to": source["functions"][(i + 1) % 3000]["hex"]})
            source["strings"].append({"from": function["hex"], "address": hex(0x80000 + i // 30),
                                      "text": f"cluster {i // 30}"})
        result = partition.partition(source, max_functions=64, max_bytes=32768, summary_bytes=4096)
        self.check_bounds(source, result, 64, 32768, 4096)
        owners = owner(result)
        cuts = [r for r in source["calls"] if owners[r["from"]] != owners[r["to"]]]
        self.assertEqual(sorted((r["from"], r["to"]) for r in result["cut_edges"]),
                         sorted((r["from"], r["to"]) for r in cuts))
        self.assertGreaterEqual(len(result["groups"]), 47)
        self.assertLessEqual(len(result["groups"]), 100)


if __name__ == "__main__":
    unittest.main()
