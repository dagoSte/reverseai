"""The Ghidra worker's pure logic, without Ghidra: requests, the file's own sections, anchor cross-checks, the M3a
selection rules and the reply.

Query outputs are built here from tests/fixtures_code.py's declared layout (addresses, offsets, sizes and calls fixed
by the fixture's own assembler), never from the worker or from Ghidra, and the expected observations come from the
same declared layout; an optional rebase delta stands for Ghidra loading the program at another base.
"""

import contextlib
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import signal
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from reverseai.contract import WorkerError, parse_worker_reply, sha256_hex
from tests.fixtures_code import TEXT_SIZE, elf_code, elf_data_only, pe_code

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "containers" / "ghidra"
SPEC = importlib.util.spec_from_file_location("ghidra_worker", SOURCE / "worker.py")
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)
DEFAULTS = {"max_functions": 64, "decompile": 8, "max_chars": 1024, "max_calls": 128}
PE_NAMES = ("entry", "FUN_140001020", "FUN_140001030", "FUN_140001050")


def query(data, layout, *, delta=0, names=None, texts=None, options=None):
    """What a correct ReverseAIQuery writes for a fixture, from its declared layout; Ghidra addresses = VA + delta."""
    text = layout["text"]
    names = names or [f["name"] for f in layout["functions"]]
    block_size = TEXT_SIZE if layout["format"] == "elf" else layout["text_raw_size"]
    blocks = [{"name": ".text", "start": text["address"] + delta, "size": block_size, "execute": True,
               "initialized": True, "file_offset": text["offset"]}]
    if "data" in layout:
        blocks.append({"name": ".data", "start": layout["data"]["address"] + delta, "size": 0x200, "execute": False,
                       "initialized": True, "file_offset": layout["data"]["offset"]})
    by_entry = {f["entry"]: name for f, name in zip(layout["functions"], names)}
    functions = []
    for function, name in zip(layout["functions"], names):
        calls = [{"address": c["address"] + delta, "length": c["length"], "file_offset": c["offset"],
                  "bytes": data[c["offset"]:c["offset"] + c["length"]].hex(), "to": c["to"] + delta,
                  "to_file_offset": c["to"] - text["address"] + text["offset"], "to_name": by_entry[c["to"]]}
                 for c in layout["calls"] if c["from"] == function["entry"]]
        functions.append({"name": name, "entry": function["entry"] + delta, "size": function["size"],
                          "file_offset": function["offset"], "anchored": True,
                          "bytes": data[function["offset"]:function["offset"] + function["size"]].hex(), "calls": calls})
    texts = texts if texts is not None else {f["entry"]: f"int f_{f['offset']:x}(void)\n{{\n}}\n" for f in layout["functions"]}
    return {"format": "x", "options_off": options or {}, "blocks": blocks, "functions": functions,
            "pseudocode": [{"entry": entry + delta, "text": t} for entry, t in texts.items()]}


def expected(layout, names=None, *, args=DEFAULTS, texts=None):
    """The M3a observations for the declared layout and request."""
    names = names or [f["name"] for f in layout["functions"]]
    functions = [dict(f, name=n, index=i) for i, (f, n) in enumerate(zip(layout["functions"], names))][:args["max_functions"]]
    end = layout["text"]["offset"] + TEXT_SIZE
    result = [{"location": {"offset": f["offset"], "length": min(f["size"], 4096, end - f["offset"])},
               "value": {"kind": "function", "index": f["index"], "name": f["name"], "entry": f["entry"], "size": f["size"]}}
              for f in functions]
    texts = texts if texts is not None else {f["entry"]: f"int f_{f['offset']:x}(void)\n{{\n}}\n" for f in layout["functions"]}
    order = [f for f in functions if f["entry"] == layout["entry"]]
    order += sorted((f for f in functions if f["entry"] != layout["entry"]), key=lambda f: (-f["size"], f["entry"]))
    for f in order[:args["decompile"]]:
        text = texts.get(f["entry"])
        if text is not None:
            result.append({"location": result[f["index"]]["location"],
                           "value": {"kind": "pseudocode", "index": f["index"], "entry": f["entry"],
                                     "text": text[:args["max_chars"]], "truncated": len(text) > args["max_chars"]}})
    entries = {f["entry"] for f in functions}
    by_entry = {f["entry"]: f["name"] for f in functions} | {f["entry"]: n for f, n in zip(layout["functions"], names)}
    calls = sorted((c for c in layout["calls"] if c["from"] in entries), key=lambda c: c["address"])[:args["max_calls"]]
    result += [{"location": {"offset": c["offset"], "length": 5},
                "value": {"kind": "call", "from": c["from"], "to": c["to"], "to_name": by_entry[c["to"]]}} for c in calls]
    return result


def observe(data, q, **args):
    return worker.observations(data, q, dict(DEFAULTS, **args))


class KnownAnswerTests(unittest.TestCase):
    def test_elf_and_pe_observations_equal_the_declared_layout(self):
        for label, (data, layout), names in (("elf", elf_code(), None), ("pe", pe_code(), PE_NAMES)):
            with self.subTest(label):
                self.assertEqual(observe(data, query(data, layout, names=names)), expected(layout, names))

    def test_a_rebased_program_still_reports_the_files_own_addresses(self):
        for delta in (0x100000, -0x400000 + 0x1000):
            data, layout = elf_code()
            with self.subTest(delta=hex(delta)):
                self.assertEqual(observe(data, query(data, layout, delta=delta)), expected(layout))

    def test_known_values(self):
        data, layout = elf_code()
        result = observe(data, query(data, layout))
        self.assertEqual([o["value"]["name"] for o in result if o["value"]["kind"] == "function"],
                         ["_start", "add_numbers", "compute", "constant"])
        self.assertEqual([(o["location"]["offset"], o["location"]["length"]) for o in result if o["value"]["kind"] == "function"],
                         [(0x100, 20), (0x120, 10), (0x130, 27), (0x150, 6)])
        self.assertEqual([o["value"]["entry"] for o in result if o["value"]["kind"] == "pseudocode"],
                         [0x400100, 0x400130, 0x400120, 0x400150])  # entry point, then by size
        self.assertEqual([(o["location"]["offset"], o["value"]["from"], o["value"]["to"], o["value"]["to_name"])
                          for o in result if o["value"]["kind"] == "call"],
                         [(0x100, 0x400100, 0x400120, "add_numbers"), (0x105, 0x400100, 0x400130, "compute"),
                          (0x13B, 0x400130, 0x400120, "add_numbers"), (0x142, 0x400130, 0x400150, "constant")])

    def test_the_data_only_control_has_no_observations(self):
        data, layout = elf_data_only()
        q = {"options_off": {}, "blocks": [{"start": layout["data"]["address"], "size": layout["data"]["size"],
                                            "file_offset": layout["data"]["offset"]}], "functions": [], "pseudocode": []}
        self.assertEqual(observe(data, q), [])

    def test_observation_values_have_exactly_the_seam_fields(self):
        data, layout = pe_code()
        fields = {"function": {"kind", "index", "name", "entry", "size"}, "pseudocode": {"kind", "index", "entry", "text", "truncated"},
                  "call": {"kind", "from", "to", "to_name"}}
        for item in observe(data, query(data, layout, names=PE_NAMES)):
            self.assertEqual(set(item["value"]), fields[item["value"]["kind"]])
            self.assertTrue(1 <= item["location"]["length"] <= 4096)


class SelectionTests(unittest.TestCase):
    def test_caps_and_the_emitted_function_rule(self):
        data, layout = elf_code()
        for args in ({"max_functions": 1}, {"max_functions": 2}, {"max_functions": 3, "decompile": 2},
                     {"decompile": 0}, {"decompile": 1}, {"max_calls": 0}, {"max_calls": 3}, {"max_chars": 64},
                     {"max_functions": 2, "decompile": 1, "max_chars": 64, "max_calls": 1}):
            with self.subTest(args=args):
                self.assertEqual(observe(data, query(data, layout), **args), expected(layout, args=dict(DEFAULTS, **args)))

    def test_the_first_functions_are_chosen_by_address_whatever_the_query_order(self):
        data, layout = elf_code()
        q = query(data, layout)
        q["functions"].reverse()
        self.assertEqual(observe(data, q, max_functions=2), expected(layout, args=dict(DEFAULTS, max_functions=2)))

    def test_max_functions_2_keeps_calls_and_pseudocode_of_emitted_functions_only(self):
        data, layout = elf_code()
        result = observe(data, query(data, layout), max_functions=2)
        self.assertEqual([o["value"]["entry"] for o in result if o["value"]["kind"] == "pseudocode"], [0x400100, 0x400120])
        self.assertEqual([o["value"]["from"] for o in result if o["value"]["kind"] == "call"], [0x400100, 0x400100])

    def test_largest_ties_go_to_the_lower_entry(self):
        data, layout = elf_code()
        q = query(data, layout)
        for function in q["functions"][1:]:
            function["size"] = 6
            function["bytes"] = function["bytes"][:12]
        result = observe(data, q)
        self.assertEqual([o["value"]["entry"] for o in result if o["value"]["kind"] == "pseudocode"],
                         [0x400100, 0x400120, 0x400130, 0x400150])

    def test_text_is_cut_at_max_chars_and_marked_truncated(self):
        data, layout = elf_code()
        long = "x" * 100
        texts = {f["entry"]: long for f in layout["functions"]}
        result = observe(data, query(data, layout, texts=texts), max_chars=64)
        pseudo = [o["value"] for o in result if o["value"]["kind"] == "pseudocode"]
        self.assertTrue(all(p["text"] == "x" * 64 and p["truncated"] for p in pseudo))
        exact = observe(data, query(data, layout, texts={f["entry"]: "y" * 64 for f in layout["functions"]}), max_chars=64)
        self.assertTrue(all(o["value"]["truncated"] is False for o in exact if o["value"]["kind"] == "pseudocode"))

    def test_pseudocode_of_a_function_that_is_not_emitted_is_ignored(self):
        data, layout = elf_code()
        q = query(data, layout)
        q["pseudocode"].append({"entry": 0x401000, "text": "int stray(void)\n"})
        self.assertEqual(observe(data, q), expected(layout))

    def test_a_failed_decompilation_is_omitted(self):
        data, layout = elf_code()
        texts = {layout["functions"][2]["entry"]: "int compute(void)\n"}
        result = observe(data, query(data, layout, texts=texts))
        self.assertEqual([o["value"]["entry"] for o in result if o["value"]["kind"] == "pseudocode"], [0x400130])

    def test_functions_the_query_did_not_anchor_or_outside_an_executable_section_are_not_emitted(self):
        data, layout = pe_code()
        q = query(data, layout, names=PE_NAMES)
        q["functions"][1]["anchored"] = False
        data_function = dict(q["functions"][0], entry=layout["data"]["address"], file_offset=layout["data"]["offset"], size=4,
                             bytes=data[layout["data"]["offset"]:layout["data"]["offset"] + 4].hex(), calls=[])
        q["functions"].append(data_function)
        q["blocks"][1]["execute"] = True  # even if Ghidra marks it executable, the file's .data is not
        names = [o["value"]["name"] for o in observe(data, q) if o["value"]["kind"] == "function"]
        self.assertEqual(names, ["entry", "FUN_140001030", "FUN_140001050"])

    def test_calls_outside_their_function_or_longer_than_16_bytes_are_dropped(self):
        data, layout = elf_code()
        q = query(data, layout)
        q["functions"][1]["calls"].append(dict(q["functions"][0]["calls"][0]))  # before add_numbers: entry's call
        q["functions"][1]["calls"].append(dict(q["functions"][2]["calls"][1]))  # after add_numbers ends: compute's call
        long = dict(q["functions"][2]["calls"][0], length=17)
        q["functions"][2]["calls"][0] = long
        result = observe(data, q)
        self.assertEqual([(o["value"]["from"], o["location"]["offset"]) for o in result if o["value"]["kind"] == "call"],
                         [(0x400100, 0x100), (0x400100, 0x105), (0x400130, 0x142)])

    def test_a_call_to_an_unmapped_target_keeps_the_rebased_address(self):
        data, layout = elf_code()
        q = query(data, layout, delta=0x100000)
        q["functions"][0]["calls"][0].update(to=0x900000 + 0x100000, to_file_offset=-1, to_name="external")
        call = [o for o in observe(data, q) if o["value"]["kind"] == "call"][0]
        self.assertEqual((call["value"]["to"], call["value"]["to_name"]), (0x900000, "external"))


class BoundTests(unittest.TestCase):
    def test_an_anchor_stops_at_the_section_end_and_at_max_location(self):
        data, layout = elf_code()
        q = query(data, layout)
        last = q["functions"][3]  # constant: 6 bytes left in .text
        last.update(size=40, bytes=data[last["file_offset"]:last["file_offset"] + 40].hex())
        result = {o["value"]["name"]: (o["location"]["length"], o["value"]["size"]) for o in observe(data, q)
                  if o["value"]["kind"] == "function"}
        self.assertEqual(result["constant"], (6, 40))
        small = query(data, layout)
        for function in small["functions"]:
            function["bytes"] = function["bytes"][:16]  # the query sends at most MAX_LOCATION bytes
        with patch.object(worker, "MAX_LOCATION", 8):
            lengths = [o["location"]["length"] for o in observe(data, small) if o["value"]["kind"] == "function"]
        self.assertEqual(lengths, [8, 8, 8, 6])

    def test_a_sparse_body_keeps_the_calls_in_its_span(self):
        """Decision m3a-function-span: size is entry to last body byte, so a call after a gap is still inside."""
        data, layout = elf_code()
        q = query(data, layout)
        start = q["functions"][0]
        start["size"] = 0x56  # _start's span reaching the end of .text, as if its body continued there
        start["bytes"] = data[start["file_offset"]:start["file_offset"] + 0x56].hex()
        late = dict(q["functions"][2]["calls"][1])  # compute's call at 0x142, now also inside _start's span
        start["calls"].append(late)
        froms = [(o["value"]["from"], o["location"]["offset"]) for o in observe(data, q) if o["value"]["kind"] == "call"]
        self.assertIn((0x400100, 0x142), froms)

    def test_the_native_sparse_body_shape_is_accepted_with_its_span(self):
        """The shape Ghidra reported for the native sparse case: _start's body is [0x00, 0x17) and [0x2a, 0x30)."""
        data, layout = elf_code()
        patched, text = bytearray(data), layout["text"]["offset"]
        code = (b"\xe8" + (0x20 - 0x05).to_bytes(4, "little") + b"\x85\xc0" + b"\x0f\x84" + (0x2a - 0x0d).to_bytes(4, "little")
                + b"\xb8\x3c\x00\x00\x00\x31\xff\x0f\x05\xc3")
        patched[text:text + 0x20] = code + b"\xcc" * (0x20 - len(code))
        patched[text + 0x2a:text + 0x30] = b"\xe8" + (0x30 - 0x2f).to_bytes(4, "little") + b"\xc3"
        data = bytes(patched)
        q = query(data, layout)
        start = q["functions"][0]
        late = {"address": 0x40012a, "length": 5, "file_offset": text + 0x2a, "bytes": data[text + 0x2a:text + 0x2f].hex(),
                "to": 0x400130, "to_file_offset": text + 0x30, "to_name": "compute"}
        start.update(size=0x30, bytes=data[text:text + 0x30].hex(), calls=[start["calls"][0], late])
        result = observe(data, q)
        self.assertEqual([(o["location"]["offset"], o["location"]["length"], o["value"]["size"]) for o in result
                          if o["value"]["kind"] == "function"][0], (text, 0x30, 0x30))
        self.assertEqual([(o["value"]["from"], o["location"]["offset"]) for o in result if o["value"]["kind"] == "call"][:2],
                         [(0x400100, text), (0x400100, text + 0x2a)])
        start["size"] = 29  # the old byte count: the call after the gap falls outside and is dropped
        start["bytes"] = start["bytes"][:58]
        froms = [o["location"]["offset"] for o in observe(data, q) if o["value"]["kind"] == "call" and o["value"]["from"] == 0x400100]
        self.assertEqual(froms, [text])

    def test_a_call_whose_target_maps_below_zero_is_dropped(self):
        data, layout = elf_code()
        q = query(data, layout, delta=0x100000)
        q["functions"][0]["calls"][0].update(to=0x1000, to_file_offset=-1)  # 0x1000 - delta < 0
        calls = [o["location"]["offset"] for o in observe(data, q) if o["value"]["kind"] == "call"]
        self.assertEqual(calls, [0x105, 0x13B, 0x142])

    def test_a_too_large_input_is_refused_and_the_digest_covers_the_whole_file(self):
        data, layout = elf_code()
        with patch.object(worker, "MAX_INPUT_BYTES", len(data) - 1):
            self.assertEqual(worker.reply(["ghidra.analyze", "{}"], data, lambda f, a, o: query(data, layout))["error"], "InputTooLarge")
        with tempfile.TemporaryDirectory() as folder, patch.object(worker, "MAX_INPUT_BYTES", 16):
            path = Path(folder, "input")
            path.write_bytes(data)
            kept, digest = worker.read_snapshot(path)
        self.assertEqual((len(kept), digest), (17, hashlib.sha256(data).hexdigest()))


class CrossCheckTests(unittest.TestCase):
    def refused(self, data, q, error=worker.InconsistentAnchor):
        with self.assertRaises(error):
            observe(data, q)

    def test_bytes_blocks_and_rebase_must_agree_at_every_anchor(self):
        data, layout = elf_code()
        cases = {
            "function bytes": lambda q: q["functions"][1].update(bytes="00" + q["functions"][1]["bytes"][2:]),
            "function bytes too short": lambda q: q["functions"][1].update(bytes=q["functions"][1]["bytes"][:4]),
            "file offset of another function": lambda q: q["functions"][1].update(file_offset=layout["functions"][2]["offset"]),
            "block offset": lambda q: q["blocks"][0].update(file_offset=q["blocks"][0]["file_offset"] + 1),
            "a second delta": lambda q: q["functions"][3].update(entry=q["functions"][3]["entry"] + 0x1000),
            "call bytes": lambda q: q["functions"][0]["calls"][0].update(bytes="e800000000"),
            "call address": lambda q: q["functions"][0]["calls"][0].update(address=q["functions"][0]["calls"][0]["address"] + 1),
            "a second rebase through a second block": lambda q: (
                q["blocks"].append(dict(q["blocks"][0], start=q["blocks"][0]["start"] + 0x1000)),
                q["functions"][3].update(entry=q["functions"][3]["entry"] + 0x1000)),
        }
        for label, change in cases.items():
            with self.subTest(label):
                q = query(data, layout)
                change(q)
                self.refused(data, q)

    def test_options_ghidra_should_have_turned_off_must_be_off(self):
        data, layout = pe_code()
        self.assertTrue(observe(data, query(data, layout, names=PE_NAMES, options={"PDB Universal": "false", "x.Path": ""})))
        for options in ({"PDB Universal": "true"}, {"DWARF": "TRUE"}, {"PDB Universal.Search untrusted symbol servers": "true"}):
            with self.subTest(options=options):
                self.refused(data, query(data, layout, names=PE_NAMES, options=options), worker.AnalysisOptionOn)

    def test_malformed_query_output_is_refused(self):
        data, layout = elf_code()
        cases = {
            "not an object": lambda q: [],
            "no options": lambda q: {k: v for k, v in q.items() if k != "options_off"},
            "option not text": lambda q: dict(q, options_off={"PDB": False}),
            "functions not a list": lambda q: dict(q, functions={}),
            "function not an object": lambda q: dict(q, functions=["f"]),
            "entry not an int": lambda q: (q["functions"][0].update(entry="0x400100"), q)[1],
            "negative size": lambda q: (q["functions"][0].update(size=-1), q)[1],
            "bytes not hex": lambda q: (q["functions"][0].update(bytes="zz"), q)[1],
            "name not text": lambda q: (q["functions"][0].update(name=7), q)[1],
            "pseudocode not an object": lambda q: (q["pseudocode"].append("text"), q)[1],
            "pseudocode entry not an int": lambda q: (q["pseudocode"][0].update(entry=None), q)[1],
            "pseudocode text not text": lambda q: (q["pseudocode"][0].update(text=None), q)[1],
            "call not an object": lambda q: (q["functions"][0]["calls"].append("call"), q)[1],
            "block without size": lambda q: (q["blocks"][0].pop("size"), q)[1],
        }
        for label, change in cases.items():
            with self.subTest(label), self.assertRaises(worker.InvalidQueryOutput):
                observe(data, change(query(data, layout)))

    def test_names_are_printable_ascii_of_at_most_128_and_text_keeps_lines(self):
        data, layout = elf_code()
        names = ["caf\u00e9\x07name", "x" * 200, "ok", "tab\tname"]
        texts = {layout["functions"][0]["entry"]: "a\x00b\nc\td\u2028e"}
        result = observe(data, query(data, layout, names=names, texts=texts))
        self.assertEqual([o["value"]["name"] for o in result if o["value"]["kind"] == "function"],
                         ["caf??name", "x" * 128, "ok", "tab?name"])
        self.assertEqual([o["value"]["text"] for o in result if o["value"]["kind"] == "pseudocode"], ["a?b\nc\td?e"])


class FileMapTests(unittest.TestCase):
    def test_the_workers_section_map_matches_the_fixtures(self):
        for build, sections in ((elf_code, [(0x100, 0x156, 0x400100, True)]),
                                (pe_code, [(0x200, 0x256, 0x140001000, True), (0x400, 0x410, 0x140002000, False)])):
            data, layout = build()
            with self.subTest(build.__name__):
                self.assertEqual((build is elf_code and worker.elf_map or worker.pe_map)(data), (layout["entry"], sections))
                self.assertEqual(worker.offset_of(sections, layout["entry"]), layout["text"]["offset"])

    def test_sections_without_file_bytes_or_not_allocated_are_not_mapped(self):
        data, layout = elf_code()
        symtab = layout["shoff"] + 2 * 64
        nobits = bytearray(data)
        nobits[symtab + 4:symtab + 16] = (8).to_bytes(4, "little") + (0x2).to_bytes(8, "little")  # SHT_NOBITS, SHF_ALLOC
        alloc = bytearray(data)
        alloc[symtab + 8:symtab + 16] = (0x2).to_bytes(8, "little")  # an allocated .symtab is mapped
        self.assertEqual(worker.elf_map(bytes(nobits))[1], [(0x100, 0x156, 0x400100, True)])
        self.assertEqual(worker.elf_map(bytes(alloc))[1], [(0x100, 0x156, 0x400100, True), (0x158, 0x158 + 120, 0, False)])

    def test_pe_sections_count_their_raw_bytes_when_virtual_size_is_zero(self):
        """Decision m3a-function-span: PE extent is min(SizeOfRawData, VirtualSize), SizeOfRawData when VirtualSize is 0."""
        data, layout = pe_code()
        text_header = 0x40 + 4 + 20 + 240
        patched = bytearray(data)
        patched[text_header + 8:text_header + 12] = (0).to_bytes(4, "little")  # .text VirtualSize 0
        self.assertEqual(worker.pe_map(bytes(patched))[1][0], (0x200, 0x400, 0x140001000, True))
        patched[text_header + 8:text_header + 12] = (0x300).to_bytes(4, "little")  # larger than SizeOfRawData
        self.assertEqual(worker.pe_map(bytes(patched))[1][0], (0x200, 0x400, 0x140001000, True))

    def test_only_elf_and_pe_are_accepted(self):
        for data in (b"", b"\xcf\xfa\xed\xfe" + bytes(60), b"PK\x03\x04" + bytes(60), b"MZ" + bytes(100), bytes(64)):
            with self.subTest(data=data[:4]), self.assertRaises(worker.UnsupportedFormat):
                worker.kind(data)
        self.assertEqual((worker.kind(elf_code()[0]), worker.kind(pe_code()[0])), ("elf", "pe"))

    def test_truncated_tables_are_refused(self):
        data, layout = elf_code()
        with self.assertRaises(worker.TruncatedStructure):
            worker.elf_map(data[:layout["shoff"] + 10])
        pe = pe_code()[0]
        with self.assertRaises(worker.TruncatedStructure):
            worker.pe_map(pe[:0x100])


class RequestAndCommandTests(unittest.TestCase):
    def test_requests_are_exact(self):
        self.assertEqual(worker.parse_request(["ghidra.analyze", "{}"]), ("ghidra.analyze", DEFAULTS))
        self.assertEqual(worker.parse_request(["ghidra.analyze", json.dumps({"max_functions": 1, "decompile": 0, "max_chars": 64, "max_calls": 0})])[1],
                         {"max_functions": 1, "decompile": 0, "max_chars": 64, "max_calls": 0})
        self.assertEqual(worker.parse_request(["ghidra.analyze", json.dumps({"max_functions": 128, "decompile": 16, "max_chars": 2048, "max_calls": 256})])[1],
                         {"max_functions": 128, "decompile": 16, "max_chars": 2048, "max_calls": 256})
        for argv in (["ghidra.analyze"], ["ghidra.analyze", "{}", "x"], ["yarax.matches", "{}"], ["ghidra.script", "{}"],
                     ["ghidra.analyze", '{"max_functions": 0}'], ["ghidra.analyze", '{"max_functions": 129}'],
                     ["ghidra.analyze", '{"decompile": 17}'], ["ghidra.analyze", '{"max_chars": 63}'], ["ghidra.analyze", '{"max_chars": 2049}'],
                     ["ghidra.analyze", '{"max_calls": -1}'], ["ghidra.analyze", '{"max_calls": 257}'], ["ghidra.analyze", '{"decompile": true}'],
                     ["ghidra.analyze", '{"decompile": 1.0}'], ["ghidra.analyze", '{"script": "Evil.java"}'], ["ghidra.analyze", '{"loader": "BinaryLoader"}'],
                     ["ghidra.analyze", '{"decompile": 1, "decompile": 2}'], ["ghidra.analyze", "[]"], ["ghidra.analyze", "{"]):
            with self.subTest(argv=argv), self.assertRaises(worker.InvalidRequest):
                worker.parse_request(argv)

    def test_the_headless_command_is_fixed_and_takes_only_bounded_numbers(self):
        argv = worker.ghidra_argv("elf", "/tmp/reverseai-ghidra/query.json", dict(DEFAULTS, max_functions=7, decompile=3), 256)
        self.assertEqual(argv[:2], ["/bin/bash", "/opt/ghidra/support/analyzeHeadless"])
        self.assertEqual(argv[argv.index("-import") + 1], "/snapshot/input")
        for flag in ("-readOnly", "-deleteProject"):
            self.assertIn(flag, argv)
        self.assertEqual(argv[argv.index("-loader") + 1:argv.index("-loader") + 6],
                         ["ElfLoader", "-loader-loadLibraries", "false", "-loader-linkExistingProjectLibraries", "false"])
        self.assertEqual(worker.ghidra_argv("pe", "q", DEFAULTS, 1)[argv.index("-loader") + 1], "PeLoader")
        self.assertEqual(argv[argv.index("-preScript") + 1], "ReverseAIOptions.java")
        post = argv.index("-postScript")
        self.assertEqual(argv[post + 1:post + 7], ["ReverseAIQuery.java", "/tmp/reverseai-ghidra/query.json", "7", "3", "256", "40"])
        self.assertEqual(argv[argv.index("-scriptPath") + 1], str(worker.SCRIPTS))
        self.assertEqual(argv[argv.index("-max-cpu") + 1], "2")
        self.assertEqual(argv[argv.index("-analysisTimeoutPerFile") + 1], "120")
        self.assertLess(worker.ANALYSIS_SECONDS + worker.DECOMPILE_SECONDS, worker.GHIDRA_SECONDS)
        self.assertLess(worker.GHIDRA_SECONDS, 240)

    def test_the_environment_is_fixed_and_inherits_nothing(self):
        with patch.dict("os.environ", {"GHIDRA_JAVA_OPTIONS": "-agentlib:jdwp", "JAVA_TOOL_OPTIONS": "-Dx=y", "LD_PRELOAD": "/x"}):
            env = worker.ghidra_env()
        self.assertEqual(env, {"PATH": "/usr/bin:/bin", "HOME": "/tmp/reverseai-ghidra/home", "LANG": "C.UTF-8",
                               "JAVA_HOME": "/opt/jdk", "GHIDRA_HEADLESS_MAXMEM": "1G",
                               "JAVA_TOOL_OPTIONS": "-Duser.home=/tmp/reverseai-ghidra/home -Djava.io.tmpdir=/tmp/reverseai-ghidra"})


class FakeProcess:
    def __init__(self, write=None, hang=False):
        self.write, self.hang, self.pid, self.killed = write, hang, 4242, False

    def __call__(self, argv, **kwargs):
        self.argv, self.kwargs = argv, kwargs
        if self.write is not None:
            Path(argv[argv.index("-postScript") + 2]).write_bytes(self.write)
        return self

    def wait(self, timeout=None):
        if self.hang and not self.killed:
            raise subprocess.TimeoutExpired("analyzeHeadless", timeout)
        return 0


class RunGhidraTests(unittest.TestCase):
    def run_with(self, process):
        with tempfile.TemporaryDirectory() as folder, patch.object(worker, "WORK", Path(folder) / "work"), \
                patch.object(worker.subprocess, "Popen", process), \
                patch.object(worker.os, "killpg", side_effect=lambda pid, sig: setattr(process, "killed", (pid, sig))):
            process.expected_env = worker.ghidra_env()
            process.expected_argv = worker.ghidra_argv("elf", worker.WORK / "query.json", DEFAULTS, 256)
            return worker.run_ghidra("elf", DEFAULTS, 256)

    def test_the_query_output_is_read_back(self):
        process = FakeProcess(json.dumps({"functions": []}).encode())
        self.assertEqual(self.run_with(process), {"functions": []})
        self.assertTrue(process.kwargs["start_new_session"])
        self.assertIs(process.kwargs["stdin"], subprocess.DEVNULL)
        self.assertEqual(process.kwargs["env"], process.expected_env)
        self.assertEqual(process.argv, process.expected_argv)

    def test_failures_have_their_own_errors(self):
        for label, process, error in (("no output", FakeProcess(), worker.GhidraFailed),
                                      ("not JSON", FakeProcess(b"{"), worker.InvalidQueryOutput),
                                      ("too large", FakeProcess(b"{}" + b" " * 64), worker.InvalidQueryOutput)):
            with self.subTest(label), self.assertRaises(error), patch.object(worker, "MAX_QUERY_BYTES", 16):
                self.run_with(process)

    def test_a_hung_analysis_kills_its_whole_process_group(self):
        process = FakeProcess(hang=True)
        with self.assertRaises(worker.GhidraTimeout):
            self.run_with(process)
        self.assertEqual(process.killed, (4242, signal.SIGKILL))


class ReplyTests(unittest.TestCase):
    def test_replies_pass_the_hosts_parser(self):
        data, layout = elf_code()
        message = worker.reply(["ghidra.analyze", "{}"], data, lambda f, a, o: query(data, layout))
        observations = parse_worker_reply(worker.encode(message), input_sha256=sha256_hex(data), max_observations=400)
        self.assertEqual(len(observations), 12)
        error = worker.reply(["ghidra.analyze", '{"decompile": 17}'], data)
        with self.assertRaisesRegex(WorkerError, "^InvalidRequest$"):
            parse_worker_reply(worker.encode(error), input_sha256=sha256_hex(data), max_observations=400)

    def test_the_query_receives_the_format_the_args_and_the_entry_file_offset(self):
        seen = []
        for build in (elf_code, pe_code):
            data, layout = build()
            worker.reply(["ghidra.analyze", '{"decompile": 2}'], data, lambda f, a, o: seen.append((f, a["decompile"], o)) or {})
        self.assertEqual(seen, [("elf", 2, 0x100), ("pe", 2, 0x200)])

    def test_unexpected_failures_become_short_error_names_and_large_replies_are_refused(self):
        def broken(f, a, o):
            raise RuntimeError("/private/path secret")

        data, layout = elf_code()
        self.assertEqual(worker.reply(["ghidra.analyze", "{}"], data, broken)["error"], "RuntimeError")
        with patch.object(worker, "MAX_REPLY_BYTES", 500):
            self.assertEqual(worker.reply(["ghidra.analyze", "{}"], data, lambda f, a, o: query(data, layout))["error"], "ReplyTooLarge")

    def test_main_prints_one_json_object_and_reports_an_unreadable_snapshot(self):
        with tempfile.TemporaryDirectory() as folder:
            out = io.StringIO()
            with contextlib.redirect_stdout(out), patch.object(worker.sys, "stdout", type("S", (), {"buffer": io.BytesIO(), "flush": lambda self: None})()) as stdout:
                worker.main(["ghidra.analyze", "{}"], snapshot=Path(folder, "missing"))
                text = stdout.buffer.getvalue().decode()
        self.assertTrue(text.endswith("\n") and text.count("\n") == 1)
        self.assertEqual(json.loads(text), {"protocol": "reverseai.worker/1", "status": "error",
                                            "snapshot_sha256": hashlib.sha256(b"").hexdigest(), "error": "SnapshotUnreadable"})


class BuildInputTests(unittest.TestCase):
    def test_scripts_lock_and_dockerfile_are_pinned_consistently(self):
        lock = json.loads((SOURCE / "image.lock.json").read_text(encoding="utf-8"))
        self.assertEqual(set(lock), {"adapter_version", "base_digest", "ghidra_sha256", "image_id", "jdk_sha256", "platform"})
        self.assertEqual((lock["adapter_version"], lock["platform"], worker.ADAPTER_VERSION), ("12.1.4-r2", "linux/arm64", "12.1.4-r2"))
        self.assertEqual(lock["ghidra_sha256"], "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db")
        self.assertEqual(lock["jdk_sha256"], "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223")
        self.assertEqual(lock["base_digest"], json.loads((ROOT / "containers" / "lief" / "image.lock.json").read_text())["base_digest"])
        self.assertRegex(lock["image_id"], r"^sha256:[0-9a-f]{64}$")
        self.assertEqual(sorted(p.name for p in (SOURCE / "ghidra_scripts").iterdir()), ["ReverseAIOptions.java", "ReverseAIQuery.java"])
        rule = re.compile(r'Pattern\.compile\("\(\?i\)\.\*\(pdb\|dwarf\|swift\)\.\*"\)')
        for name in ("ReverseAIOptions.java", "ReverseAIQuery.java"):
            self.assertRegex((SOURCE / "ghidra_scripts" / name).read_text(), rule)
        self.assertIn("if (args.length != 5)", (SOURCE / "ghidra_scripts" / "ReverseAIQuery.java").read_text())
        dockerfile = (SOURCE / "Dockerfile").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"^USER .*$", dockerfile, re.M | re.I), ["USER 65534:65534"])
        self.assertIn("g++=4:14.2.0-1 make=4.4.1-2", dockerfile)
        self.assertTrue(dockerfile.rstrip().endswith('ENTRYPOINT ["python3", "-I", "-B", "/opt/reverseai/worker.py"]'))
        self.assertEqual(worker.SNAPSHOT, "/snapshot/input")


if __name__ == "__main__":
    unittest.main()
