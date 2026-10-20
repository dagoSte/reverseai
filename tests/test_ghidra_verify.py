"""Anchor tests use declared synthetic layouts and never invoke a native parser."""

import copy
import struct
import unittest

from reverseai.contract import ContractError, Location, Observation
from reverseai.tools import ghidra_verify
from tests.fixtures_code import elf_code, pe_code, elf_data_only
from tests.fixtures_structure import elf, pe

ARGS = {"max_functions": 64, "decompile": 8, "max_chars": 1024, "max_calls": 128}


def records(layout):
    functions = [{"location": {"offset": value["offset"], "length": value["size"]},
                  "value": {"kind": "function", "index": index, "name": value["name"] or f"function_{index}",
                            "entry": value["entry"], "size": value["size"]}}
                 for index, value in enumerate(layout["functions"])]
    ordered = sorted(functions, key=lambda item: (item["value"]["entry"] != layout["entry"],
                                                 -item["value"]["size"], item["value"]["entry"]))
    pseudocode = [{"location": copy.deepcopy(item["location"]),
                   "value": {"kind": "pseudocode", "index": item["value"]["index"], "entry": item["value"]["entry"],
                             "text": "return 42;\n", "truncated": False}} for item in ordered]
    calls = [{"location": {"offset": value["offset"], "length": value["length"]},
              "value": {"kind": "call", "from": value["from"], "to": value["to"],
                        "to_name": value["to_name"] or "target"}} for value in layout["calls"]]
    return functions + pseudocode + calls


def observations(items):
    return tuple(Observation(Location(**item["location"]), item["value"]) for item in items)


class AnchorTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout = elf_code()
        self.items = records(self.layout)

    def check(self, items=None, *, data=None, args=None):
        return ghidra_verify.verify(self.data if data is None else data,
                                    observations(self.items if items is None else items), ARGS if args is None else args)

    def refuse(self, items=None, **kwargs):
        with self.assertRaisesRegex(ContractError, "^" + ghidra_verify.REFUSED + "$"):
            self.check(items, **kwargs)

    def accepts(self, items, **kwargs):
        try:
            self.check(items, **kwargs)
            return True
        except ContractError:
            return False

    def test_shared_elf_pe_and_data_only_fixtures_have_valid_exact_anchors(self):
        for generator in (elf_code, pe_code, elf_data_only):
            data, layout = generator()
            with self.subTest(format=layout["format"], functions=len(layout["functions"])):
                self.assertIsNone(self.check(records(layout), data=data))
                self.assertIsNone(self.check([], data=data))

    def test_function_interpretation_is_derived_but_its_exact_byte_anchor_is_checked(self):
        item = copy.deepcopy(self.items[0])
        item["value"].update(name="a_tool_interpretation", size=3)
        item["location"]["length"] = 3
        self.check([item])
        item["location"]["offset"] += 1
        self.refuse([item])
        item = copy.deepcopy(self.items[0])
        item["value"]["entry"] += 1
        self.refuse([item])

    def test_each_kind_requires_its_exact_fields(self):
        for index in (0, 4, 8):
            for field in self.items[index]["value"]:
                items = copy.deepcopy(self.items)
                del items[index]["value"][field]
                with self.subTest(index=index, missing=field):
                    self.refuse(items)
            items = copy.deepcopy(self.items)
            items[index]["value"]["extra"] = 1
            self.refuse(items)
        for kind in ("unknown", None, ["function"]):
            items = copy.deepcopy(self.items)
            items[0]["value"]["kind"] = kind
            self.refuse(items)

    def test_function_field_types_bounds_and_contiguous_address_order(self):
        for key, value in (("index", True), ("index", 1), ("index", -1), ("entry", True), ("entry", -1),
                           ("entry", "4194560"), ("size", 0), ("size", True), ("size", -1),
                           ("name", "x" * 129), ("name", "hidden\x1b[31m"), ("name", "bidi\u202e"), ("name", [])):
            items = copy.deepcopy(self.items)
            items[0]["value"][key] = value
            with self.subTest(key=key, value=value):
                self.refuse(items)
                self.refuse([items[0]])
        for changed in ([self.items[1], self.items[0]], [self.items[0], self.items[0]], self.items[1:]):
            self.refuse(changed)
        for changed in (copy.deepcopy(list(reversed(self.items[:2]))), copy.deepcopy([self.items[0], self.items[0]])):
            for index, item in enumerate(changed):
                item["value"]["index"] = index
            self.refuse(changed)
        items = copy.deepcopy(self.items[:1])
        items[0]["value"].update(entry=2**64 - 1, size=2)
        self.refuse(items)
        items = copy.deepcopy(self.items[:1])
        items[0]["value"]["size"] = 2**64 - 1
        items[0]["location"]["length"] = self.layout["text"]["size"]
        self.refuse(items)

    def test_non_executable_sections_cannot_anchor_code(self):
        for generator in (elf_code, pe_code):
            data, layout = generator()
            data = bytearray(data)
            if layout["format"] == "elf":
                struct.pack_into("<Q", data, layout["shoff"] + 64 + 8, 0x2)
            else:
                struct.pack_into("<I", data, 0x40 + 24 + 240 + 36, 0x40000020)
            with self.subTest(format=layout["format"]):
                self.refuse(records(layout), data=bytes(data))
        data, layout = elf_data_only()
        item = {"location": {"offset": layout["data"]["offset"], "length": 1},
                "value": {"kind": "function", "index": 0, "name": "invented", "entry": layout["data"]["address"], "size": 1}}
        self.refuse([item], data=data)

    def test_overlapping_virtual_sections_or_file_aliases_are_ambiguous(self):
        for field, value in ((16, self.layout["text"]["address"]), (24, self.layout["text"]["offset"]),
                             (16, self.layout["text"]["address"] + 10), (24, self.layout["text"]["offset"] + 10)):
            data = bytearray(self.data)
            struct.pack_into("<Q", data, self.layout["shoff"] + 2 * 64 + 8, 0x2)
            struct.pack_into("<Q", data, self.layout["shoff"] + 2 * 64 + field, value)
            with self.subTest(elf_field=field):
                self.refuse(data=bytes(data))
        data, layout = pe_code()
        for field, value in ((12, 0x1000), (20, 0x200)):
            changed = bytearray(data)
            struct.pack_into("<I", changed, 0x40 + 24 + 240 + 40 + field, value)
            with self.subTest(pe_field=field):
                self.refuse(records(layout), data=bytes(changed))

    def test_pie_code_ignores_non_allocated_virtual_and_file_aliases(self):
        data, layout = elf(kind=3, entry=0x10,
                           sections=((b".text", 1, 6, 32), (b".debug", 1, 0, 128)))
        data = bytearray(data)
        struct.pack_into("<Q", data, layout["shoff"] + 64 + 16, 0x10)
        item = {"location": {"offset": layout["offsets"][0], "length": 16},
                "value": {"kind": "function", "index": 0, "name": "pie_entry", "entry": 0x10, "size": 16}}
        for flags in (0, 4):
            changed = bytearray(data)
            struct.pack_into("<Q", changed, layout["shoff"] + 2 * 64 + 8, flags)
            with self.subTest(non_allocated_flags=flags):
                self.assertTrue(self.accepts([item], data=bytes(changed)))
                struct.pack_into("<Q", changed, layout["shoff"] + 2 * 64 + 24, layout["offsets"][0])
                self.assertTrue(self.accepts([item], data=bytes(changed)))

    def test_executable_but_non_allocated_elf_section_cannot_anchor_code(self):
        data = bytearray(self.data)
        struct.pack_into("<Q", data, self.layout["shoff"] + 64 + 8, 0x4)
        self.refuse(self.items[:1], data=bytes(data))

    def test_pe_raw_padding_is_not_mapped_and_zero_virtual_size_uses_raw_size(self):
        data, layout = pe_code()
        item = records(layout)[0]
        for relative, admitted in ((layout["text"]["size"] - 1, True), (layout["text"]["size"], False),
                                   (layout["text_raw_size"] - 1, False)):
            item["value"].update(entry=layout["text"]["address"] + relative, size=1)
            item["location"] = {"offset": layout["text"]["offset"] + relative, "length": 1}
            with self.subTest(relative=relative):
                self.assertEqual(self.accepts([item], data=data), admitted)
        changed = bytearray(data)
        struct.pack_into("<I", changed, 0x40 + 24 + 240 + 8, 0)
        self.assertTrue(self.accepts([item], data=bytes(changed)))

    def test_function_only_reply_rejects_file_aliases_without_call_records(self):
        for generator in (elf_code, pe_code):
            data, layout = generator()
            item = records(layout)[0]
            self.assertTrue(self.accepts([item], data=data))
            changed = bytearray(data)
            if layout["format"] == "elf":
                at = layout["shoff"] + 2 * 64
                struct.pack_into("<Q", changed, at + 8, 0x2)
                struct.pack_into("<Q", changed, at + 16, 0x600000)
                struct.pack_into("<Q", changed, at + 24, layout["text"]["offset"] + 10)
            else:
                struct.pack_into("<I", changed, 0x40 + 24 + 240 + 40 + 20, layout["text"]["offset"] + 10)
            with self.subTest(format=layout["format"]):
                self.refuse([item], data=bytes(changed))

    def test_function_only_reply_rejects_virtual_overlap_away_from_its_entry(self):
        for generator in (elf_code, pe_code):
            data, layout = generator()
            item = records(layout)[0]
            self.assertTrue(self.accepts([item], data=data))
            changed = bytearray(data)
            if layout["format"] == "elf":
                at = layout["shoff"] + 2 * 64
                struct.pack_into("<Q", changed, at + 8, 0x2)
                struct.pack_into("<Q", changed, at + 16, layout["text"]["address"] + 10)
            else:
                struct.pack_into("<I", changed, 0x40 + 24 + 240 + 40 + 12, 0x1000 + 10)
            with self.subTest(format=layout["format"]):
                self.refuse([item], data=bytes(changed))

    def test_virtual_only_nobits_and_pe_tail_bytes_cannot_be_file_anchors(self):
        data = bytearray(self.data)
        struct.pack_into("<I", data, self.layout["shoff"] + 64 + 4, 8)
        self.refuse(data=bytes(data))
        data, layout = pe_code()
        changed = bytearray(data)
        struct.pack_into("<I", changed, 0x40 + 24 + 240 + 8, 0x300)
        item = records(layout)[0]
        item["value"].update(entry=layout["text"]["address"] + 0x200, size=1)
        item["location"] = {"offset": 0x400, "length": 1}
        self.refuse([item], data=bytes(changed))

    def test_pseudocode_must_match_function_index_entry_anchor_and_selection_order(self):
        for key, value in (("index", True), ("index", -1), ("index", 4), ("entry", -1),
                           ("entry", self.layout["functions"][1]["entry"]), ("text", []),
                           ("text", "x" * 1025), ("truncated", 1)):
            items = copy.deepcopy(self.items)
            items[4]["value"][key] = value
            with self.subTest(key=key, value=value):
                self.refuse(items)
        for location in ({"offset": 0, "length": 1}, {"offset": 0x100, "length": 1}):
            items = copy.deepcopy(self.items)
            items[4]["location"] = location
            self.refuse(items)
        self.refuse(self.items[:4] + list(reversed(self.items[4:8])))
        self.refuse(self.items[:5] + self.items[4:5])
        self.check(self.items[:4] + self.items[6:7], args=dict(ARGS, decompile=1))
        self.refuse(self.items, args=dict(ARGS, decompile=0))
        items = copy.deepcopy(self.items)
        items[4]["value"].update(text="x" * 1024, truncated=True)
        items[0]["value"]["name"] = "n" * 128
        self.check(items)

    def test_calls_require_emitted_from_function_and_full_instruction_inside_it(self):
        for key, value in (("from", True), ("from", -1), ("from", self.layout["entry"] + 1),
                           ("to", True), ("to", -1), ("to_name", "x" * 129), ("to_name", "escape\x1b")):
            items = copy.deepcopy(self.items)
            items[8]["value"][key] = value
            with self.subTest(key=key, value=value):
                self.refuse(items)
        for offset, length in ((0x100, 17), (0x100 + 20, 1), (0x100 + 18, 5), (0x100 + 0x54, 5)):
            items = copy.deepcopy(self.items)
            items[8]["location"] = {"offset": offset, "length": length}
            self.refuse(items)
        self.refuse(self.items[8:])
        items = copy.deepcopy(self.items)
        items[8]["value"].update(to=2**64 - 1, to_name="external_target")
        self.check(items)

    def test_call_cannot_precede_its_from_function_even_when_the_upper_bound_passes(self):
        function = copy.deepcopy(self.items[1])
        function["value"]["index"] = 0
        call = copy.deepcopy(self.items[8])
        call["value"]["from"] = function["value"]["entry"]
        call["location"] = {"offset": function["location"]["offset"], "length": 1}
        self.check([function, call])
        call["location"]["offset"] -= 1
        self.refuse([function, call])

    def test_function_span_keeps_a_later_call_in_a_sparse_body(self):
        data, layout = elf(entry=0x1000, sections=((b".text", 1, 6, 0x80),))
        data = bytearray(data)
        struct.pack_into("<Q", data, layout["shoff"] + 64 + 16, 0x1000)
        function = {"location": {"offset": layout["offsets"][0], "length": 0x65},
                    "value": {"kind": "function", "index": 0, "name": "sparse", "entry": 0x1000, "size": 0x65}}
        call = {"location": {"offset": layout["offsets"][0] + 0x60, "length": 5},
                "value": {"kind": "call", "from": 0x1000, "to": 0, "to_name": "external"}}
        self.check([function, call], data=bytes(data))
        call["location"]["offset"] += 1
        self.refuse([function, call], data=bytes(data))

    def test_call_after_the_4096_byte_function_anchor_still_requires_a_unique_virtual_map(self):
        data, layout = elf(entry=0x1000, sections=((b".text", 1, 6, 8192), (b".data", 1, 3, 16)))
        data = bytearray(data)
        struct.pack_into("<Q", data, layout["shoff"] + 64 + 16, 0x1000)
        function = {"location": {"offset": layout["offsets"][0], "length": 4096},
                    "value": {"kind": "function", "index": 0, "name": "large", "entry": 0x1000, "size": 7000}}
        call = {"location": {"offset": layout["offsets"][0] + 5000, "length": 5},
                "value": {"kind": "call", "from": 0x1000, "to": 0, "to_name": "external"}}
        self.check([function, call], data=bytes(data))
        struct.pack_into("<Q", data, layout["shoff"] + 2 * 64 + 16, 0x1000 + 5000)
        self.refuse([function, call], data=bytes(data))

    def test_function_only_entries_are_strictly_increasing_with_valid_reindexed_records(self):
        items = copy.deepcopy(self.items[:2])
        self.check(items)
        for reordered in (list(reversed(items)), [items[0], copy.deepcopy(items[0])]):
            changed = copy.deepcopy(reordered)
            for index, item in enumerate(changed):
                item["value"]["index"] = index
            self.refuse(changed)

    def test_individual_request_limits_and_overall_observation_cap_are_enforced(self):
        for args in (dict(ARGS, max_functions=3), dict(ARGS, decompile=3), dict(ARGS, max_calls=3)):
            self.refuse(args=args)
        self.refuse([self.items[0]] * 401)
        self.check(self.items[:4], args=dict(ARGS, decompile=0, max_calls=0))

    def test_elf_width_endianness_extended_count_and_pe32_image_base(self):
        for width in (32, 64):
            for order in ("<", ">"):
                for extended in (False, True):
                    data, layout = elf(width=width, order=order, entry=0x1000, extended=extended)
                    data = bytearray(data)
                    for index in (1, 2, 3):
                        struct.pack_into(order + ("I" if width == 32 else "Q"), data,
                                         layout["shoff"] + layout["entry_size"] * index + (12 if width == 32 else 16), index * 0x1000)
                    item = {"location": {"offset": layout["offsets"][0], "length": 16},
                            "value": {"kind": "function", "index": 0, "name": "function", "entry": 0x1000, "size": 16}}
                    with self.subTest(width=width, order=order, extended=extended):
                        self.check([item], data=bytes(data))
        data, layout = pe(plus=False)
        data = bytearray(data)
        struct.pack_into("<I", data, layout["lfanew"] + 24 + 28, 0x400000)
        item["location"]["offset"] = layout["raw_offsets"][0]
        item["value"]["entry"] = 0x401000
        self.check([item], data=bytes(data))
        struct.pack_into("<I", data, layout["lfanew"] + 24 + 28, 0xFFFFFFF0)
        self.refuse([], data=bytes(data))

    def test_anchor_length_is_minimum_of_size_4096_and_file_bytes_left_in_section(self):
        data, layout = elf(entry=0x1000, sections=((b".text", 1, 6, 7000),))
        data = bytearray(data)
        struct.pack_into("<Q", data, layout["shoff"] + 64 + 16, 0x1000)
        item = {"location": {"offset": layout["offsets"][0], "length": 4096},
                "value": {"kind": "function", "index": 0, "name": "large", "entry": 0x1000, "size": 7000}}
        self.check([item], data=bytes(data))
        item["location"]["length"] = 4095
        self.refuse([item], data=bytes(data))
        item["value"].update(entry=0x1000 + 6998, size=50)
        item["location"] = {"offset": layout["offsets"][0] + 6998, "length": 2}
        self.check([item], data=bytes(data))
        for length in (1, 3):
            item["location"]["length"] = length
            self.refuse([item], data=bytes(data))

    def test_unknown_macho_truncated_or_inconsistent_tables_fail_even_with_no_observations(self):
        variants = [b"", b"unknown", b"\xcf\xfa\xed\xfe" + bytes(64), self.data[:40], self.data[:-1]]
        for offset, fmt, value in ((40, "<Q", len(self.data)), (58, "<H", 40), (60, "<H", 65535)):
            data = bytearray(self.data)
            struct.pack_into(fmt, data, offset, value)
            variants.append(bytes(data))
        data, _ = pe_code()
        variants.extend([data[:30], data[:0x40 + 24 + 240 + 70]])
        for data in variants:
            with self.subTest(bytes=len(data)):
                self.refuse([], data=data)

    def test_section_file_ranges_are_checked_even_when_the_worker_returns_no_code(self):
        data = bytearray(self.data)
        struct.pack_into("<Q", data, self.layout["shoff"] + 64 + 24, len(data) - 1)
        self.refuse([], data=bytes(data))
        data, _ = pe_code()
        changed = bytearray(data)
        struct.pack_into("<I", changed, 0x40 + 24 + 240 + 20, len(data) - 1)
        self.refuse([], data=bytes(changed))
