import random
import unittest

from reverseai.contract import MAX_EXCERPT_BYTES, ContractError, Location, Observation
from reverseai.tools import structure
from tests.fixtures_structure import ELF_SECTIONS, PE_SECTIONS, elf, malformed, patched, pe


def run(operation, data, **args):
    spec = structure.TOOL.operations[operation]
    return spec.handler(data, spec.validate_args(args))


class IdentifyTests(unittest.TestCase):
    def test_each_format_is_identified_by_its_magic_bytes(self):
        elf64, _ = elf()
        pe64, layout = pe()
        cases = (
            (elf64, Observation(Location(0, 4), {"format": "elf", "magic": "7f454c46"})),
            (pe64, Observation(Location(layout["lfanew"], 4), {"format": "pe", "magic": "50450000"})),
            (b"\xcf\xfa\xed\xfe" + bytes(28), Observation(Location(0, 4), {"format": "macho", "magic": "cffaedfe"})),
            (b"PK\x03\x04" + bytes(26), Observation(Location(0, 4), {"format": "zip", "magic": "504b0304"})),
            (b"#!/bin/sh\necho hello world\n", Observation(Location(0, 16), {"format": "unknown", "magic": "23212f62696e2f73680a6563686f2068"})),
            (b"MZ" + bytes(10), Observation(Location(0, 12), {"format": "unknown", "magic": "4d5a" + "00" * 10})),
        )
        for data, expected in cases:
            with self.subTest(expected=expected.value["format"]):
                self.assertEqual(run("structure.identify", data), [expected])

    def test_a_dos_header_without_a_pe_signature_is_not_pe(self):
        pe64, layout = pe()
        broken = patched(pe64, layout["lfanew"], "<I", 0)
        self.assertEqual(run("structure.identify", broken)[0].value["format"], "unknown")
        far = patched(pe64, 0x3C, "<I", len(pe64))
        self.assertEqual(run("structure.identify", far)[0].value["format"], "unknown")

    def test_an_empty_input_has_no_observation(self):
        self.assertEqual(run("structure.identify", b""), [])
        self.assertEqual(run("structure.headers", b""), [])
        self.assertEqual(run("structure.sections", b""), [])


class HeaderTests(unittest.TestCase):
    def test_elf64_little_endian_header(self):
        data, layout = elf(machine=62, entry=0x401000)
        self.assertEqual(run("structure.headers", data), [Observation(Location(0, 64), {
            "format": "elf", "class": 64, "endianness": "little", "type": 2, "type_name": "executable",
            "machine": 62, "machine_name": "x86_64", "entry": 0x401000, "shnum": 5, "shoff": layout["shoff"],
        })])

    def test_elf32_big_endian_header(self):
        data, layout = elf(width=32, order=">", kind=3, machine=8, entry=0x400100)
        self.assertEqual(run("structure.headers", data), [Observation(Location(0, 52), {
            "format": "elf", "class": 32, "endianness": "big", "type": 3, "type_name": "shared",
            "machine": 8, "machine_name": "mips", "entry": 0x400100, "shnum": 5, "shoff": layout["shoff"],
        })])

    def test_pe32_plus_and_pe32_headers(self):
        for plus, magic, machine, name in ((True, "pe32+", 0x8664, "x86_64"), (False, "pe32", 0x14C, "x86")):
            data, layout = pe(plus=plus, machine=machine, entry_rva=0x1234)
            with self.subTest(magic=magic):
                self.assertEqual(run("structure.headers", data), [Observation(Location(layout["lfanew"], 44), {
                    "format": "pe", "machine": machine, "machine_name": name, "number_of_sections": 3,
                    "timestamp": 0x5F5E1000, "characteristics": 0x22, "optional_magic": magic, "entry_rva": 0x1234,
                })])

    def test_unknown_machines_are_named_unknown(self):
        data, _ = elf(machine=0x1234)
        self.assertEqual(run("structure.headers", data)[0].value["machine_name"], "unknown")


class SectionTests(unittest.TestCase):
    def test_elf_sections_with_names_flags_and_one_entry_per_location(self):
        data, layout = elf()
        found = run("structure.sections", data)
        expected = [Observation(Location(layout["shoff"], 64), {
            "index": 0, "name": "", "type": 0, "flags": 0, "offset": 0, "size": 0, "executable": False, "writable": False})]
        for index, ((name, kind, flags, size), offset) in enumerate(zip(ELF_SECTIONS, layout["offsets"]), start=1):
            expected.append(Observation(Location(layout["shoff"] + 64 * index, 64), {
                "index": index, "name": name.decode(), "type": kind, "flags": flags, "offset": offset, "size": size,
                "executable": bool(flags & 4), "writable": bool(flags & 1)}))
        expected.append(Observation(Location(layout["shoff"] + 64 * 4, 64), {
            "index": 4, "name": ".shstrtab", "type": 3, "flags": 0, "offset": layout["strtab_offset"],
            "size": 1 + sum(len(name) + 1 for name, *_ in ELF_SECTIONS) + 10, "executable": False, "writable": False}))
        self.assertEqual(found, expected)
        self.assertEqual([o.value["name"] for o in found if o.value["writable"] and o.value["executable"]], [".rwx"])

    def test_pe_sections(self):
        data, layout = pe()
        found = run("structure.sections", data)
        self.assertEqual(found, [Observation(Location(layout["table_offset"] + 40 * index, 40), {
            "index": index, "name": name.decode(), "virtual_address": 0x1000 * (index + 1), "virtual_size": size,
            "offset": layout["raw_offsets"][index], "size": size, "characteristics": flags,
            "executable": bool(flags & 0x20000000), "writable": bool(flags & 0x80000000)})
            for index, (name, flags, size) in enumerate(PE_SECTIONS)])

    def test_max_sections_bounds_the_entries_read(self):
        data, _ = elf()
        self.assertEqual([o.value["index"] for o in run("structure.sections", data, max_sections=2)], [0, 1])
        spec = structure.TOOL.operations["structure.sections"]
        for value in (0, 257, "64", 1.5, -1):
            with self.subTest(value=value), self.assertRaises(ContractError):
                spec.validate_args({"max_sections": value})
        with self.assertRaises(ContractError):
            spec.validate_args({"max_sections": 4, "path": "x"})
        self.assertEqual(spec.validate_args({}), {"max_sections": 64})

    def test_untrusted_names_become_printable_ascii(self):
        data, _ = elf(sections=((b"\x1b[31m\xffname", 1, 0x6, 4),))
        self.assertEqual(run("structure.sections", data)[1].value["name"], "\\x1b[31m\\xffname")
        long_name, _ = elf(sections=((b"n" * 300, 1, 0x6, 4),))
        self.assertEqual(run("structure.sections", long_name)[1].value["name"], "n" * 64)


class MalformedInputTests(unittest.TestCase):
    OPERATIONS = ("structure.identify", "structure.headers", "structure.sections")

    def check(self, data):
        for operation in self.OPERATIONS:
            try:
                found = run(operation, data)
            except ValueError:
                continue  # ContractError is a ValueError; nothing else may escape
            self.assertIsInstance(found, list)
            self.assertLessEqual(len(found), structure.TOOL.operations[operation].max_observations)
            for item in found:
                self.assertIsInstance(item, Observation)
                self.assertTrue(item.location.within(len(data)))
                self.assertLessEqual(item.location.length, MAX_EXCERPT_BYTES)

    def test_named_malformed_inputs_are_rejected_with_value_error(self):
        for name, (data, rejecting) in malformed().items():
            with self.subTest(name=name):
                self.check(data)
                for operation in self.OPERATIONS:
                    if operation in rejecting:
                        with self.assertRaises(ValueError):
                            run(operation, data)
                    else:
                        self.assertIsInstance(run(operation, data), list)

    def test_every_truncation_and_seeded_corruption_stays_inside_the_contract(self):
        generator = random.Random(20261020)
        for data in (elf()[0], elf(width=32, order=">")[0], pe()[0], pe(plus=False)[0]):
            for length in range(len(data) + 1):
                self.check(data[:length])
            for _ in range(300):
                corrupt = bytearray(data)
                for _ in range(generator.randint(1, 8)):
                    corrupt[generator.randrange(len(corrupt))] = generator.randrange(256)
                self.check(bytes(corrupt))


if __name__ == "__main__":
    unittest.main()
