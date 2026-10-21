"""DEX declared bytes and malformed controls, built in code and never executed."""

import hashlib
import gc
import random
import struct
import sys
from types import SimpleNamespace
import unittest
import weakref
import zlib
from unittest.mock import patch

from reverseai.contract import ContractError
from reverseai.tools import dex


def leb(value):
    result = bytearray()
    while True:
        byte, value = value & 127, value >> 7
        result.append(byte | (128 if value else 0))
        if not value:
            return bytes(result)


def seal(data):
    data = bytearray(data)
    data[12:32] = hashlib.sha1(data[32:], usedforsecurity=False).digest()
    struct.pack_into("<I", data, 8, zlib.adler32(data[12:]) & 0xFFFFFFFF)
    return bytes(data)


def minimal_dex(*, version=35, extra_strings=(), extra_code_units=0, shared_code=False):
    names = sorted({"I", "Ldemo/Main;", "Ljava/lang/Object;", "Main.java", "V", "VI",
                    "field", "hello", "method", *extra_strings})
    ids = {s: i for i, s in enumerate(names)}
    types = ("I", "Ldemo/Main;", "Ljava/lang/Object;", "V")
    t = {s: i for i, s in enumerate(types)}
    widths = ((1, len(names), 4), (2, 4, 4), (3, 2, 12), (4, 1, 8), (5, 2, 8), (6, 1, 32))
    position, tables, map_rows = 112, {}, [(0, 1, 0)]
    for kind, count, width in widths:
        tables[kind] = position
        map_rows.append((kind, count, position))
        position += count * width
    data_off = position
    data = bytearray(position)

    def align():
        data.extend(bytes(-len(data) % 4))

    string_offsets = []
    for text in names:
        string_offsets.append(len(data))
        raw = text.encode("utf-8")
        data.extend(leb(len(text)) + raw + b"\0")
    map_rows.append((0x2002, len(names), string_offsets[0]))
    align()
    params = len(data)
    data.extend(struct.pack("<IH", 1, t["I"]))
    map_rows.append((0x1001, 1, params))
    align()
    code0 = len(data)
    ins0 = (0x001A, ids["hello"], 0x1071, 1, 0, 0x000E) + (0,) * extra_code_units
    data.extend(struct.pack("<4H2I", 1, 0, 1, 0, 0, len(ins0))
                + struct.pack("<" + str(len(ins0)) + "H", *ins0))
    align()
    code1 = len(data)
    ins1 = (0x0060, 0, 0x0022, t["Ldemo/Main;"], 0x000E)
    data.extend(struct.pack("<4H2I", 1, 1, 0, 0, 0, len(ins1)) + struct.pack("<5H", *ins1))
    map_rows.append((0x2001, 2, code0))
    class_data = len(data)
    data.extend(b"\x01\0\x02\0" + leb(0) + leb(9) + leb(0) + leb(9) + leb(code0)
                + leb(1) + leb(9) + leb(code0 if shared_code else code1))
    map_rows.append((0x2000, 1, class_data))
    align()
    map_off = len(data)
    map_rows.append((0x1000, 1, map_off))
    map_rows.sort(key=lambda row: row[2])
    data.extend(struct.pack("<I", len(map_rows)))
    for kind, count, offset in map_rows:
        data.extend(struct.pack("<HHII", kind, 0, count, offset))
    align()
    for i, offset in enumerate(string_offsets):
        struct.pack_into("<I", data, tables[1] + 4 * i, offset)
    for i, name in enumerate(types):
        struct.pack_into("<I", data, tables[2] + 4 * i, ids[name])
    struct.pack_into("<6I", data, tables[3], ids["V"], t["V"], 0, ids["VI"], t["V"], params)
    struct.pack_into("<HHI", data, tables[4], t["Ldemo/Main;"], t["I"], ids["field"])
    for i in range(2):
        struct.pack_into("<HHI", data, tables[5] + 8 * i, t["Ldemo/Main;"], i, ids["method"])
    struct.pack_into("<8I", data, tables[6], t["Ldemo/Main;"], 1, t["Ljava/lang/Object;"],
                     0, ids["Main.java"], 0, class_data, 0)
    data[:8] = b"dex\n" + f"{version:03}".encode() + b"\0"
    fields = [len(data), 112, 0x12345678, 0, 0, map_off]
    for kind, count, _ in widths:
        fields.extend((count, tables[kind]))
    fields.extend((len(data) - data_off, data_off))
    struct.pack_into("<20I", data, 32, *fields)
    return seal(data), {"tables": tables, "strings": ids, "string_offsets": string_offsets,
                        "code": (code0, code1), "class_data": class_data, "params": params,
                        "map_off": map_off, "data_off": data_off}


class DexParsingTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout = minimal_dex()

    def altered(self, offset, format_, *values):
        changed = bytearray(self.data)
        struct.pack_into(format_, changed, offset, *values)
        return seal(changed)

    def test_declared_tables_class_data_and_code_spans(self):
        parsed = dex.parse(self.data)
        self.assertEqual(parsed["header"]["version"], 35)
        self.assertEqual((len(parsed["strings"]), len(parsed["types"]), len(parsed["protos"]),
                          len(parsed["fields"]), len(parsed["methods"]), len(parsed["classes"])), (9, 4, 2, 1, 2, 1))
        self.assertEqual([r["descriptor"] for r in parsed["types"]], ["I", "Ldemo/Main;", "Ljava/lang/Object;", "V"])
        self.assertEqual(parsed["protos"][1]["parameters"], ("I",))
        self.assertEqual(parsed["protos"][1]["shorty"], "VI")
        self.assertEqual(parsed["fields"][0]["name"], "field")
        self.assertEqual([r["prototype"]["shorty"] for r in parsed["methods"]], ["V", "VI"])
        cls = parsed["classes"][0]
        self.assertEqual((cls["class_descriptor"], cls["superclass"], cls["source_file"]),
                         ("Ldemo/Main;", "Ljava/lang/Object;", "Main.java"))
        methods = cls["class_data"]["direct_methods"]
        self.assertEqual([m["index"] for m in methods], [0, 1])
        self.assertEqual([m["code"]["insns_size"] for m in methods], [6, 5])
        for row in parsed["map"] + parsed["types"] + parsed["protos"] + parsed["fields"] + parsed["methods"] + parsed["classes"]:
            self.assertLessEqual(row["offset"] + row["length"], len(self.data))

    def test_only_documented_versions_and_little_endian(self):
        for version in (35, 37, 38, 39):
            with self.subTest(version=version):
                self.assertEqual(dex.parse(minimal_dex(version=version)[0])["header"]["version"], version)
        for version in (0, 9, 36, 40, 41):
            with self.subTest(version=version), self.assertRaises(dex.DexError):
                dex.parse(minimal_dex(version=version)[0])
        with self.assertRaises(dex.DexError):
            dex.parse(self.altered(40, "<I", 0x78563412))

    def test_digest_checksum_size_and_header_are_checked_separately(self):
        checksum = bytearray(self.data); checksum[8] ^= 1
        signature = bytearray(self.data); signature[12] ^= 1
        struct.pack_into("<I", signature, 8, zlib.adler32(signature[12:]) & 0xFFFFFFFF)
        for data in (bytes(checksum), bytes(signature), self.altered(32, "<I", len(self.data) - 1),
                     self.altered(36, "<I", 120), self.data[:111], b"cdex" + self.data[4:]):
            with self.subTest(data=data[:12]), self.assertRaises(dex.DexError):
                dex.parse(data)
        with patch.object(dex, "MAX_CHILD_BYTES", len(self.data) - 1), self.assertRaises(dex.DexError):
            dex.parse(self.data)

    def test_tables_cannot_point_outside_or_overlap(self):
        for offset, value in ((56, 0xFFFFFFFF), (60, len(self.data)), (64, 65537),
                               (68, self.layout["tables"][1]), (52, 0), (108, 111)):
            with self.subTest(offset=offset), self.assertRaises(dex.DexError):
                dex.parse(self.altered(offset, "<I", value))

    def test_map_counts_kinds_and_offsets_are_bound_to_the_header(self):
        at = self.layout["map_off"]
        for offset, format_, value in ((at, "<I", 65537), (at + 4, "<H", 0xFFFF),
                                      (at + 6, "<H", 1), (at + 8, "<I", 2),
                                      (at + 12, "<I", 1), (at + 16, "<H", 0)):
            with self.subTest(offset=offset, value=value), self.assertRaises(dex.DexError):
                dex.parse(self.altered(offset, format_, value))

    def test_lazy_strings_carry_exact_spans_and_cannot_poison_cached_rows(self):
        parsed = dex.parse(self.data)
        index = self.layout["strings"]["hello"]
        with patch.object(dex, "mutf8", wraps=dex.mutf8) as decode:
            row = parsed["strings"][index]
            self.assertEqual(row["text"], "hello")
            self.assertEqual(row["data_offset"], self.layout["string_offsets"][index])
            self.assertEqual(self.data[row["data_offset"]:row["data_offset"] + row["data_length"]], b"\x05hello\0")
            row["text"] = "poison"
            self.assertEqual(parsed["strings"][index]["text"], "hello")
            self.assertEqual(decode.call_count, 1)
        changed = self.altered(self.layout["tables"][1] + 4 * index, "<I", len(self.data))
        table = dex.parse(changed)["strings"]
        with self.assertRaises(dex.DexError):
            table[index]

    def test_string_cache_is_bounded_and_does_not_retain_previous_children(self):
        data, _ = minimal_dex(extra_strings=tuple(f"extra{i:03}" for i in range(300)))
        result = dex.parse(data)
        table = result["strings"]
        for i in range(len(table)):
            table[i]
        self.assertLessEqual(len(table._cache), 256)
        reference = weakref.ref(table)
        del table, result
        gc.collect()
        self.assertIsNone(reference())

    def test_decoded_byte_budget_includes_cache_misses_but_not_cache_hits(self):
        parsed = dex.parse(self.data)
        table = parsed['strings']
        before = table._parser.string_budget[0]
        hello = self.layout['strings']['hello']
        with patch.object(dex, 'MAX_DECODED_BYTES', before + 7):
            self.assertEqual(table[hello]['text'], 'hello')
            self.assertEqual(table._parser.string_budget[0], before + 7)
            self.assertEqual(table[hello]['text'], 'hello')
            self.assertEqual(table._parser.string_budget[0], before + 7)
            table._cache.clear()
            with self.assertRaises(dex.DexError):
                table[self.layout['strings']['field']]

    def test_a_million_unused_string_ids_stay_lazy_and_the_next_id_is_refused(self):
        count = dex.MAX_STRING_IDS
        data_off = 112 + 4 * count
        map_off = data_off + 4
        data = bytearray(data_off) + b"\0\0\0\0"
        rows = ((0, 1, 0), (1, count, 112), (0x2002, 1, data_off), (0x1000, 1, map_off))
        data.extend(struct.pack("<I", len(rows)))
        for kind, size, at in rows:
            data.extend(struct.pack("<HHII", kind, 0, size, at))
        data[:8] = b"dex\n035\0"
        struct.pack_into("<20I", data, 32, len(data), 112, 0x12345678, 0, 0, map_off,
                         count, 112, *([0] * 10), len(data) - data_off, data_off)
        data = seal(data)
        with patch.object(dex, "mutf8", wraps=dex.mutf8) as decode:
            table = dex.parse(data)["strings"]
            self.assertEqual(len(table), 1048576)
            self.assertEqual(decode.call_count, 0)
            self.assertFalse(table._cache)
        broken = bytearray(data)
        struct.pack_into("<I", broken, 56, count + 1)
        with self.assertRaises(dex.DexError):
            dex.parse(seal(broken))

    def test_identity_bounds_and_printable_string_prefixes(self):
        self.assertEqual(dex._identity(("x" * 255,)), "x" * 255)
        for parts in (("x" * 256,), ("prefix", "x" * 255)):
            with self.assertRaises(dex.DexError):
                dex._identity(parts)
        self.assertEqual(dex._render(("a\\\0\ud800\U0001f600",)),
                         (r"a\x5c\x00\ud800\U0001f600", False))
        self.assertEqual(dex._render(("a" * 253 + "\ud800",)), ("a" * 253 + "\\ud", True))

    def test_foreign_indices_shorty_void_fields_and_inheritance_cycles(self):
        table = self.layout["tables"]
        cases = ((table[2], "<I", 99), (table[3], "<I", self.layout["strings"]["I"]),
                 (table[4] + 2, "<H", 3), (table[5] + 2, "<H", 99),
                 (table[6] + 8, "<I", 1), (self.layout["params"] + 4, "<H", 3))
        for at, format_, value in cases:
            with self.subTest(offset=at), self.assertRaises(dex.DexError):
                dex.parse(self.altered(at, format_, value))

    def test_class_data_counts_and_code_headers_are_bounded(self):
        cls = self.layout["class_data"]
        for at, value in ((cls, b"\xff" * 5), (cls + 6, b"\x7f")):
            data = bytearray(self.data); data[at:at + len(value)] = value
            with self.subTest(offset=at), self.assertRaises(dex.DexError):
                dex.parse(seal(data))
        for at, format_, value in ((self.layout["code"][0] + 12, "<I", 0xFFFFFFFF),
                                   (self.layout["code"][0] + 2, "<H", 2)):
            with self.subTest(offset=at), self.assertRaises(dex.DexError):
                dex.parse(self.altered(at, format_, value))
        with patch.object(dex, "MAX_MEMBER_ENTRIES", 2), self.assertRaises(dex.DexError):
            dex.parse(self.data)

    def test_mutated_bytes_never_leak_struct_unicode_or_index_errors(self):
        random_ = random.Random(194)
        for i in range(250):
            data = bytearray(self.data)
            at = random_.randrange(32, len(data))
            data[at] ^= random_.randrange(1, 256)
            try:
                result = dex.parse(seal(data))
                # Force the otherwise unused string rows too.
                for row in result["strings"]:
                    self.assertGreaterEqual(row["data_offset"], result["header"]["data_off"])
            except ContractError as error:
                self.assertIsInstance(error, dex.DexError)
                self.assertEqual(str(error), "Invalid DEX structure")


class ScalarDecoderTests(unittest.TestCase):
    def test_uleb32_bounds_and_truncation(self):
        self.assertEqual(dex.uleb128(b"\xff\xff\xff\xff\x0f", 0), (0xFFFFFFFF, 5))
        self.assertEqual(dex.uleb128(b"\x80\0", 0), (0, 2))
        for data in (b"", b"\x80", b"\x80" * 5, b"\xff\xff\xff\xff\x1f"):
            with self.subTest(data=data), self.assertRaises(dex.DexError):
                dex.uleb128(data, 0)

    def test_mutf8_nul_surrogate_pairs_and_isolated_surrogates(self):
        for raw, value in ((b"\0\0", ""), (b"\x03a\xc0\x80b\0", "a\0b"),
                           (b"\x02\xed\xa0\xbd\xed\xb8\x80\0", "\U0001f600"),
                           (b"\x01\xed\xa0\x80\0", "\ud800")):
            with self.subTest(raw=raw):
                self.assertEqual(dex.mutf8(raw, 0)[0], value)
        for raw in (b"\x01\0", b"\x01\xc0\x81\0", b"\x01\xc2\0", b"\x02\xf0\x9f\x98\x80\0", b"\x02ab"):
            with self.subTest(raw=raw), self.assertRaises(dex.DexError):
                dex.mutf8(raw, 0)
        with patch.object(dex, "MAX_STRING_BYTES", 2), self.assertRaises(dex.DexError):
            dex.mutf8(b"\x03abc\0", 0)

    def test_code_try_handlers_padding_and_offsets(self):
        # One one-unit instruction; zero padding, one try item and one catch-all.
        data = struct.pack("<4H2I2H IHH", 1, 0, 0, 1, 0, 1, 0xE, 0, 0, 1, 1) + b"\x01\0\0"
        parsed = dex.code_item(data, 0)
        self.assertEqual((parsed["insns_offset"], parsed["insns_size"], parsed["length"]), (16, 1, len(data)))
        for at, value in ((18, 1), (26, 2)):
            broken = bytearray(data); broken[at] = value
            with self.subTest(offset=at), self.assertRaises(dex.DexError):
                dex.code_item(bytes(broken), 0)
        with self.assertRaises(dex.DexError):
            dex.code_item(data[:-1], 0)


from reverseai.tools.dex import DexError, decode_instructions


def units(*values):
    return struct.pack('<' + 'H' * len(values), *values)


def dword(value):
    return struct.pack('<I', value & 0xFFFFFFFF)


# Independent groups transcribed as format families from the official opcode table;
# these do not use the production width tuple or private decoder helpers.
_EXPECTED = {}
for width, groups in (
    (1, ((0, 1), (4, 4), (7, 7), (0x0A, 0x12), (0x1D, 0x1E),
         (0x21, 0x21), (0x27, 0x28), (0x7B, 0x8F), (0xB0, 0xCF))),
    (2, ((2, 2), (5, 5), (8, 8), (0x13, 0x13), (0x15, 0x16),
         (0x19, 0x1A), (0x1C, 0x1C), (0x1F, 0x20), (0x22, 0x23),
         (0x29, 0x29), (0x2D, 0x3D), (0x44, 0x6D), (0x90, 0xAF),
         (0xD0, 0xE2), (0xFE, 0xFF))),
    (3, ((3, 3), (6, 6), (9, 9), (0x14, 0x14), (0x17, 0x17),
         (0x1B, 0x1B), (0x24, 0x26), (0x2A, 0x2C), (0x6E, 0x72),
         (0x74, 0x78), (0xFC, 0xFD))),
    (4, ((0xFA, 0xFB),)),
    (5, ((0x18, 0x18),)),
):
    for first, last in groups:
        for opcode in range(first, last + 1):
            if opcode in _EXPECTED:
                raise AssertionError('overlapping independent expected groups')
            _EXPECTED[opcode] = width


def payload(kind, count=1):
    if kind == 'packed-switch':
        return units(0x0100, count) + dword(0) + dword(0) * count
    if kind == 'sparse-switch':
        return units(0x0200, count) + b''.join(dword(i) for i in range(count)) + dword(0) * count
    if kind == 'fill-array-data':
        return units(0x0300, 1) + dword(count) + bytes(count) + bytes(count % 2)
    raise AssertionError(kind)


def referenced_payload(opcode, kind, count=1):
    return units(opcode) + dword(4) + units(0) + payload(kind, count)


def decoded(data, offset=0, insns_size=None, version=39):
    if insns_size is None:
        insns_size = (len(data) - offset) // 2
    return list(decode_instructions(data, offset, insns_size, version=version))


class EveryOpcodeWidthTests(unittest.TestCase):
    pass


def opcode_test(opcode):
    def check(self):
        width = _EXPECTED.get(opcode)
        if width is None:
            with self.assertRaisesRegex(DexError, '^unused DEX opcode$'):
                decoded(units(opcode))
            return
        if opcode in (0x26, 0x2B, 0x2C):
            kind = {0x26: 'fill-array-data', 0x2B: 'packed-switch', 0x2C: 'sparse-switch'}[opcode]
            data = referenced_payload(opcode, kind)
        else:
            data = units(opcode, *([0x00E3] * (width - 1)))
        # A reference sentinel after the instruction proves the independently
        # expected width even when the tested instruction has no references.
        sentinel_at = len(data)
        rows = decoded(data + units(0x1A, 0xBEEF))
        self.assertEqual(rows[-1], {'offset': sentinel_at, 'length': 4,
                                   'opcode': 0x1A, 'kind': 'string', 'index': 0xBEEF})
        for row in rows[:-1]:
            self.assertEqual(row['opcode'], opcode)
            self.assertEqual(row['offset'], 0)
            self.assertEqual(row['length'], width * 2)
    return check


for _opcode in range(256):
    setattr(EveryOpcodeWidthTests, 'test_opcode_%02x' % _opcode, opcode_test(_opcode))


class DalvikDecoderTests(unittest.TestCase):
    def test_independent_table_covers_exact_standard_unused_set(self):
        unused = set(range(0x3E, 0x44)) | {0x73, 0x79, 0x7A} | set(range(0xE3, 0xFA))
        self.assertEqual(set(_EXPECTED), set(range(256)) - unused)

    def test_all_multicodeunit_instructions_refuse_every_short_span(self):
        for opcode, width in _EXPECTED.items():
            if width <= 1:
                continue
            data = units(opcode, *([0] * (width - 1)))
            for short in range(1, width):
                with self.subTest(opcode=opcode, short=short):
                    with self.assertRaises(DexError):
                        decoded(data, insns_size=short)
                    with self.assertRaises(DexError):
                        decoded(data[:short * 2], insns_size=width)

    def test_reference_kinds_and_unsigned_indexes(self):
        expected = {
            'string': [0x1A, 0x1B],
            'type': [0x1C, 0x1F, 0x20, 0x22, 0x23, 0x24, 0x25],
            'field': list(range(0x52, 0x6E)),
            'method': list(range(0x6E, 0x73)) + list(range(0x74, 0x79)),
            'call_site': [0xFC, 0xFD], 'method_handle': [0xFE], 'proto': [0xFF],
        }
        for kind, opcodes in expected.items():
            for opcode in opcodes:
                with self.subTest(kind=kind, opcode=opcode):
                    width = _EXPECTED[opcode]
                    data = units(opcode, 0xFFFF, *([0x5678] * (width - 2)))
                    if opcode == 0x1B:
                        data = units(opcode) + dword(0xDEADBEEF)
                    rows = decoded(b'abcd' + data, 4, width)
                    index = 0xDEADBEEF if opcode == 0x1B else 0xFFFF
                    self.assertEqual(rows, [{'offset': 4, 'length': width * 2, 'opcode': opcode,
                                             'kind': kind, 'index': index}])

    def test_polymorphic_has_method_and_proto(self):
        for opcode in (0xFA, 0xFB):
            rows = decoded(units(opcode, 0x8123, 0xFFFF, 0xABCD), version=38)
            self.assertEqual([(r['kind'], r['index']) for r in rows], [('method', 0x8123), ('proto', 0xABCD)])
            self.assertTrue(all(r['offset'] == 0 and r['length'] == 8 for r in rows))

    def test_new_opcodes_version_gated(self):
        for opcode in range(0xFA, 0x100):
            for version in (35, 37, 38, 39):
                data = units(opcode, *([0] * (_EXPECTED[opcode] - 1)))
                with self.subTest(opcode=opcode, version=version):
                    if version < (39 if opcode >= 0xFE else 38):
                        with self.assertRaisesRegex(DexError, '^opcode requires newer DEX version$'):
                            decoded(data, version=version)
                    else:
                        self.assertGreater(len(decoded(data, version=version)), 0)

    def test_nonreference_literals_do_not_become_pool_references(self):
        for opcode in (0x13, 0x14, 0x17, 0x18, 0x2D, 0x44, 0x90, 0xD0, 0xE2):
            data = units(opcode, *([0x006E] * (_EXPECTED[opcode] - 1)))
            self.assertEqual(decoded(data), [])

    def test_payloads_skip_exact_body_width_without_fake_references(self):
        for ident in (0x0100, 0x0200):
            body = units(ident, 1) + dword(0x006E) + dword(0x001A)
            self.assertEqual(decoded(body), [])
            self.assertEqual(decoded(body + units(0x1A, 0x4321))[0]['offset'], len(body))
        body = units(0x0300, 2) + dword(4) + units(0x006E, 0x1234, 0x001A, 0xABCD)
        self.assertEqual(decoded(body), [])
        self.assertEqual(decoded(body + units(0x1A, 0x4321))[0]['offset'], 16)

    def test_payload_alignment_is_absolute_child_offset(self):
        body = payload('packed-switch')
        with self.assertRaisesRegex(DexError, '^invalid instruction payload$'):
            decoded(b'xx' + body, 2)
        self.assertEqual(decoded(b'abcd' + body, 4), [])

    def test_unknown_payload_identifiers_are_refused(self):
        for ident in (0x0400, 0xFF00):
            with self.assertRaisesRegex(DexError, '^invalid instruction payload$'):
                decoded(units(ident))

    def test_payloads_cannot_overrun_method_into_following_file_bytes(self):
        for kind in ('packed-switch', 'sparse-switch', 'fill-array-data'):
            body = payload(kind, 3)
            for short in range(1, len(body) // 2):
                with self.subTest(kind=kind, short=short):
                    with self.assertRaises(DexError):
                        decoded(body, insns_size=short)

    def test_unsigned_max_array_size_refused_without_allocation(self):
        for element_width in (1, 2, 4, 8):
            data = units(0x0300, element_width) + dword(0xFFFFFFFF)
            with self.assertRaisesRegex(DexError, '^truncated instruction payload$'):
                decoded(data)

    def test_max_switch_size_refused_without_allocation(self):
        for ident in (0x0100, 0x0200):
            with self.assertRaisesRegex(DexError, '^truncated instruction payload$'):
                decoded(units(ident, 0xFFFF) + bytes(4))

    def test_sparse_keys_must_increase_as_signed_ints(self):
        for keys in ((-1, -1), (2, 1), (0x7FFFFFFF, -0x80000000)):
            data = units(0x0200, 2) + b''.join(dword(v) for v in keys) + bytes(8)
            with self.assertRaisesRegex(DexError, '^invalid sparse switch keys$'):
                decoded(data)
        self.assertEqual(decoded(units(0x0200, 2) + dword(-0x80000000) + dword(0x7FFFFFFF) + bytes(8)), [])

    def test_packed_switch_key_range_cannot_overflow_signed_int(self):
        data = units(0x0100, 2) + dword(0x7FFFFFFF) + bytes(8)
        with self.assertRaisesRegex(DexError, '^invalid packed switch keys$'):
            decoded(data)

    def test_array_widths_and_odd_byte_padding(self):
        for width in (0, 3, 0xFFFF):
            with self.assertRaisesRegex(DexError, '^invalid array element width$'):
                decoded(units(0x0300, width) + dword(0))
        data = units(0x0300, 1) + dword(3) + b'abc\0' + units(0x1A, 7)
        self.assertEqual(decoded(data), [{'offset': 12, 'length': 4, 'opcode': 0x1A, 'kind': 'string', 'index': 7}])
        for width in (1, 2, 4, 8):
            self.assertEqual(decoded(units(0x0300, width) + dword(0)), [])

    def test_payload_pointers_match_opcode_kind(self):
        kinds = {0x26: 'fill-array-data', 0x2B: 'packed-switch', 0x2C: 'sparse-switch'}
        for opcode, kind in kinds.items():
            self.assertEqual(decoded(referenced_payload(opcode, kind)), [])
            for other in set(kinds.values()) - {kind}:
                with self.assertRaisesRegex(DexError, '^invalid instruction payload target$'):
                    decoded(referenced_payload(opcode, other))

    def test_backward_payload_pointers_are_signed(self):
        body = payload('packed-switch')
        self.assertEqual(decoded(body + units(0x2B) + dword(-(len(body) // 2))), [])

    def test_payload_pointers_cannot_point_to_middle_nop_or_outside(self):
        for target in (-0x80000000, -1, 0, 1, 2, 3, 5, 6, 7, 0x7FFFFFFF):
            with self.subTest(target=target):
                with self.assertRaisesRegex(DexError, '^invalid instruction payload target$'):
                    decoded(units(0x2B) + dword(target) + units(0) + payload('packed-switch'))

    def test_payload_body_cannot_hide_target_payload_boundary(self):
        body = units(0x0300, 2) + dword(6) + payload('packed-switch')
        with self.assertRaisesRegex(DexError, '^invalid instruction payload target$'):
            decoded(units(0x2B) + dword(8) + units(0) + body)

    def test_malformed_later_pointer_prevents_even_first_reference(self):
        stream = decode_instructions(units(0x1A, 9, 0x2B, 0, 0), 0, 5)
        with self.assertRaisesRegex(DexError, '^invalid instruction payload target$'):
            next(stream)

    def test_streams_without_arbitrary_instruction_count_limit(self):
        count = 65_537
        data = bytes(count * 2) + units(0x1A, 0x1234)
        stream = decode_instructions(data, 0, len(data) // 2)
        self.assertIs(iter(stream), stream)
        self.assertEqual(next(stream), {'offset': count * 2, 'length': 4, 'opcode': 0x1A,
                                        'kind': 'string', 'index': 0x1234})
        self.assertRaises(StopIteration, next, stream)

    def test_offsets_counts_and_versions_are_closed(self):
        for offset, count in ((True, 1), (-2, 1), (1, 1), (0, True), (0, 0), (0, -1), (0, 2**32)):
            with self.subTest(offset=offset, count=count):
                with self.assertRaises(DexError):
                    decoded(bytes(4), offset, count)
        for version in (34, 36, 40, True, '39'):
            with self.assertRaisesRegex(DexError, '^unsupported DEX version$'):
                decoded(bytes(2), version=version)
        self.assertEqual(decoded(b'xx' + units(0x1A, 7) + b'yy', 2, 2)[0]['offset'], 2)

    def test_trailing_odd_byte_cannot_fill_truncated_code_unit(self):
        with self.assertRaises(DexError):
            decoded(bytes(3), insns_size=2)

    def test_reserved_high_bits_and_excess_invoke_argument_count(self):
        for opcode in (0x03, 0x06, 0x09, 0x0E, 0x29, 0x2A):
            width = _EXPECTED[opcode]
            with self.assertRaisesRegex(DexError, '^invalid instruction padding$'):
                decoded(units(0x0100 | opcode, *([0] * (width - 1))))
        for opcode in (0x24, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0xFA, 0xFC):
            width = _EXPECTED[opcode]
            with self.assertRaisesRegex(DexError, '^invalid invoke register count$'):
                decoded(units(0x6000 | opcode, *([0] * (width - 1))))




class DexOperationTests(unittest.TestCase):
    def setUp(self):
        self.child, self.layout = minimal_dex()
        self.class_name = 'Ldemo/Main;'

    def run_operation(self, name, args, *, children=None, encrypted=()):
        children = {'classes.dex': self.child} if children is None else children
        members = [SimpleNamespace(name=key, flags=('encrypted',) if key in encrypted else (), size=len(value))
                   for key, value in children.items()]
        fake = SimpleNamespace(
            members=lambda _: members,
            materialize=lambda _, member: (children[member.name], hashlib.sha256(children[member.name]).hexdigest()),
            artifact=lambda member, child: {
                'member': member.name, 'method': 0, 'data_offset': 0,
                'compressed_size': len(child), 'size': len(child),
                'crc32': zlib.crc32(child) & 0xFFFFFFFF, 'sha256': hashlib.sha256(child).hexdigest(),
            },
        )
        spec = dex.TOOL.operations[name]
        validated = spec.validate_args(args)
        with patch.dict(sys.modules, {'reverseai.tools.apk': fake}), patch('reverseai.tools.apk', fake, create=True):
            return spec.handler(b'fake archive; APK seam is substituted by this test', validated)

    def references(self, **args):
        return self.run_operation('dex.references', {'class': self.class_name, 'method': 'method', **args})

    def test_classes_exact_schema_and_class_definition_anchor(self):
        row, = self.run_operation('dex.classes', {})
        self.assertEqual((row.location.offset, row.location.length), (self.layout['tables'][6], 32))
        self.assertEqual(row.value, {'kind': 'class', 'dex': 'classes.dex', 'name': self.class_name,
                                    'access': 1, 'superclass': 'Ljava/lang/Object;', 'interfaces': [],
                                    'source_file': 'Main.java', 'index': 0, 'total': 1})
        self.assertEqual(row.artifact['member'], 'classes.dex')
        self.assertEqual(row.artifact['sha256'], hashlib.sha256(self.child).hexdigest())

    def test_class_query_and_member_selectors_match_exact_child(self):
        children = {'classes.dex': self.child, 'classes2.dex': self.child, 'res/raw/not.dex': b'invalid'}
        rows = self.run_operation('dex.classes', {'query': 'Main', 'member': 'classes2.dex'}, children=children)
        self.assertEqual([row.value['dex'] for row in rows], ['classes2.dex'])
        self.assertEqual(self.run_operation('dex.classes', {'query': 'main'}, children=children), [])
        self.assertEqual(self.run_operation('dex.classes', {'member': 'missing.dex'}, children=children), [])
        self.assertEqual([row.value['total'] for row in self.run_operation('dex.classes', {}, children=children)], [2, 2])

    def test_methods_preserve_overloads_prototypes_and_id_anchors(self):
        rows = self.run_operation('dex.methods', {'member': 'classes.dex', 'class': self.class_name})
        self.assertEqual([row.value for row in rows], [
            {'kind': 'method', 'dex': 'classes.dex', 'class': self.class_name, 'name': 'method',
             'prototype': proto, 'access': 9, 'code_offset': self.layout['code'][i],
             'code_units': [6, 5][i], 'index': i, 'total': 2}
            for i, proto in enumerate(('()V', '(I)V'))])
        self.assertEqual([(r.location.offset, r.location.length) for r in rows],
                         [(self.layout['tables'][5], 8), (self.layout['tables'][5] + 8, 8)])

    def test_methods_page_total_and_empty_selectors(self):
        rows = self.run_operation('dex.methods', {'member': 'classes.dex', 'class': self.class_name,
                                                  'start': 1, 'limit': 1})
        self.assertEqual([(r.value['index'], r.value['total'], r.value['prototype']) for r in rows], [(1, 2, '(I)V')])
        for args in ({'start': 2}, {'start': 65535}, {'class': 'Lmissing/Class;'}, {'member': 'missing.dex'}):
            with self.subTest(args=args):
                self.assertEqual(self.run_operation('dex.methods', {'member': 'classes.dex',
                                  'class': self.class_name, **args}), [])

    def test_first_overload_references_string_and_method_with_exact_instruction_anchors(self):
        rows = self.references(prototype='()V')
        self.assertEqual([r.value['ref_kind'] for r in rows], ['string', 'method'])
        self.assertEqual([r.value['target'] for r in rows], ['hello', 'Ldemo/Main;->method(I)V'])
        start = self.layout['code'][0] + 16
        self.assertEqual([(r.location.offset, r.location.length) for r in rows], [(start, 4), (start + 4, 6)])
        for i, row in enumerate(rows):
            self.assertEqual(row.value, {'kind': 'dex_ref', 'dex': 'classes.dex',
                'from_class': self.class_name, 'from_method': 'method', 'from_prototype': '()V',
                'at': row.location.offset, 'ref_kind': ['string', 'method'][i],
                'target': ['hello', 'Ldemo/Main;->method(I)V'][i], 'target_truncated': False, 'index': i, 'total': 2})

    def test_second_overload_references_field_and_type(self):
        rows = self.references(prototype='(I)V')
        self.assertEqual([(r.value['ref_kind'], r.value['target']) for r in rows],
                         [('field', 'Ldemo/Main;->field:I'), ('type', self.class_name)])
        start = self.layout['code'][1] + 16
        self.assertEqual([(r.location.offset, r.location.length) for r in rows], [(start, 4), (start + 4, 4)])
        self.assertTrue(all(r.value['from_prototype'] == '(I)V' for r in rows))

    def test_incoming_selects_target_overload_and_cites_calling_instruction(self):
        row, = self.references(prototype='(I)V', direction='to')
        self.assertEqual(row.value['target'], 'Ldemo/Main;->method(I)V')
        self.assertEqual((row.value['from_prototype'], row.value['ref_kind'], row.value['index'], row.value['total']),
                         ('()V', 'method', 0, 1))
        self.assertEqual((row.location.offset, row.location.length), (self.layout['code'][0] + 20, 6))
        self.assertEqual(self.references(prototype='()V', direction='to'), [])

    def test_unqualified_overloads_reference_page_counts_entire_result(self):
        rows = self.references(start=1, limit=2)
        self.assertEqual([(r.value['index'], r.value['total'], r.value['ref_kind']) for r in rows],
                         [(1, 4, 'method'), (2, 4, 'field')])
        self.assertEqual(self.references(start=4, limit=1), [])
        self.assertEqual(self.references(start=65535, limit=1), [])

    def test_reference_selectors_do_not_confuse_prototypes_or_method_names(self):
        for args in ({'prototype': '(J)V'}, {'prototype': '()'}, {'method': 'missing'},
                     {'class': 'Lmissing/Class;'}, {'member': 'missing.dex'}):
            with self.subTest(args=args):
                self.assertEqual(self.references(**args), [])
        self.assertEqual(len(self.references(prototype='')), 4)
        self.assertEqual(len(self.references(direction='to')), 1)

    def test_late_malformed_code_refuses_instead_of_returning_full_first_page(self):
        corrupt = bytearray(self.child)
        struct.pack_into('<H', corrupt, self.layout['code'][1] + 16, 0x00E3)
        with self.assertRaises(dex.DexError):
            self.run_operation('dex.references', {'class': self.class_name, 'method': 'method', 'limit': 1},
                               children={'classes.dex': seal(corrupt)})

    def test_late_out_of_range_reference_refuses_after_page_was_already_filled(self):
        corrupt = bytearray(self.child)
        struct.pack_into('<H', corrupt, self.layout['code'][0] + 22, 2)  # method pool only has indices 0 and 1
        with self.assertRaises(dex.DexError):
            self.run_operation('dex.references', {'class': self.class_name, 'method': 'method', 'limit': 1},
                               children={'classes.dex': seal(corrupt)})

    def test_incoming_checks_later_nonmatching_reference_pool_indices(self):
        corrupt = bytearray(self.child)
        struct.pack_into('<H', corrupt, self.layout['code'][1] + 18, 1)  # only one field, valid index 0
        with self.assertRaises(dex.DexError):
            self.run_operation('dex.references', {'class': self.class_name, 'method': 'method',
                               'prototype': '(I)V', 'direction': 'to', 'limit': 1},
                               children={'classes.dex': seal(corrupt)})

    def test_encrypted_or_malformed_later_child_refuses_full_first_class_page(self):
        with self.assertRaises(dex.DexError):
            self.run_operation('dex.classes', {'limit': 1},
                               children={'classes.dex': self.child, 'classes2.dex': b'invalid'})
        with self.assertRaises(dex.DexError):
            self.run_operation('dex.classes', {}, encrypted=('classes.dex',))

    def test_only_long_string_targets_report_explicit_truncation(self):
        text = 'X' * 300
        child, layout = minimal_dex(extra_strings=(text,))
        changed = bytearray(child)
        struct.pack_into('<H', changed, layout['code'][0] + 18, layout['strings'][text])
        rows = self.run_operation('dex.references', {'class': self.class_name, 'method': 'method',
                                  'prototype': '()V'}, children={'classes.dex': seal(changed)})
        self.assertEqual(rows[0].value['target'], 'X' * 256)
        self.assertTrue(rows[0].value['target_truncated'])
        self.assertFalse(rows[1].value['target_truncated'])

    def test_operation_defaults_caps_and_closed_argument_schemas(self):
        specs = dex.TOOL.operations
        self.assertEqual(set(specs), {'dex.classes', 'dex.methods', 'dex.references'})
        self.assertEqual(specs['dex.classes'].validate_args({}), {'member': '', 'query': '', 'start': 0, 'limit': 128})
        args = specs['dex.references'].validate_args({'class': self.class_name, 'method': 'method'})
        self.assertEqual(args, {'member': '', 'class': self.class_name, 'method': 'method', 'prototype': '',
                                'direction': 'from', 'start': 0, 'limit': 128})
        self.assertTrue(all(spec.max_observations == 256 and not spec.derived for spec in specs.values()))
        for operation, base in (('dex.classes', {}),
                                ('dex.methods', {'member': 'classes.dex', 'class': self.class_name}),
                                ('dex.references', {'class': self.class_name, 'method': 'method'})):
            for bad in ({'extra': 1}, {'start': -1}, {'start': True}, {'limit': 0}, {'limit': 257},
                        {'member': '\n'}, {'member': 'a' * 256}):
                with self.subTest(operation=operation, bad=bad):
                    with self.assertRaises(ContractError):
                        specs[operation].validate_args({**base, **bad})
        for bad in ({'direction': 'both'}, {'prototype': 1}, {'method': ''}, {'class': ''}):
            with self.assertRaises(ContractError):
                specs['dex.references'].validate_args({'class': self.class_name, 'method': 'method', **bad})
        self.assertEqual(specs['dex.methods'].validate_args({'class': self.class_name})['member'], '')
        with self.assertRaises(ContractError):
            specs['dex.methods'].validate_args({})

    def test_methods_can_page_the_same_class_across_two_dex_members(self):
        rows = self.run_operation('dex.methods', {'class': self.class_name, 'start': 1, 'limit': 2},
                                  children={'classes.dex': self.child, 'classes2.dex': self.child})
        self.assertEqual([(r.value['dex'], r.value['prototype'], r.value['index'], r.value['total']) for r in rows],
                         [('classes.dex', '(I)V', 1, 4), ('classes2.dex', '()V', 2, 4)])

    def test_aliased_long_code_cannot_multiply_work_past_the_child_size(self):
        child, _ = minimal_dex(extra_code_units=1024, shared_code=True)
        parsed = dex.parse(child)
        methods = parsed['classes'][0]['class_data']['direct_methods']
        self.assertEqual(methods[0]['code_off'], methods[1]['code_off'])
        with self.assertRaisesRegex(dex.DexError, '^Invalid DEX structure$'):
            self.run_operation('dex.references', {'class': self.class_name, 'method': 'method', 'limit': 1},
                               children={'classes.dex': child})

    def test_decoded_string_budget_is_shared_across_all_selected_members(self):
        parsed = dex.parse(self.child)
        used = parsed['strings']._parser.string_budget[0]
        with patch.object(dex, 'MAX_DECODED_BYTES', used):
            self.assertEqual(len(self.run_operation('dex.classes', {})), 1)
            with self.assertRaises(dex.DexError):
                self.run_operation('dex.classes', {'limit': 1},
                                   children={'classes.dex': self.child, 'classes2.dex': self.child})


class DexChildEvidenceTests(unittest.TestCase):
    def test_shared_fixture_classes_and_methods_equal_declared_layouts(self):
        from tests.fixtures_apk import apk_basic
        data, layout = apk_basic()
        spec = dex.TOOL.operations['dex.classes']
        rows = spec.handler(data, spec.validate_args({}))
        expected = []
        for member, child in layout['dex'].items():
            for cls in child['classes']:
                expected.append((member, cls))
        self.assertEqual(len(rows), len(expected))
        for i, (row, (member, cls)) in enumerate(zip(rows, expected)):
            self.assertEqual((row.location.offset, row.location.length), (cls['offset'], 32))
            self.assertEqual(row.value, dict(kind='class', index=i, total=len(expected), dex=member,
                                           **{k: cls[k] for k in ('name', 'access', 'superclass', 'interfaces', 'source_file')}))
            spec = dex.TOOL.operations['dex.methods']
            methods = spec.handler(data, spec.validate_args({'member': member, 'class': cls['name']}))
            self.assertEqual(len(methods), len(cls['methods']))
            for j, (observed, declared) in enumerate(zip(methods, cls['methods'])):
                self.assertEqual((observed.location.offset, observed.location.length), (declared['offset'], 8))
                self.assertEqual(observed.value, dict(kind='method', dex=member, index=j, total=len(methods),
                                                     **{k: declared[k] for k in ('class', 'name', 'prototype', 'access',
                                                                                'code_offset', 'code_units')}))

    def test_shared_fixture_every_declared_reference_and_cross_member_incoming(self):
        from tests.fixtures_apk import HELPER, apk_basic
        data, layout = apk_basic()
        spec = dex.TOOL.operations['dex.references']
        for member, child in layout['dex'].items():
            for cls in child['classes']:
                for method in cls['methods']:
                    args = dict(member=member, **{'class': cls['name'], 'method': method['name'],
                                                 'prototype': method['prototype']})
                    rows = spec.handler(data, spec.validate_args(args))
                    expected = [r for r in child['references'] if (r['class'], r['method'], r['prototype'])
                                == (cls['name'], method['name'], method['prototype'])]
                    self.assertEqual(len(rows), len(expected))
                    for i, (row, ref) in enumerate(zip(rows, expected)):
                        self.assertEqual((row.location.offset, row.location.length), (ref['at'], ref['length']))
                        self.assertEqual(row.value, dict(kind='dex_ref', index=i, total=len(expected), dex=member,
                                                        from_class=ref['class'], from_method=ref['method'],
                                                        from_prototype=ref['prototype'],
                                                        **{k: ref[k] for k in ('at', 'ref_kind', 'target', 'target_truncated')}))
                        self.assertEqual(row.artifact, next(m['artifact'] for m in layout['members'] if m['name'] == member))
        args = {'class': HELPER, 'method': 'compute', 'prototype': '(II)I', 'direction': 'to'}
        rows = spec.handler(data, spec.validate_args(args))
        self.assertEqual([(r.value['dex'], r.value['from_method'], r.value['at']) for r in rows],
                         [('classes.dex', 'helper', 552), ('classes2.dex', 'run', 308)])
        self.assertEqual([r.value['total'] for r in rows], [2, 2])
        page = spec.handler(data, spec.validate_args({**args, 'start': 1, 'limit': 1}))
        self.assertEqual(page, rows[1:])

    def test_shared_fixture_versions_and_hostile_dex_controls(self):
        from tests.fixtures_apk import classes_dex, classes2_dex, dex_hostile
        for version in ('035', '037', '038', '039'):
            for builder in (classes_dex, classes2_dex):
                child, layout = builder(version)
                parsed = dex.parse(child)
                self.assertEqual(parsed['header']['checksum'], layout['checksum'])
                self.assertEqual([r['descriptor'] for r in parsed['types']], [r['descriptor'] for r in layout['types']])
        for defect in ('checksum', 'version_040', 'string_ids'):
            with self.subTest(defect=defect), self.assertRaisesRegex(dex.DexError, '^Invalid DEX structure$'):
                dex.parse(dex_hostile(defect)[0])

    def test_real_stored_and_deflated_children_flow_through_gateway_and_reviewer(self):
        from reverseai import claims
        from reverseai.contract import (
            AnalysisResult, AnalysisTask, Budget, InputRef, OperationRequest, content_id, make_finding, sha256_hex,
        )
        from reverseai.gateway import Gateway
        from reverseai.review import review
        from tests.test_apk_parsing import zip_bytes
        child, _ = minimal_dex()
        for method in (0, 8):
            with self.subTest(method=method):
                data, _ = zip_bytes([('classes.dex', child)], method=method)
                input_ref = InputRef(sha256_hex(data), len(data), 'synthetic.apk')
                requests = (OperationRequest('dex.classes'),
                            OperationRequest('dex.methods', {'class': 'Ldemo/Main;'}),
                            OperationRequest('dex.references', {'class': 'Ldemo/Main;', 'method': 'method'}))
                task = AnalysisTask(content_id('tk', {'dex': method}), 'structural', input_ref, requests, Budget())
                result = Gateway((dex.TOOL,), Budget()).run(task, data)
                self.assertEqual(result.status, 'ok', result)
                self.assertEqual(len(result.evidence), 7)
                for item in result.evidence:
                    self.assertEqual(item.artifact['method'], method)
                    self.assertEqual(item.artifact['sha256'], sha256_hex(child))
                    at, length = item.location.offset, item.location.length
                    self.assertEqual(item.excerpt_sha256, sha256_hex(child[at:at + length]))
                findings = []
                for operation, key in (('dex.classes', 'android.classes'), ('dex.methods', 'android.methods'),
                                       ('dex.references', 'android.references')):
                    evidence = [e for e in result.evidence if e.operation == operation]
                    value = claims.RULES[key][1][operation]([e.observation for e in evidence])
                    self.assertIsNotNone(value)
                    findings.append(make_finding('structural', claims.statement(key), key, value,
                                                 [e.id for e in evidence], 'observed'))
                final = AnalysisResult(task.id, 'structural', 'ok', result.evidence, tuple(findings))
                self.assertEqual([v.status for v in review(data, input_ref, [final], {'dex': dex.TOOL})],
                                 ['supported'] * 3)

    def test_real_multidex_keeps_distinct_artifacts_for_identical_child_offsets(self):
        from reverseai.contract import make_evidence
        from tests.test_apk_parsing import zip_bytes
        child, _ = minimal_dex()
        data, _ = zip_bytes([('classes.dex', child), ('classes2.dex', child)], method=8)
        spec = dex.TOOL.operations['dex.classes']
        rows = spec.handler(data, spec.validate_args({}))
        self.assertEqual([r.value['total'] for r in rows], [2, 2])
        self.assertEqual(rows[0].location, rows[1].location)
        evidence = [make_evidence(data, dex.TOOL.ref, spec.name, row) for row in rows]
        self.assertNotEqual(evidence[0].id, evidence[1].id)
        self.assertNotEqual(evidence[0].artifact['data_offset'], evidence[1].artifact['data_offset'])

    def test_real_late_invalid_child_discards_the_first_page(self):
        from reverseai.contract import AnalysisTask, Budget, InputRef, OperationRequest, content_id, sha256_hex
        from reverseai.gateway import Gateway
        from tests.test_apk_parsing import zip_bytes
        child, _ = minimal_dex()
        data, _ = zip_bytes([('classes.dex', child), ('classes2.dex', b'not a DEX')])
        input_ref = InputRef(sha256_hex(data), len(data), 'synthetic.apk')
        task = AnalysisTask(content_id('tk', {'late_child': True}), 'structural', input_ref,
                            (OperationRequest('dex.classes', {'limit': 1}),), Budget())
        result = Gateway((dex.TOOL,), Budget()).run(task, data)
        self.assertEqual(result.status, 'error')
        self.assertEqual(result.evidence, ())
        spec = dex.TOOL.operations['dex.classes']
        self.assertEqual(len(spec.handler(data, spec.validate_args({'member': 'classes.dex'}))), 1)
