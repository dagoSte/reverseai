"""The LIEF worker's pure logic, without LIEF: byte decoding, observations, cross-checks and the reply protocol."""

import importlib.util
import json
from pathlib import Path
import re
import tempfile
import unittest

from reverseai.contract import WorkerError, parse_worker_reply, sha256_hex
from reverseai.tools import structure
from tests.fixtures_structure import elf, malformed, patched, pe

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("lief_worker", ROOT / "containers" / "lief" / "worker.py")
worker = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(worker)


def faithful(data, format_):
    """What a correct LIEF parse reports: the byte decode, with the whole section list when the table is readable."""
    facts = dict(worker.elf_raw(data) if format_ == "elf" else worker.pe_raw(data))
    try:
        if format_ == "elf":
            rows = worker.elf_section_rows(data, facts, facts["shnum"])
            facts["sections"] = [(r["offset"], r["size"], r["flags"]) for r in rows]
        else:
            rows = worker.pe_section_rows(data, facts, 65535)
            facts["sections"] = [(r["offset"], r["size"], r["characteristics"]) for r in rows]
    except worker.WorkerFailure:
        facts["sections"] = None  # a header-only answer, as LIEF gives for a broken table
    return facts


def far_pe(e_lfanew=0x2000):
    """The generated PE with its headers moved after a gap: e_lfanew beyond the 4,096-byte location cap."""
    data, _ = pe()
    head = bytearray(data[:0x40]) + bytearray(e_lfanew - 0x40)
    head[0x3C:0x40] = e_lfanew.to_bytes(4, "little")
    return bytes(head) + data[0x80:]


def run(operation, data, facts_of=faithful, **args):
    request = [operation, json.dumps(args)]
    return worker.reply(request, data, facts_of)


def values(reply):
    return [item["value"] for item in reply["observations"]]


class HeaderTests(unittest.TestCase):
    def test_elf_header_matches_the_m1_structure_tool(self):
        for label, data in (("elf64 le", elf()[0]), ("elf32 be mips", elf(width=32, order=">", kind=3, machine=8)[0]),
                            ("elf64 be ppc64", elf(order=">", machine=21)[0])):
            with self.subTest(label):
                reply = run("lief.headers", data)
                (observation,) = reply["observations"]
                m1 = structure.headers(data, {})[0]
                self.assertEqual(observation["location"], {"offset": m1.location.offset, "length": m1.location.length})
                for field in ("format", "class", "endianness", "type", "machine", "machine_name", "entry", "shnum", "shoff"):
                    self.assertEqual(observation["value"][field], m1.value[field], field)

    def test_pe_headers_are_three_physical_observations(self):
        data, layout = pe(entry_rva=0x1234)
        reply = run("lief.headers", data)
        self.assertEqual([item["location"] for item in reply["observations"]],
                         [{"offset": 0, "length": 64}, {"offset": 0x80, "length": 24}, {"offset": 0x98, "length": 240}])
        dos, coff, optional = values(reply)
        self.assertEqual(dos, {"structure": "dos", "e_lfanew": 0x80})
        m1 = structure.headers(data, {})[0].value
        for field in ("format", "machine", "machine_name", "number_of_sections", "timestamp", "characteristics"):
            self.assertEqual(coff[field], m1[field], field)
        self.assertEqual(optional, {"structure": "optional", "optional_magic": "pe32+", "entry_rva": 0x1234})
        self.assertNotIn("format", dos)
        self.assertNotIn("format", optional)  # each field only in the structure that holds it

    def test_a_distant_pe_header_is_never_spanned_by_one_location(self):
        reply = run("lief.headers", far_pe())
        self.assertEqual([item["location"] for item in reply["observations"]],
                         [{"offset": 0, "length": 64}, {"offset": 0x2000, "length": 24}, {"offset": 0x2018, "length": 240}])

    def test_optional_header_fields_only_inside_the_declared_size(self):
        data, layout = pe()
        coff = layout["lfanew"] + 4
        cases = ((pe(optional_size=20)[0], {"structure": "optional", "optional_magic": "pe32+", "entry_rva": 0x1000}),
                 (patched(data, coff + 16, "<H", 8), {"structure": "optional", "optional_magic": "pe32+"}),
                 (patched(data, coff + 16, "<H", 0), None))
        for data_, expected in cases:
            with self.subTest(expected=expected):
                found = [v for v in values(run("lief.headers", data_)) if v["structure"] == "optional"]
                self.assertEqual(found, [expected] if expected else [])
        self.assertEqual(run("lief.headers", patched(data, coff + 16, "<H", 5000))["error"], "StructureTooLarge")

    def test_machine_names_are_m1_names(self):
        self.assertEqual(worker.ELF_MACHINES, structure.ELF_MACHINES)
        self.assertEqual(worker.PE_MACHINES, structure.PE_MACHINES)
        self.assertEqual(worker.PE_OPTIONAL, structure.PE_OPTIONAL)


class SectionTests(unittest.TestCase):
    def test_elf_sections_are_physical_entries_without_names(self):
        data, layout = elf()
        reply = run("lief.sections", data)
        self.assertEqual([item["location"] for item in reply["observations"]],
                         [{"offset": layout["shoff"] + 64 * i, "length": 64} for i in range(5)])
        self.assertEqual(values(reply)[3], {"structure": "section", "index": 3, "offset": layout["offsets"][2], "size": 8,
                                            "flags": 7, "writable": True, "executable": True})
        self.assertTrue(all("name" not in value for value in values(reply)))
        m1 = [o.value for o in structure.sections(data, {"max_sections": 64})]
        for mine, theirs in zip(values(reply), m1):
            for field in ("index", "offset", "size", "flags", "writable", "executable"):
                self.assertEqual(mine[field], theirs[field], field)

    def test_pe_sections(self):
        data, layout = pe()
        reply = run("lief.sections", data)
        self.assertEqual([item["location"] for item in reply["observations"]],
                         [{"offset": layout["table_offset"] + 40 * i, "length": 40} for i in range(3)])
        self.assertEqual([v["index"] for v in values(reply) if v["writable"] and v["executable"]], [2])
        self.assertEqual(values(reply)[0], {"structure": "section", "index": 0, "offset": layout["raw_offsets"][0], "size": 0x200,
                                            "characteristics": 0x60000020, "writable": False, "executable": True})

    def test_max_sections_caps_the_entries(self):
        self.assertEqual(len(run("lief.sections", elf()[0], max_sections=2)["observations"]), 2)
        self.assertEqual(len(run("lief.sections", elf()[0])["observations"]), 5)

    def test_elf_extended_numbering_is_refused_not_listed_empty(self):
        data, _ = elf(extended=True)
        self.assertEqual(run("lief.sections", data)["error"], "UnsupportedLayout")
        self.assertEqual(values(run("lief.headers", data))[0]["shnum"], 0)  # with shoff set: no count claim can follow


class RefusalTests(unittest.TestCase):
    # Expected (headers, sections) outcome per M1 malformed input. The worker differs from M1 by design where names
    # are deferred (a bad name table does not matter) and where the PE optional header is read only inside its
    # declared size, the section table then starting where the COFF header says, as the Windows loader does.
    MALFORMED = {
        "elf truncated identification": ("TruncatedStructure", "TruncatedStructure"),
        "elf truncated header": ("TruncatedStructure", "TruncatedStructure"),
        "elf bad class": ("UnsupportedLayout", "UnsupportedLayout"),
        "elf bad byte order": ("UnsupportedLayout", "UnsupportedLayout"),
        "elf section table past end": ("ok", "TruncatedStructure"),
        "elf huge section count": ("ok", "TruncatedStructure"),
        "elf wrong section entry size": ("ok", "UnsupportedLayout"),
        "elf name table past end": ("ok", "ok"),
        "elf truncated section table": ("ok", "TruncatedStructure"),
        "pe truncated coff": ("TruncatedStructure", "TruncatedStructure"),
        "pe truncated optional": ("TruncatedStructure", "TruncatedStructure"),
        "pe huge section count": ("ok", "TruncatedStructure"),
        "pe huge optional size": ("StructureTooLarge", "StructureTooLarge"),
        "pe zero optional size": ("ok", "ok"),
        "pe optional size below its fields": ("ok", "ok"),
        "pe truncated section table": ("ok", "TruncatedStructure"),
    }

    def test_malformed_inputs_have_exact_outcomes_and_in_range_locations(self):
        cases = malformed()
        self.assertEqual(set(cases), set(self.MALFORMED))
        for name, (data, _) in cases.items():
            for operation, expected in zip(("lief.headers", "lief.sections"), self.MALFORMED[name]):
                with self.subTest(name=name, operation=operation):
                    reply = run(operation, data)
                    self.assertEqual(reply.get("error", reply["status"]), expected)
                    for item in reply.get("observations", ()):
                        location = item["location"]
                        self.assertTrue(0 < location["length"] <= 4096 and location["offset"] + location["length"] <= len(data))

    def test_only_elf_and_pe_are_accepted(self):
        for data in (b"", b"PK\x03\x04" + bytes(40), b"\xcf\xfa\xed\xfe" + bytes(40), b"MZ" + bytes(100)):
            with self.subTest(data=data[:4]):
                self.assertEqual(run("lief.headers", data)["error"], "UnsupportedFormat")

    def test_a_lief_parse_that_disagrees_with_the_bytes_is_refused(self):
        def changed(field, value):
            def facts_of(data, format_):
                facts = faithful(data, format_)
                facts[field] = value
                return facts
            return facts_of
        for operation, data, field, value in (
                ("lief.headers", elf()[0], "machine", 0x3E00),  # LIEF 1.0.0 reads x86_64 ELF as little-endian whatever EI_DATA says
                ("lief.headers", elf()[0], "endianness", "big"),
                ("lief.headers", pe()[0], "entry_rva", 0),
                ("lief.headers", pe()[0], "optional_magic", 0x10B),
                ("lief.sections", elf()[0], "sections", [(0, 0, 0)] * 4),
                ("lief.sections", pe()[0], "sections", [(512, 512, 0), (1024, 512, 0), (1536, 512, 0)]),
                ("lief.sections", pe()[0], "number_of_sections", 41)):
            with self.subTest(operation=operation, field=field):
                self.assertEqual(run(operation, data, facts_of=changed(field, value))["error"], "InconsistentParse")

    def test_lief_must_list_exactly_the_declared_sections(self):
        def listing(change):
            def facts_of(data, format_):
                facts = faithful(data, format_)
                facts["sections"] = change(facts["sections"])
                return facts
            return facts_of
        for label, change in (("one more", lambda listed: listed + [(0, 0, 0)]), ("one fewer", lambda listed: listed[:-1])):
            with self.subTest(label):
                self.assertEqual(run("lief.sections", elf()[0], facts_of=listing(change), max_sections=2)["error"], "InconsistentParse")

    def test_the_whole_declared_table_must_be_inside_the_input_even_when_fewer_entries_are_read(self):
        data, layout = elf()
        cut = data[:layout["shoff"] + 2 * 64]  # entries 0 and 1 fit, the declared five do not
        self.assertEqual(run("lief.sections", cut, max_sections=1)["error"], "TruncatedStructure")
        table = pe()[1]["table_offset"]
        self.assertEqual(run("lief.sections", pe()[0][:table + 40], max_sections=1)["error"], "TruncatedStructure")

    def test_requests_are_exact(self):
        data = elf()[0]
        for request in ([], ["lief.headers"], ["lief.headers", "{}", "x"], ["lief.imports", "{}"], ["lief.headers", '{"x": 1}'],
                        ["lief.sections", '{"max_sections": 0}'], ["lief.sections", '{"max_sections": 65}'],
                        ["lief.sections", '{"max_sections": true}'], ["lief.sections", '{"max_sections": "8"}'],
                        ["lief.sections", '{"max_sections": 8, "max_sections": 9}'], ["lief.sections", "[]"],
                        ["lief.sections", "not json"]):
            with self.subTest(request=request):
                self.assertEqual(worker.reply(request, data, faithful)["error"], "InvalidRequest")

    def test_unexpected_failures_become_short_error_names(self):
        def broken(data, format_):
            raise RuntimeError("detail with /host/path and bytes")
        reply = run("lief.headers", elf()[0], facts_of=broken)
        self.assertEqual(reply, {"protocol": worker.PROTOCOL, "status": "error", "snapshot_sha256": sha256_hex(elf()[0]),
                                 "error": "RuntimeError"})


class ProtocolTests(unittest.TestCase):
    def test_replies_pass_the_hosts_parser(self):
        for operation, data in (("lief.headers", elf()[0]), ("lief.headers", pe()[0]), ("lief.sections", pe()[0])):
            with self.subTest(operation=operation):
                raw = (json.dumps(run(operation, data), sort_keys=True, separators=(",", ":")) + "\n").encode()
                observations = parse_worker_reply(raw, input_sha256=sha256_hex(data), max_observations=64)
                self.assertEqual(len(observations), len(run(operation, data)["observations"]))
        error = (json.dumps(run("lief.sections", elf(extended=True)[0])) + "\n").encode()
        with self.assertRaises(WorkerError):
            parse_worker_reply(error, input_sha256=sha256_hex(elf(extended=True)[0]), max_observations=64)

    def test_main_reads_the_snapshot_and_prints_one_json_object(self):
        data = pe()[0]
        with tempfile.TemporaryDirectory() as temporary:
            snapshot = Path(temporary, "input")
            snapshot.write_bytes(data)
            import contextlib
            import io
            out = io.StringIO()
            original = worker.lief_facts
            worker.lief_facts = faithful
            try:
                with contextlib.redirect_stdout(out):
                    self.assertEqual(worker.main(["lief.headers", "{}"], snapshot=str(snapshot)), 0)
            finally:
                worker.lief_facts = original
        text = out.getvalue()
        self.assertTrue(text.endswith("\n") and text.count("\n") == 1)
        self.assertEqual(json.loads(text)["snapshot_sha256"], sha256_hex(data))

    def test_build_inputs_are_pinned_consistently(self):
        build = (ROOT / "tools" / "build_lief_image.py").read_text()
        dockerfile = (ROOT / "containers" / "lief" / "Dockerfile").read_text()
        requirements = (ROOT / "containers" / "lief" / "requirements.txt").read_text()
        digest = re.search(r'BASE_DIGEST = "(sha256:[0-9a-f]{64})"', build).group(1)
        self.assertIn("FROM python:3.12-slim@" + digest + "\n", dockerfile)
        self.assertIn('ADAPTER_VERSION = "' + worker.ADAPTER_VERSION + '"', build)
        self.assertEqual(re.findall(r"--hash=sha256:([0-9a-f]{64})", requirements),
                         ["a9e4b9e165bde0163624e159c8c7a096e3d6f671371c70d008baac7ac1f04f0d"])
        self.assertIn('ENTRYPOINT ["python3", "-I", "-B", "/opt/reverseai/worker.py"]', dockerfile)
        self.assertIn("USER 65534:65534", dockerfile)
        lock = ROOT / "containers" / "lief" / "image.lock.json"
        if lock.exists():
            value = json.loads(lock.read_text())
            self.assertEqual(set(value), {"image_id", "platform", "base_digest", "wheel_sha256", "adapter_version"})
            self.assertEqual((value["base_digest"], value["platform"], value["adapter_version"]),
                             (digest, "linux/arm64", worker.ADAPTER_VERSION))


if __name__ == "__main__":
    unittest.main()
