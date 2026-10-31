import json
import tempfile
import unittest
import zlib
from pathlib import Path

from hive import preflight

# Low-entropy stand-in for machine code: a few repeating instruction-like words.
CODE = (b"\xfd\x7b\xbf\xa9\xfd\x03\x00\x91\x00\x00\x80\x52\xc0\x03\x5f\xd6" * 8192)[:96 * 1024]
PACKED = zlib.compress(bytes(range(256)) * 64 + b"".join(i.to_bytes(4, "little") * 3 for i in range(40000)), 9)
PACKED = (PACKED * 4)[:96 * 1024]
NORMAL_IMPORTS = ["_printf", "_fopen", "_fread", "_fwrite", "_malloc", "_free", "_strcmp", "_exit"]


def segments(code_name="__TEXT", size=96 * 1024):
    return [("__PAGEZERO", 0, 0, 0, 1 << 32, False, False, False),
            (code_name, 0, size, 1 << 32, size, True, False, True),
            ("__DATA", size, 4096, (1 << 32) + size, 4096, True, True, False)]


def functions(count, size=256, dominant=None):
    rows = [{"size": size} for _ in range(count)]
    if dominant:
        rows.append({"size": dominant})
    return rows


class AssessTests(unittest.TestCase):
    def test_entropy_bounds(self):
        self.assertEqual(preflight.entropy(b""), 0.0)
        self.assertEqual(preflight.entropy(b"\x00" * 100), 0.0)
        self.assertAlmostEqual(preflight.entropy(bytes(range(256))), 8.0)
        self.assertGreater(preflight.entropy(PACKED), preflight.STRONG_SEGMENT_ENTROPY)
        self.assertLess(preflight.entropy(CODE), preflight.WEAK_SEGMENT_ENTROPY)

    def test_ordinary_program_is_clean(self):
        data = CODE + b"\x00" * 4096
        result = preflight.assess(data, segments(), NORMAL_IMPORTS, functions(300), strings=500)
        self.assertEqual(result["verdict"], "clean")
        self.assertEqual(result["signals"], [])

    def test_compressed_code_is_packed(self):
        data = PACKED + b"\x00" * 4096
        result = preflight.assess(data, segments(), NORMAL_IMPORTS, functions(300), strings=500)
        self.assertEqual(result["verdict"], "packed")
        self.assertIn("executable entropy", [s["signal"] for s in result["signals"]])
        self.assertIn("Unpack", result["advice"])

    def test_packer_section_names_and_markers(self):
        data = CODE + b"\x00" * 4096
        result = preflight.assess(data, segments("UPX1"), NORMAL_IMPORTS, functions(300), strings=500)
        self.assertEqual((result["verdict"], result["packers"]), ("packed", ["UPX"]))
        marked = CODE[:2048] + b"$Info: This file is packed with the UPX executable packer $" + CODE[2048:]
        result = preflight.assess(marked, segments(), NORMAL_IMPORTS, functions(300), strings=500)
        self.assertEqual(result["packers"], ["UPX"])
        for name in (".vmp0", ".MPRESS1", ".themida"):
            self.assertEqual(preflight.assess(data, segments(name), NORMAL_IMPORTS)["verdict"], "packed", name)

    def test_weak_signals_need_company(self):
        data = CODE + b"\x00" * 4096
        one = preflight.assess(data, segments(), ["_dlopen", "_dlsym", "_mprotect"], functions(300), strings=500)
        self.assertEqual(one["verdict"], "clean")
        self.assertEqual([s["signal"] for s in one["signals"]], ["loader-only imports"])
        many = preflight.assess(data, segments(), ["LoadLibraryA", "GetProcAddress"], functions(1, dominant=80000),
                                strings=0)
        self.assertEqual(many["verdict"], "suspected")
        self.assertEqual(sorted(s["signal"] for s in many["signals"]),
                         ["few functions", "few strings", "loader-only imports", "one dominant function"])

    def test_small_programs_are_not_judged_by_density(self):
        small = CODE[:16 * 1024] + b"\x00" * 4096
        result = preflight.assess(small, segments(size=16 * 1024), NORMAL_IMPORTS, functions(1), strings=0)
        self.assertEqual(result["verdict"], "clean")


class RunTests(unittest.TestCase):
    def test_run_reads_segments_and_imports_from_reverseai(self):
        tmp = Path(tempfile.mkdtemp())
        (tmp / "program").write_bytes(PACKED + b"\x00" * 4096)

        class Engine:
            path = tmp / "program"
            asked = []

            def query(self, name, args, out):
                self.asked.append((name, dict(args)))
                if name == "list_segments":
                    rows = [list(row) for row in segments()][args["start"]:args["start"] + args["limit"]]
                    return {"results": [{"findings": [{"claim_key": "segments.list", "verdict": "supported",
                                                       "value": {"rows": rows}}]}]}
                return {"results": [{"findings": [{"claim_key": "imports.symbols", "verdict": "supported",
                                                   "value": NORMAL_IMPORTS}]}]}

        engine = Engine()
        result = preflight.run(engine, {"functions": functions(300), "strings": [{}] * 500}, tmp / "pre")
        self.assertEqual(result["verdict"], "packed")
        self.assertEqual([name for name, _ in engine.asked], ["list_segments", "binary_overview"])
        self.assertEqual(json.loads((tmp / "pre" / "preflight.json").read_text())["verdict"], "packed")


if __name__ == "__main__":
    unittest.main()
