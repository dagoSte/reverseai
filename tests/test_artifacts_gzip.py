"""M5c: children inside one whole gzip stream (artifact method 1, decision m5c-contract)."""

import gzip
import io
import tarfile
import unittest
import zlib

import reverseai.contract as contract_module
import reverseai.review as review_module
from reverseai import claims
from reverseai.contract import (
    AnalysisResult, ContractError, InputRef, Location, Observation, OperationSpec, ToolRef, ToolSpec, check_artifact,
    content_id, inflate_stream, make_evidence, make_finding, materialize, sha256_hex,
)
from reverseai.review import review


def tarball(files):
    """A code-built npm-style tarball and the decompressed offset of each file (test inputs only)."""
    raw = io.BytesIO()
    with tarfile.open(fileobj=raw, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, body in files:
            info = tarfile.TarInfo("package/" + name)
            info.size, info.mtime = len(body), 0
            archive.addfile(info, io.BytesIO(body))
    stream = raw.getvalue()
    offsets = {name: stream.index(body) for name, body in files}
    return gzip.compress(stream, mtime=0), stream, offsets


FILES = [("index.js", b"fetch('https://example.test/x');\n"), ("lib/a.js", b"eval(atob('eA=='));\n")]
DATA, STREAM, OFFSETS = tarball(FILES)
INPUT = InputRef(sha256_hex(DATA), len(DATA), "pkg.tgz")


def artifact(name, **change):
    body = dict(FILES)[name]
    value = {"member": "package/" + name, "method": 1, "data_offset": 0, "compressed_size": len(DATA),
             "inner_offset": OFFSETS[name], "size": len(body), "crc32": zlib.crc32(body), "sha256": sha256_hex(body)}
    value.update(change)
    return value


class GzipStreamTests(unittest.TestCase):
    def test_the_whole_stream_inflates_with_header_options_and_trailer_checked(self):
        self.assertEqual(inflate_stream(DATA, 0, len(DATA)), STREAM)
        header = bytearray(DATA[:10])
        header[3] = 8 | 2  # FNAME and FHCRC
        named = bytes(header) + b"pkg.tar\x00"
        named += zlib.crc32(named).to_bytes(4, "little")[:2]
        with_name = named + DATA[10:]
        self.assertEqual(inflate_stream(with_name, 0, len(with_name)), STREAM)
        bad = [DATA + b"x", DATA[:-1], DATA[:-8] + bytes(8), b"\x1f\x8b\x07" + DATA[3:], DATA[:3] + b"\x20" + DATA[4:]]
        for value in bad:
            with self.assertRaises(ContractError):
                inflate_stream(value, 0, len(value))
        bomb = gzip.compress(bytes(1 << 20), mtime=0)
        self.assertGreater(1 << 20, 100 * len(bomb))
        with self.assertRaises(ContractError):
            inflate_stream(bomb, 0, len(bomb))

    def test_a_member_is_its_exact_range_of_the_stream(self):
        for name, body in FILES:
            self.assertEqual(materialize(DATA, artifact(name)), body)
        for value in (artifact("index.js", inner_offset=OFFSETS["index.js"] + 1), artifact("index.js", crc32=1),
                      artifact("index.js", size=len(STREAM)), artifact("index.js", compressed_size=len(DATA) - 1),
                      artifact("index.js", method=8), {**artifact("index.js"), "extra": 1}):
            with self.assertRaises(ContractError, msg=value):
                materialize(DATA, value)
        stored = {k: v for k, v in artifact("index.js").items() if k != "inner_offset"}
        with self.assertRaises(ContractError):
            check_artifact(stored)  # method 1 needs inner_offset
        with self.assertRaises(ContractError):
            check_artifact({**artifact("index.js"), "inner_offset": 10**9, "compressed_size": 10})  # past 100:1

    def test_one_inflation_serves_every_member_through_the_cache(self):
        streams, calls, real = {}, [], inflate_stream
        contract_module.inflate_stream = lambda *args: calls.append(args) or real(*args)
        try:
            for name, _ in FILES:
                materialize(DATA, artifact(name), streams=streams)
        finally:
            contract_module.inflate_stream = real
        self.assertEqual(len(calls), 1)

    def test_the_reviewer_inflates_a_stream_once_and_charges_its_bound(self):
        tool = ToolRef("js", "0.1.0")
        tools = {"js": ToolSpec(tool, {"js.files": OperationSpec("js.files", {}, lambda d, a: [])})}
        claims.RULES["test.gz"] = ("observed", {"js.files": lambda observations: "gz"})
        self.addCleanup(claims.RULES.pop, "test.gz")
        evidence = [make_evidence(DATA, tool, "js.files", Observation(Location(0, 4), {"kind": "x"}, artifact(name)))
                    for name, _ in FILES]
        findings = [make_finding("structural", "Gz %d." % i, "test.gz", "gz", [e.id], "observed")
                    for i, e in enumerate(evidence)]
        calls, real = [], review_module.inflate_stream
        review_module.inflate_stream = lambda *args: calls.append(args) or real(*args)
        try:
            result = AnalysisResult(content_id("tk", {"t": "gz"}), "structural", "ok", tuple(evidence), tuple(findings))
            statuses = [v.status for v in review(DATA, INPUT, [result], tools)]
        finally:
            review_module.inflate_stream = real
        self.assertEqual((statuses, len(calls)), (["supported", "supported"], 1))


if __name__ == "__main__":
    unittest.main()
