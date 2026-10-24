"""R1 native-controller unit fakes. No Docker, probes or generated inputs are executed."""

import copy
import io
import json
import os
from pathlib import Path
import struct
import sys
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

from reverseai.contract import canonical_json, sha256_hex
from tests import verify_m2_runtime as old, verify_r1_runtime as verifier
from tests.fixtures_scale import elf_scale
from tests.test_verify_m2_runtime import GhidraFakeBoundary, ghidra_lock_fixture, ghidra_probe_fixture, image_fixture


def r7_lock():
    return {**ghidra_lock_fixture(), "adapter_version": old.GHIDRA_R7_VERSION,
            "parent_image_id": old.GHIDRA_PARENT_IMAGE_ID, "bundle_sha256": old.ghidra_bundle_hash(), "cache_format": 1}


class FakeBoundary(GhidraFakeBoundary):
    GHIDRA_PREPARE_WALL_SECONDS, GHIDRA_PREPARE_MAX_BYTES = 900, 64 * 1024**2
    default_lock = staticmethod(lambda tool: None)

    @staticmethod
    def resource_profile(operation):
        return {"pids": 256, "memory": "2g", "cpus": 2, "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=512m",
                "wall_seconds": 900 if operation == "ghidra.prepare" else 240}

    def __init__(self):
        super().__init__()
        self.prepare_calls, self.projects = [], []
        self.prepare_error = None
        boundary = self
        class Executor:
            def __init__(self, lock, *, runner, prepare_runner, staging_root, **kwargs):
                self.lock, self.runner, self.prepare_runner, self.root = lock, runner, prepare_runner, staging_root

            def available(self):
                return True

            def _call(self, data, operation, args, project=None, sink=None):
                with tempfile.TemporaryDirectory(dir=self.root) as folder:
                    Path(folder, "input").write_bytes(data)
                    if project is not None:
                        project.stage(folder)
                        boundary.projects.append((dict(project.manifest), Path(folder, "project.tar").read_bytes(),
                                                  json.loads(Path(folder, "cache.json").read_bytes())))
                    argv = boundary.build_argv(self.lock["image_id"], "reverseai-unit", folder, operation, args)
                    if sink is not None:
                        return self.prepare_runner(argv, sink, timeout=900)
                    return self.runner(argv, timeout=240, max_output=262144)

            def run(self, operation, args, data, digest, *, project=None):
                if sha256_hex(data) != digest:
                    raise AssertionError("fake snapshot mismatch")
                return self._call(data, operation, args, project=project)

            def prepare(self, data, digest, sink):
                if sha256_hex(data) != digest:
                    raise AssertionError("fake snapshot mismatch")
                return self._call(data, "ghidra.prepare", {}, sink=sink)
        self.DockerExecutor = Executor

    def run_prepare_bounded(self, argv, sink, *, timeout):
        self.prepare_calls.append((list(argv), timeout))
        if self.prepare_error is not None:
            raise self.prepare_error
        sink.write(self.output)


def page_report(data, functions, start, *, analysis_id="f" * 64, total=None):
    digest = sha256_hex(data)
    total = len(functions) if total is None else total
    selected = functions[start:start + 128]
    metadata = {"kind": "export_page", "scope": "program", "part": "functions", "entry": None,
                "status": "ok", "start": start, "total": total, "count": len(selected),
                "next_start": start + len(selected) if start + len(selected) < total else None,
                "analysis_id": analysis_id}
    evidence = [{"id": "ev-meta", "input_sha256": digest, "location": {"offset": 0, "length": 1},
                 "observation": metadata}]
    for index, function in enumerate(selected, start):
        evidence.append({"id": f"ev-{index}", "input_sha256": digest,
                         "location": {"offset": function["offset"], "length": min(16, function["size"])},
                         "observation": {"kind": "function_export", "index": index, "entry": function["entry"],
                                         "name": function["name"], "size": function["size"], "analysis_id": analysis_id}})
    return {"results": [{"role": "code", "status": "ok", "errors": [], "evidence": evidence,
                         "findings": [{"claim_key": "code.export_page", "verdict": "derived", "value": metadata}]}]}


def function_report(data, entry, part, start, total, records, *, status="ok", count=None):
    count = len(records) if count is None else count
    page = {"kind": "export_page", "scope": "function", "part": part, "entry": entry, "status": status,
            "start": start, "total": total, "count": count, "next_start": start + count if start + count < total else None,
            "analysis_id": "f" * 64}
    evidence = [{"input_sha256": sha256_hex(data), "location": {"offset": 0, "length": 1}, "observation": page}]
    evidence.extend({"input_sha256": sha256_hex(data), "location": location, "observation": {**value, "analysis_id": "f" * 64}}
                    for location, value in records)
    return {"results": [{"role": "code", "status": "ok", "errors": [], "evidence": evidence,
                          "findings": [{"claim_key": "code.export_page", "verdict": "derived", "value": page}]}]}


class SourcePins(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.source = Path(self.folder.name)
        for name in old.GHIDRA_BUNDLE_FILES:
            path = self.source / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("reviewed " + name)
        self.pins = patch.object(old, "GHIDRA_SOURCE", self.source)
        self.pins.start()
        self.addCleanup(self.pins.stop)

    def test_r6_stays_exact_and_r7_requires_nine_exact_bound_keys(self):
        old.verify_ghidra_lock(ghidra_lock_fixture())
        old.verify_ghidra_lock(r7_lock())
        verifier.verify_lock(r7_lock())
        self.assertEqual(old.lock_options("ghidra", r7_lock()), {"adapter_version": "12.1.4-r7"})
        self.assertEqual(old.lock_options("ghidra", ghidra_lock_fixture()), {"adapter_version": "12.1.4-r6"})
        with self.assertRaises(old.VerificationError):
            verifier.verify_lock(ghidra_lock_fixture())
        for key in r7_lock():
            changed = r7_lock()
            del changed[key]
            with self.subTest(key=key), self.assertRaises(old.VerificationError):
                old.verify_ghidra_lock(changed)
        for key, value in (("adapter_version", "12.1.4-r8"), ("adapter_version", "12.1.4-r6"),
                           ("cache_format", True), ("cache_format", 2), ("bundle_sha256", "0" * 64),
                           ("unexpected", True)):
            with self.subTest(key=key, value=value), self.assertRaises(old.VerificationError):
                old.verify_ghidra_lock({**r7_lock(), key: value})
        for parent in (None, "sha256:" + "a" * 64):
            lock = {**r7_lock(), "parent_image_id": parent}
            old.verify_ghidra_lock(lock)
            with self.assertRaises(old.VerificationError):
                verifier.verify_lock(lock)

    def test_source_change_missing_file_or_symlink_invalidates_revision(self):
        lock = r7_lock()
        path = self.source / old.GHIDRA_BUNDLE_FILES[0]
        path.write_text("changed")
        with self.assertRaises(old.VerificationError):
            old.verify_ghidra_lock(lock)
        path.unlink()
        with self.assertRaises(old.VerificationError):
            old.ghidra_bundle_hash()
        path.symlink_to(self.source / old.GHIDRA_BUNDLE_FILES[1])
        with self.assertRaises(old.VerificationError):
            old.ghidra_bundle_hash()


class HarnessTests(SourcePins):
    def setUp(self):
        super().setUp()
        self.work = tempfile.TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.boundary = FakeBoundary()
        self.receipt = {"checks": [], "cleanup": []}
        self.native = verifier.R1Verifier(self.boundary, r7_lock(), self.receipt, self.work.name)
        self.native.image = image_fixture()

    def test_both_profiles_are_fixed_and_checked_without_boundary_calls(self):
        verifier.verify_profiles(self.boundary)
        for field, value in (("wall_seconds", 901), ("pids", 257), ("memory", "3g"), ("cpus", 2.0)):
            original = self.boundary.resource_profile
            with patch.object(self.boundary, "resource_profile", side_effect=lambda operation, f=field, v=value:
                              {**original(operation), f: v} if operation == "ghidra.prepare" else original(operation)):
                with self.assertRaises(old.VerificationError):
                    verifier.verify_profiles(self.boundary)
        self.assertEqual(self.boundary.calls, [])

    def test_prepare_uses_true_stream_wrapper_and_stopped_inspection_and_cleanup(self):
        self.boundary.output = canonical_json(ghidra_probe_fixture("runtime_identity")).encode()
        result = self.native.prepare_control("runtime_identity", b"fixture")
        self.assertEqual(result["uid"], 65534)
        self.assertEqual(self.native.requests, [{"operation": "ghidra.prepare", "args": {}, "probe": "runtime_identity",
                                               "timeout": 900, "max_output": 64 * 1024**2}])
        self.assertEqual(self.boundary.prepare_calls[0][1], 900)
        self.assertEqual(self.boundary.prepare_calls[0][0][:3], ["docker", "start", "--attach"])
        created = next(argv for argv, _, _ in self.boundary.calls if argv[:2] == ["docker", "create"])
        self.assertIn("--read-only", created)
        self.assertEqual(created[created.index("--pull") + 1], "never")
        self.assertEqual(created[created.index("--entrypoint") + 1], "python3")
        self.assertEqual(self.native.inspected, 1)
        self.assertTrue(self.receipt["cleanup"][0]["verified"])
        self.assertTrue(self.receipt["cleanup"][0]["staging_removed"])

    def test_prepare_cap_plus_one_is_fixed_and_failure_is_observed_at_real_drain_seam(self):
        self.boundary.prepare_error = self.boundary.ContainedError("WorkerOutputLimit")
        result = self.native.prepare_control("stdout", b"fixture")
        self.assertEqual(result["max_output"], 64 * 1024**2)
        self.assertEqual(self.native.requests[0]["failure"], "WorkerOutputLimit")
        self.native.active, self.native.stream = "stdout", io.BytesIO()
        source = self.native.control_code()
        self.assertIn(str(64 * 1024**2 + 1), source)
        compile(source, "trusted-prepare-flood", "exec")
        self.native.active = "wall"
        self.assertIn("915", self.native.control_code())
        self.native.stream = None
        self.assertIn("262145", old.probe_code("stdout", tool="ghidra"))

    def test_new_fixed_probe_sources_compile_but_are_never_run(self):
        for name in ("cache_write", "program_no_jvm"):
            self.native.active = name
            source = self.native.control_code()
            compile(source, "trusted-r1-" + name, "exec")
            if name == "program_no_jvm":
                self.assertIn("subprocess.Popen=deny", source)
                self.assertIn("export_rows", source)
        self.native.active = "arbitrary;import os"
        with self.assertRaises(old.VerificationError):
            self.native.control_code()

    def test_public_cli_injection_uses_same_real_executor_and_isolates_cache_root(self):
        import reverseai
        from reverseai import cli
        from reverseai.tools import ghidra_tool
        cache = types.ModuleType("reverseai.ghidra_cache")
        cache.default_root = lambda: Path("/unselected")
        chosen = Path(self.work.name, "cache")
        def public(argv):
            self.assertEqual(cache.default_root(), chosen)
            self.assertEqual(ghidra_tool.DEFAULT_LOCK, self.native.lock)
            executor = ghidra_tool.DockerExecutor(ghidra_tool.DEFAULT_LOCK, adapter_version="12.1.4-r7")
            self.assertIsInstance(executor, self.native.true_executor)
            executor.run("ghidra.analyze", old.ghidra_args(), b"fixture", sha256_hex(b"fixture"))
            print("static CLI receipt")
            return 0
        with patch.dict(sys.modules, {"reverseai.ghidra_cache": cache}), \
                patch.object(reverseai, "ghidra_cache", cache, create=True), patch.object(cli, "main", side_effect=public):
            output = self.native.public_call(["analyze", "trusted-fixture"], chosen)
        self.assertEqual(output, "static CLI receipt\n")
        self.assertEqual(self.native.requests[0]["operation"], "ghidra.analyze")
        self.assertTrue(self.receipt["cleanup"][0]["staging_removed"])

    def test_unknown_operation_arguments_and_widened_limits_are_refused_before_create(self):
        for operation, args in (("ghidra.shell", {}), ("ghidra.prepare", {"timeout": 900}),
                                ("ghidra.export_program", {**verifier.PROGRAM_ARGS, "path": "/outside"})):
            argv = self.boundary.build_argv(self.native.lock["image_id"], "reverseai-unit", "/snapshot-test", operation, args)
            with self.subTest(operation=operation), self.assertRaises(old.VerificationError):
                self.native.runner(argv, timeout=240, max_output=262144)
        self.assertFalse(any(argv[:2] == ["docker", "create"] for argv, _, _ in self.boundary.calls))

    def test_restore_negatives_reach_worker_with_correct_host_manifest_and_body_hash(self):
        data = b"fixture"
        self.boundary.output = canonical_json({"protocol": "reverseai.worker/1", "status": "error",
            "snapshot_sha256": sha256_hex(data), "error": "InvalidCachedProject"}).encode()
        for variant in verifier.RESTORE_CASES:
            result = self.native.restore(data, variant)
            self.assertTrue(result["refused"])
            manifest, body, staged_manifest = self.boundary.projects[-1]
            self.assertEqual(manifest, staged_manifest)
            self.assertEqual(manifest["artifact_sha256"], sha256_hex(body))
            self.assertEqual(manifest["size"], len(body))
            self.assertEqual(set(manifest), {"format", "input_sha256", "image_id", "bundle_sha256", "size", "artifact_sha256"})
        self.boundary.output = b'{"status":"error","error":"anything"}'
        with self.assertRaises(old.VerificationError):
            self.native.restore(data, "traversal")

    def test_scale_enumerates_all_10000_functions_and_refuses_false_completeness(self):
        data, layout = elf_scale()
        prepared = {"analysis_id": "f" * 64, "artifact_size": 123, "elapsed_seconds": .1}
        def query(sample, cache, name, args):
            return page_report(data, layout["functions"], args["start"])
        with patch.object(self.native, "public_prepare", return_value=prepared) as prepare, \
                patch.object(self.native, "public_query", side_effect=query) as pages:
            result = self.native.scale()
        self.assertEqual((result["functions"], result["pages"]), (10_000, 79))
        prepare.assert_called_once()
        self.assertEqual(pages.call_count, 79)
        self.assertEqual(result["input_sha256"], sha256_hex(data))
        # A separate folder lets the same proof reject one dishonest native page.
        (Path(self.work.name) / "scale/fixture.bin").unlink()
        (Path(self.work.name) / "scale").rmdir()
        with patch.object(self.native, "public_prepare", return_value=prepared), \
                patch.object(self.native, "public_query", return_value=page_report(data, layout["functions"], 0, total=9999)), \
                self.assertRaises(old.VerificationError):
            self.native.scale()

    def test_function_parts_pseudocode_routes_and_not_found_use_real_shape_oracles(self):
        data, layout = old.elf_refs()
        function = next(row for row in layout["functions"] if row["name"] == "describe")
        anchor = {"offset": function["offset"], "length": min(16, function["size"])}
        text = "Derived statement;\n" * 10
        digest = sha256_hex(text.encode())
        def query(sample, cache, name, args):
            self.native.requests.append({"operation": "ghidra.pseudocode" if name == "procedure_pseudo_code" else "ghidra.export_function"})
            part = "pseudocode" if name == "procedure_pseudo_code" else args["part"]
            if args["entry"] == 2**64 - 1:
                return function_report(data, None, part, 0, 0, [], status="not_found")
            if part == "pseudocode":
                start = args.get("text_start", 0)
                piece = text[start:start + 64]
                value = {"kind": "pseudocode_page", "entry": function["entry"], "start": start, "total": len(text),
                         "text": piece, "text_sha256": digest, "status": "ok",
                         "next_start": start + len(piece) if start + len(piece) < len(text) else None}
                return function_report(data, function["entry"], part, start, len(text), [(anchor, value)], count=len(piece))
            records = []
            if part == "assembly":
                records = [({"offset": function["offset"] + delta, "length": length},
                    {"kind": "instruction_export", "index": index, "from": function["entry"],
                     "at": function["entry"] + delta, "length": length})
                    for index, (delta, length) in enumerate(function["instructions"])]
            elif part != "callees":
                kind = {"info": "function_info", "callers": "call_export", "references": "reference_export", "strings": "string_export"}[part]
                records = [(anchor, {"kind": kind}) for _ in range(2 if part == "strings" else 1)]
            return function_report(data, function["entry"], part, 0, len(records), records)
        with patch.object(self.native, "public_query", side_effect=query) as public:
            parts = self.native.function_parts()
            reading = self.native.pseudocode()
            missing = self.native.not_found()
        self.assertEqual(parts["requests"], 7)
        self.assertEqual(reading["characters"], len(text))
        self.assertEqual(reading["text_sha256"], digest)
        self.assertEqual((reading["export_pages"], reading["procedure_pages"]), (3, 3))
        self.assertEqual(missing["rows"], 0)
        self.assertEqual(public.call_count, 14)
        def dishonest(sample, cache, name, args):
            report = query(sample, cache, name, args)
            if args.get("text_start", 0) > 0:
                report["results"][0]["evidence"][1]["observation"]["text_sha256"] = "0" * 64
            return report
        with patch.object(self.native, "public_query", side_effect=dishonest), self.assertRaises(old.VerificationError):
            self.native.pseudocode()


class OracleTests(unittest.TestCase):
    def test_scale_is_deterministic_and_declares_exact_named_symbol_and_byte_oracles(self):
        data, layout = elf_scale()
        self.assertEqual(elf_scale()[0], data)
        self.assertEqual(len(layout["functions"]), 10_000)
        self.assertEqual(len({row["entry"] for row in layout["functions"]}), 10_000)
        section_at = struct.unpack_from("<Q", data, 40)[0]
        sym_at, sym_bytes = struct.unpack_from("<QQ", data, section_at + 2 * 64 + 24)
        self.assertEqual(sym_bytes, 24 * 10_001)
        self.assertEqual(struct.unpack_from("<Q", data, sym_at + 24 + 8)[0], layout["functions"][0]["entry"])
        for index in (0, 1, 9999):
            function = layout["functions"][index]
            self.assertEqual(data[function["offset"]:function["offset"] + 6], b"\xb8" + struct.pack("<I", index) + b"\xc3")
        for count in (True, 0, 65_538):
            with self.assertRaises(ValueError):
                elf_scale(count)

    def test_page_oracle_refuses_boolean_counts_no_progress_mixed_ids_or_non_derived_verdicts(self):
        data, layout = elf_scale(3)
        report = page_report(data, layout["functions"], 0)
        page, rows = verifier.validate_page(report, data, "functions", 0)
        self.assertEqual((page["count"], len(rows)), (3, 3))
        for mutate in (lambda r: r["results"][0]["evidence"][0]["observation"].update(count=True),
                       lambda r: r["results"][0]["evidence"][0]["observation"].update(next_start=0),
                       lambda r: r["results"][0]["evidence"][1]["observation"].update(analysis_id="0" * 64),
                       lambda r: r["results"][0]["findings"][0].update(verdict="supported"),
                       lambda r: r["results"][0]["evidence"][1]["location"].update(offset=len(data))):
            changed = copy.deepcopy(report)
            mutate(changed)
            with self.assertRaises(old.VerificationError):
                verifier.validate_page(changed, data, "functions", 0)

    def test_semantic_comparison_keeps_values_locations_and_verdicts(self):
        data, layout = elf_scale(2)
        left = page_report(data, layout["functions"], 0)
        right = page_report(data, layout["functions"], 0, analysis_id="0" * 64)
        self.assertEqual(verifier.semantic_report(left), verifier.semantic_report(right))
        right["results"][0]["findings"][0]["verdict"] = "supported"
        self.assertNotEqual(verifier.semantic_report(left), verifier.semantic_report(right))


class SmokeTests(SourcePins):
    def test_raw_smoke_prepares_once_restores_three_times_and_checks_exact_bytes_and_shapes(self):
        with tempfile.TemporaryDirectory() as folder:
            boundary, lock = FakeBoundary(), r7_lock()
            receipt = {"schema": "reverseai.r1-smoke/1", "offline": True, "platform": old.PLATFORM,
                       "checks": [], "cleanup": [], "lock": lock, "lock_sha256": "a" * 64,
                       "sources": {"trusted": "b" * 64}, "image_id": lock["image_id"]}
            native = verifier.R1Verifier(boundary, lock, receipt, folder)
            native.image = image_fixture()
            data, layout = old.elf_code()
            def anchor(function):
                return {"offset": function["offset"], "length": function["size"]}
            def reply(rows):
                return canonical_json({"protocol": "reverseai.worker/1", "status": "ok",
                    "snapshot_sha256": sha256_hex(data), "observations": rows}).encode()
            def page(scope, part, entry, count):
                return {"location": {"offset": 0, "length": 64}, "value": {
                    "kind": "export_page", "scope": scope, "part": part, "entry": entry,
                    "status": "ok", "start": 0, "total": count, "count": count, "next_start": None}}
            original = boundary.run_bounded
            creates = 0
            def run(argv, **kwargs):
                nonlocal creates
                if argv[:2] == ["docker", "create"]:
                    creates += 1
                    boundary.CID = f"{creates:064x}"
                    boundary.created_id = (boundary.CID + "\n").encode()
                    boundary.inspect["Id"] = boundary.CID
                    operation = argv[argv.index(lock["image_id"]) + 1]
                    if operation == "ghidra.prepare":
                        boundary.output = b"bounded opaque project stand-in"
                    elif operation == "ghidra.export_program":
                        rows = [page("program", "functions", None, 4)]
                        rows += [{"location": anchor(function), "value": {"kind": "function_export", "index": index,
                            **{key: function[key] for key in ("entry", "size", "name")},
                            "signature": None, "signature_truncated": False, "library_hint": None}}
                            for index, function in enumerate(layout["functions"])]
                        boundary.output = reply(rows)
                    elif operation == "ghidra.export_function":
                        function = layout["functions"][0]
                        boundary.output = reply([page("function", "info", function["entry"], 1), {
                            "location": anchor(function), "value": {"kind": "function_info",
                            **{key: function[key] for key in ("entry", "size", "name")}, "matches": 1,
                            "signature": None, "signature_truncated": False, "library_hint": None,
                            "totals": {"assembly": 6, "callees": 2, "callers": 0, "references": 0, "strings": 0},
                            "pseudocode_status": "not_requested"}}])
                    elif operation == "ghidra.functions":
                        function = layout["functions"][0]
                        boundary.output = reply([{"location": anchor(function), "value": {"kind": "function_row", "index": 0,
                            "total": 4, **{key: function[key] for key in ("entry", "size", "name")}}}])
                    else:
                        self.fail("unexpected smoke operation")
                return original(argv, **kwargs)
            with patch.object(boundary, "run_bounded", side_effect=run), \
                    patch.object(native, "local_daemon", return_value={"os": "linux", "arch": "arm64"}), \
                    patch.object(native, "image_check", return_value={"image_id": lock["image_id"]}):
                native.smoke()
            receipt["checks"].append({"id": "sources", "status": "passed"})
            receipt["requests"] = native.requests
            with patch.object(verifier, "source_hashes", return_value={"trusted": "b" * 64}):
                self.assertTrue(verifier.smoke_passes(receipt), receipt["checks"])
                for mutate in (lambda r: r["checks"].pop(), lambda r: r["requests"].pop(),
                               lambda r: r["manifest"].update(input_sha256="0" * 64),
                               lambda r: r["requests"][0].update(timeout=240),
                               lambda r: r["checks"][2]["evidence"].update(artifact_sha256="0" * 64)):
                    changed = copy.deepcopy(receipt)
                    mutate(changed)
                    self.assertFalse(verifier.smoke_passes(changed))
            self.assertEqual(len(boundary.prepare_calls), 1)
            self.assertEqual([row["operation"] for row in native.requests],
                             ["ghidra.prepare", "ghidra.export_program", "ghidra.export_function", "ghidra.functions"])
            self.assertEqual(len(boundary.projects), 3)
            self.assertTrue(all(body == b"bounded opaque project stand-in" for _, body, _ in boundary.projects))

    def test_smoke_cli_uses_existing_lock_and_never_calls_revision_builder(self):
        with tempfile.TemporaryDirectory() as folder:
            lock, receipt = Path(folder, "existing.lock"), Path(folder, "receipt.json")
            lock.write_text(canonical_json(r7_lock()))
            fake_native = Mock()
            fake_native.requests = []
            with patch.object(verifier, "source_hashes", return_value={"trusted": "b" * 64}), \
                    patch.object(verifier, "R1Verifier", return_value=fake_native), \
                    patch.object(verifier, "smoke_passes", return_value=False), \
                    patch.object(verifier.importlib, "import_module") as load, patch.object(sys, "stderr", io.StringIO()):
                result = verifier.main(["--offline", "--smoke", "--lock", str(lock), "--receipt", str(receipt)])
            self.assertEqual(result, 1)
            self.assertTrue(receipt.exists())
            load.assert_not_called()
            fake_native.smoke.assert_called_once()


class ReceiptTests(SourcePins):
    def receipt(self):
        lock = r7_lock()
        runtime = {"image": lock["image_id"], "platform": old.PLATFORM, "bundle_sha256": lock["bundle_sha256"]}
        def prepared(data):
            return {"schema": "reverseai.prepare/1", "input": {"sha256": sha256_hex(data), "size": len(data)},
                    "analysis_id": "f" * 64, "state": "created", "runtime": runtime, "cache_format": 1,
                    "artifact_size": 10_240, "elapsed_seconds": .1}
        evidence = {name: None for name in verifier.REQUIRED_CHECKS}
        evidence["revision"] = {"route": "B", "parent_image_id": old.GHIDRA_PARENT_IMAGE_ID,
                                "bundle_sha256": lock["bundle_sha256"]}
        for name, data in old.ghidra_fixtures().items():
            evidence[name + ".cached_equal"] = {"input_sha256": sha256_hex(data), "input_bytes": len(data),
                "prepare": prepared(data), "fresh_equal_cached": True, "prepare_operations": 1,
                "query_cases": 4 if name in old.GHIDRA_QUERY_FIXTURES else 0,
                "fresh_semantics_sha256": "a" * 64, "cached_semantics_sha256": "a" * 64, "elapsed_seconds": .2}
        data, _ = elf_scale()
        evidence["scale.10000"] = {"input_sha256": sha256_hex(data), "input_bytes": len(data), "functions": 10_000,
                                   "pages": 79, "prepare": prepared(data), "elapsed_seconds": .5}
        refs, layout = old.elf_refs()
        entry = layout["functions"][-1]["entry"]
        evidence["function.parts"] = {"input_sha256": sha256_hex(refs), "entry": entry, "analysis_id": "f" * 64,
            "totals": {"info": 1, "pseudocode": 130, "assembly": 6, "callees": 0, "callers": 1,
                       "references": 6, "strings": 2}, "requests": 7}
        evidence["function.pseudocode"] = {"input_sha256": sha256_hex(refs), "entry": entry, "analysis_id": "f" * 64,
            "characters": 130, "text_sha256": "b" * 64, "export_pages": 3, "procedure_pages": 3, "requests": 6}
        evidence["function.not_found"] = {"input_sha256": sha256_hex(refs), "analysis_id": "f" * 64, "rows": 0}
        counts = {("ghidra.prepare", None): 8, ("ghidra.analyze", None): 21, ("ghidra.functions", None): 9,
                  ("ghidra.function", None): 18, ("ghidra.xrefs", None): 9, ("ghidra.export_program", None): 116,
                  ("ghidra.export_function", None): 11, ("ghidra.pseudocode", None): 3,
                  ("ghidra.export_program", "program_no_jvm"): 1, ("ghidra.export_program", "cache_write"): 1,
                  **{(operation, name): 1 for operation in ("ghidra.prepare", "ghidra.analyze") for name in old.CONTROL_NAMES}}
        requests = [{"operation": operation, "probe": probe, "args": {}, "timeout": 900 if operation == "ghidra.prepare" else 240,
                     "max_output": 64 * 1024**2 if operation == "ghidra.prepare" else 262144}
                    for (operation, probe), count in counts.items() for _ in range(count)]
        return {"schema": "reverseai.r1-runtime/1", "offline": True, "platform": old.PLATFORM, "lock": lock,
                "lock_sha256": "c" * 64, "image_id": lock["image_id"], "sources": {"trusted": "d" * 64},
                "checks": [{"id": name, "status": "passed", "evidence": evidence[name]} for name in verifier.REQUIRED_CHECKS],
                "requests": requests, "cleanup": [{"container_id": f"{index:064x}", "verified": True, "staging_removed": True}
                                                    for index in range(len(requests))]}

    def test_receipt_requires_actual_counts_profiles_measurements_and_current_sources(self):
        with patch.object(verifier, "source_hashes", return_value={"trusted": "d" * 64}):
            proof = self.receipt()
            self.assertTrue(verifier.receipt_passes(proof))
            mutations = [lambda r: r["checks"].pop(), lambda r: r["checks"].append(r["checks"][0]),
                         lambda r: r["checks"][0].update(status="not_run"), lambda r: r["requests"].pop(),
                         lambda r: r["cleanup"][0].update(verified=False), lambda r: r["cleanup"][0].update(staging_removed=False),
                         lambda r: r["sources"].update(trusted="0" * 64), lambda r: r["requests"][0].update(timeout=901),
                         lambda r: r["requests"][0].update(max_output=64 * 1024**2 + 1),
                         lambda r: r["requests"][0].update(operation="ghidra.arbitrary")]
            for mutate in mutations:
                changed = copy.deepcopy(proof)
                mutate(changed)
                self.assertFalse(verifier.receipt_passes(changed))
            for check, field, value in (("scale.10000", "functions", 9999), ("scale.10000", "pages", 78),
                                       ("function.pseudocode", "characters", 64), ("function.pseudocode", "export_pages", 1),
                                       ("elf_code.cached_equal", "prepare_operations", 2),
                                       ("elf_code.cached_equal", "cached_semantics_sha256", "0" * 64)):
                changed = copy.deepcopy(proof)
                row = next(row for row in changed["checks"] if row["id"] == check)
                row["evidence"][field] = value
                self.assertFalse(verifier.receipt_passes(changed))

    def test_full_builder_parent_is_informational_but_r1_receipt_binds_approved_revision_parent(self):
        proof = self.receipt()
        proof["lock"]["parent_image_id"] = None
        old.verify_ghidra_lock(proof["lock"])
        self.assertFalse(verifier.receipt_passes(proof))


class MainTests(SourcePins):
    def test_cli_only_selects_reviewed_revision_route_and_new_lock_and_receipt(self):
        with tempfile.TemporaryDirectory() as folder:
            target, receipt = Path(folder, "r7.lock"), Path(folder, "receipt.json")
            lock = r7_lock()
            def revise(argv):
                self.assertEqual(argv, ["revise", "--route", "B", "--lock", str(target)])
                target.write_text(canonical_json(lock))
                return 0
            builder = types.SimpleNamespace(main=Mock(side_effect=revise))
            fake_native = Mock()
            fake_native.requests = []
            with patch.object(verifier, "source_hashes", return_value={"source": "a" * 64}), \
                    patch.object(verifier.importlib, "import_module", return_value=builder), \
                    patch.object(verifier, "preflight") as preflight, \
                    patch.object(verifier, "R1Verifier", return_value=fake_native), \
                    patch.object(verifier, "receipt_passes", return_value=False), \
                    patch.object(sys, "stderr", io.StringIO()):
                self.assertEqual(verifier.main(["--offline", "--route", "B", "--lock", str(target), "--receipt", str(receipt)]), 1)
            self.assertTrue(target.exists())
            self.assertFalse(json.loads(receipt.read_bytes())["passed"])
            self.assertEqual(fake_native.run_r1.call_count, 1)
            preflight.assert_called_once()

    def test_existing_lock_is_never_overwritten_or_sent_to_builder(self):
        with tempfile.TemporaryDirectory() as folder:
            target, receipt = Path(folder, "r6.lock"), Path(folder, "receipt.json")
            target.write_text("existing lock")
            with patch.object(verifier.importlib, "import_module") as load, patch.object(sys, "stderr", io.StringIO()):
                self.assertEqual(verifier.main(["--offline", "--route", "B", "--lock", str(target), "--receipt", str(receipt)]), 1)
            load.assert_not_called()
            self.assertEqual(target.read_text(), "existing lock")
            proof = json.loads(receipt.read_bytes())
            self.assertFalse(proof["passed"])
            self.assertEqual(proof["checks"][0]["reason"], "R1NewOutputRequired")
            self.assertTrue(any(row["status"] == "not_run" for row in proof["checks"]))


if __name__ == "__main__":
    unittest.main()
