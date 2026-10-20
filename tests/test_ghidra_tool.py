"""Ghidra tool tests use the shared inert fixtures and a canned executor."""

import copy
import importlib
import json
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from reverseai.contained import ContainedTimeout
from reverseai.contract import (
    AnalysisTask, Budget, ContractError, InputRef, MAX_WORKER_REPLY_BYTES, OperationRequest,
    WORKER_PROTOCOL, WorkerError, content_id, sha256_hex,
)
from reverseai.gateway import Gateway
from reverseai.tools import ghidra_tool, ghidra_verify
from tests.fixtures_code import elf_code, pe_code
from tests.fixtures_structure import elf
from tests.test_contained import ghidra_lock
from tests.test_ghidra_verify import ARGS, observations, records


def reply(data, items, **changes):
    value = {"protocol": WORKER_PROTOCOL, "status": "ok", "snapshot_sha256": sha256_hex(data), "observations": items}
    value.update(changes)
    return json.dumps(value).encode()


class FakeExecutor:
    def __init__(self, response):
        self.lock, self.response, self.calls = ghidra_lock(), response, []

    def run(self, operation, args, data, digest):
        self.calls.append((operation, args, data, digest))
        if isinstance(self.response, Exception):
            raise self.response
        return self.response


class ToolTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout = elf_code()
        self.items = records(self.layout)
        self.executor = FakeExecutor(reply(self.data, self.items))
        self.tool = ghidra_tool.make_tool(self.executor)
        self.operation = self.tool.operations["ghidra.analyze"]

    def test_metadata_defaults_derived_declaration_and_snapshot_binding(self):
        self.assertEqual((self.tool.ref.name, self.tool.ref.version), ("ghidra", "12.1.4-r3"))
        self.assertTrue(self.tool.contained)
        self.assertTrue(self.operation.derived)
        self.assertEqual(self.operation.max_observations, 400)
        self.assertEqual(set(self.tool.operations), {"ghidra.analyze"})
        self.assertEqual(self.tool.runtime, {"image": ghidra_lock()["image_id"], "platform": "linux/arm64"})
        self.assertEqual(self.operation.handler(self.data, {}), observations(self.items))
        self.assertEqual(self.executor.calls, [("ghidra.analyze", ARGS, self.data, sha256_hex(self.data))])
        for generator in (elf_code, pe_code):
            data, layout = generator()
            tool = ghidra_tool.make_tool(FakeExecutor(reply(data, records(layout))))
            self.assertEqual(tool.operations["ghidra.analyze"].handler(data, {}), observations(records(layout)))

    def test_invalid_analyst_arguments_fail_before_the_executor(self):
        for key, low, high in (("max_functions", 1, 128), ("decompile", 0, 16),
                               ("max_chars", 64, 2048), ("max_calls", 0, 256)):
            for value in (True, low - 1, high + 1, str(low)):
                with self.subTest(key=key, value=value), self.assertRaises(ContractError):
                    self.operation.handler(self.data, {key: value})
        for key in ("path", "script", "loader", "profile", "timeout"):
            with self.subTest(key=key), self.assertRaises(ContractError):
                self.operation.handler(self.data, {key: "untrusted"})
        self.assertEqual(self.executor.calls, [])

    def test_forged_last_anchor_refuses_the_whole_gateway_operation(self):
        items = copy.deepcopy(self.items)
        items[-1]["location"]["offset"] = 0
        self.executor.response = reply(self.data, items)
        task = AnalysisTask(content_id("tk", {"input": sha256_hex(self.data)}), "code", InputRef(sha256_hex(self.data), len(self.data), "inert"),
                            (OperationRequest("ghidra.analyze"),))
        result = Gateway((self.tool,), Budget()).run(task, self.data)
        self.assertEqual(result.status, "error")
        self.assertEqual(result.evidence, ())
        self.assertEqual(len(self.executor.calls), 1)

    def test_bad_replies_and_encoding_are_constant_refusals(self):
        bad_text = copy.deepcopy(self.items)
        bad_text[4]["value"]["text"] = "\ud800"
        bad = (b"\xff", b"{", None, b"x" * (MAX_WORKER_REPLY_BYTES + 1),
               reply(self.data, self.items, snapshot_sha256="0" * 64),
               reply(self.data, self.items, protocol="reverseai.worker/2"),
               reply(self.data, bad_text), reply(self.data, self.items[:1] * 401))
        for raw in bad:
            self.executor.response = raw
            with self.subTest(length=None if raw is None else len(raw)), \
                    self.assertRaisesRegex(ContractError, "^" + ghidra_verify.REFUSED + "$"):
                self.operation.handler(self.data, {})

    def test_worker_error_and_contained_timeout_preserve_their_types(self):
        self.executor.response = json.dumps({"protocol": WORKER_PROTOCOL, "status": "error",
            "snapshot_sha256": sha256_hex(self.data), "error": "AnalysisTimedOut"}).encode()
        with self.assertRaisesRegex(WorkerError, "^AnalysisTimedOut$"):
            self.operation.handler(self.data, {})
        failure = ContainedTimeout("WorkerTimeout")
        self.executor.response = failure
        with self.assertRaises(ContainedTimeout) as caught:
            self.operation.handler(self.data, {})
        self.assertIs(caught.exception, failure)

    def test_the_exact_maximum_of_400_observations_is_admitted_and_the_next_is_refused(self):
        data, layout = elf(entry=0x1000, sections=((b".text", 1, 6, 8192),))
        data = bytearray(data)
        struct.pack_into("<Q", data, layout["shoff"] + 64 + 16, 0x1000)
        data = bytes(data)
        functions, pseudocode, calls = [], [], []
        for index in range(128):
            entry, offset = 0x1000 + 32 * index, layout["offsets"][0] + 32 * index
            location = {"offset": offset, "length": 16}
            functions.append({"location": location, "value": {
                "kind": "function", "index": index, "entry": entry, "name": f"f{index}", "size": 16}})
            if index < 16:
                pseudocode.append({"location": dict(location), "value": {
                    "kind": "pseudocode", "index": index, "entry": entry, "text": "return;", "truncated": False}})
            for shift in (0, 5):
                calls.append({"location": {"offset": offset + shift, "length": 5}, "value": {
                    "kind": "call", "from": entry, "to": 0, "to_name": "external"}})
        items = functions + pseudocode + calls
        executor = FakeExecutor(reply(data, items))
        handler = ghidra_tool.make_tool(executor).operations["ghidra.analyze"].handler
        args = {"max_functions": 128, "decompile": 16, "max_chars": 64, "max_calls": 256}
        self.assertEqual(len(handler(data, args)), 400)
        executor.response = reply(data, items + calls[:1])
        with self.assertRaises(ContractError):
            handler(data, args)

    def test_import_is_lazy_and_default_factory_uses_the_agreed_adapter(self):
        with patch("reverseai.contained.DockerExecutor") as factory:
            importlib.reload(ghidra_tool)
            factory.assert_not_called()
        importlib.reload(ghidra_tool)
        with patch.object(ghidra_tool, "DockerExecutor", return_value=self.executor) as factory:
            tool = ghidra_tool.make_tool()
            factory.assert_called_once_with(ghidra_tool.DEFAULT_LOCK, adapter_version="12.1.4-r3")
            self.assertTrue(tool.operations["ghidra.analyze"].derived)

    def test_availability_requires_exact_lock_and_local_image_without_host_native_imports(self):
        inspected = []
        def inspect(image):
            inspected.append(image)
            return image
        self.assertTrue(ghidra_tool.available(ghidra_lock(), inspect=inspect))
        self.assertEqual(inspected, [ghidra_lock()["image_id"]])
        self.assertFalse(ghidra_tool.available(dict(ghidra_lock(), ghidra_sha256="0" * 64), inspect=inspect))
        self.assertEqual(len(inspected), 1)
        self.assertFalse(ghidra_tool.available(ghidra_lock(), inspect=lambda image: "other"))
        def unavailable(image):
            raise OSError("/private/socket")
        self.assertFalse(ghidra_tool.available(ghidra_lock(), inspect=unavailable))
        with tempfile.TemporaryDirectory() as folder:
            self.assertFalse(ghidra_tool.available(Path(folder) / "missing", inspect=inspect))
        self.assertEqual(len(inspected), 1)
