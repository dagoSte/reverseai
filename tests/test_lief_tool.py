import importlib
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from reverseai import contained
from reverseai.contract import ContractError, Location, Observation, WorkerError, WORKER_PROTOCOL, sha256_hex
from reverseai.tools import lief_tool
from tests.test_contained import lock


class FakeExecutor:
    def __init__(self, reply):
        self.lock = lock()
        self.reply = reply
        self.calls = []

    def run(self, *args):
        self.calls.append(args)
        return json.dumps(self.reply).encode("utf-8")


def reply(data, observations=()):
    return {"protocol": WORKER_PROTOCOL, "status": "ok", "snapshot_sha256": sha256_hex(data),
            "observations": list(observations)}


def item(offset=0, length=4, **value):
    return {"location": {"offset": offset, "length": length}, "value": value}


class LiefToolTests(unittest.TestCase):
    data = b"\x7fELF" + bytes(128)

    def test_metadata_and_headers_bind_the_snapshot_digest(self):
        executor = FakeExecutor(reply(self.data, [item(format="elf", machine_name="aarch64", shnum=4)]))
        tool = lief_tool.make_tool(executor)
        self.assertEqual((tool.ref.name, tool.ref.version), ("lief", "1.0.0-r1"))
        self.assertTrue(tool.contained)
        self.assertEqual(tool.runtime, {"image": lock()["image_id"], "platform": "linux/arm64"})
        self.assertEqual(tool.operations["lief.headers"].max_observations, 3)
        observed = tool.operations["lief.headers"].handler(self.data, {})
        self.assertEqual(observed, (Observation(Location(0, 4), {"format": "elf", "machine_name": "aarch64", "shnum": 4}),))
        self.assertEqual(executor.calls, [("lief.headers", {}, self.data, sha256_hex(self.data))])

    def test_sections_default_and_range_are_enforced_before_executor(self):
        executor = FakeExecutor(reply(self.data, [item(index=2, writable=True, executable=True)]))
        operation = lief_tool.make_tool(executor).operations["lief.sections"]
        self.assertEqual(operation.max_observations, 64)
        self.assertEqual(operation.handler(self.data, {})[0].value["index"], 2)
        self.assertEqual(executor.calls[-1][1], {"max_sections": 32})
        for count in (1, 64):
            operation.handler(self.data, {"max_sections": count})
        previous_calls = len(executor.calls)
        for args in ({"max_sections": 0}, {"max_sections": 65}, {"max_sections": True},
                     {"max_sections": "--network=host"}, {"path": "/private/input"}):
            with self.subTest(args=args), self.assertRaises(ContractError):
                operation.handler(self.data, args)
        self.assertEqual(len(executor.calls), previous_calls)

    def test_worker_errors_remain_errors_and_never_become_empty_successes(self):
        error = {"protocol": WORKER_PROTOCOL, "status": "error", "snapshot_sha256": sha256_hex(self.data),
                 "error": "MalformedHeader"}
        executor = FakeExecutor(error)
        with self.assertRaisesRegex(WorkerError, "^MalformedHeader$"):
            lief_tool.make_tool(executor).operations["lief.headers"].handler(self.data, {})

    def test_digest_mismatch_protocol_and_out_of_snapshot_locations_are_refused(self):
        for bad in (dict(reply(self.data), snapshot_sha256="0" * 64),
                    dict(reply(self.data), protocol="other"), reply(self.data, [item(offset=len(self.data))]),
                    reply(self.data, [item(offset=len(self.data) - 2, length=4)])):
            with self.subTest(reply=bad), self.assertRaises(ContractError):
                lief_tool.make_tool(FakeExecutor(bad)).operations["lief.headers"].handler(self.data, {})

    def test_headers_and_sections_observation_caps_are_enforced(self):
        for name, count in (("lief.headers", 4), ("lief.sections", 65)):
            executor = FakeExecutor(reply(self.data, [item(index=i) for i in range(count)]))
            with self.subTest(name=name), self.assertRaises(ContractError):
                lief_tool.make_tool(executor).operations[name].handler(self.data, {})

    def test_headers_cannot_send_unknown_arguments(self):
        executor = FakeExecutor(reply(self.data))
        with self.assertRaises(ContractError):
            lief_tool.make_tool(executor).operations["lief.headers"].handler(self.data, {"command": "sh"})
        self.assertEqual(executor.calls, [])


class AvailabilityTests(unittest.TestCase):
    def test_missing_or_invalid_lock_disables_the_optional_tool(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "lock.json"
            with patch("reverseai.contained.inspect_image") as inspect:
                self.assertFalse(lief_tool.available(path, inspect=inspect))
                path.write_text("bad")
                self.assertFalse(lief_tool.available(path, inspect=inspect))
                inspect.assert_not_called()

    def test_image_must_match_the_lock_and_daemon_failure_is_silent(self):
        self.assertTrue(lief_tool.available(lock(), inspect=lambda image: image))
        self.assertFalse(lief_tool.available(lock(), inspect=lambda image: "sha256:" + "d" * 64))

        def denied(image):
            raise OSError("private Docker socket")

        self.assertFalse(lief_tool.available(lock(), inspect=denied))

    def test_import_never_launches_docker_and_default_tool_reads_the_current_lock(self):
        with patch("reverseai.contained.subprocess.Popen", side_effect=AssertionError("unexpected Docker call")):
            importlib.reload(lief_tool)
            with tempfile.TemporaryDirectory() as folder:
                path = Path(folder) / "lock.json"
                with patch.object(lief_tool, "DEFAULT_LOCK", path):
                    with self.assertRaises(contained.ContainedError):
                        lief_tool.make_tool()
                    path.write_text(json.dumps(lock()))
                    tool = lief_tool.TOOL
                    self.assertEqual(tool.runtime["image"], lock()["image_id"])
                    newer = dict(lock(), image_id="sha256:" + "d" * 64)
                    path.write_text(json.dumps(newer))
                    self.assertEqual(lief_tool.TOOL.runtime["image"], newer["image_id"])
                    self.assertEqual(tool.runtime["image"], lock()["image_id"])
