"""JADX stand-ins: all identities, instructions and child provenance come from DEX bytes."""

import copy
import os
from pathlib import Path
import struct
import tempfile
import unittest
from unittest.mock import patch

from reverseai import contained
from reverseai.contract import (
    AnalysisResult, AnalysisTask, Budget, ContractError, InputRef, Location, OperationRequest,
    WORKER_PROTOCOL, WorkerError, canonical_json, content_id, make_finding, sha256_hex,
)
from reverseai.gateway import Gateway
from reverseai.review import review
from reverseai.tools import apk, jadx_tool, jadx_verify
from tests import fixtures_apk as F
from tests.test_apk_parsing import zip_bytes

LOCK = {"image_id": "sha256:" + "a" * 64, "platform": "linux/arm64", "adapter_version": "1.5.6-r1",
        **contained.JADX_PINS, "driver_sha256": "1" * 64, "worker_sha256": "2" * 64}
TEXT = 'public int helper(int x) {\n\treturn x + 1;\n}'


def packet(data, rows):
    return canonical_json({"protocol": WORKER_PROTOCOL, "status": "ok",
                           "snapshot_sha256": sha256_hex(data), "observations": rows}).encode()


class Executor:
    def __init__(self, layout, change=None, raw=None):
        self.lock, self.layout, self.change, self.raw, self.calls = LOCK, layout, change, raw, []

    def run(self, operation, request, data, digest):
        self.calls.append(copy.deepcopy(request))
        assert digest == sha256_hex(data)
        contained.build_argv(LOCK["image_id"], "reverseai-jadxfixture", "/private/tmp/jadx-fixture", operation, request)
        rows = []
        for index, target in enumerate(request["targets"]):
            member = request["members"][target["member"]]["member"]
            cls, name, proto = (bytes.fromhex(target[k]).decode() for k in ("class", "method", "prototype"))
            method, = [method for c in self.layout["dex"][member]["classes"] if c["name"] == cls
                       for method in c["methods"] if method["name"] == name and method["prototype"] == proto]
            rows.append({"target": index, "status": "ok", "code_offset": method["code_offset"],
                         "insns_count": method["code_units"], "total": len(TEXT),
                         "text": TEXT[request["start"]:request["start"] + request["max_chars"]]})
        if self.change:
            rows = self.change(rows)
        return self.raw(data) if self.raw else packet(data, rows)


class HostTests(unittest.TestCase):
    def setUp(self):
        self.data, self.layout = F.apk_basic()

    def invoke(self, args=None, *, executor=None, change=None, raw=None, data=None):
        executor = executor or Executor(self.layout, change=change, raw=raw)
        spec = jadx_tool.make_tool(executor).operations["jadx.method"]
        checked = spec.validate_args({"class": F.MAIN, "method": "helper", **(args or {})})
        return spec.handler(self.data if data is None else data, checked), executor

    def test_honest_overloads_have_exact_instruction_anchors_and_derived_verdicts(self):
        rows, executor = self.invoke()
        methods = sorted((m for m in self.layout["dex"]["classes.dex"]["classes"][0]["methods"]
                          if m["name"] == "helper"), key=lambda m: m["index"])
        self.assertEqual([o.value["prototype"] for o in rows], [m["prototype"] for m in methods])
        self.assertEqual([o.location for o in rows], [Location(m["code_offset"] + 16, 2 * m["code_units"]) for m in methods])
        self.assertTrue(all(o.artifact == self.layout["members"][1]["artifact"] for o in rows))
        self.assertEqual([m["member"] for m in executor.calls[0]["members"]], ["classes.dex", "classes2.dex"])
        self.assertEqual([t["member"] for t in executor.calls[0]["targets"]], [0, 0])
        spec = jadx_tool.make_tool(Executor(self.layout))
        ref = InputRef(sha256_hex(self.data), len(self.data), "fixture.apk")
        task = AnalysisTask(content_id("tk", {"q": "java"}), "code", ref,
                            (OperationRequest("jadx.method", {"class": F.MAIN, "method": "helper"}),), Budget())
        result = Gateway((spec,), Budget()).run(task, self.data)
        self.assertEqual(result.status, "ok", result.errors)
        findings = tuple(make_finding("code", "Java.", "android.java",
                         {k: v for k, v in e.observation.items() if k != "kind"}, [e.id], "inferred") for e in result.evidence)
        final = AnalysisResult(task.id, "code", "ok", result.evidence, findings)
        self.assertEqual([v.status for v in review(self.data, ref, [final], {"jadx": spec})], ["derived", "derived"])

    def test_member_selection_and_prototype_filter_use_exact_escaped_identities(self):
        rows, executor = self.invoke({"member": "classes2.dex", "class": F.WORKER, "method": "run", "prototype": "()V"})
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0].artifact["member"], "classes2.dex")
        self.assertEqual(executor.calls[0]["targets"][0]["member"], 1)
        rows, _ = self.invoke({"prototype": "(I)I"})
        self.assertEqual([o.value["prototype"] for o in rows], ["(I)I"])
        for args in ({"method": "absent"}, {"class": "Lmissing;"}, {"member": "missing.dex"}, {"prototype": "()V"}):
            rows, executor = self.invoke(args)
            self.assertEqual((rows, executor.calls), ((), []))

    def test_method_id_order_and_unicode_raw_identities_are_preserved(self):
        cls = {'name': 'La;', 'super': F.OBJECT, 'access': 1,
               'direct': (F._method('m', 'V', (F.STRING,), 2, 2, 2, 0, ('return-void',)),),
               'virtual': (F._method('m', 'V', ('I',), 1, 2, 2, 0, ('return-void',)),)}
        child, layout = F.dex_file((cls,))
        data, _ = zip_bytes([('classes.dex', child)])
        rows, _ = self.invoke({'class': 'La;', 'method': 'm'}, executor=Executor({'dex': {'classes.dex': layout}}), data=data)
        self.assertEqual([o.value['prototype'] for o in rows], ['(I)V', '(Ljava/lang/String;)V'])
        cls = {'name': 'La/\u00e9;', 'super': F.OBJECT, 'access': 1,
               'direct': (F._method('m\u00e9', 'V', (), 9, 0, 0, 0, ('return-void',)),)}
        child, layout = F.dex_file((cls,))
        data, _ = zip_bytes([('classes\u00e9.dex', child)])
        executor = Executor({'dex': {'classes\\xe9.dex': layout}})
        rows, _ = self.invoke({'member': 'classes\\xe9.dex', 'class': 'La/\\xe9;', 'method': 'm\\xe9'},
                              executor=executor, data=data)
        self.assertEqual(rows[0].value['class'], 'La/\\xe9;')
        self.assertEqual(rows[0].value['name'], 'm\\xe9')
        self.assertEqual(executor.calls[0]['targets'][0]['class'], 'La/\u00e9;'.encode().hex())
        self.assertEqual(executor.calls[0]['targets'][0]['method'], 'm\u00e9'.encode().hex())

    def test_unknown_missing_extra_duplicate_and_reordered_targets_fail_the_whole_reply(self):
        changes = [lambda r: [], lambda r: r[:1], lambda r: r + r[:1], lambda r: [r[0], r[0]],
                   lambda r: list(reversed(r)), lambda r: [{**r[0], "target": 99}, r[1]],
                   lambda r: [{**r[0], "target": True}, r[1]],
                   lambda r: [{**r[0], "class": "Llying;"}, r[1]],
                   lambda r: [{**r[0], "artifact": {}}, r[1]],
                   lambda r: [{**r[0], "location": {"offset": 0, "length": 1}}, r[1]],
                   lambda r: [{**r[0], "member": "classes2.dex"}, r[1]]]
        for change in changes:
            with self.subTest(change=change), self.assertRaisesRegex(ContractError, jadx_verify.REFUSED):
                self.invoke(change=change)

    def test_wrong_code_ranges_shapes_text_and_paging_are_refused(self):
        bad = [("code_offset", 0), ("insns_count", 999), ("insns_count", True), ("status", "unknown"),
               ("total", -1), ("total", True), ("total", 2**32), ("total", 1),
               ("text", "é"), ("text", "a\rb"), ("text", "\x1b[31m"), ("text", "\x7f"),
               ("text", "x" * 65)]
        for key, value in bad:
            with self.subTest(key=key, value=repr(value)), self.assertRaisesRegex(ContractError, jadx_verify.REFUSED):
                self.invoke({"max_chars": 64}, change=lambda r: [{**r[0], key: value}, r[1]])
        with self.assertRaises(ContractError):
            self.invoke(change=lambda r: [{k: v for k, v in r[0].items() if k != "status"}, r[1]])

    def test_java_fallback_error_and_end_pages_preserve_the_verified_anchor(self):
        rows, _ = self.invoke({"start": 7}, change=lambda r: [{**v, "status": "fallback"} for v in r])
        self.assertTrue(all(o.value["form"] == "fallback" and o.value["start"] == 7 and o.value["text"] == TEXT[7:] for o in rows))
        for start in (len(TEXT), len(TEXT) + 1, 1048575):
            rows, _ = self.invoke({"start": start})
            self.assertTrue(all((o.value["start"], o.value["total"], o.value["text"]) == (len(TEXT), len(TEXT), "") for o in rows))
        for status in ("decompile_failed", "class_not_found", "method_not_found", "no_code"):
            def change(rows):
                return [{**r, "status": status, "code_offset": None, "insns_count": None, "total": 0, "text": ""} for r in rows]
            rows, _ = self.invoke({"start": 7}, change=change)
            self.assertTrue(all((o.value["form"], o.value["start"], o.value["total"], o.value["text"]) == ("error", 0, 0, "") for o in rows))
            with self.assertRaises(ContractError):
                self.invoke(change=lambda r: [{**r[0], "status": status}, r[1]])

    def test_worker_envelope_and_json_bounds_are_strict(self):
        def valid(data):
            return {"protocol": WORKER_PROTOCOL, "status": "ok", "snapshot_sha256": sha256_hex(data), "observations": []}
        raws = [lambda d: b'\xff', lambda d: b'{', lambda d: b'[]', lambda d: b'0' * 262145,
                lambda d: b'{"protocol":1,"protocol":2}',
                lambda d: b'{"protocol":NaN}', lambda d: b'[' * 2000 + b']' * 2000,
                lambda d: canonical_json({**valid(d), "protocol": "other"}).encode(),
                lambda d: canonical_json({**valid(d), "snapshot_sha256": "0" * 64}).encode(),
                lambda d: canonical_json({**valid(d), "extra": 1}).encode(),
                lambda d: canonical_json({**valid(d), "observations": [None] * 17}).encode()]
        for raw in raws:
            with self.subTest(raw=raw), self.assertRaises(ContractError):
                self.invoke(raw=raw)
        for error in ("memory", "timeout", "input"):
            with self.subTest(error=error), self.assertRaises(WorkerError):
                self.invoke(raw=lambda d: canonical_json({"protocol": WORKER_PROTOCOL, "status": "error",
                            "snapshot_sha256": sha256_hex(d), "error": error}).encode())

    def test_longest_instruction_prefix_is_capped_and_large_observations_are_refused(self):
        cls = {"name": "La;", "super": F.OBJECT, "access": 1,
               "direct": (F._method("large", "V", (), 9, 0, 0, 0, *([("return-void",)] * 2200)),)}
        child, layout = F.dex_file((cls,))
        data, _ = zip_bytes([("classes.dex", child)])
        executor = Executor({"dex": {"classes.dex": layout}})
        rows, _ = self.invoke({"class": "La;", "method": "large"}, executor=executor, data=data)
        self.assertEqual(rows[0].location, Location(layout["code_items"][0]["offset"] + 16, 4096))
        def oversized(rows):
            return [{**r, "total": 2048, "text": '"' * 2048} for r in rows]
        with self.assertRaises(ContractError):
            self.invoke({"max_chars": 2048}, change=oversized)

    def test_abstract_native_and_zero_instruction_methods_are_not_targets(self):
        for access in (0x401, 0x101):
            cls = {"name": "La;", "super": F.OBJECT, "access": 0x401,
                   "virtual": (F._method("m", "V", (), access, 0, 0, 0),)}
            child, layout = F.dex_file((cls,))
            data, _ = zip_bytes([("classes.dex", child)])
            executor = Executor({"dex": {"classes.dex": layout}})
            rows, _ = self.invoke({"class": "La;", "method": "m"}, executor=executor, data=data)
            self.assertEqual((rows, executor.calls), ((), []))
            checked = jadx_tool.make_tool(executor).operations["jadx.method"].validate_args({"class": "La;", "method": "m"})
            with self.assertRaises(ContractError):
                jadx_verify.verify(data, [{"target": 0}], checked)
        child, layout = F.classes2_dex()
        buffer = bytearray(child)
        struct.pack_into('<I', buffer, layout['code_items'][0]['offset'] + 12, 0)
        F._seal(buffer)
        data, _ = zip_bytes([('classes.dex', bytes(buffer))])
        executor = Executor({'dex': {'classes.dex': layout}})
        rows, _ = self.invoke({'class': F.WORKER, 'method': '<init>'}, executor=executor, data=data)
        self.assertEqual((rows, executor.calls), ((), []))

    def test_more_than_16_members_or_matches_fail_before_the_worker(self):
        child, _ = F.classes2_dex()
        data, _ = zip_bytes([(f'classes{i}.dex', child) for i in range(17)])
        executor = Executor(self.layout)
        with self.assertRaises(ContractError):
            self.invoke(executor=executor, data=data)
        self.assertEqual(executor.calls, [])
        child, layout = F.classes2_dex()
        data, _ = zip_bytes([(f'classes{i}.dex', child) for i in range(16)])
        executor = Executor({'dex': {f'classes{i}.dex': layout for i in range(16)}})
        rows, _ = self.invoke({'class': F.WORKER, 'method': 'run'}, executor=executor, data=data)
        self.assertEqual(len(rows), 16)
        self.assertEqual([t['member'] for t in executor.calls[0]['targets']], list(range(16)))
        for count in (16, 17):
            cls = {'name': 'La;', 'super': F.OBJECT, 'access': 1,
                   'direct': tuple(F._method('m', 'V', ('I',) * n, 9, n, n, 0, ('return-void',)) for n in range(count))}
            child, layout = F.dex_file((cls,))
            data, _ = zip_bytes([('classes.dex', child)])
            executor = Executor({'dex': {'classes.dex': layout}})
            if count == 17:
                with self.assertRaises(ContractError):
                    self.invoke({'class': 'La;', 'method': 'm'}, executor=executor, data=data)
                self.assertEqual(executor.calls, [])
            else:
                rows, _ = self.invoke({'class': 'La;', 'method': 'm'}, executor=executor, data=data)
                self.assertEqual(len(rows), 16)

    def test_flagged_dex_members_refuse_the_whole_operation(self):
        child, _ = F.classes2_dex()
        data, _ = zip_bytes([('classes' + 'x' * 245 + '.dex', child)])
        executor = Executor(self.layout)
        with self.assertRaises(ContractError):
            self.invoke(executor=executor, data=data)
        self.assertEqual(executor.calls, [])


class BoundaryTests(unittest.TestCase):
    def test_fixed_lock_profile_and_schema(self):
        self.assertEqual(contained.load_lock(LOCK, adapter_version='1.5.6-r1'), LOCK)
        for key in ('base_digest', 'jadx_zip_sha256', 'jadx_jar_sha256', 'jdk_sha256', 'driver_sha256', 'worker_sha256'):
            with self.subTest(key=key), self.assertRaises(contained.ContainedError):
                contained.load_lock({**LOCK, key: 'bad'}, adapter_version='1.5.6-r1')
        for key in ('base_digest', 'jadx_zip_sha256', 'jadx_jar_sha256', 'jdk_sha256'):
            wrong = ('sha256:' if key == 'base_digest' else '') + '0' * 64
            with self.subTest(pin=key), self.assertRaises(contained.ContainedError):
                contained.load_lock({**LOCK, key: wrong}, adapter_version='1.5.6-r1')
        for extra in ({'wheel_sha256': '1' * 64}, {'extra': 1}):
            with self.assertRaises(contained.ContainedError):
                contained.load_lock({**LOCK, **extra}, adapter_version='1.5.6-r1')
        self.assertEqual(dict(contained.resource_profile('jadx.method')),
                         {'pids': 256, 'memory': '2g', 'cpus': 2, 'tmpfs': '/tmp:rw,noexec,nosuid,nodev,size=512m', 'wall_seconds': 120})
        with self.assertRaises(TypeError):
            contained.resource_profile('jadx.method')['memory'] = '9g'
        tool = jadx_tool.make_tool(Executor({}))
        self.assertTrue(tool.contained)
        self.assertEqual(tool.runtime, {'image': LOCK['image_id'], 'platform': 'linux/arm64'})
        spec = tool.operations['jadx.method']
        self.assertTrue(spec.derived)
        self.assertEqual(spec.max_observations, 16)
        for args in ({'class': 'La;', 'method': 'm', 'start': -1}, {'class': 'La;', 'method': 'm', 'max_chars': 63},
                     {'class': 'Lé;', 'method': 'm'}, {'class': 'La;', 'method': 'm', 'extra': 1}):
            with self.assertRaises(ContractError):
                spec.validate_args(args)
        self.assertTrue(jadx_tool.available(LOCK, inspect=lambda _: LOCK['image_id']))
        self.assertFalse(jadx_tool.available(LOCK, inspect=lambda _: 'wrong'))
        self.assertFalse(jadx_tool.available({}))

    def test_only_the_resolved_worker_request_is_allowed_in_the_fixed_argv(self):
        data, layout = F.apk_basic()
        executor = Executor(layout)
        spec = jadx_tool.make_tool(executor).operations['jadx.method']
        args = spec.validate_args({'class': F.MAIN, 'method': 'helper'})
        request, _ = jadx_verify.prepare(data, args)
        argv = contained.build_argv(LOCK['image_id'], 'reverseai-test', '/private/tmp/jadx', 'jadx.method', request)
        self.assertEqual(argv, ['docker', 'run', '--rm', '--init', '--pull', 'never', '--name', 'reverseai-test',
                         '--platform', 'linux/arm64', '--network', 'none', '--read-only', '--cap-drop', 'ALL',
                         '--security-opt', 'no-new-privileges', '--user', '65534:65534', '--pids-limit', '256',
                         '--memory', '2g', '--memory-swap', '2g', '--cpus', '2', '--tmpfs',
                         '/tmp:rw,noexec,nosuid,nodev,size=512m', '--log-driver', 'none', '--mount',
                         'type=bind,source=/private/tmp/jadx,target=/snapshot,readonly', LOCK['image_id'],
                         'jadx.method', canonical_json(request)])
        changes = [lambda r: {**r, 'entrypoint': 'sh'}, lambda r: {**r, 'targets': []},
                   lambda r: {**r, 'members': r['members'] * 9}, lambda r: {**r, 'start': True},
                   lambda r: {**r, 'targets': [{**r['targets'][0], 'member': -1}]},
                   lambda r: {**r, 'targets': [{**r['targets'][0], 'class': 'ff'}]},
                   lambda r: {**r, 'targets': [r['targets'][0]] * 2}]
        for change in changes:
            with self.assertRaises(contained.ContainedError):
                contained.build_argv(LOCK['image_id'], 'reverseai-test', '/private/tmp/jadx', 'jadx.method', change(request))

    def test_docker_executor_keeps_the_jadx_wall_and_operation_binding(self):
        data, layout = F.apk_basic()
        spec = jadx_tool.make_tool(Executor(layout)).operations['jadx.method']
        request, _ = jadx_verify.prepare(data, spec.validate_args({'class': F.MAIN, 'method': 'helper'}))
        calls = []
        with tempfile.TemporaryDirectory() as temporary:
            os.chmod(temporary, 0o700)
            executor = contained.DockerExecutor(LOCK, adapter_version='1.5.6-r1', staging_root=temporary,
                inspect=lambda _: LOCK['image_id'], runner=lambda argv, **kw: calls.append((argv, kw)) or b'{}')
            self.assertEqual(executor.run('jadx.method', request, data, sha256_hex(data)), b'{}')
            self.assertEqual(calls[0][1], {'timeout': 120, 'max_output': 262144})
            self.assertEqual(list(Path(temporary).iterdir()), [])
            with self.assertRaises(contained.ContainedError):
                executor.run('lief.headers', {}, data, sha256_hex(data))
        default = contained.DockerExecutor(LOCK, adapter_version='1.5.6-r1')
        self.assertEqual(default.runner.keywords, {'profile': 'jadx'})


if __name__ == '__main__':
    unittest.main()
