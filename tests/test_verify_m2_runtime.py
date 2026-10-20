"""Canned validator checks only: this suite supplies no native containment proof."""

from __future__ import annotations

import copy
import io
import json
from pathlib import Path
import stat
import struct
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

import reverseai

from reverseai.contract import (
    MAX_WORKER_REPLY_BYTES, WORKER_PROTOCOL,
    parse_worker_reply, sha256_hex,
)
from tests import verify_m2_runtime as verifier
from tests.fixtures_structure import elf, pe


IMAGE_ID = "sha256:" + "a" * 64
SNAPSHOT = Path("/private/test-staging/frozen-input")


def image_fixture():
    return {
        "Id": IMAGE_ID, "Os": "linux", "Architecture": "arm64",
        "Config": {
            "User": "65534:65534", "Entrypoint": list(verifier.ENTRYPOINT),
            "Volumes": None, "Env": ["PATH=/usr/local/bin:/usr/bin:/bin"],
        },
    }


def lock_fixture():
    return {"image_id": IMAGE_ID, "platform": "linux/arm64", "base_digest": "sha256:" + "b" * 64,
            "wheel_sha256": "c" * 64, "adapter_version": "1.0.0-r2"}


def container_fixture():
    return {
        "Image": IMAGE_ID,
        "State": {"Running": False},
        "Config": {
            "User": "65534:65534", "Entrypoint": list(verifier.ENTRYPOINT),
            "Cmd": ["lief.headers", "{}"], "Volumes": None,
            "Env": list(image_fixture()["Config"]["Env"]),
        },
        "HostConfig": {
            "Privileged": False, "ReadonlyRootfs": True, "Init": True,
            "AutoRemove": True, "NetworkMode": "none", "PidsLimit": 64,
            "Memory": 536870912, "MemorySwap": 536870912,
            "NanoCpus": 1000000000, "CapDrop": ["ALL"], "CapAdd": None,
            "SecurityOpt": ["no-new-privileges"],
            "LogConfig": {"Type": "none", "Config": {}},
            "Tmpfs": {"/tmp": "rw,noexec,nosuid,nodev,size=64m"},
            "Binds": None, "VolumesFrom": None, "Devices": [],
            "DeviceRequests": None, "DeviceCgroupRules": None,
            "GroupAdd": None, "PidMode": "", "UTSMode": "",
            "UsernsMode": "", "PortBindings": {}, "PublishAllPorts": False,
            "ExtraHosts": None, "IpcMode": "private", "CgroupnsMode": "private",
        },
        "Mounts": [{
            "Type": "bind", "Source": str(SNAPSHOT), "Destination": "/snapshot",
            "RW": False,
        }],
    }


def probe_fixture(name):
    value = {"protocol": "reverseai.native-probe/1", "probe": name}
    if name == "runtime_identity":
        value.update(uid=65534, gid=65534, cap_eff=0, cap_prm=0,
                     cap_inh=0, cap_amb=0, no_new_privs=1, seccomp=2)
        return value
    value.update(attempted=True, blocked=True)
    if name in ("network", "write_root", "write_snapshot", "setuid", "capability"):
        value["errno"] = 1
    elif name == "pids":
        value.update(errno=11, limit=64, spawned=61)
    elif name == "memory":
        value.update(limit=536870912, child_returncode=-9, oom_kill_delta=1)
    elif name == "wall":
        value.update(error="WorkerTimeout", running_observed=True, timeout=45, elapsed=45.1)
    elif name == "stdout":
        value.update(error="WorkerOutputLimit", max_output=262144)
    return value


def receipt_fixture():
    return {
        "schema": "reverseai.m2-runtime/1", "platform": "linux/arm64",
        "tool": "lief", "profile": "small", "offline": True,
        "lock_sha256": "1" * 64, "verifier_sha256": "2" * 64,
        "executor_sha256": "3" * 64, "lock": lock_fixture(), "image_id": IMAGE_ID,
        "checks": [{"id": name, "status": "passed"} for name in verifier.REQUIRED_CHECKS],
        "cleanup": [{"container_id": f"{index + 1:064x}", "verified": True,
                     "staging_removed": True} for index in range(18)],
    }


def worker_records(name, operation):
    """Independent canned worker records from the declared fixture layout."""
    if name.startswith("elf"):
        width, machine = (64, "x86_64") if name == "elf64le" else (32, "mips")
        _, layout = elf(width=width, order="<" if width == 64 else ">",
                        machine=62 if width == 64 else 8)
        if operation == "lief.headers":
            return [{"location": {"offset": 0, "length": layout["header_size"]},
                     "value": {"format": "elf", "machine_name": machine, "shnum": 5}}]
        # Null, three declared sections, then the section-name string table.
        values = [(0, 0, False, False)]
        values += [(layout["offsets"][0], 32, False, True),
                   (layout["offsets"][1], 16, True, False),
                   (layout["offsets"][2], 8, True, True)]
        values += [(layout["strtab_offset"], len(b"\0.text\0.data\0.rwx\0.shstrtab\0"), False, False)]
        return [{"location": {"offset": layout["shoff"] + index * layout["entry_size"],
                              "length": layout["entry_size"]},
                 "value": {"index": index, "offset": offset, "size": size,
                           "writable": writable, "executable": executable}}
                for index, (offset, size, writable, executable) in enumerate(values)]
    pe_offset = 0x2000 if name == "pe32plus-distant" else 0x80
    shift = pe_offset - 0x80
    if operation == "lief.headers":
        return [
            {"location": {"offset": 0, "length": 64},
             "value": {"structure": "dos", "e_lfanew": pe_offset}},
            {"location": {"offset": pe_offset, "length": 24},
             "value": {"structure": "coff", "format": "pe", "machine_name": "x86_64",
                       "number_of_sections": 3}},
            {"location": {"offset": pe_offset + 24, "length": 20},
             "value": {"structure": "optional", "optional_magic": "pe32+", "entry_rva": 0x1000}},
        ]
    return [{"location": {"offset": pe_offset + 24 + 240 + 40 * index, "length": 40},
             "value": {"index": index, "offset": 512 * (index + 1) + shift, "size": 512,
                       "writable": index in (1, 2), "executable": index in (0, 2)}}
            for index in range(3)]


def worker_observations(data, records):
    reply = {"protocol": WORKER_PROTOCOL, "status": "ok", "snapshot_sha256": sha256_hex(data),
             "observations": records}
    return parse_worker_reply(json.dumps(reply).encode(), input_sha256=sha256_hex(data), max_observations=64)


class ImageInspectTests(unittest.TestCase):
    def check(self, image=None, lock=None):
        verifier.verify_image(image_fixture() if image is None else image,
                              lock_fixture() if lock is None else lock)

    def test_valid_pinned_image(self):
        self.check()

    def test_image_and_lock_must_be_objects(self):
        for value in (None, [], "image", False):
            with self.subTest(value=value), self.assertRaises(verifier.VerificationError):
                verifier.verify_image(value, lock_fixture())
            with self.subTest(lock=value), self.assertRaises(verifier.VerificationError):
                verifier.verify_image(image_fixture(), value)

    def test_identity_and_platform_changes_fail(self):
        for field, bad in (("Id", "sha256:" + "b" * 64), ("Os", "windows"),
                           ("Architecture", "amd64")):
            for value in (bad, None, False):
                image = image_fixture()
                image[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    self.check(image)
            image = image_fixture()
            del image[field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                self.check(image)

    def test_lock_requires_full_image_id_and_arm64(self):
        for field, values in {"image_id": ("sha256:abc", "sha256:" + "A" * 64, "a" * 64, None),
                              "platform": ("linux/amd64", None, "linux/arm64/v8")}.items():
            for value in values:
                lock = lock_fixture()
                lock[field] = value
                image = image_fixture()
                if field == "image_id":
                    image["Id"] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    self.check(image, lock)
            lock = lock_fixture()
            del lock[field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                self.check(lock=lock)

    def test_config_shape_user_entrypoint_and_environment_fail_closed(self):
        for value in (None, [], "config", False):
            image = image_fixture()
            image["Config"] = value
            with self.subTest(config=value), self.assertRaises(verifier.VerificationError):
                self.check(image)
        for field, values in {
            "User": ("0", "65534", 65534, None),
            "Entrypoint": (["/bin/sh"], "python3 -I -B /opt/reverseai/worker.py", None),
            "Env": (None, {}, "PATH=/bin", ["PATH=/bin", 1]),
        }.items():
            for value in values:
                image = image_fixture()
                image["Config"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    self.check(image)
            image = image_fixture()
            del image["Config"][field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                self.check(image)

    def test_declared_or_malformed_volumes_are_refused(self):
        for value in ({"/data": {}}, [], "", False, 0):
            image = image_fixture()
            image["Config"]["Volumes"] = value
            with self.subTest(value=value), self.assertRaises(verifier.VerificationError):
                self.check(image)
        image = image_fixture()
        del image["Config"]["Volumes"]
        self.check(image)
        image["Config"]["Volumes"] = {}
        self.check(image)


class ContainerInspectTests(unittest.TestCase):
    def check(self, data, **kwargs):
        verifier.verify_container(data, image_fixture(), lock_fixture(), SNAPSHOT, **kwargs)

    def test_valid_container_and_explicit_control_override(self):
        self.check(container_fixture())
        data = container_fixture()
        data["Config"]["Entrypoint"] = ["python3"]
        data["Config"]["Cmd"] = ["-I", "-B", "-c", "fixed probe"]
        self.check(data, entrypoint=["python3"], command=["-I", "-B", "-c", "fixed probe"])

    def test_inspect_shape_missing_or_wrong_sections_refused(self):
        for value in (None, [], "container", False):
            with self.subTest(shape=value), self.assertRaises(verifier.VerificationError):
                self.check(value)
        for field in ("HostConfig", "Config", "State"):
            for value in (None, [], "section", False):
                data = container_fixture()
                data[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    self.check(data)
            data = container_fixture()
            del data[field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                self.check(data)

    def test_image_must_match_pin_and_not_be_running(self):
        for field, value in (("Image", "sha256:" + "b" * 64), ("Image", None)):
            data = container_fixture()
            data[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                self.check(data)
        data = container_fixture()
        del data["Image"]
        with self.assertRaises(verifier.VerificationError):
            self.check(data)
        for value in (True, None, 0, "false"):
            data = container_fixture()
            data["State"]["Running"] = value
            with self.subTest(running=value), self.assertRaises(verifier.VerificationError):
                self.check(data)
        data = container_fixture()
        del data["State"]["Running"]
        with self.assertRaises(verifier.VerificationError):
            self.check(data)

    def test_worker_identity_arguments_and_environment_are_exact(self):
        for field, values in {
            "User": ("0", "65534", 65534),
            "Entrypoint": (["sh"], [], "python3"),
            "Cmd": (["lief.sections", "{}"], ["lief.headers", '{"unexpected":true}'], []),
            "Env": (["PATH=/malicious/bin"], ["PATH=/usr/local/bin:/usr/bin:/bin", "LD_PRELOAD=/tmp/a"], {}),
        }.items():
            for value in (*values, None):
                data = container_fixture()
                data["Config"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    self.check(data)
            data = container_fixture()
            del data["Config"][field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                self.check(data)

    def test_inner_volumes_cannot_hide_image_declared_mounts(self):
        for value in ({"/data": {}}, [], "", False, 0):
            data = container_fixture()
            data["Config"]["Volumes"] = value
            with self.subTest(value=value), self.assertRaises(verifier.VerificationError):
                self.check(data)
        data = container_fixture()
        del data["Config"]["Volumes"]
        self.check(data)
        data["Config"]["Volumes"] = {}
        self.check(data)

    def test_host_security_and_resource_limits_are_present_and_exact(self):
        alternatives = {
            "Privileged": (True, 0), "ReadonlyRootfs": (False, 1),
            "Init": (False, 1), "AutoRemove": (False, 1),
            "NetworkMode": ("host", "bridge", 0),
            "PidsLimit": (-1, 65, 64.0, True),
            "Memory": (0, 536870913, 536870912.0, False),
            "MemorySwap": (-1, 1073741824, 536870912.0, False),
            "NanoCpus": (0, 2000000000, 1000000000.0, False),
        }
        for field, values in alternatives.items():
            for value in (*values, None):
                data = container_fixture()
                data["HostConfig"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    self.check(data)
            data = container_fixture()
            del data["HostConfig"][field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                self.check(data)

    def test_all_capabilities_are_dropped_and_none_added(self):
        for field, values in {
            "CapDrop": ([], ["NET_RAW"], ["ALL", "SYS_ADMIN"], "ALL", None),
            "CapAdd": (["SYS_ADMIN"], "", False, {}, 0),
        }.items():
            for value in values:
                data = container_fixture()
                data["HostConfig"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    self.check(data)
            data = container_fixture()
            del data["HostConfig"][field]
            if field == "CapAdd":
                self.check(data)
            else:
                with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                    self.check(data)

    def test_no_new_privileges_is_required_and_unconfined_is_refused(self):
        data = container_fixture()
        data["HostConfig"]["SecurityOpt"] = ["no-new-privileges:true"]
        self.check(data)
        for value in ([], None, "no-new-privileges", ["seccomp=unconfined"],
                      ["no-new-privileges:false"], ["no-new-privileges", "seccomp=unconfined"]):
            data = container_fixture()
            data["HostConfig"]["SecurityOpt"] = value
            with self.subTest(value=value), self.assertRaises(verifier.VerificationError):
                self.check(data)
        data = container_fixture()
        del data["HostConfig"]["SecurityOpt"]
        with self.assertRaises(verifier.VerificationError):
            self.check(data)

    def test_logging_and_tmpfs_require_the_full_policy(self):
        for field, values in {
            "LogConfig": ({"Type": "json-file"}, {}, {"Type": None}, [], None),
            "Tmpfs": ({}, {"/tmp": "rw,size=64m"},
                      {"/tmp": "rw,noexec,nosuid,nodev,size=128m"},
                      {"/tmp": "rw,noexec,nosuid,nodev,size=64m", "/other": "rw"}, [], None),
        }.items():
            for value in values:
                data = container_fixture()
                data["HostConfig"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    self.check(data)
            data = container_fixture()
            del data["HostConfig"][field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                self.check(data)

    def test_no_extra_host_access_groups_devices_or_published_ports(self):
        dangerous = {
            "Binds": ["/var/run/docker.sock:/var/run/docker.sock"], "VolumesFrom": ["other"],
            "Devices": [{"PathOnHost": "/dev/mem"}], "DeviceRequests": [{"Count": -1}],
            "DeviceCgroupRules": ["a *:* rwm"], "GroupAdd": ["0"],
            "PidMode": "host", "UTSMode": "host", "UsernsMode": "host",
            "PortBindings": {"80/tcp": [{"HostPort": "8080"}]},
            "PublishAllPorts": True, "ExtraHosts": ["host.docker.internal:host-gateway"],
        }
        for field, value in dangerous.items():
            data = container_fixture()
            data["HostConfig"][field] = value
            with self.subTest(field=field), self.assertRaises(verifier.VerificationError):
                self.check(data)

    def test_absent_or_wrong_shape_host_access_fields_fail_closed(self):
        sequence_fields = ("Binds", "VolumesFrom", "Devices", "DeviceRequests",
                           "DeviceCgroupRules", "GroupAdd", "ExtraHosts")
        fields = (*sequence_fields, "PidMode", "UTSMode", "UsernsMode", "PortBindings", "PublishAllPorts")
        for field in fields:
            data = container_fixture()
            del data["HostConfig"][field]
            if field in (*sequence_fields, "PortBindings"):
                self.check(data)
            else:
                with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                    self.check(data)
            if field in sequence_fields:
                for allowed in (None, []):
                    data = container_fixture()
                    data["HostConfig"][field] = allowed
                    self.check(data)
                bad = (False, {}, "", 0)
            elif field == "PortBindings":
                data = container_fixture()
                data["HostConfig"][field] = None
                self.check(data)
                bad = (False, [], "", 0)
            else:
                bad = (None, [], 0)
            for value in bad:
                data = container_fixture()
                data["HostConfig"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    self.check(data)

    def test_ipc_and_cgroup_namespaces_are_private(self):
        for field in ("IpcMode", "CgroupnsMode"):
            for allowed in ("private", ""):
                data = container_fixture()
                data["HostConfig"][field] = allowed
                self.check(data)
            for value in ("host", "container:other", None, False, []):
                data = container_fixture()
                data["HostConfig"][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    self.check(data)
            data = container_fixture()
            del data["HostConfig"][field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                self.check(data)

    def test_exactly_one_read_only_snapshot_mount_from_our_staging_dir(self):
        for value in (None, {}, [], [None], [container_fixture()["Mounts"][0]] * 2):
            data = container_fixture()
            data["Mounts"] = value
            with self.subTest(mounts=value), self.assertRaises(verifier.VerificationError):
                self.check(data)
        for field, values in {
            "Type": ("volume", "tmpfs", None), "Source": ("/var/run/docker.sock", "/other", None),
            "Destination": ("/", "/var/run/docker.sock", None), "RW": (True, 0, "false", None),
        }.items():
            for value in values:
                data = container_fixture()
                data["Mounts"][0][field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    self.check(data)
            data = container_fixture()
            del data["Mounts"][0][field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                self.check(data)
        data = container_fixture()
        del data["Mounts"]
        with self.assertRaises(verifier.VerificationError):
            self.check(data)


class ProbeValidationTests(unittest.TestCase):
    def test_each_required_probe_has_a_valid_canned_result(self):
        self.assertEqual(len(verifier.CONTROL_NAMES), 10)
        for name in verifier.CONTROL_NAMES:
            with self.subTest(name=name):
                verifier.validate_probe(name, probe_fixture(name))

    def test_unknown_protocol_probe_and_non_objects_are_refused(self):
        for value in (None, [], "blocked", False):
            with self.subTest(value=value), self.assertRaises(verifier.VerificationError):
                verifier.validate_probe("network", value)
        for field, values in {"protocol": (None, "reverseai.native-probe/2"),
                              "probe": (None, "write_root")}.items():
            for value in values:
                result = probe_fixture("network")
                result[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    verifier.validate_probe("network", result)
            result = probe_fixture("network")
            del result[field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                verifier.validate_probe("network", result)
        with self.assertRaises(verifier.VerificationError):
            verifier.validate_probe("unknown", probe_fixture("unknown"))

    def test_controls_must_be_attempted_and_blocked_not_truthy(self):
        for name in verifier.CONTROL_NAMES[1:]:
            for field in ("attempted", "blocked"):
                for value in (False, None, 1, "true"):
                    result = probe_fixture(name)
                    result[field] = value
                    with self.subTest(name=name, field=field, value=value), self.assertRaises(verifier.VerificationError):
                        verifier.validate_probe(name, result)
                result = probe_fixture(name)
                del result[field]
                with self.subTest(name=name, missing=field), self.assertRaises(verifier.VerificationError):
                    verifier.validate_probe(name, result)

    def test_skipped_controls_cannot_claim_success(self):
        for name in verifier.CONTROL_NAMES:
            for field, value in (("skipped", True), ("status", "skipped")):
                result = probe_fixture(name)
                result[field] = value
                with self.subTest(name=name, field=field), self.assertRaises(verifier.VerificationError):
                    verifier.validate_probe(name, result)

    def test_runtime_identity_includes_every_kernel_security_field(self):
        for field in ("uid", "gid", "cap_eff", "cap_prm", "cap_inh", "cap_amb", "no_new_privs", "seccomp"):
            original = probe_fixture("runtime_identity")[field]
            for value in (original + 1, float(original), bool(original), str(original), None):
                result = probe_fixture("runtime_identity")
                result[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    verifier.validate_probe("runtime_identity", result)
            result = probe_fixture("runtime_identity")
            del result[field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                verifier.validate_probe("runtime_identity", result)

    def test_os_controls_require_an_expected_failure_errno(self):
        allowed = {"network": (1, 13, 101, 113), "write_root": (1, 13, 30),
                   "write_snapshot": (1, 13, 30), "setuid": (1, 13), "capability": (1, 13)}
        for name, accepted in allowed.items():
            for errno in accepted:
                result = probe_fixture(name)
                result["errno"] = errno
                verifier.validate_probe(name, result)
            for errno in (0, 2, 11, True, "1", 1.0, None):
                result = probe_fixture(name)
                result["errno"] = errno
                with self.subTest(name=name, errno=errno), self.assertRaises(verifier.VerificationError):
                    verifier.validate_probe(name, result)
            result = probe_fixture(name)
            del result["errno"]
            with self.subTest(name=name, missing="errno"), self.assertRaises(verifier.VerificationError):
                verifier.validate_probe(name, result)

    def test_pids_requires_eagain_after_some_children_under_the_actual_limit(self):
        for spawned in (1, 63):
            result = probe_fixture("pids")
            result["spawned"] = spawned
            verifier.validate_probe("pids", result)
        for field, values in {
            "errno": (1, 12, 11.0, True, None), "limit": (0, 65, 64.0, True, None),
            "spawned": (0, 64, -1, 1.0, True, None),
        }.items():
            for value in values:
                result = probe_fixture("pids")
                result[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    verifier.validate_probe("pids", result)
            result = probe_fixture("pids")
            del result[field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                verifier.validate_probe("pids", result)

    def test_memory_requires_a_real_oom_event_and_sigkill_child(self):
        for field, values in {
            "limit": (0, 536870913, 536870912.0, None),
            "child_returncode": (0, 1, 9, -15, -9.0, None),
            "oom_kill_delta": (0, -1, True, 1.0, "1", None),
        }.items():
            for value in values:
                result = probe_fixture("memory")
                result[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    verifier.validate_probe("memory", result)
            result = probe_fixture("memory")
            del result[field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                verifier.validate_probe("memory", result)

    def test_wall_requires_running_container_actual_elapsed_time_and_production_reason(self):
        for elapsed in (44.5, 45, 50):
            result = probe_fixture("wall")
            result["elapsed"] = elapsed
            verifier.validate_probe("wall", result)
        for field, values in {
            "error": ("Timeout", "TimeoutExpired", "WorkerError", None),
            "running_observed": (False, 1, None), "timeout": (44, 46, 45.0, None),
            "elapsed": (0, 44.49, 50.01, True, "45", float("nan"), float("inf"), None),
        }.items():
            for value in values:
                result = probe_fixture("wall")
                result[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    verifier.validate_probe("wall", result)
            result = probe_fixture("wall")
            del result[field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                verifier.validate_probe("wall", result)

    def test_stdout_requires_actual_reply_cap_and_production_reason(self):
        self.assertEqual(MAX_WORKER_REPLY_BYTES, 262144)
        for field, values in {
            "error": ("OutputLimit", "WorkerTimeout", "WorkerError", None),
            "max_output": (0, 262143, 262145, 262144.0, True, None),
        }.items():
            for value in values:
                result = probe_fixture("stdout")
                result[field] = value
                with self.subTest(field=field, value=value), self.assertRaises(verifier.VerificationError):
                    verifier.validate_probe("stdout", result)
            result = probe_fixture("stdout")
            del result[field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                verifier.validate_probe("stdout", result)


class KnownAnswerTests(unittest.TestCase):
    def setUp(self):
        self.data = verifier.fixtures()

    def compare(self, name, operation, records):
        data = self.data[name]
        verifier.compare_observations(data, operation, worker_observations(data, records))

    def test_all_four_generated_inputs_have_declared_formats_and_layouts(self):
        self.assertEqual(set(self.data), {"elf64le", "elf32be", "pe32plus", "pe32plus-distant"})
        self.assertEqual(self.data["elf64le"], elf()[0])
        self.assertEqual(self.data["elf32be"], elf(width=32, order=">", machine=8)[0])
        self.assertEqual(self.data["pe32plus"], pe()[0])
        distant = self.data["pe32plus-distant"]
        self.assertEqual(struct.unpack_from("<I", distant, 0x3C)[0], 0x2000)
        self.assertEqual(distant[0x2000:0x2004], b"PE\0\0")
        shift = 0x2000 - 0x80
        for index, raw in enumerate((512, 1024, 1536)):
            pointer = struct.unpack_from("<I", distant, 0x2000 + 24 + 240 + index * 40 + 20)[0]
            self.assertEqual(pointer, raw + shift)
            self.assertLessEqual(pointer + 512, len(distant))

    def test_synthetic_worker_replies_match_m1_for_every_fixture_and_operation(self):
        for name in self.data:
            for operation in ("lief.headers", "lief.sections"):
                with self.subTest(name=name, operation=operation):
                    self.compare(name, operation, worker_records(name, operation))

    def test_unknown_operations_and_wrong_observation_collections_are_refused(self):
        for operation, observations in (("structure.headers", []), ("lief.headers", None),
                                        ("lief.sections", {}), ("lief.headers", "headers")):
            with self.subTest(operation=operation, observations=observations), self.assertRaises(verifier.VerificationError):
                verifier.compare_observations(self.data["elf64le"], operation, observations)

    def test_malformed_observation_items_are_refused_with_a_static_verdict(self):
        for value in (None, [], {}, {"location": {"offset": 0, "length": 64}, "value": {}}, "observation"):
            with self.subTest(value=value), self.assertRaises(verifier.VerificationError):
                verifier.compare_observations(self.data["elf64le"], "lief.headers", [value])

    def test_header_values_missing_wrong_duplicated_and_wrong_types_fail(self):
        for name in self.data:
            fields = ("format", "machine_name", "shnum" if name.startswith("elf") else "number_of_sections")
            index = 0 if name.startswith("elf") else 1
            for field in fields:
                for mutation in ("missing", "wrong", "wrong_type", "duplicate"):
                    records = worker_records(name, "lief.headers")
                    value = records[index]["value"][field]
                    if mutation == "missing":
                        del records[index]["value"][field]
                    elif mutation == "wrong":
                        records[index]["value"][field] = value + 1 if type(value) is int else "incorrect"
                    elif mutation == "wrong_type":
                        records[index]["value"][field] = str(value) if type(value) is int else 1
                    else:
                        records.append(copy.deepcopy(records[index]))
                    with self.subTest(name=name, field=field, mutation=mutation), self.assertRaises(verifier.VerificationError):
                        self.compare(name, "lief.headers", records)

    def test_all_header_and_section_ranges_must_be_inside_the_frozen_input(self):
        for name, data in self.data.items():
            for operation in ("lief.headers", "lief.sections"):
                records = worker_records(name, operation)
                records[0]["location"] = {"offset": len(data), "length": 1}
                with self.subTest(name=name, operation=operation), self.assertRaises(verifier.VerificationError):
                    self.compare(name, operation, records)

    def test_elf_headers_must_cite_the_physical_header_only(self):
        for name in ("elf64le", "elf32be"):
            for field, delta in (("offset", 1), ("length", -1), ("length", 1)):
                records = worker_records(name, "lief.headers")
                records[0]["location"][field] += delta
                with self.subTest(name=name, field=field, delta=delta), self.assertRaises(verifier.VerificationError):
                    self.compare(name, "lief.headers", records)
            records = worker_records(name, "lief.headers")
            records.append({"location": {"offset": 0, "length": 4}, "value": {"extra": True}})
            with self.subTest(name=name, extra=True), self.assertRaises(verifier.VerificationError):
                self.compare(name, "lief.headers", records)

    def test_pe_headers_require_separate_dos_coff_and_optional_physical_parts(self):
        for name in ("pe32plus", "pe32plus-distant"):
            for index in range(3):
                records = worker_records(name, "lief.headers")
                del records[index]
                with self.subTest(name=name, missing=index), self.assertRaises(verifier.VerificationError):
                    self.compare(name, "lief.headers", records)
            for index, field, value in (
                (0, "structure", "coff"), (0, "e_lfanew", 1), (1, "structure", "optional"),
                (2, "structure", "dos"),
            ):
                records = worker_records(name, "lief.headers")
                records[index]["value"][field] = value
                with self.subTest(name=name, index=index, field=field), self.assertRaises(verifier.VerificationError):
                    self.compare(name, "lief.headers", records)
            for index, field, value in ((0, "offset", 1), (0, "length", 63),
                                         (1, "offset", 0), (1, "length", 23),
                                         (2, "offset", 0), (2, "length", 19), (2, "length", 241)):
                records = worker_records(name, "lief.headers")
                records[index]["location"][field] = value
                with self.subTest(name=name, index=index, field=field, value=value), self.assertRaises(verifier.VerificationError):
                    self.compare(name, "lief.headers", records)
            # The complete 240-byte optional header is also an admissible physical range.
            records = worker_records(name, "lief.headers")
            records[2]["location"]["length"] = 240
            self.compare(name, "lief.headers", records)

    def test_pe_cannot_hide_coff_facts_in_another_record(self):
        for name in ("pe32plus", "pe32plus-distant"):
            for field in ("format", "machine_name", "number_of_sections"):
                records = worker_records(name, "lief.headers")
                records[0]["value"][field] = records[1]["value"].pop(field)
                with self.subTest(name=name, field=field), self.assertRaises(verifier.VerificationError):
                    self.compare(name, "lief.headers", records)

    def test_section_facts_types_and_physical_ranges_must_agree_with_m1(self):
        for name in self.data:
            for field in ("index", "offset", "size", "writable", "executable"):
                for mutation in ("missing", "wrong", "wrong_type"):
                    records = worker_records(name, "lief.sections")
                    value = records[0]["value"][field]
                    if mutation == "missing":
                        del records[0]["value"][field]
                    elif mutation == "wrong":
                        records[0]["value"][field] = not value if type(value) is bool else value + 1
                    else:
                        records[0]["value"][field] = int(value) if type(value) is bool else bool(value)
                    with self.subTest(name=name, field=field, mutation=mutation), self.assertRaises(verifier.VerificationError):
                        self.compare(name, "lief.sections", records)
            for field in ("offset", "length"):
                records = worker_records(name, "lief.sections")
                records[0]["location"][field] += 1
                with self.subTest(name=name, location=field), self.assertRaises(verifier.VerificationError):
                    self.compare(name, "lief.sections", records)

    def test_sections_cannot_be_missing_extra_duplicated_or_reordered(self):
        for name in self.data:
            for mutation in ("missing", "extra", "duplicate", "reordered"):
                records = worker_records(name, "lief.sections")
                if mutation == "missing":
                    records.pop()
                elif mutation == "extra":
                    records.append(copy.deepcopy(records[-1]))
                elif mutation == "duplicate":
                    records[1] = copy.deepcopy(records[0])
                else:
                    records[0], records[1] = records[1], records[0]
                with self.subTest(name=name, mutation=mutation), self.assertRaises(verifier.VerificationError):
                    self.compare(name, "lief.sections", records)


class ReceiptTests(unittest.TestCase):
    def test_complete_receipt_has_21_required_checks_and_18_unique_cleanups(self):
        receipt = receipt_fixture()
        self.assertEqual(len(verifier.REQUIRED_CHECKS), 21)
        self.assertEqual(verifier.NATIVE_RUNS, 18)
        self.assertEqual(len(receipt["cleanup"]), 18)
        self.assertTrue(verifier.receipt_passes(receipt))

    def test_missing_top_level_fields_and_wrong_shapes_are_refused(self):
        for field in receipt_fixture():
            receipt = receipt_fixture()
            del receipt[field]
            with self.subTest(missing=field):
                self.assertFalse(verifier.receipt_passes(receipt))
        for value in (None, [], False, "receipt", 1):
            with self.subTest(value=value):
                self.assertFalse(verifier.receipt_passes(value))
        for field in ("checks", "cleanup", "lock"):
            for value in (None, [], {}, False, "invalid"):
                receipt = receipt_fixture()
                receipt[field] = value
                with self.subTest(field=field, value=value):
                    self.assertFalse(verifier.receipt_passes(receipt))

    def test_receipt_identity_and_offline_are_exact(self):
        for field, values in {
            "schema": ("reverseai.m2-runtime/2", None), "platform": ("linux/amd64", None),
            "tool": ("structure", None), "profile": ("large", None),
            "offline": (False, 1, "true", None),
        }.items():
            for value in values:
                receipt = receipt_fixture()
                receipt[field] = value
                with self.subTest(field=field, value=value):
                    self.assertFalse(verifier.receipt_passes(receipt))

    def test_all_three_bindings_must_be_full_lowercase_sha256(self):
        for field in ("lock_sha256", "verifier_sha256", "executor_sha256"):
            for value in ("", "a" * 63, "a" * 65, "A" * 64, "g" * 64, None, [], 7, True):
                receipt = receipt_fixture()
                receipt[field] = value
                with self.subTest(field=field, value=value):
                    self.assertFalse(verifier.receipt_passes(receipt))

    def test_locked_platform_and_image_identity_are_required(self):
        for field in ("platform", "image_id"):
            receipt = receipt_fixture()
            del receipt["lock"][field]
            with self.subTest(missing=field):
                self.assertFalse(verifier.receipt_passes(receipt))
        for field, value in (("platform", "linux/amd64"), ("image_id", "sha256:" + "b" * 64)):
            receipt = receipt_fixture()
            receipt["lock"][field] = value
            with self.subTest(field=field):
                self.assertFalse(verifier.receipt_passes(receipt))
        for value in ("sha256:bad", "sha256:" + "A" * 64, "a" * 64, None, 1):
            receipt = receipt_fixture()
            receipt["image_id"] = receipt["lock"]["image_id"] = value
            with self.subTest(image_id=value):
                self.assertFalse(verifier.receipt_passes(receipt))

    def test_receipt_requires_base_wheel_and_adapter_pins(self):
        for field, values in {
            "base_digest": ("", "sha256:bad", "sha256:" + "A" * 64, "b" * 64, None, []),
            "wheel_sha256": ("", "c" * 63, "C" * 64, "sha256:" + "c" * 64, None, []),
            "adapter_version": ("", "1.0.0", "1.0.0-r1", None, []),
        }.items():
            for value in values:
                receipt = receipt_fixture()
                receipt["lock"][field] = value
                with self.subTest(field=field, value=value):
                    self.assertFalse(verifier.receipt_passes(receipt))
            receipt = receipt_fixture()
            del receipt["lock"][field]
            with self.subTest(missing=field):
                self.assertFalse(verifier.receipt_passes(receipt))

    def test_every_mandatory_check_must_be_present_once_and_passed(self):
        for index, name in enumerate(verifier.REQUIRED_CHECKS):
            for mutation in ("missing", "duplicate", "skipped", "false", "failed", "status_missing", "id_missing"):
                receipt = receipt_fixture()
                if mutation == "missing":
                    receipt["checks"].pop(index)
                elif mutation == "duplicate":
                    receipt["checks"][index] = copy.deepcopy(receipt["checks"][(index + 1) % len(receipt["checks"])])
                elif mutation == "status_missing":
                    del receipt["checks"][index]["status"]
                elif mutation == "id_missing":
                    del receipt["checks"][index]["id"]
                else:
                    receipt["checks"][index]["status"] = False if mutation == "false" else mutation
                with self.subTest(check=name, mutation=mutation):
                    self.assertFalse(verifier.receipt_passes(receipt))
        receipt = receipt_fixture()
        receipt["checks"].append({"id": "unexpected", "status": "passed"})
        self.assertFalse(verifier.receipt_passes(receipt))

    def test_malformed_check_rows_are_refused(self):
        for value in (None, [], "passed", False, {"id": []}, {"id": {}, "status": "passed"}):
            receipt = receipt_fixture()
            receipt["checks"][0] = value
            with self.subTest(value=value):
                self.assertFalse(verifier.receipt_passes(receipt))

    def test_cleanup_requires_exactly_18_distinct_verified_containers_and_removed_staging(self):
        for mutation in ("missing", "extra", "duplicate"):
            receipt = receipt_fixture()
            if mutation == "missing":
                receipt["cleanup"].pop()
            elif mutation == "extra":
                receipt["cleanup"].append({"container_id": "f" * 64, "verified": True, "staging_removed": True})
            else:
                receipt["cleanup"][1] = copy.deepcopy(receipt["cleanup"][0])
            with self.subTest(mutation=mutation):
                self.assertFalse(verifier.receipt_passes(receipt))
        for index in range(18):
            for field in ("verified", "staging_removed"):
                for value in (False, None, 1, "true"):
                    receipt = receipt_fixture()
                    receipt["cleanup"][index][field] = value
                    with self.subTest(index=index, field=field, value=value):
                        self.assertFalse(verifier.receipt_passes(receipt))
                receipt = receipt_fixture()
                del receipt["cleanup"][index][field]
                with self.subTest(index=index, missing=field):
                    self.assertFalse(verifier.receipt_passes(receipt))

    def test_malformed_cleanup_ids_rows_and_missing_ids_are_refused(self):
        for value in ("", "a" * 63, "a" * 65, "A" * 64, "g" * 64, "sha256:" + "a" * 64, None, [], 4):
            receipt = receipt_fixture()
            receipt["cleanup"][0]["container_id"] = value
            with self.subTest(container_id=value):
                self.assertFalse(verifier.receipt_passes(receipt))
        for value in (None, [], False, "cleanup", {}):
            receipt = receipt_fixture()
            receipt["cleanup"][0] = value
            with self.subTest(row=value):
                self.assertFalse(verifier.receipt_passes(receipt))
        receipt = receipt_fixture()
        del receipt["cleanup"][0]["container_id"]
        self.assertFalse(verifier.receipt_passes(receipt))


class FakeBoundary:
    """An in-memory executor seam; its command allowlist never invokes a process."""

    CID = "d" * 64

    class ContainedError(RuntimeError):
        pass

    class ContainedTimeout(ContainedError):
        pass

    def __init__(self):
        self.calls = []
        self.inspect = container_fixture()
        self.inspect["Id"] = self.CID
        self.created_id = self.CID.encode() + b"\n"
        self.output = b"canned worker reply"
        self.start_error = None
        self.remove_error = None
        self.ps_error = None
        self.present_after_cleanup = False
        self.running_observed = threading.Event()
        self.wait_for_running = False

    @staticmethod
    def build_argv(image_id, name, snapshot, operation, args):
        return [
            "docker", "run", "--rm", "--init", "--name", name,
            "--platform", "linux/arm64", "--network", "none", "--read-only",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65534:65534", "--pids-limit", "64", "--memory", "512m",
            "--memory-swap", "512m", "--cpus", "1", "--tmpfs",
            "/tmp:rw,noexec,nosuid,nodev,size=64m", "--log-driver", "none",
            "--mount", f"type=bind,source={snapshot},target=/snapshot,readonly",
            image_id, operation, json.dumps(args, sort_keys=True, separators=(",", ":")),
        ]

    def run_bounded(self, argv, *, timeout, max_output):
        self.calls.append((list(argv), timeout, max_output))
        if argv[:2] == ["docker", "create"]:
            index = argv.index(IMAGE_ID)
            self.inspect["Config"]["Cmd"] = argv[index + 1:]
            if "--entrypoint" in argv[:index]:
                self.inspect["Config"]["Entrypoint"] = [argv[argv.index("--entrypoint") + 1]]
            return self.created_id
        if argv == ["docker", "inspect", self.CID]:
            return json.dumps([self.inspect]).encode()
        if argv == ["docker", "inspect", "--format", "{{.State.Running}}", self.CID]:
            self.running_observed.set()
            return b"true\n"
        if argv == ["docker", "start", "--attach", self.CID]:
            if self.wait_for_running and not self.running_observed.wait(timeout=1):
                raise AssertionError("fake wall watcher did not run")
            if self.start_error is not None:
                raise self.start_error
            return self.output
        if argv == ["docker", "rm", "--force", self.CID]:
            if self.remove_error is not None:
                raise self.remove_error
            return b""
        if argv == ["docker", "ps", "--all", "--no-trunc", "--filter", "id=" + self.CID,
                    "--format", "{{.ID}}"]:
            if self.ps_error is not None:
                raise self.ps_error
            return self.CID.encode() + b"\n" if self.present_after_cleanup else b""
        if argv == ["docker", "version"]:
            return b"delegated metadata"
        raise AssertionError("command outside the fake boundary allowlist")


class ControlArgvTests(unittest.TestCase):
    def setUp(self):
        self.argv = FakeBoundary.build_argv(IMAGE_ID, "reverseai-unit-owned", str(SNAPSHOT), "lief.headers", {})

    def test_worker_create_retains_all_flags_arguments_and_source_argv(self):
        original = list(self.argv)
        result = verifier.derive_control_argv(self.argv, IMAGE_ID)
        self.assertEqual(result, ["docker", "create", *original[2:]])
        self.assertEqual(self.argv, original)
        self.assertIsNot(result, self.argv)

    def test_control_changes_only_lifecycle_entrypoint_and_fixed_worker_tail(self):
        code = verifier.probe_code("write_snapshot")
        at = self.argv.index(IMAGE_ID)
        result = verifier.derive_control_argv(self.argv, IMAGE_ID, code)
        self.assertEqual(result[:2], ["docker", "create"])
        self.assertEqual(result[2:at], self.argv[2:at])
        self.assertEqual(result[at:], ["--entrypoint", "python3", IMAGE_ID, "-I", "-B", "-c", code])
        self.assertIn("--init", result[:at])
        self.assertEqual(self.argv[-2:], ["lief.headers", "{}"])

    def test_non_run_commands_and_missing_or_duplicate_image_are_refused(self):
        malformed = (None, [], "docker run", tuple(self.argv), ["docker", "start", IMAGE_ID],
                     ["podman", "run", IMAGE_ID], ["docker", "run", "other-image"],
                     [*self.argv, IMAGE_ID])
        for argv in malformed:
            with self.subTest(argv=argv), self.assertRaises(verifier.VerificationError):
                verifier.derive_control_argv(argv, IMAGE_ID)

    def test_non_string_argv_members_and_control_source_are_refused(self):
        for argv in ([*self.argv[:2], None, *self.argv[2:]],
                     [*self.argv[:2], 0, *self.argv[2:]]):
            with self.subTest(argv=argv), self.assertRaises(verifier.VerificationError):
                verifier.derive_control_argv(argv, IMAGE_ID)
        for code in (False, 7, [], {}):
            with self.subTest(code=code), self.assertRaises(verifier.VerificationError):
                verifier.derive_control_argv(self.argv, IMAGE_ID, code)


class TrustedProbeSourceTests(unittest.TestCase):
    def test_every_fixed_probe_compiles_without_running_it(self):
        for name in verifier.CONTROL_NAMES:
            with self.subTest(name=name):
                source = verifier.probe_code(name)
                self.assertIsInstance(source, str)
                self.assertTrue(source.strip())
                # Deliberately compile only. These probes must never run on the host.
                compile(source, f"<fixed-probe-{name}>", "exec")

    def test_only_the_closed_probe_name_set_can_select_source(self):
        for name in ("", "unknown", "../../sample", "network;import os", None):
            with self.subTest(name=name), self.assertRaises(verifier.VerificationError):
                verifier.probe_code(name)


class ReceiptFileAndDecodeTests(unittest.TestCase):
    def test_new_receipt_is_private_complete_json(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "receipt.json"
            verifier.write_receipt(path, receipt_fixture())
            self.assertEqual(json.loads(path.read_text()), receipt_fixture())
            self.assertTrue(path.read_bytes().endswith(b"\n"))
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)

    def test_existing_receipt_is_refused_without_overwriting(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "receipt.json"
            path.write_bytes(b"original receipt")
            with self.assertRaises(FileExistsError):
                verifier.write_receipt(path, receipt_fixture())
            self.assertEqual(path.read_bytes(), b"original receipt")

    def test_existing_and_broken_symlinks_are_refused_without_touching_targets(self):
        with tempfile.TemporaryDirectory() as folder:
            target = Path(folder) / "target.json"
            target.write_bytes(b"owned target")
            for target_path in (target, Path(folder) / "missing.json"):
                path = Path(folder) / (target_path.stem + "-link.json")
                path.symlink_to(target_path)
                with self.subTest(target=target_path), self.assertRaises(OSError):
                    verifier.write_receipt(path, receipt_fixture())
                self.assertTrue(path.is_symlink())
            self.assertEqual(target.read_bytes(), b"owned target")
            self.assertFalse((Path(folder) / "missing.json").exists())

    def test_receipt_writer_refuses_nonfinite_numbers(self):
        for value in (float("nan"), float("inf"), -float("inf")):
            with tempfile.TemporaryDirectory() as folder:
                with self.subTest(value=value), self.assertRaises(ValueError):
                    verifier.write_receipt(Path(folder) / "receipt.json", {"invalid": value})

    def test_json_decoder_accepts_valid_json_and_rejects_ambiguous_or_nonfinite_input(self):
        self.assertEqual(verifier.decode(b'{"a":[1,true,null],"b":{"x":"value"}}'),
                         {"a": [1, True, None], "b": {"x": "value"}})
        for raw in (b'{"id":1,"id":2}', b'{"nested":{"x":1,"x":1}}',
                    b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}',
                    b'{"truncated":', b'{} {}', b'\xff', None):
            with self.subTest(raw=raw), self.assertRaises(verifier.VerificationError):
                verifier.decode(raw)


class NativeRunnerBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.boundary = FakeBoundary()
        self.receipt = {"checks": [], "cleanup": []}
        self.native = verifier.NativeVerifier(self.boundary, lock_fixture(), self.receipt)
        self.native.image = image_fixture()
        self.argv = self.boundary.build_argv(IMAGE_ID, "reverseai-unit-owned", str(SNAPSHOT), "lief.headers", {})

    def run_worker(self):
        return self.native.runner(self.argv, timeout=45, max_output=262144)

    def commands(self):
        return [row[0] for row in self.boundary.calls]

    def assert_owned_cleanup(self):
        self.assertEqual(self.commands()[-2:], [
            ["docker", "rm", "--force", FakeBoundary.CID],
            ["docker", "ps", "--all", "--no-trunc", "--filter", "id=" + FakeBoundary.CID,
             "--format", "{{.ID}}"],
        ])
        self.assertEqual(self.receipt["cleanup"][0]["container_id"], FakeBoundary.CID)

    def test_create_inspect_start_cleanup_order_and_limits_use_only_the_created_id(self):
        self.assertEqual(self.run_worker(), b"canned worker reply")
        commands = self.commands()
        self.assertEqual([argv[:2] for argv in commands], [
            ["docker", "create"], ["docker", "inspect"], ["docker", "start"],
            ["docker", "rm"], ["docker", "ps"],
        ])
        self.assertEqual(commands[0][commands[0].index("--name") + 1], "reverseai-unit-owned")
        self.assertEqual(commands[1], ["docker", "inspect", FakeBoundary.CID])
        self.assertEqual(commands[2], ["docker", "start", "--attach", FakeBoundary.CID])
        self.assertEqual(self.boundary.calls[2][1:], (45, 262144))
        self.assertEqual(self.native.inspected, 1)
        self.assertEqual(self.receipt["cleanup"], [{"container_id": FakeBoundary.CID,
                         "verified": True, "staging_removed": False}])
        self.assert_owned_cleanup()

    def test_unsafe_inspect_prevents_start_and_still_cleans_the_exact_created_container(self):
        for field, value in (("Privileged", True), ("ReadonlyRootfs", False), ("Init", False),
                             ("NetworkMode", "host"), ("Memory", 0), ("CapAdd", ["SYS_ADMIN"])):
            self.setUp()
            self.boundary.inspect["HostConfig"][field] = value
            with self.subTest(field=field), self.assertRaises(verifier.VerificationError):
                self.run_worker()
            self.assertFalse(any(argv[:2] == ["docker", "start"] for argv in self.commands()))
            self.assertEqual(self.native.inspected, 0)
            self.assert_owned_cleanup()
            self.assertTrue(self.receipt["cleanup"][0]["verified"])

    def test_inspect_id_mismatch_is_refused_and_cleans_the_created_id(self):
        self.boundary.inspect["Id"] = "e" * 64
        with self.assertRaises(verifier.VerificationError):
            self.run_worker()
        self.assertFalse(any(argv[:2] == ["docker", "start"] for argv in self.commands()))
        self.assert_owned_cleanup()

    def test_missing_inspect_id_is_refused_and_cleans_the_created_id(self):
        del self.boundary.inspect["Id"]
        with self.assertRaises(verifier.VerificationError):
            self.run_worker()
        self.assertFalse(any(argv[:2] == ["docker", "start"] for argv in self.commands()))
        self.assert_owned_cleanup()

    def test_changed_executor_limits_are_refused_before_creation(self):
        for timeout, max_output in ((44, 262144), (45, 262143), (45, 262145)):
            with self.subTest(timeout=timeout, max_output=max_output), self.assertRaises(verifier.VerificationError):
                self.native.runner(self.argv, timeout=timeout, max_output=max_output)
        self.assertEqual(self.boundary.calls, [])
        self.assertEqual(self.receipt["cleanup"], [])

    def test_builder_mismatch_is_refused_before_creation(self):
        self.argv[self.argv.index("--memory") + 1] = "1g"
        with self.assertRaises(verifier.VerificationError):
            self.run_worker()
        self.assertEqual(self.boundary.calls, [])
        self.assertEqual(self.receipt["cleanup"], [])

    def test_bad_created_id_never_starts_or_cleans_an_unowned_name(self):
        for value in (b"name\n", b"d" * 63, b"D" * 64, b"../container", b""):
            self.setUp()
            self.boundary.created_id = value
            with self.subTest(value=value), self.assertRaises(verifier.VerificationError):
                self.run_worker()
            self.assertEqual(len(self.boundary.calls), 1)
            self.assertEqual(self.receipt["cleanup"], [])

    def test_correct_output_limit_error_is_recorded_as_the_stdout_control(self):
        self.native.active = "stdout"
        self.boundary.start_error = self.boundary.ContainedError("WorkerOutputLimit")
        result = verifier.decode(self.run_worker())
        verifier.validate_probe("stdout", result)
        self.assertEqual(result["error"], "WorkerOutputLimit")
        self.assertEqual(result["max_output"], 262144)
        self.assert_owned_cleanup()

    def test_wrong_output_error_or_wrong_control_cannot_claim_a_pass(self):
        for active, reason in (("stdout", "OutputLimit"), ("stdout", "WorkerError"),
                               (None, "WorkerOutputLimit"), ("network", "WorkerOutputLimit")):
            self.setUp()
            self.native.active = active
            self.boundary.start_error = self.boundary.ContainedError(reason)
            with self.subTest(active=active, reason=reason), self.assertRaises(verifier.VerificationError):
                self.run_worker()
            self.assert_owned_cleanup()

    def test_correct_wall_error_requires_observed_running_and_real_elapsed_time(self):
        self.native.active = "wall"
        self.boundary.wait_for_running = True
        self.boundary.start_error = self.boundary.ContainedTimeout("WorkerTimeout")
        with mock.patch.object(verifier.time, "monotonic", side_effect=(100.0, 145.1)):
            result = verifier.decode(self.run_worker())
        verifier.validate_probe("wall", result)
        self.assertTrue(result["running_observed"])
        self.assertAlmostEqual(result["elapsed"], 45.1)
        self.assert_owned_cleanup()

    def test_wrong_timeout_error_or_wrong_control_is_refused(self):
        for active, reason in (("wall", "TimeoutExpired"), (None, "WorkerTimeout"),
                               ("stdout", "WorkerTimeout")):
            self.setUp()
            self.native.active = active
            self.boundary.start_error = self.boundary.ContainedTimeout(reason)
            with self.subTest(active=active, reason=reason), self.assertRaises(verifier.VerificationError):
                self.run_worker()
            self.assert_owned_cleanup()

    def test_cleanup_failure_overrides_successful_output(self):
        self.boundary.present_after_cleanup = True
        with self.assertRaises(verifier.VerificationError):
            self.run_worker()
        self.assert_owned_cleanup()
        self.assertFalse(self.receipt["cleanup"][0]["verified"])

    def test_cleanup_failure_is_recorded_as_a_failed_check(self):
        self.boundary.present_after_cleanup = True
        self.assertFalse(self.native.record("stdout", self.run_worker))
        self.assertEqual(self.receipt["checks"][0]["status"], "failed")
        self.assertEqual(self.receipt["checks"][0]["reason"], "ContainerCleanupUnverified")
        self.assertFalse(verifier.receipt_passes(self.receipt))

    def test_remove_error_is_tolerated_only_when_absence_is_proved(self):
        self.boundary.remove_error = self.boundary.ContainedError("already removed")
        self.assertEqual(self.run_worker(), b"canned worker reply")
        self.assertTrue(self.receipt["cleanup"][0]["verified"])
        self.assert_owned_cleanup()

    def test_ps_failure_cannot_prove_cleanup(self):
        self.boundary.ps_error = self.boundary.ContainedError("ps refused")
        with self.assertRaises(verifier.VerificationError):
            self.run_worker()
        self.assertFalse(self.receipt["cleanup"][0]["verified"])
        self.assert_owned_cleanup()

    def test_metadata_command_is_delegated_without_container_lifecycle(self):
        output = self.native.runner(["docker", "version"], timeout=5, max_output=64)
        self.assertEqual(output, b"delegated metadata")
        self.assertEqual(self.boundary.calls, [(["docker", "version"], 5, 64)])
        self.assertEqual(self.receipt["cleanup"], [])


class MainFailureReceiptTests(unittest.TestCase):
    def test_incompatible_fake_executor_writes_a_failed_receipt_with_all_unrun_checks(self):
        fake_executor = SimpleNamespace(WALL_SECONDS=44)
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "receipt.json"
            with mock.patch.object(reverseai, "contained", fake_executor, create=True), \
                    mock.patch.object(verifier.sys, "stderr", new=io.StringIO()):
                result = verifier.main(["--tool", "lief", "--profile", "small", "--offline",
                                        "--lock", str(Path(folder) / "unused-lock.json"),
                                        "--receipt", str(output)])
            receipt = json.loads(output.read_bytes())
        self.assertEqual(result, 1)
        self.assertFalse(receipt["passed"])
        self.assertEqual(receipt["cleanup"], [])
        self.assertEqual(receipt["checks"][0], {"id": "controller", "status": "failed",
                                              "reason": "ExecutorWallLimit"})
        not_run = {row["id"] for row in receipt["checks"] if row["status"] == "not_run"}
        self.assertEqual(not_run, set(verifier.REQUIRED_CHECKS))


if __name__ == "__main__":
    unittest.main()
