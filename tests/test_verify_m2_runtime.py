"""Canned validator checks only: this suite supplies no native containment proof."""

from __future__ import annotations

import copy
import csv
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
        self.create_error = None
        self.lookup_output = self.created_id
        self.lookup_error = None
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
            "docker", "run", "--rm", "--init", "--pull", "never", "--name", name,
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
            self.inspect["Name"] = "/" + argv[argv.index("--name") + 1]
            mount = next(csv.reader([argv[argv.index("--mount") + 1]]))
            self.inspect["Mounts"][0]["Source"] = next(v.removeprefix("source=") for v in mount if v.startswith("source="))
            self.inspect["Config"]["Cmd"] = argv[index + 1:]
            if "--entrypoint" in argv[:index]:
                self.inspect["Config"]["Entrypoint"] = [argv[argv.index("--entrypoint") + 1]]
            if self.create_error is not None:
                raise self.create_error
            return self.created_id
        if argv == ["docker", "ps", "--all", "--no-trunc", "--filter", "name=^" + self.inspect.get("Name", "") + "$",
                    "--format", "{{.ID}}"]:
            if self.lookup_error is not None:
                raise self.lookup_error
            return self.lookup_output
        if argv == ["docker", "kill", self.inspect.get("Name", "").removeprefix("/")]:
            return b""
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

    def test_pull_policy_must_be_one_explicit_never_before_the_image(self):
        at = self.argv.index("--pull")
        missing = self.argv[:at] + self.argv[at + 2:]
        malformed = [missing, missing + ["--pull", "never"],
                     [*missing[:2], "--pull=never", *missing[2:]],
                     [*self.argv[:2], "--pull", "always", *self.argv[2:]],
                     [*self.argv[:2], "--pull=always", *self.argv[2:]]]
        image = self.argv.index(IMAGE_ID)
        malformed.extend([*self.argv[:image], "--pull", policy, *self.argv[image:]]
                         for policy in ("always", "never"))
        for policy in ("missing", "always"):
            changed = list(self.argv)
            changed[at + 1] = policy
            malformed.append(changed)
        for argv in malformed:
            for code in (None, verifier.probe_code("network")):
                with self.subTest(argv=argv, control=code is not None):
                    with self.assertRaisesRegex(verifier.VerificationError, "^BuilderPullPolicy$"):
                        verifier.derive_control_argv(argv, IMAGE_ID, code)


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

    def test_missing_or_malformed_create_reply_reconciles_only_the_owned_container(self):
        for value in (b"name\n", b"d" * 63, b"D" * 64, b"../container", b"", b"\xff", None):
            self.setUp()
            self.boundary.created_id = value
            with self.subTest(value=value):
                with self.assertRaises(BaseException) as caught:
                    self.run_worker()
                self.assertIs(type(caught.exception), verifier.VerificationError)
                self.assertEqual(str(caught.exception), "CreatedContainerID")
                self.assertFalse(any(argv[:2] == ["docker", "start"] for argv in self.commands()))
                self.assertGreaterEqual(len(self.commands()), 2)
                self.assertEqual(self.commands()[1], [
                    "docker", "ps", "--all", "--no-trunc", "--filter", "name=^/reverseai-unit-owned$",
                    "--format", "{{.ID}}",
                ])
                self.assert_owned_cleanup()
                self.assertTrue(self.receipt["cleanup"][0]["verified"])
                self.assertTrue(self.receipt["cleanup"][0]["uncertain_create"])

    def test_pull_policy_is_checked_independently_of_a_regressed_builder_before_create(self):
        at = self.argv.index("--pull")
        for policy in (None, "missing", "always"):
            self.boundary.calls.clear()
            changed = list(self.argv)
            if policy is None:
                del changed[at:at + 2]
            else:
                changed[at + 1] = policy
            with self.subTest(policy=policy), mock.patch.object(self.boundary, "build_argv", return_value=changed):
                with self.assertRaisesRegex(verifier.VerificationError, "^BuilderPullPolicy$"):
                    self.native.runner(changed, timeout=45, max_output=262144)
                self.assertEqual(self.commands(), [])
                self.assertEqual(self.receipt["cleanup"], [])

    def test_lost_create_reply_preserves_failure_after_verified_owned_cleanup(self):
        for failure in (self.boundary.ContainedTimeout("WorkerTimeout"), OSError("create transport lost"),
                        KeyboardInterrupt(), SystemExit(17)):
            self.setUp()
            self.boundary.create_error = failure
            with self.subTest(failure=type(failure).__name__):
                with self.assertRaises(BaseException) as caught:
                    self.run_worker()
                self.assertIs(caught.exception, failure)
                self.assert_owned_cleanup()
                self.assertTrue(self.receipt["cleanup"][0]["verified"])
                self.assertEqual(self.receipt["cleanup"][0]["container_name"], "reverseai-unit-owned")
                self.assertFalse(any(argv[:2] == ["docker", "start"] for argv in self.commands()))

    def test_uncertain_create_with_no_match_records_verified_name_absence_without_removal(self):
        self.boundary.created_id = b""
        self.boundary.lookup_output = b""
        with self.assertRaisesRegex(verifier.VerificationError, "^CreatedContainerID$"):
            self.run_worker()
        self.assertEqual([argv[:2] for argv in self.commands()], [["docker", "create"], ["docker", "ps"]])
        self.assertEqual(self.receipt["cleanup"], [{
            "container_id": None, "container_name": "reverseai-unit-owned", "uncertain_create": True,
            "verified": True, "staging_removed": False,
        }])
        self.assertFalse(verifier.receipt_passes(self.receipt))

    def test_uncertain_create_lookup_failure_or_bad_ids_cannot_prove_cleanup(self):
        for output in (b"name", b"d" * 63, b"D" * 64, b"\xff", (FakeBoundary.CID + "\n" + "e" * 64).encode(), None):
            self.setUp()
            self.boundary.created_id = b""
            self.boundary.lookup_output = output
            with self.subTest(output=output):
                with self.assertRaisesRegex(verifier.VerificationError, "^CreateCleanupUnverified$"):
                    self.run_worker()
                self.assertEqual(len(self.commands()), 2)
                self.assertFalse(self.receipt["cleanup"][0]["verified"])
        self.setUp()
        self.boundary.created_id = b""
        self.boundary.lookup_error = OSError("/private/lookup-failure")
        with self.assertRaisesRegex(verifier.VerificationError, "^CreateCleanupUnverified$"):
            self.run_worker()
        self.assertFalse(self.receipt["cleanup"][0]["verified"])

    def test_uncertain_create_rejects_inspect_identity_name_or_image_mismatch_without_removal(self):
        for field, value in (("Id", "e" * 64), ("Name", "/unrelated"), ("Image", "sha256:" + "b" * 64)):
            self.setUp()
            self.boundary.created_id = b""
            wrong = dict(self.boundary.inspect, Name="/reverseai-unit-owned")
            wrong[field] = value
            with self.subTest(field=field), mock.patch.object(self.native, "one_inspect", return_value=wrong):
                with self.assertRaisesRegex(verifier.VerificationError, "^CreateCleanupUnverified$"):
                    self.run_worker()
                self.assertFalse(any(argv[:2] in (["docker", "start"], ["docker", "rm"]) for argv in self.commands()))
                self.assertFalse(self.receipt["cleanup"][0]["verified"])

    def test_uncertain_create_cleanup_failure_is_recorded_and_fails_closed(self):
        self.boundary.created_id = b""
        self.boundary.present_after_cleanup = True
        self.assertFalse(self.native.record("runtime_identity", self.run_worker))
        self.assertEqual(self.receipt["checks"][0]["reason"], "CreateCleanupUnverified")
        self.assertFalse(self.receipt["cleanup"][0]["verified"])

    def test_uncertain_create_through_executor_records_owned_cleanup_and_removed_snapshot(self):
        from reverseai.contained import DockerExecutor, ContainedError

        with tempfile.TemporaryDirectory() as folder:
            self.boundary.create_error = OSError("/private/lost-create-reply")
            self.boundary.DockerExecutor = lambda lock, runner: DockerExecutor(
                lock, runner=runner, inspect=lambda image: image, staging_root=folder)
            with self.assertRaisesRegex(ContainedError, "^WorkerProcessError$"):
                self.native.invoke(b"inert snapshot", "lief.headers", {})
            self.assertEqual(list(Path(folder).iterdir()), [])
        self.assertEqual(len(self.receipt["cleanup"]), 1)
        row = self.receipt["cleanup"][0]
        self.assertTrue(row["verified"])
        self.assertTrue(row["staging_removed"])
        self.assertTrue(row["uncertain_create"])
        self.assertEqual(row["container_id"], FakeBoundary.CID)
        self.assertIsNone(self.native.active)
        self.assertFalse(any(argv[:2] == ["docker", "start"] for argv in self.commands()))
        self.assertIn(["docker", "rm", "--force", FakeBoundary.CID], self.commands())

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


class InvokeStagingCleanupGuardTests(unittest.TestCase):
    def invoke_with_staging(self, snapshot, *, remove):
        receipt = {"checks": [], "cleanup": []}
        row = {"container_id": FakeBoundary.CID, "verified": True, "staging_removed": False}
        executor = mock.Mock()
        boundary = SimpleNamespace(DockerExecutor=mock.Mock(return_value=executor))
        native = verifier.NativeVerifier(boundary, lock_fixture(), receipt)

        def run(operation, args, data, digest):
            native.last = (row, snapshot)
            if remove:
                snapshot.unlink()
            return b"successful worker reply"

        executor.run.side_effect = run
        return native, row

    def test_removed_staging_allows_the_worker_reply(self):
        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder) / "input"
            snapshot.write_bytes(b"frozen input")
            native, row = self.invoke_with_staging(snapshot, remove=True)
            self.assertEqual(native.invoke(b"frozen input", "lief.headers", {}),
                             b"successful worker reply")
            self.assertTrue(row["staging_removed"])
            self.assertFalse(snapshot.exists())
            self.assertIsNone(native.active)

    def test_surviving_staging_refuses_even_a_successful_worker_reply(self):
        with tempfile.TemporaryDirectory() as folder:
            snapshot = Path(folder) / "input"
            snapshot.write_bytes(b"frozen input")
            native, row = self.invoke_with_staging(snapshot, remove=False)
            with self.assertRaisesRegex(verifier.VerificationError, "^SnapshotCleanupUnverified$"):
                native.invoke(b"frozen input", "lief.headers", {})
            self.assertFalse(row["staging_removed"])
            self.assertTrue(snapshot.exists())


class RunInspectionCountGuardTests(unittest.TestCase):
    def run_with_count(self, count):
        receipt = {"checks": [], "cleanup": []}
        native = verifier.NativeVerifier(SimpleNamespace(), lock_fixture(), receipt)
        native.inspected = count
        values = {name: b"generated fixture" for name in verifier.FIXTURE_NAMES}
        with mock.patch.object(native, "local_daemon", return_value={}), \
                mock.patch.object(native, "image_check", return_value={}), \
                mock.patch.object(native, "control", return_value={}) as control, \
                mock.patch.object(native, "known_answer", return_value={}) as known_answer, \
                mock.patch.object(verifier, "fixtures", return_value=values):
            native.run()
        self.assertEqual(control.call_count, 10)
        self.assertEqual(known_answer.call_count, 8)
        return next(row for row in receipt["checks"] if row["id"] == "container")

    def test_every_expected_inspection_allows_the_container_check(self):
        self.assertEqual(self.run_with_count(18),
                         {"id": "container", "status": "passed", "evidence": None})

    def test_missing_or_extra_inspections_fail_the_container_check(self):
        for count in (0, 17, 19):
            with self.subTest(inspected=count):
                self.assertEqual(self.run_with_count(count),
                                 {"id": "container", "status": "failed",
                                  "reason": "ContainerInspectionMissing"})


class OneInspectShapeGuardTests(unittest.TestCase):
    def inspect_value(self, value):
        boundary = SimpleNamespace(run_bounded=mock.Mock(return_value=json.dumps(value).encode()))
        native = verifier.NativeVerifier(boundary, lock_fixture(), {"checks": [], "cleanup": []})
        return native.one_inspect(["context", "inspect"])

    def test_exactly_one_object_is_returned(self):
        self.assertEqual(self.inspect_value([{"name": "owned object"}]), {"name": "owned object"})

    def test_multiple_objects_cannot_be_silently_reduced_to_the_first(self):
        with self.assertRaisesRegex(verifier.VerificationError, "^InspectShape$"):
            self.inspect_value([{"name": "first"}, {"name": "second"}])

    def test_empty_nonlist_and_nonobject_inspections_are_refused(self):
        for value in ([], {}, None, "object", False, [None], [[]], ["object"], [False]):
            with self.subTest(value=value), \
                    self.assertRaisesRegex(verifier.VerificationError, "^InspectShape$"):
                self.inspect_value(value)


class LocalDaemonGuardTests(unittest.TestCase):
    def native(self, *, endpoint="unix:///var/run/docker.sock", server=None):
        context = [{"Endpoints": {"docker": {"Host": endpoint}}}]
        if server is None:
            server = {"Os": "linux", "Arch": "arm64", "Version": "test-version"}
        boundary = SimpleNamespace(run_bounded=mock.Mock(side_effect=(
            json.dumps(context).encode(), json.dumps(server).encode())))
        native = verifier.NativeVerifier(boundary, lock_fixture(), {"checks": [], "cleanup": []})
        return native, boundary

    def test_unset_or_empty_overrides_allow_a_local_linux_arm64_daemon(self):
        for environment in ({}, {"DOCKER_HOST": "", "DOCKER_CONTEXT": ""}):
            native, boundary = self.native()
            with self.subTest(environment=environment), \
                    mock.patch.dict(verifier.os.environ, environment, clear=True):
                self.assertEqual(native.local_daemon(),
                                 {"os": "linux", "arch": "arm64", "version": "test-version"})
            self.assertEqual(boundary.run_bounded.call_count, 2)

    def test_environment_overrides_are_refused_before_contacting_the_daemon(self):
        for key, value in (("DOCKER_HOST", "unix:///alternate.sock"),
                           ("DOCKER_CONTEXT", "alternate-context")):
            native, boundary = self.native()
            with self.subTest(variable=key), \
                    mock.patch.dict(verifier.os.environ, {key: value}, clear=True), \
                    self.assertRaisesRegex(verifier.VerificationError, "^DockerEnvironmentOverride$"):
                native.local_daemon()
            boundary.run_bounded.assert_not_called()

    def test_a_user_local_unix_socket_is_accepted(self):
        native, _ = self.native(endpoint="unix:///Users/test/.docker/run/docker.sock")
        with mock.patch.dict(verifier.os.environ, {}, clear=True):
            self.assertEqual(native.local_daemon()["arch"], "arm64")

    def test_remote_relative_or_nonstring_endpoints_are_refused(self):
        for endpoint in ("tcp://127.0.0.1:2375", "ssh://remote", "npipe:////./pipe/docker_engine",
                         "unix://relative.sock", "", None, False, 17, []):
            native, boundary = self.native(endpoint=endpoint)
            with self.subTest(endpoint=endpoint), \
                    mock.patch.dict(verifier.os.environ, {}, clear=True), \
                    self.assertRaisesRegex(verifier.VerificationError, "^NonlocalDockerDaemon$"):
                native.local_daemon()
            self.assertEqual(boundary.run_bounded.call_count, 1)

    def test_a_non_linux_server_is_refused(self):
        native, _ = self.native(server={"Os": "windows", "Arch": "arm64"})
        with mock.patch.dict(verifier.os.environ, {}, clear=True), \
                self.assertRaisesRegex(verifier.VerificationError, "^DaemonPlatform$"):
            native.local_daemon()

    def test_a_non_arm64_server_is_refused(self):
        native, _ = self.native(server={"Os": "linux", "Arch": "amd64"})
        with mock.patch.dict(verifier.os.environ, {}, clear=True), \
                self.assertRaisesRegex(verifier.VerificationError, "^DaemonPlatform$"):
            native.local_daemon()

    def test_missing_server_platform_fields_are_refused(self):
        for server in ({"Os": "linux"}, {"Arch": "arm64"}, {}):
            native, _ = self.native(server=server)
            with self.subTest(server=server), \
                    mock.patch.dict(verifier.os.environ, {}, clear=True), \
                    self.assertRaisesRegex(verifier.VerificationError, "^DaemonPlatform$"):
                native.local_daemon()

    def test_nonobject_server_metadata_is_refused(self):
        for server in ([], "linux/arm64", False, 1):
            native, _ = self.native(server=server)
            with self.subTest(server=server), \
                    mock.patch.dict(verifier.os.environ, {}, clear=True), \
                    self.assertRaisesRegex(verifier.VerificationError, "^DaemonPlatform$"):
                native.local_daemon()


class WatcherCleanupGuardTests(unittest.TestCase):
    def setUp(self):
        self.boundary = FakeBoundary()
        self.receipt = {"checks": [], "cleanup": []}
        self.native = verifier.NativeVerifier(self.boundary, lock_fixture(), self.receipt)
        self.native.image = image_fixture()
        self.native.active = "wall"
        self.argv = self.boundary.build_argv(IMAGE_ID, "reverseai-unit-owned", str(SNAPSHOT),
                                             "lief.headers", {})

    def run_worker(self):
        return self.native.runner(self.argv, timeout=45, max_output=262144)

    def test_a_stopped_watcher_is_joined_before_success_returns(self):
        watcher = mock.Mock()
        watcher.is_alive.return_value = False
        with mock.patch.object(verifier.threading, "Thread", return_value=watcher):
            self.assertEqual(self.run_worker(), b"canned worker reply")
        watcher.start.assert_called_once_with()
        watcher.join.assert_called_once_with(timeout=2.5)
        watcher.is_alive.assert_called_once_with()
        self.assertTrue(self.receipt["cleanup"][0]["verified"])

    def test_a_watcher_still_alive_after_join_refuses_successful_output(self):
        watcher = mock.Mock()
        watcher.is_alive.return_value = True
        with mock.patch.object(verifier.threading, "Thread", return_value=watcher), \
                self.assertRaisesRegex(verifier.VerificationError, "^MonitorCleanupUnverified$"):
            self.run_worker()
        watcher.join.assert_called_once_with(timeout=2.5)
        self.assertTrue(self.receipt["cleanup"][0]["verified"])
        self.assertEqual([call[0][:2] for call in self.boundary.calls][-2:],
                         [["docker", "rm"], ["docker", "ps"]])


class MainSourceChangeGuardTests(unittest.TestCase):
    def run_with_source_change(self, change=None):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            sources = {"verifier": root / "verifier.py", "executor": root / "executor.py"}
            initial = {"verifier": b"trusted verifier revision one", "executor": b"trusted executor revision one"}
            for name, path in sources.items():
                path.write_bytes(initial[name])
            lock = root / "lock.json"
            lock.write_text(json.dumps(lock_fixture()))
            output = root / "receipt.json"
            boundary = SimpleNamespace(WALL_SECONDS=45, __file__=str(sources["executor"]),
                                       load_lock=mock.Mock(return_value=lock_fixture()))

            def native_factory(boundary, lock, receipt):
                def run():
                    canned = receipt_fixture()
                    for key in ("image_id", "checks", "cleanup"):
                        receipt[key] = canned[key]
                    if change is not None:
                        sources[change].write_bytes(initial[change] + b" changed during verification")
                return SimpleNamespace(run=run)

            with mock.patch.object(reverseai, "contained", boundary, create=True), \
                    mock.patch.object(verifier, "__file__", str(sources["verifier"])), \
                    mock.patch.object(verifier, "NativeVerifier", side_effect=native_factory), \
                    mock.patch.object(verifier.sys, "stderr", new=io.StringIO()):
                result = verifier.main(["--tool", "lief", "--profile", "small", "--offline",
                                        "--lock", str(lock), "--receipt", str(output)])
            receipt = json.loads(output.read_bytes())
            for name in sources:
                self.assertEqual(receipt[name + "_sha256"], sha256_hex(initial[name]))
            return result, receipt

    def test_unchanged_sources_allow_a_complete_canned_receipt(self):
        result, receipt = self.run_with_source_change()
        self.assertEqual(result, 0)
        self.assertTrue(receipt["passed"])
        self.assertEqual(len(receipt["checks"]), 21)
        self.assertTrue(all(row["status"] == "passed" for row in receipt["checks"]))

    def assert_source_change_refused(self, source):
        result, receipt = self.run_with_source_change(source)
        self.assertEqual(result, 1)
        self.assertFalse(receipt["passed"])
        self.assertIn({"id": "controller", "status": "failed", "reason": "SourceChangedDuringVerification"},
                      receipt["checks"])

    def test_verifier_source_changed_during_the_run_refuses_the_receipt(self):
        self.assert_source_change_refused("verifier")

    def test_executor_source_changed_during_the_run_refuses_the_receipt(self):
        self.assert_source_change_refused("executor")


class YaraxRulesetTests(unittest.TestCase):
    REVIEWED_SHA256 = "e2217ff703858af17fe8eee8ac0d4cc44dfefd632e096bb4b527b89b08a062a7"

    def lock(self):
        return {"ruleset_sha256": self.REVIEWED_SHA256}

    def test_repository_ruleset_has_the_reviewed_bytes_and_declared_literal_patterns(self):
        raw = verifier.YARAX_RULESET_PATH.read_bytes()
        self.assertEqual(sha256_hex(raw), self.REVIEWED_SHA256)
        self.assertEqual(verifier.YARAX_RULESET_SHA256, self.REVIEWED_SHA256)
        ruleset = verifier.load_yarax_ruleset(self.lock())
        self.assertEqual(ruleset, json.loads(raw))
        self.assertEqual(ruleset["ruleset"], "m2_fixture_v1")
        self.assertEqual([rule["id"] for rule in ruleset["rules"]],
                         ["upx_packed", "powershell_encoded_command", "base64_decode_api",
                          "credential_dump_marker"])
        self.assertEqual(sum(len(rule["patterns"]) for rule in ruleset["rules"]), 9)
        for rule in ruleset["rules"]:
            for pattern in rule["patterns"]:
                with self.subTest(rule=rule["id"], pattern=pattern["id"]):
                    self.assertGreaterEqual(len(bytes.fromhex(pattern["hex"])), 4)
                    self.assertLessEqual(len(bytes.fromhex(pattern["hex"])), 256)

    def test_an_explicit_path_accepts_only_the_identical_reviewed_bytes(self):
        raw = verifier.YARAX_RULESET_PATH.read_bytes()
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ruleset.json"
            path.write_bytes(raw)
            self.assertEqual(verifier.load_yarax_ruleset(self.lock(), path), json.loads(raw))
            for corrupted in (raw + b"\n", raw.replace(b"55505821", b"55505822"), b"not JSON"):
                path.write_bytes(corrupted)
                with self.subTest(corrupted=corrupted[:20]), \
                        self.assertRaises(verifier.VerificationError):
                    verifier.load_yarax_ruleset(self.lock(), path)

    def test_a_matching_unreviewed_lock_hash_cannot_authorize_changed_rules(self):
        raw = verifier.YARAX_RULESET_PATH.read_bytes() + b"\n"
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ruleset.json"
            path.write_bytes(raw)
            with self.assertRaises(verifier.VerificationError):
                verifier.load_yarax_ruleset({"ruleset_sha256": sha256_hex(raw)}, path)

    def test_missing_wrong_or_malformed_lock_hashes_are_refused(self):
        for lock in (None, [], False, {}, {"ruleset_sha256": None},
                     {"ruleset_sha256": "e" * 64}, {"ruleset_sha256": self.REVIEWED_SHA256.upper()},
                     {"ruleset_sha256": []}, {"ruleset_sha256": True}):
            with self.subTest(lock=lock), self.assertRaises(verifier.VerificationError):
                verifier.load_yarax_ruleset(lock)

    def test_missing_and_unreadable_rulesets_are_refused(self):
        with tempfile.TemporaryDirectory() as folder:
            missing = Path(folder) / "missing.json"
            with self.assertRaises(verifier.VerificationError):
                verifier.load_yarax_ruleset(self.lock(), missing)
            with mock.patch.object(verifier, "YARAX_RULESET_PATH", missing), \
                    self.assertRaises(verifier.VerificationError):
                verifier.load_yarax_ruleset(self.lock())
        with mock.patch.object(Path, "open", side_effect=PermissionError), \
                self.assertRaises(verifier.VerificationError):
            verifier.load_yarax_ruleset(self.lock())

    def test_ruleset_read_is_bounded_and_oversized_bytes_never_reach_the_decoder(self):
        opened = mock.mock_open(read_data=b"x" * 65_537)
        with mock.patch.object(Path, "open", opened), \
                mock.patch.object(verifier, "decode") as decoder, \
                self.assertRaises(verifier.VerificationError):
            verifier.load_yarax_ruleset(self.lock())
        opened.return_value.read.assert_called_once()
        requested = opened.return_value.read.call_args.args[0]
        self.assertGreater(requested, 0)
        self.assertLessEqual(requested, 65_537)
        decoder.assert_not_called()

    def test_hashes_are_checked_before_attempting_to_decode_untrusted_bytes(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "ruleset.json"
            path.write_bytes(b"not JSON")
            with mock.patch.object(verifier, "decode") as decoder, \
                    self.assertRaises(verifier.VerificationError):
                verifier.load_yarax_ruleset(self.lock(), path)
        decoder.assert_not_called()


class YaraxKnownAnswerTests(unittest.TestCase):
    def setUp(self):
        self.ruleset = verifier.load_yarax_ruleset({
            "ruleset_sha256": "e2217ff703858af17fe8eee8ac0d4cc44dfefd632e096bb4b527b89b08a062a7"})
        self.data = verifier.yarax_fixtures()

    def record(self, offset, length, rule="upx_packed", pattern="$a"):
        return {"location": {"offset": offset, "length": length},
                "value": {"ruleset": "m2_fixture_v1", "rule": rule, "pattern": pattern}}

    def observations(self, records):
        from reverseai.contract import Location, Observation
        return tuple(Observation(Location(**record["location"]), record["value"]) for record in records)

    def compare(self, data, records, max_matches=64, ruleset=None):
        return verifier.compare_yarax_observations(data, self.observations(records),
                                                  self.ruleset if ruleset is None else ruleset,
                                                  max_matches=max_matches)

    def upx_records(self):
        return [self.record(1, 4), self.record(9, 4, pattern="$b"),
                self.record(17, 4, pattern="$c"),
                self.record(22, 15, "powershell_encoded_command"),
                self.record(38, 16, "base64_decode_api"),
                self.record(55, 10, "credential_dump_marker")]

    def repeated_records(self, max_matches=64):
        return ([self.record(4 * index, 4) for index in range(4)] +
                [self.record(320, 10, "credential_dump_marker")])[:max_matches]

    def test_four_fixtures_are_deterministic_declared_inert_bytes(self):
        self.assertEqual(verifier.YARAX_FIXTURE_NAMES,
                         ("upx_markers", "utf16_markers", "clean", "repeated_markers"))
        self.assertEqual(self.data, {
            "upx_markers": b"\0UPX!----UPX0----UPX1\0-EncodedCommand\0FromBase64String\0sekurlsa::",
            "utf16_markers": b"\0\0" + "-EncodedCommand\0FromBase64String\0sekurlsa::".encode("utf-16le"),
            "clean": b"deterministic clean fixture\0",
            "repeated_markers": b"UPX!" * 80 + b"sekurlsa::",
        })
        self.assertEqual(verifier.yarax_fixtures(), self.data)
        self.assertTrue(all(type(data) is bytes for data in self.data.values()))

    def test_upx_matches_use_the_declared_offsets_and_pattern_ids(self):
        self.assertIsNone(self.compare(self.data["upx_markers"], self.upx_records()))

    def test_utf16_matches_have_byte_offsets_and_full_byte_lengths(self):
        records = [self.record(2, 30, "powershell_encoded_command", "$w"),
                   self.record(34, 32, "base64_decode_api", "$w"),
                   self.record(68, 20, "credential_dump_marker", "$w")]
        self.assertIsNone(self.compare(self.data["utf16_markers"], records))
        for index in range(3):
            changed = copy.deepcopy(records)
            changed[index]["location"]["length"] //= 2
            with self.subTest(character_length=index), self.assertRaises(verifier.VerificationError):
                self.compare(self.data["utf16_markers"], changed)

    def test_all_ascii_rule_families_are_verified_against_manually_declared_ranges(self):
        data = b"UPX!\0UPX0\0UPX1\0-EncodedCommand\0FromBase64String\0sekurlsa::"
        records = [self.record(0, 4), self.record(5, 4, pattern="$b"),
                   self.record(10, 4, pattern="$c"),
                   self.record(15, 15, "powershell_encoded_command"),
                   self.record(31, 16, "base64_decode_api"),
                   self.record(48, 10, "credential_dump_marker")]
        self.assertIsNone(self.compare(data, records))

    def test_clean_input_has_exactly_no_matches(self):
        self.assertIsNone(self.compare(self.data["clean"], []))
        with self.assertRaises(verifier.VerificationError):
            self.compare(self.data["clean"], [self.record(0, 4)])
        with self.assertRaises(verifier.VerificationError):
            self.compare(self.data["upx_markers"], [])

    def test_per_pattern_limit_retains_a_later_rule_before_the_requested_cut(self):
        data = self.data["repeated_markers"]
        for cap in (1, 32, 64):
            records = self.repeated_records(cap)
            with self.subTest(cap=cap):
                self.assertIsNone(self.compare(data, records, max_matches=cap))
        records = self.repeated_records()
        self.assertIsNone(verifier.compare_yarax_observations(data, self.observations(records), self.ruleset))

    def test_capped_results_cannot_omit_early_matches_or_include_later_real_matches(self):
        data = self.data["repeated_markers"]
        for cap in (1, 32, 64):
            expected = self.repeated_records(cap)
            for mutation in ("missing", "extra", "later", "duplicate"):
                changed = copy.deepcopy(expected)
                if mutation == "missing":
                    changed.pop()
                elif mutation == "extra":
                    changed.append(self.record(4 * cap, 4))
                elif mutation == "later":
                    changed[-1] = self.record(4 * cap, 4)
                else:
                    changed.append(copy.deepcopy(changed[0]))
                with self.subTest(cap=cap, mutation=mutation), \
                        self.assertRaises(verifier.VerificationError):
                    self.compare(data, changed, max_matches=cap)

    def test_matches_cannot_be_omitted_duplicated_added_or_reordered(self):
        for mutation in ("missing_first", "missing_middle", "missing_last", "duplicate", "extra", "reordered"):
            records = self.upx_records()
            if mutation.startswith("missing"):
                records.pop({"missing_first": 0, "missing_middle": 1, "missing_last": 2}[mutation])
            elif mutation == "duplicate":
                records[1] = copy.deepcopy(records[0])
            elif mutation == "extra":
                records.append(copy.deepcopy(records[-1]))
            else:
                records[0], records[1] = records[1], records[0]
            with self.subTest(mutation=mutation), self.assertRaises(verifier.VerificationError):
                self.compare(self.data["upx_markers"], records)

    def test_match_values_require_exactly_three_correct_string_fields(self):
        for field in ("ruleset", "rule", "pattern"):
            for bad in ("unknown", None, False, 1, [], {}):
                records = self.upx_records()
                records[0]["value"][field] = bad
                with self.subTest(field=field, bad=bad), self.assertRaises(verifier.VerificationError):
                    self.compare(self.data["upx_markers"], records)
            records = self.upx_records()
            del records[0]["value"][field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                self.compare(self.data["upx_markers"], records)
        records = self.upx_records()
        records[0]["value"]["category"] = "packer"
        with self.assertRaises(verifier.VerificationError):
            self.compare(self.data["upx_markers"], records)

    def test_json_object_field_order_does_not_change_a_valid_match(self):
        records = self.upx_records()
        records[0]["value"] = {"pattern": "$a", "rule": "upx_packed", "ruleset": "m2_fixture_v1"}
        self.assertIsNone(self.compare(self.data["upx_markers"], records))

    def test_duplicate_json_value_fields_are_refused_at_the_worker_reply_boundary(self):
        from reverseai.contract import ContractError
        data = self.data["upx_markers"]
        reply = {"protocol": WORKER_PROTOCOL, "status": "ok", "snapshot_sha256": sha256_hex(data),
                 "observations": self.upx_records()}
        raw = json.dumps(reply).replace('"rule": "upx_packed"',
                                        '"rule": "upx_packed", "rule": "upx_packed"', 1).encode()
        with self.assertRaises(ContractError):
            parse_worker_reply(raw, input_sha256=sha256_hex(data), max_observations=64)

    def test_match_ranges_require_exact_pattern_bytes_lengths_and_in_bounds_locations(self):
        data = self.data["upx_markers"]
        for offset, length in ((0, 4), (2, 4), (1, 3), (1, 5), (len(data), 4), (len(data) - 1, 4)):
            records = self.upx_records()
            records[0]["location"] = {"offset": offset, "length": length}
            with self.subTest(offset=offset, length=length), self.assertRaises(verifier.VerificationError):
                self.compare(data, records)

    def test_invalid_caps_inputs_collections_and_observation_shapes_are_refused(self):
        for cap in (0, 65, -1, True, 1.0, "32", None):
            with self.subTest(cap=cap), self.assertRaises(verifier.VerificationError):
                self.compare(self.data["upx_markers"], self.upx_records(), max_matches=cap)
        for data in (None, "UPX!", bytearray(b"UPX!"), []):
            with self.subTest(data=data), self.assertRaises(verifier.VerificationError):
                verifier.compare_yarax_observations(data, [], self.ruleset)
        for observations in (None, {}, "matches", False, [None], [{}], ["match"]):
            with self.subTest(observations=observations), self.assertRaises(verifier.VerificationError):
                verifier.compare_yarax_observations(self.data["clean"], observations, self.ruleset)

    def test_equal_offset_matches_are_sorted_by_rule_then_pattern_before_capping(self):
        ruleset = {"ruleset": "m2_fixture_v1", "rules": [
            {"id": "z_rule", "patterns": [{"id": "$z", "hex": "55505821"},
                                           {"id": "$a", "hex": "55505821"}]},
            {"id": "a_rule", "patterns": [{"id": "$a", "hex": "55505821"}]},
        ]}
        records = [self.record(0, 4, "a_rule"), self.record(0, 4, "z_rule"),
                   self.record(0, 4, "z_rule", "$z")]
        self.assertIsNone(self.compare(b"UPX!", records, ruleset=ruleset))
        self.assertIsNone(self.compare(b"UPX!", records[:1], max_matches=1, ruleset=ruleset))
        for left, right in ((0, 1), (1, 2)):
            changed = copy.deepcopy(records)
            changed[left], changed[right] = changed[right], changed[left]
            with self.subTest(left=left, right=right), self.assertRaises(verifier.VerificationError):
                self.compare(b"UPX!", changed, ruleset=ruleset)

    def test_overlapping_literal_matches_are_not_skipped(self):
        ruleset = {"ruleset": "m2_fixture_v1", "rules": [
            {"id": "overlap", "patterns": [{"id": "$a", "hex": "41414141"}]}]}
        records = [self.record(offset, 4, "overlap") for offset in (0, 1, 2)]
        self.assertIsNone(self.compare(b"AAAAAA", records, ruleset=ruleset))
        with self.assertRaises(verifier.VerificationError):
            self.compare(b"AAAAAA", records[:1], ruleset=ruleset)


class YaraxReceiptTests(unittest.TestCase):
    def receipt(self):
        receipt = receipt_fixture()
        receipt.update(tool="yarax", ruleset_sha256=
                       "e2217ff703858af17fe8eee8ac0d4cc44dfefd632e096bb4b527b89b08a062a7")
        receipt["lock"] = {
            "adapter_version": "1.21.0-r2",
            "base_digest": "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e",
            "image_id": IMAGE_ID, "platform": "linux/arm64",
            "ruleset_sha256": receipt["ruleset_sha256"],
            "wheel_sha256": "9bd9961b44b47dd747d526e61c703a2a8170426d003e789e7724bc7862de6d56",
        }
        names = ("local_daemon", "image", "container", "runtime_identity", "network", "write_root",
                 "write_snapshot", "setuid", "capability", "pids", "memory", "wall", "stdout",
                 "upx_markers.matches", "utf16_markers.matches", "clean.matches", "repeated_markers.matches")
        receipt["checks"] = [{"id": name, "status": "passed"} for name in names]
        receipt["cleanup"] = [{"container_id": f"{index + 1:064x}", "verified": True,
                               "staging_removed": True} for index in range(14)]
        return receipt

    def test_complete_yarax_receipt_has_seventeen_checks_and_fourteen_unique_cleanups(self):
        receipt = self.receipt()
        self.assertEqual(verifier.YARAX_RULESET_NAME, "m2_fixture_v1")
        self.assertEqual(verifier.YARAX_ADAPTER_VERSION, receipt["lock"]["adapter_version"])
        self.assertEqual(verifier.YARAX_BASE_DIGEST, receipt["lock"]["base_digest"])
        self.assertEqual(verifier.YARAX_WHEEL_SHA256, receipt["lock"]["wheel_sha256"])
        self.assertEqual(verifier.YARAX_REQUIRED_CHECKS, tuple(row["id"] for row in receipt["checks"]))
        self.assertEqual(len(verifier.YARAX_REQUIRED_CHECKS), 17)
        self.assertEqual(verifier.YARAX_NATIVE_RUNS, 14)
        self.assertTrue(verifier.receipt_passes(receipt))

    def test_yarax_lock_requires_exactly_the_six_profile_keys(self):
        for field in self.receipt()["lock"]:
            receipt = self.receipt()
            del receipt["lock"][field]
            with self.subTest(missing=field):
                self.assertFalse(verifier.receipt_passes(receipt))
        receipt = self.receipt()
        receipt["lock"]["unexpected"] = "unreviewed"
        self.assertFalse(verifier.receipt_passes(receipt))

    def test_well_formed_but_unreviewed_base_wheel_adapter_and_ruleset_pins_are_refused(self):
        for field, value in (("base_digest", "sha256:" + "b" * 64), ("wheel_sha256", "c" * 64),
                             ("adapter_version", "1.21.0"), ("adapter_version", "1.0.0-r2"),
                             ("ruleset_sha256", "d" * 64)):
            receipt = self.receipt()
            receipt["lock"][field] = value
            with self.subTest(field=field, value=value):
                self.assertFalse(verifier.receipt_passes(receipt))
        receipt = self.receipt()
        receipt["lock"]["ruleset_sha256"] = receipt["ruleset_sha256"] = "d" * 64
        self.assertFalse(verifier.receipt_passes(receipt))

    def test_top_level_ruleset_hash_is_required_and_bound_to_the_reviewed_lock(self):
        receipt = self.receipt()
        del receipt["ruleset_sha256"]
        self.assertFalse(verifier.receipt_passes(receipt))
        for value in ("d" * 64, self.receipt()["ruleset_sha256"].upper(), None, [], True):
            receipt = self.receipt()
            receipt["ruleset_sha256"] = value
            with self.subTest(value=value):
                self.assertFalse(verifier.receipt_passes(receipt))

    def test_lief_and_yarax_profile_evidence_cannot_be_relabelled(self):
        lief = receipt_fixture()
        lief["tool"] = "yarax"
        self.assertFalse(verifier.receipt_passes(lief))
        yarax = self.receipt()
        yarax["tool"] = "lief"
        self.assertFalse(verifier.receipt_passes(yarax))
        for key in ("checks", "cleanup", "lock"):
            receipt = self.receipt()
            receipt[key] = receipt_fixture()[key]
            with self.subTest(lief_evidence=key):
                self.assertFalse(verifier.receipt_passes(receipt))

    def test_yarax_identity_offline_and_source_digest_bindings_are_exact(self):
        for field, values in {
            "schema": ("reverseai.m2-runtime/2", None), "platform": ("linux/amd64", None),
            "tool": ("yara", None), "profile": ("large", None), "offline": (False, 1, "true", None),
            "lock_sha256": ("a" * 63, "A" * 64, None),
            "verifier_sha256": ("a" * 65, "g" * 64, None),
            "executor_sha256": ("sha256:" + "a" * 64, [], True),
        }.items():
            for value in values:
                receipt = self.receipt()
                receipt[field] = value
                with self.subTest(field=field, value=value):
                    self.assertFalse(verifier.receipt_passes(receipt))
            receipt = self.receipt()
            del receipt[field]
            with self.subTest(missing=field):
                self.assertFalse(verifier.receipt_passes(receipt))

    def test_yarax_image_and_locked_platform_must_agree(self):
        for field, value in (("image_id", "sha256:" + "d" * 64), ("platform", "linux/amd64")):
            receipt = self.receipt()
            receipt["lock"][field] = value
            with self.subTest(field=field):
                self.assertFalse(verifier.receipt_passes(receipt))
        for value in ("sha256:bad", "sha256:" + "A" * 64, None, 1):
            receipt = self.receipt()
            receipt["image_id"] = receipt["lock"]["image_id"] = value
            with self.subTest(image_id=value):
                self.assertFalse(verifier.receipt_passes(receipt))

    def test_every_yarax_check_must_be_present_once_and_passed(self):
        for index, row in enumerate(self.receipt()["checks"]):
            for mutation in ("missing", "duplicate", "failed", "not_run", "false", "status_missing"):
                receipt = self.receipt()
                if mutation == "missing":
                    receipt["checks"].pop(index)
                elif mutation == "duplicate":
                    receipt["checks"][index] = copy.deepcopy(receipt["checks"][(index + 1) % 17])
                elif mutation == "status_missing":
                    del receipt["checks"][index]["status"]
                else:
                    receipt["checks"][index]["status"] = False if mutation == "false" else mutation
                with self.subTest(check=row["id"], mutation=mutation):
                    self.assertFalse(verifier.receipt_passes(receipt))
        receipt = self.receipt()
        receipt["checks"].append({"id": "unexpected", "status": "passed"})
        self.assertFalse(verifier.receipt_passes(receipt))

    def test_cleanup_requires_exactly_fourteen_distinct_containers(self):
        for mutation in ("missing", "extra", "duplicate"):
            receipt = self.receipt()
            if mutation == "missing":
                receipt["cleanup"].pop()
            elif mutation == "extra":
                receipt["cleanup"].append({"container_id": "f" * 64, "verified": True,
                                           "staging_removed": True})
            else:
                receipt["cleanup"][1] = copy.deepcopy(receipt["cleanup"][0])
            with self.subTest(mutation=mutation):
                self.assertFalse(verifier.receipt_passes(receipt))

    def test_every_yarax_cleanup_requires_verified_absence_and_removed_staging(self):
        for index in range(14):
            for field in ("verified", "staging_removed"):
                for value in (False, None, 1, "true"):
                    receipt = self.receipt()
                    receipt["cleanup"][index][field] = value
                    with self.subTest(index=index, field=field, value=value):
                        self.assertFalse(verifier.receipt_passes(receipt))
                receipt = self.receipt()
                del receipt["cleanup"][index][field]
                with self.subTest(index=index, missing=field):
                    self.assertFalse(verifier.receipt_passes(receipt))

    def test_malformed_yarax_sections_rows_and_cleanup_ids_are_refused(self):
        for field in ("checks", "cleanup", "lock"):
            for value in (None, [], {}, False, "invalid"):
                receipt = self.receipt()
                receipt[field] = value
                with self.subTest(field=field, value=value):
                    self.assertFalse(verifier.receipt_passes(receipt))
        for value in (None, [], False, "row", {}):
            for field in ("checks", "cleanup"):
                receipt = self.receipt()
                receipt[field][0] = value
                with self.subTest(field=field, row=value):
                    self.assertFalse(verifier.receipt_passes(receipt))
        for value in ("", "a" * 63, "A" * 64, "sha256:" + "a" * 64, None, [], 1):
            receipt = self.receipt()
            receipt["cleanup"][0]["container_id"] = value
            with self.subTest(container_id=value):
                self.assertFalse(verifier.receipt_passes(receipt))
        receipt = self.receipt()
        del receipt["cleanup"][0]["container_id"]
        self.assertFalse(verifier.receipt_passes(receipt))


class YaraxNativeProfileTests(unittest.TestCase):
    def setUp(self):
        self.boundary = FakeBoundary()
        self.lock = YaraxReceiptTests().receipt()["lock"]
        self.ruleset = verifier.load_yarax_ruleset(self.lock)
        self.receipt = {"checks": [], "cleanup": []}
        self.native = verifier.NativeVerifier(self.boundary, self.lock, self.receipt,
                                               tool="yarax", ruleset=self.ruleset)
        self.native.image = image_fixture()
        self.data = verifier.yarax_fixtures()
        self.args = {"ruleset": "m2_fixture_v1", "max_matches": 64}
        self.argv = self.boundary.build_argv(IMAGE_ID, "reverseai-yarax-owned", str(SNAPSHOT),
                                             "yarax.matches", self.args)

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
        self.assertTrue(self.receipt["cleanup"][0]["verified"])

    def records(self, name):
        declared = YaraxKnownAnswerTests()
        if name == "upx_markers":
            return declared.upx_records()
        if name == "utf16_markers":
            return [declared.record(2, 30, "powershell_encoded_command", "$w"),
                    declared.record(34, 32, "base64_decode_api", "$w"),
                    declared.record(68, 20, "credential_dump_marker", "$w")]
        if name == "repeated_markers":
            return declared.repeated_records()
        self.assertEqual(name, "clean")
        return []

    def reply(self, data, records, **changes):
        value = {"protocol": WORKER_PROTOCOL, "status": "ok", "snapshot_sha256": sha256_hex(data),
                 "observations": records}
        value.update(changes)
        return json.dumps(value).encode()

    def run_with_inspections(self, count):
        self.native.inspected = count
        with mock.patch.object(self.native, "local_daemon", return_value={}), \
                mock.patch.object(self.native, "image_check", return_value={}), \
                mock.patch.object(self.native, "control", return_value={}) as control, \
                mock.patch.object(self.native, "known_answer", return_value={}) as known_answer, \
                mock.patch.object(verifier, "fixtures", side_effect=AssertionError("LIEF fixture fallback")):
            self.native.run()
        self.assertEqual(control.call_args_list,
                         [mock.call(name, self.data["upx_markers"]) for name in verifier.CONTROL_NAMES])
        self.assertEqual(known_answer.call_args_list,
                         [mock.call(data, "yarax.matches") for data in self.data.values()])
        self.assertEqual({row["id"] for row in self.receipt["checks"]}, set(verifier.YARAX_REQUIRED_CHECKS))
        self.assertEqual(len(self.receipt["checks"]), 17)
        return next(row for row in self.receipt["checks"] if row["id"] == "container")

    def test_full_profile_routes_ten_controls_four_fixtures_and_fourteen_inspections(self):
        self.assertEqual(self.run_with_inspections(14),
                         {"id": "container", "status": "passed", "evidence": None})
        self.assertTrue(all(row["status"] == "passed" for row in self.receipt["checks"]))

    def test_missing_or_extra_yarax_inspections_refuse_the_container_check(self):
        for count in (0, 13, 15, 18):
            self.setUp()
            with self.subTest(count=count):
                self.assertEqual(self.run_with_inspections(count),
                                 {"id": "container", "status": "failed", "reason": "ContainerInspectionMissing"})

    def test_yarax_constructor_requires_reviewed_pins_and_a_ruleset(self):
        for ruleset in (None, [], "ruleset", False):
            with self.subTest(ruleset=ruleset), self.assertRaises(verifier.VerificationError):
                verifier.NativeVerifier(self.boundary, self.lock, self.receipt, tool="yarax", ruleset=ruleset)
        for field in self.lock:
            lock = dict(self.lock)
            del lock[field]
            with self.subTest(missing=field), self.assertRaises(verifier.VerificationError):
                verifier.NativeVerifier(self.boundary, lock, self.receipt, tool="yarax", ruleset=self.ruleset)
        self.assertEqual(self.boundary.calls, [])

    def test_each_control_uses_yarax_operation_arguments_and_its_probe_name(self):
        for name in verifier.CONTROL_NAMES:
            value = probe_fixture(name)
            with self.subTest(probe=name), \
                    mock.patch.object(self.native, "invoke", return_value=json.dumps(value).encode()) as invoke:
                self.assertEqual(self.native.control(name, self.data["upx_markers"]), value)
                invoke.assert_called_once_with(self.data["upx_markers"], "yarax.matches",
                                               {"ruleset": "m2_fixture_v1", "max_matches": 32}, probe=name)

    def test_known_answers_accept_every_fixture_including_flood_and_late_rule(self):
        for name, data in self.data.items():
            records = self.records(name)
            with self.subTest(fixture=name), \
                    mock.patch.object(self.native, "invoke", return_value=self.reply(data, records)) as invoke, \
                    mock.patch.object(verifier, "compare_observations", side_effect=AssertionError("LIEF comparison fallback")):
                self.assertEqual(self.native.known_answer(data, "yarax.matches"),
                                 {"input_sha256": sha256_hex(data), "input_bytes": len(data),
                                  "observations": len(records)})
                invoke.assert_called_once_with(data, "yarax.matches",
                                               {"ruleset": "m2_fixture_v1", "max_matches": 64})

    def test_known_answer_refuses_other_operations_without_invoking_a_worker(self):
        with mock.patch.object(self.native, "invoke") as invoke:
            for operation in ("lief.headers", "lief.sections", "yara.matches", "yarax.headers"):
                with self.subTest(operation=operation), self.assertRaises(verifier.VerificationError):
                    self.native.known_answer(self.data["upx_markers"], operation)
        invoke.assert_not_called()

    def test_known_answer_refuses_forged_protocol_snapshot_and_over_cap_replies(self):
        from reverseai.contract import ContractError
        data = self.data["repeated_markers"]
        records = self.records("repeated_markers")
        for raw in (self.reply(data, records, protocol="reverseai.worker/2"),
                    self.reply(data, records, snapshot_sha256="0" * 64),
                    self.reply(data, [YaraxKnownAnswerTests().record(4 * index, 4) for index in range(65)]),
                    b"x" * (MAX_WORKER_REPLY_BYTES + 1)):
            with self.subTest(reply_bytes=len(raw)), mock.patch.object(self.native, "invoke", return_value=raw), \
                    self.assertRaises(ContractError):
                self.native.known_answer(data, "yarax.matches")

    def test_known_answer_refuses_well_formed_but_forged_or_hidden_observations(self):
        data = self.data["upx_markers"]
        for mutation in ("wrong_rule", "wrong_range", "hidden", "duplicate", "reordered"):
            records = self.records("upx_markers")
            if mutation == "wrong_rule":
                records[0]["value"]["rule"] = "credential_dump_marker"
            elif mutation == "wrong_range":
                records[0]["location"]["offset"] = 0
            elif mutation == "hidden":
                records.pop()
            elif mutation == "duplicate":
                records[1] = copy.deepcopy(records[0])
            else:
                records.reverse()
            with self.subTest(mutation=mutation), \
                    mock.patch.object(self.native, "invoke", return_value=self.reply(data, records)), \
                    self.assertRaises(verifier.VerificationError):
                self.native.known_answer(data, "yarax.matches")

    def test_invoke_passes_yarax_adapter_and_extra_lock_key_to_the_executor_factory(self):
        executor = SimpleNamespace(run=mock.Mock(return_value=b"canned reply"))
        self.boundary.DockerExecutor = mock.Mock(return_value=executor)
        data = self.data["upx_markers"]
        self.assertEqual(self.native.invoke(data, "yarax.matches", self.args, probe="stdout"), b"canned reply")
        self.boundary.DockerExecutor.assert_called_once_with(
            self.lock, runner=self.native.runner, adapter_version="1.21.0-r2", extra_keys=("ruleset_sha256",))
        executor.run.assert_called_once_with("yarax.matches", self.args, data, sha256_hex(data))
        self.assertIsNone(self.native.active)

    def test_yarax_runner_inspects_the_operation_and_cleans_only_the_created_id(self):
        self.assertEqual(self.run_worker(), b"canned worker reply")
        commands = self.commands()
        self.assertEqual([argv[:2] for argv in commands],
                         [["docker", "create"], ["docker", "inspect"], ["docker", "start"],
                          ["docker", "rm"], ["docker", "ps"]])
        self.assertEqual(commands[0][-2:], ["yarax.matches", '{"max_matches":64,"ruleset":"m2_fixture_v1"}'])
        self.assertEqual(commands[1], ["docker", "inspect", FakeBoundary.CID])
        self.assertEqual(commands[2], ["docker", "start", "--attach", FakeBoundary.CID])
        self.assertEqual(self.boundary.calls[2][1:], (45, MAX_WORKER_REPLY_BYTES))
        self.assertEqual(self.native.inspected, 1)
        self.assert_owned_cleanup()

    def test_yarax_unsafe_inspection_blocks_start_and_still_cleans_the_created_id(self):
        self.boundary.inspect["HostConfig"]["NetworkMode"] = "host"
        with self.assertRaises(verifier.VerificationError):
            self.run_worker()
        self.assertFalse(any(argv[:2] == ["docker", "start"] for argv in self.commands()))
        self.assertEqual(self.native.inspected, 0)
        self.assert_owned_cleanup()

    def test_yarax_stdout_probe_records_only_the_exact_output_limit_failure(self):
        self.native.active = "stdout"
        self.boundary.start_error = self.boundary.ContainedError("WorkerOutputLimit")
        value = verifier.decode(self.run_worker())
        verifier.validate_probe("stdout", value)
        self.assertEqual(value["error"], "WorkerOutputLimit")
        self.assert_owned_cleanup()

    def test_yarax_wall_probe_requires_observed_running_and_the_full_wall_limit(self):
        self.native.active = "wall"
        self.boundary.wait_for_running = True
        self.boundary.start_error = self.boundary.ContainedTimeout("WorkerTimeout")
        with mock.patch.object(verifier.time, "monotonic", side_effect=(100.0, 145.1)):
            value = verifier.decode(self.run_worker())
        verifier.validate_probe("wall", value)
        self.assertTrue(value["running_observed"])
        self.assertAlmostEqual(value["elapsed"], 45.1)
        self.assert_owned_cleanup()

    def test_yarax_uncertain_create_keeps_the_failure_and_removes_owned_staging(self):
        failure = OSError("lost create reply")
        self.boundary.create_error = failure
        with tempfile.TemporaryDirectory() as folder:
            staging = Path(folder) / "snapshot"

            def executor_factory(lock, *, runner, adapter_version, extra_keys):
                self.assertEqual(lock, self.lock)
                self.assertEqual(adapter_version, "1.21.0-r2")
                self.assertEqual(extra_keys, ("ruleset_sha256",))

                def run(operation, args, data, digest):
                    staging.mkdir()
                    (staging / "input").write_bytes(data)
                    argv = self.boundary.build_argv(IMAGE_ID, "reverseai-yarax-owned", str(staging), operation, args)
                    try:
                        return runner(argv, timeout=45, max_output=MAX_WORKER_REPLY_BYTES)
                    finally:
                        (staging / "input").unlink()
                        staging.rmdir()
                return SimpleNamespace(run=run)

            self.boundary.DockerExecutor = mock.Mock(side_effect=executor_factory)
            with self.assertRaises(OSError) as caught:
                self.native.invoke(self.data["upx_markers"], "yarax.matches", self.args)
            self.assertIs(caught.exception, failure)
            self.assertEqual(list(Path(folder).iterdir()), [])
        self.assert_owned_cleanup()
        self.assertTrue(self.receipt["cleanup"][0]["uncertain_create"])
        self.assertTrue(self.receipt["cleanup"][0]["staging_removed"])
        self.assertIsNone(self.native.active)
        self.assertFalse(any(argv[:2] == ["docker", "start"] for argv in self.commands()))


class YaraxMainTests(unittest.TestCase):
    def run_cli(self, *, lock=None, ruleset_state="reviewed", change=None, native_error=None):
        reviewed = verifier.YARAX_RULESET_PATH.read_bytes()
        lock = YaraxReceiptTests().receipt()["lock"] if lock is None else lock
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            initial = {"verifier": b"inert verifier source one", "executor": b"inert executor source one"}
            sources = {name: root / (name + ".py") for name in initial}
            for name, path in sources.items():
                path.write_bytes(initial[name])
            ruleset = root / "ruleset.json"
            if ruleset_state != "missing":
                ruleset.write_bytes(reviewed if ruleset_state == "reviewed" else
                                    b"x" * 65_537 if ruleset_state == "oversized" else reviewed + b"\n")
            lock_path = root / "image.lock.json"
            lock_raw = json.dumps(lock).encode()
            lock_path.write_bytes(lock_raw)
            output = root / "receipt.json"
            boundary = SimpleNamespace(WALL_SECONDS=45, __file__=str(sources["executor"]),
                                       load_lock=mock.Mock(side_effect=lambda value, **kwargs: copy.deepcopy(value)),
                                       run_bounded=mock.Mock(side_effect=AssertionError("unexpected process boundary")))

            def native_factory(called_boundary, called_lock, receipt, **options):
                self.assertIs(called_boundary, boundary)

                def run():
                    if native_error is not None:
                        raise native_error
                    canned = YaraxReceiptTests().receipt()
                    for key in ("image_id", "checks", "cleanup"):
                        receipt[key] = canned[key]
                    if change == "ruleset":
                        ruleset.write_bytes(reviewed + b"\n")
                    elif change == "missing_ruleset":
                        ruleset.unlink()
                    elif change in sources:
                        sources[change].write_bytes(initial[change] + b" changed during verification")
                return SimpleNamespace(run=run)

            with mock.patch.object(reverseai, "contained", boundary, create=True), \
                    mock.patch.object(verifier, "__file__", str(sources["verifier"])), \
                    mock.patch.object(verifier, "YARAX_RULESET_PATH", ruleset), \
                    mock.patch.object(verifier, "NativeVerifier", side_effect=native_factory) as factory, \
                    mock.patch.object(verifier, "load_yarax_ruleset", wraps=verifier.load_yarax_ruleset) as loader, \
                    mock.patch.object(verifier.sys, "stderr", new=io.StringIO()):
                result = verifier.main(["--tool", "yarax", "--profile", "small", "--offline",
                                        "--lock", str(lock_path), "--receipt", str(output)])
            receipt = json.loads(output.read_bytes())
        boundary.run_bounded.assert_not_called()
        return SimpleNamespace(result=result, receipt=receipt, boundary=boundary, factory=factory,
                               loader=loader, lock=lock, lock_raw=lock_raw, reviewed=reviewed, initial=initial)

    def test_complete_cli_receipt_keeps_exact_yarax_checks_cleanups_and_hash_bindings(self):
        run = self.run_cli()
        self.assertEqual(run.result, 0)
        self.assertTrue(run.receipt["passed"])
        self.assertEqual(run.receipt["tool"], "yarax")
        self.assertEqual(run.receipt["ruleset_sha256"], sha256_hex(run.reviewed))
        self.assertEqual(run.receipt["lock_sha256"], sha256_hex(run.lock_raw))
        for name, raw in run.initial.items():
            self.assertEqual(run.receipt[name + "_sha256"], sha256_hex(raw))
        self.assertEqual({row["id"] for row in run.receipt["checks"]}, set(verifier.YARAX_REQUIRED_CHECKS))
        self.assertEqual(len(run.receipt["checks"]), 17)
        self.assertTrue(all(row["status"] == "passed" for row in run.receipt["checks"]))
        self.assertEqual(len(run.receipt["cleanup"]), 14)

    def test_cli_passes_yarax_lock_options_and_verified_ruleset_to_the_native_factory(self):
        run = self.run_cli()
        run.boundary.load_lock.assert_called_once_with(
            run.lock, adapter_version="1.21.0-r2", extra_keys=("ruleset_sha256",))
        run.factory.assert_called_once()
        self.assertEqual(run.factory.call_args.args[:2], (run.boundary, run.lock))
        self.assertEqual(run.factory.call_args.kwargs,
                         {"tool": "yarax", "ruleset": json.loads(run.reviewed)})
        self.assertEqual(run.loader.call_count, 2)

    def test_cli_wrong_lock_pins_are_refused_before_shared_loading_and_native_creation(self):
        for field, value in (("adapter_version", "1.0.0-r2"), ("base_digest", "sha256:" + "b" * 64),
                             ("wheel_sha256", "c" * 64), ("ruleset_sha256", "d" * 64),
                             ("platform", "linux/amd64"), ("image_id", "sha256:bad")):
            lock = YaraxReceiptTests().receipt()["lock"]
            lock[field] = value
            with self.subTest(field=field):
                run = self.run_cli(lock=lock)
                self.assertEqual(run.result, 1)
                self.assertFalse(run.receipt["passed"])
                run.boundary.load_lock.assert_not_called()
                run.loader.assert_not_called()
                run.factory.assert_not_called()
        for mutation in ("missing", "extra"):
            lock = YaraxReceiptTests().receipt()["lock"]
            if mutation == "missing":
                del lock["ruleset_sha256"]
            else:
                lock["unreviewed"] = True
            with self.subTest(keys=mutation):
                run = self.run_cli(lock=lock)
                self.assertEqual(run.result, 1)
                run.boundary.load_lock.assert_not_called()
                run.factory.assert_not_called()

    def test_cli_missing_corrupt_or_oversized_rulesets_are_refused_before_native_creation(self):
        for state in ("missing", "corrupt", "oversized"):
            with self.subTest(ruleset=state):
                run = self.run_cli(ruleset_state=state)
                self.assertEqual(run.result, 1)
                self.assertFalse(run.receipt["passed"])
                run.boundary.load_lock.assert_called_once()
                run.factory.assert_not_called()
                self.assertNotIn("ruleset_sha256", run.receipt)

    def test_controller_failure_marks_only_the_seventeen_yarax_checks_not_run(self):
        lock = YaraxReceiptTests().receipt()["lock"]
        lock["base_digest"] = "sha256:" + "b" * 64
        run = self.run_cli(lock=lock)
        self.assertEqual(run.result, 1)
        self.assertIn({"id": "controller", "status": "failed", "reason": "YaraxLockPins"}, run.receipt["checks"])
        self.assertEqual({row["id"] for row in run.receipt["checks"] if row["status"] == "not_run"},
                         set(verifier.YARAX_REQUIRED_CHECKS))
        self.assertEqual(len(run.receipt["checks"]), 18)

    def test_ruleset_change_during_run_refuses_an_otherwise_complete_receipt(self):
        run = self.run_cli(change="ruleset")
        self.assertEqual(run.result, 1)
        self.assertFalse(run.receipt["passed"])
        self.assertIn({"id": "controller", "status": "failed", "reason": "YaraxRulesetHash"}, run.receipt["checks"])
        self.assertEqual(run.receipt["ruleset_sha256"], sha256_hex(run.reviewed))
        self.assertEqual(run.loader.call_count, 2)

    def test_ruleset_removal_during_run_refuses_an_otherwise_complete_receipt(self):
        run = self.run_cli(change="missing_ruleset")
        self.assertEqual(run.result, 1)
        self.assertFalse(run.receipt["passed"])
        self.assertIn({"id": "controller", "status": "failed", "reason": "YaraxRulesetUnavailable"},
                      run.receipt["checks"])

    def test_yarax_keeps_both_source_change_guards_and_the_original_hashes(self):
        for source in ("verifier", "executor"):
            with self.subTest(source=source):
                run = self.run_cli(change=source)
                self.assertEqual(run.result, 1)
                self.assertFalse(run.receipt["passed"])
                self.assertIn({"id": "controller", "status": "failed", "reason": "SourceChangedDuringVerification"},
                              run.receipt["checks"])
                for name, raw in run.initial.items():
                    self.assertEqual(run.receipt[name + "_sha256"], sha256_hex(raw))

    def test_yarax_runtime_failure_cannot_fall_back_to_lief_or_its_check_list(self):
        run = self.run_cli(native_error=verifier.VerificationError("CannedYaraxFailure"))
        self.assertEqual(run.result, 1)
        self.assertFalse(run.receipt["passed"])
        run.factory.assert_called_once()
        self.assertEqual(run.factory.call_args.kwargs["tool"], "yarax")
        self.assertIn({"id": "controller", "status": "failed", "reason": "CannedYaraxFailure"},
                      run.receipt["checks"])
        self.assertEqual({row["id"] for row in run.receipt["checks"] if row["status"] == "not_run"},
                         set(verifier.YARAX_REQUIRED_CHECKS))

    def test_yarax_cli_requires_explicit_lock_and_receipt_paths(self):
        base = ["--tool", "yarax", "--profile", "small", "--offline"]
        for remaining in ([], ["--lock", "unused-lock.json"], ["--receipt", "unused-receipt.json"]):
            with self.subTest(arguments=remaining), \
                    mock.patch.object(verifier.sys, "stderr", new=io.StringIO()), \
                    mock.patch.object(verifier, "NativeVerifier") as factory, \
                    self.assertRaises(SystemExit) as caught:
                verifier.main(base + remaining)
            self.assertEqual(caught.exception.code, 2)
            factory.assert_not_called()


class FixM2bVerifierTests(unittest.TestCase):
    setUp = NativeRunnerBoundaryTests.setUp
    run_worker = NativeRunnerBoundaryTests.run_worker
    commands = NativeRunnerBoundaryTests.commands

    def test_uncertain_create_refuses_unowned_snapshot_before_removal(self):
        mount = container_fixture()["Mounts"][0]
        invalid = [None, [], [mount, dict(mount)], [{}], ["mount"]]
        invalid.extend([dict(mount, **{field: value})] for field, value in (
            ("Source", str(SNAPSHOT) + "-other-run"), ("Destination", "/other"),
            ("Type", "volume"), ("RW", True), ("RW", 0)))
        for mounts in invalid:
            self.setUp()
            self.boundary.created_id = b""
            inspected = copy.deepcopy(self.boundary.inspect)
            inspected.update(Name="/reverseai-unit-owned", Mounts=mounts)
            with self.subTest(mounts=mounts), mock.patch.object(self.native, "one_inspect", return_value=inspected):
                with self.assertRaisesRegex(verifier.VerificationError, "^CreateCleanupUnverified$"):
                    self.run_worker()
                self.assertFalse(any(argv[:2] in (["docker", "rm"], ["docker", "start"]) for argv in self.commands()))
                self.assertIsNone(self.receipt["cleanup"][0]["container_id"])
                self.assertFalse(self.receipt["cleanup"][0]["verified"])

    def test_create_timeout_absence_requires_successful_exact_name_lookup(self):
        for lookup_error in (None, OSError("lost lookup"), self.boundary.ContainedTimeout("WorkerTimeout")):
            self.setUp()
            primary = self.boundary.ContainedTimeout("WorkerTimeout")
            self.boundary.create_error = primary
            self.boundary.lookup_output = b""
            self.boundary.lookup_error = lookup_error
            with self.subTest(lookup_error=type(lookup_error).__name__):
                with self.assertRaises(Exception) as stopped:
                    self.run_worker()
                row = self.receipt["cleanup"][0]
                self.assertIsNone(row["container_id"])
                self.assertEqual(row["verified"], lookup_error is None)
                if lookup_error is None:
                    self.assertIs(stopped.exception, primary)
                else:
                    self.assertEqual(str(stopped.exception), "CreateCleanupUnverified")
                self.assertEqual([argv[:2] for argv in self.commands()], [["docker", "create"], ["docker", "ps"]])
                self.assertEqual(self.commands()[1][5], "name=^/reverseai-unit-owned$")

    def test_repeated_pull_after_never_is_refused_before_create(self):
        image = self.argv.index(IMAGE_ID)
        for policy in ("always", "never"):
            changed = [*self.argv[:image], "--pull", policy, *self.argv[image:]]
            with self.subTest(policy=policy), mock.patch.object(self.boundary, "build_argv", return_value=changed):
                with self.assertRaisesRegex(verifier.VerificationError, "^BuilderPullPolicy$"):
                    self.native.runner(changed, timeout=45, max_output=262144)
                self.assertEqual(self.commands(), [])

    def test_receipt_with_other_profiles_lock_and_image_is_refused(self):
        lief, yarax = receipt_fixture(), YaraxReceiptTests().receipt()
        yarax["lock"]["adapter_version"] = verifier.YARAX_ADAPTER_VERSION
        yarax["image_id"] = yarax["lock"]["image_id"] = "sha256:" + "e" * 64
        self.assertTrue(verifier.receipt_passes(lief))
        self.assertTrue(verifier.receipt_passes(yarax))
        for receipt, other in ((lief, yarax), (yarax, lief)):
            changed = copy.deepcopy(receipt)
            changed["lock"] = copy.deepcopy(other["lock"])
            changed["image_id"] = other["image_id"]
            with self.subTest(label=receipt["tool"]):
                self.assertFalse(verifier.receipt_passes(changed))


# Independently stated reviewed literals, rather than oracle-derived expectations.
REVIEWED_LITERALS = (
    ("upx_packed", "$a", b"UPX!"),
    ("upx_packed", "$b", b"UPX0"),
    ("upx_packed", "$c", b"UPX1"),
    ("powershell_encoded_command", "$a", b"-EncodedCommand"),
    ("powershell_encoded_command", "$w", "-EncodedCommand".encode("utf-16le")),
    ("base64_decode_api", "$a", b"FromBase64String"),
    ("base64_decode_api", "$w", "FromBase64String".encode("utf-16le")),
    ("credential_dump_marker", "$a", b"sekurlsa::"),
    ("credential_dump_marker", "$w", "sekurlsa::".encode("utf-16le")),
)


class YaraxKnownAnswerRegressionTests(unittest.TestCase):
    setUp = YaraxKnownAnswerTests.setUp
    record = YaraxKnownAnswerTests.record
    observations = YaraxKnownAnswerTests.observations
    compare = YaraxKnownAnswerTests.compare

    def assert_known_answer_accepts(self, data, records, **kwargs):
        # Keep an oracle refusal as an assertion failure in regression challenges.
        try:
            result = self.compare(data, records, **kwargs)
        except verifier.VerificationError as exc:
            self.fail(f"Known answer refused: {exc}")
        self.assertIsNone(result)

    def test_native_fixtures_cover_all_nine_reviewed_ascii_and_utf16_patterns(self):
        reviewed = {(rule, pattern, literal) for rule, pattern, literal in REVIEWED_LITERALS}
        pinned = {(rule["id"], pattern["id"], bytes.fromhex(pattern["hex"]))
                  for rule in self.ruleset["rules"] for pattern in rule["patterns"]}
        self.assertEqual(pinned, reviewed)
        covered = {(rule, pattern) for rule, pattern, literal in REVIEWED_LITERALS
                   if any(literal in data for data in self.data.values())}
        self.assertEqual(covered, {(rule, pattern) for rule, pattern, _ in REVIEWED_LITERALS})
        self.assertEqual(tuple(self.data), verifier.YARAX_FIXTURE_NAMES)
        self.assertEqual(len(self.data), 4)

    def test_first_four_matches_of_each_reviewed_pattern_are_retained(self):
        for rule, pattern, literal in REVIEWED_LITERALS:
            data = (literal + b"\xff") * 6
            records = [self.record(index * (len(literal) + 1), len(literal), rule, pattern)
                       for index in range(4)]
            with self.subTest(rule=rule, pattern=pattern):
                self.assert_known_answer_accepts(data, records)
                fifth = self.record(4 * (len(literal) + 1), len(literal), rule, pattern)
                with self.assertRaises(verifier.VerificationError):
                    self.compare(data, records + [fifth])

    def test_flooded_pattern_does_not_hide_a_later_distinct_rule(self):
        data = self.data["repeated_markers"]
        self.assertEqual(data[320:], b"sekurlsa::")
        records = [self.record(offset, 4) for offset in (0, 4, 8, 12)]
        records.append(self.record(320, 10, "credential_dump_marker"))
        self.assert_known_answer_accepts(data, records)
        with self.assertRaises(verifier.VerificationError):
            self.compare(data, records[:-1])

    def test_every_match_with_wrong_ruleset_label_is_refused_y49(self):
        records = YaraxKnownAnswerTests.upx_records(self)
        self.assert_known_answer_accepts(self.data["upx_markers"], records)
        for record in records:
            record["value"]["ruleset"] = "wrong_reviewed_ruleset"
        with self.assertRaises(verifier.VerificationError):
            self.compare(self.data["upx_markers"], records)

    def test_equal_offset_matches_use_rule_before_pattern_y19(self):
        ruleset = {"ruleset": "m2_fixture_v1", "rules": [
            {"id": "z_rule", "patterns": [{"id": "$b", "hex": "55505821"},
                                             {"id": "$a", "hex": "55505821"}]},
            {"id": "a_rule", "patterns": [{"id": "$z", "hex": "55505821"}]},
        ]}
        records = [self.record(0, 4, "a_rule", "$z"),
                   self.record(0, 4, "z_rule", "$a"),
                   self.record(0, 4, "z_rule", "$b")]
        self.assert_known_answer_accepts(b"UPX!", records, ruleset=ruleset)
        self.assert_known_answer_accepts(b"UPX!", records[:1], max_matches=1, ruleset=ruleset)
        changed = [copy.deepcopy(records[index]) for index in (1, 2, 0)]
        for cap in (1, 64):
            with self.subTest(cap=cap), self.assertRaises(verifier.VerificationError):
                self.compare(b"UPX!", changed[:1] if cap == 1 else changed,
                             max_matches=cap, ruleset=ruleset)


if __name__ == "__main__":
    unittest.main()
