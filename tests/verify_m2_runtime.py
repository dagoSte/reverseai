"""Native LIEF/YARA-X/Ghidra checks; ordinary unittest discovery never runs Docker.

Run from the repository root with --tool lief (or yarax/ghidra), --profile small --offline,
--lock containers/<tool>/image.lock.json --receipt NEW_PRIVATE_FILE.
Unit tests establish validator behaviour; only a successful native run supplies
runtime evidence for its exact image, platform, executor and verifier hashes.
"""

from __future__ import annotations

import argparse
import csv
import io
import json
import os
from pathlib import Path
import re
import struct
import sys
import textwrap
import threading
import time

if __package__ in (None, ""):
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from reverseai.contract import MAX_WORKER_REPLY_BYTES, Observation, parse_worker_reply, sha256_hex
from reverseai.tools import structure, ghidra_verify
from tests.fixtures_structure import elf, pe
from tests.fixtures_code import elf_code, pe_code, elf_data_only


PLATFORM = "linux/arm64"
ENTRYPOINT = ["python3", "-I", "-B", "/opt/reverseai/worker.py"]
MEMORY = 512 * 1024**2
WALL_SECONDS = 45
PROBE_PROTOCOL = "reverseai.native-probe/1"
FIXTURE_NAMES = ("elf64le", "elf32be", "pe32plus", "pe32plus-distant")
CONTROL_NAMES = ("runtime_identity", "network", "write_root", "write_snapshot", "setuid",
                 "capability", "pids", "memory", "wall", "stdout")
REQUIRED_CHECKS = ("local_daemon", "image", "container", *CONTROL_NAMES,
                   *(f"{name}.{op}" for name in FIXTURE_NAMES for op in ("headers", "sections")))
NATIVE_RUNS = len(CONTROL_NAMES) + 2 * len(FIXTURE_NAMES)
YARAX_RULESET_NAME = "m2_fixture_v1"
YARAX_RULESET_PATH = Path(__file__).resolve().parents[1] / "containers/yarax/m2_fixture_v1.json"
YARAX_RULESET_SHA256 = "e2217ff703858af17fe8eee8ac0d4cc44dfefd632e096bb4b527b89b08a062a7"
YARAX_WHEEL_SHA256 = "9bd9961b44b47dd747d526e61c703a2a8170426d003e789e7724bc7862de6d56"
YARAX_BASE_DIGEST = "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e"
YARAX_ADAPTER_VERSION = "1.21.0-r2"
YARAX_MATCHES_PER_PATTERN = 4
YARAX_FIXTURE_NAMES = ("upx_markers", "utf16_markers", "clean", "repeated_markers")
YARAX_REQUIRED_CHECKS = ("local_daemon", "image", "container", *CONTROL_NAMES,
                         *(f"{name}.matches" for name in YARAX_FIXTURE_NAMES))
YARAX_NATIVE_RUNS = len(CONTROL_NAMES) + len(YARAX_FIXTURE_NAMES)
GHIDRA_ADAPTER_VERSION = "12.1.4-r1"
GHIDRA_BASE_DIGEST = "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e"
GHIDRA_SHA256 = "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db"
GHIDRA_JDK_SHA256 = "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223"
GHIDRA_FIXTURE_NAMES = ("elf_code", "pe_code", "elf_data_only")
GHIDRA_REQUIRED_CHECKS = ("local_daemon", "image", "container", *CONTROL_NAMES,
                          *(f"{name}.analyze" for name in GHIDRA_FIXTURE_NAMES))
GHIDRA_NATIVE_RUNS = len(CONTROL_NAMES) + len(GHIDRA_FIXTURE_NAMES)


class VerificationError(ValueError):
    """Static reasons only: do not echo daemon output, paths or environment."""


def need(condition, reason):
    if not condition:
        raise VerificationError(reason)


def limits(tool):
    """Independent fixed expectations: pids, memory, nanocpus, tmpfs, wall."""
    need(tool in ("lief", "yarax", "ghidra"), "VerifierTool")
    if tool == "ghidra":
        return (256, 2 * 1024**3, 2_000_000_000, "rw,noexec,nosuid,nodev,size=512m", 240)
    return (64, MEMORY, 1_000_000_000, "rw,noexec,nosuid,nodev,size=64m", WALL_SECONDS)


def required_checks(tool):
    need(tool in ("lief", "yarax", "ghidra"), "VerifierTool")
    return {"lief": REQUIRED_CHECKS, "yarax": YARAX_REQUIRED_CHECKS,
            "ghidra": GHIDRA_REQUIRED_CHECKS}[tool]


def native_runs(tool):
    return len(required_checks(tool)) - 3


def lock_options(tool):
    if tool == "ghidra":
        return {"adapter_version": GHIDRA_ADAPTER_VERSION}
    return {} if tool == "lief" else {"adapter_version": YARAX_ADAPTER_VERSION,
                                       "extra_keys": ("ruleset_sha256",)}


def verify_ghidra_executor_profile(boundary):
    profile = boundary.resource_profile("ghidra.analyze")
    expected = {"pids": 256, "memory": "2g", "cpus": 2,
                "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=512m", "wall_seconds": 240}
    need(dict(profile) == expected and all(type(profile[key]) is type(value) for key, value in expected.items()) and
         type(boundary.GHIDRA_WALL_SECONDS) is int and boundary.GHIDRA_WALL_SECONDS == 240,
         "ExecutorGhidraProfile")


def _unique(pairs):
    need(len(pairs) == len({k for k, _ in pairs}), "DuplicateJSONKey")
    return dict(pairs)


def _empty_optional(value, kind):
    return value is None or (type(value) is kind and not value)


def decode(raw):
    try:
        return json.loads(raw, object_pairs_hook=_unique,
                          parse_constant=lambda _: need(False, "InvalidJSONNumber"))
    except (ValueError, UnicodeError, TypeError, RecursionError):
        raise VerificationError("InvalidJSON") from None


def verify_image(image, lock):
    need(isinstance(image, dict) and isinstance(lock, dict), "ImageShape")
    need(image.get("Id") == lock.get("image_id") and
         bool(re.fullmatch(r"sha256:[0-9a-f]{64}", str(lock.get("image_id", "")))), "ImageID")
    need(lock.get("platform") == PLATFORM and image.get("Os") == "linux" and
         image.get("Architecture") == "arm64", "ImagePlatform")
    config = image.get("Config")
    need(isinstance(config, dict), "ImageConfig")
    need(config.get("User") == "65534:65534", "ImageUser")
    need(config.get("Entrypoint") == ENTRYPOINT, "ImageEntrypoint")
    need(_empty_optional(config.get("Volumes"), dict), "ImageVolumes")
    need(isinstance(config.get("Env"), list) and all(isinstance(v, str) for v in config["Env"]), "ImageEnvironment")


def verify_snapshot_mount(data, snapshot):
    mounts = data.get("Mounts")
    need(isinstance(mounts, list) and len(mounts) == 1 and isinstance(mounts[0], dict), "ContainerMountCount")
    mount = mounts[0]
    need(mount.get("Type") == "bind" and mount.get("Destination") == "/snapshot" and
         mount.get("RW") is False and mount.get("Source") == os.fspath(snapshot), "ContainerSnapshotMount")


def verify_container(data, image, lock, snapshot, *, entrypoint=None, command=None, tool="lief"):
    pids, memory, cpus, tmpfs, _ = limits(tool)
    need(isinstance(data, dict), "ContainerShape")
    host, inner, state = data.get("HostConfig"), data.get("Config"), data.get("State")
    need(all(isinstance(v, dict) for v in (host, inner, state)), "ContainerConfig")
    need(data.get("Image") == lock.get("image_id"), "ContainerImage")
    need(state.get("Running") is False, "ContainerAlreadyRunning")
    need(inner.get("User") == "65534:65534", "ContainerUser")
    need(inner.get("Entrypoint") == (ENTRYPOINT if entrypoint is None else entrypoint), "ContainerEntrypoint")
    need(inner.get("Cmd") == (["lief.headers", "{}"] if command is None else command), "ContainerCommand")
    need(inner.get("Env") == image["Config"]["Env"], "ContainerEnvironment")
    need(_empty_optional(inner.get("Volumes"), dict), "ContainerVolumes")
    for field, expected in (("Privileged", False), ("ReadonlyRootfs", True), ("Init", True),
                            ("AutoRemove", True), ("NetworkMode", "none"), ("PidsLimit", pids),
                            ("Memory", memory), ("MemorySwap", memory), ("NanoCpus", cpus)):
        value = host.get(field)
        need(type(value) is type(expected) and value == expected, "Container" + field)
    need(host.get("CapDrop") == ["ALL"] and _empty_optional(host.get("CapAdd"), list), "ContainerCapabilities")
    need(host.get("SecurityOpt") in (["no-new-privileges"], ["no-new-privileges:true"]), "ContainerSecurityOpt")
    need(isinstance(host.get("LogConfig"), dict) and host["LogConfig"].get("Type") == "none", "ContainerLogging")
    need(host.get("Tmpfs") == {"/tmp": tmpfs}, "ContainerTmpfs")
    for field in ("Binds", "VolumesFrom", "Devices", "DeviceRequests", "DeviceCgroupRules", "GroupAdd", "ExtraHosts"):
        need(_empty_optional(host.get(field), list), "Container" + field)
    for field in ("PidMode", "UTSMode", "UsernsMode"):
        need(host.get(field) == "", "Container" + field)
    need(_empty_optional(host.get("PortBindings"), dict) and host.get("PublishAllPorts") is False, "ContainerPorts")
    need(host.get("IpcMode") in ("private", ""), "ContainerIpcMode")
    need(host.get("CgroupnsMode") in ("private", ""), "ContainerCgroupnsMode")
    verify_snapshot_mount(data, snapshot)


def validate_probe(name, value, *, tool="lief"):
    pids, memory, _, _, wall = limits(tool)
    need(isinstance(value, dict) and value.get("protocol") == PROBE_PROTOCOL and value.get("probe") == name,
         "ProbeProtocol")
    need(value.get("skipped", False) is False and value.get("status", "ok") == "ok", "ProbeSkippedOrFailed")
    if name == "runtime_identity":
        for key, expected in (("uid", 65534), ("gid", 65534), ("cap_eff", 0), ("cap_prm", 0),
                              ("cap_inh", 0), ("cap_amb", 0), ("no_new_privs", 1), ("seccomp", 2)):
            need(type(value.get(key)) is int and value[key] == expected, "RuntimeIdentity")
        return
    need(name in CONTROL_NAMES and value.get("attempted") is True and value.get("blocked") is True, "ProbeNotBlocked")
    # These errors prove refusal, not its cause: permission or routing can fail first.
    # Read-only/network policy is established separately by the stopped-container inspect.
    errno_values = {"network": (1, 13, 101, 113), "write_root": (1, 13, 30),
                    "write_snapshot": (1, 13, 30), "setuid": (1, 13), "capability": (1, 13)}
    if name in errno_values:
        need(type(value.get("errno")) is int and value["errno"] in errno_values[name], "ProbeWrongFailure")
    elif name == "pids":
        need(type(value.get("errno")) is int and value["errno"] == 11 and
             type(value.get("limit")) is int and value["limit"] == pids and
             type(value.get("spawned")) is int and 1 <= value["spawned"] < pids, "ProcessLimitNotObserved")
    elif name == "memory":
        need(type(value.get("limit")) is int and value["limit"] == memory and
             type(value.get("child_returncode")) is int and value["child_returncode"] == -9 and
             type(value.get("oom_kill_delta")) is int and value["oom_kill_delta"] > 0, "OOMNotObserved")
    elif name == "wall":
        elapsed = value.get("elapsed")
        need(value.get("error") == "WorkerTimeout" and value.get("running_observed") is True and
             type(value.get("timeout")) is int and value["timeout"] == wall and type(elapsed) in (int, float) and
             wall - 0.5 <= elapsed <= wall + 5, "WallLimitNotObserved")
    elif name == "stdout":
        need(value.get("error") == "WorkerOutputLimit" and type(value.get("max_output")) is int and
             value["max_output"] == MAX_WORKER_REPLY_BYTES,
             "OutputLimitNotObserved")


def fixtures():
    data, layout = pe()
    shift = 0x2000 - layout["lfanew"]
    distant = bytearray(data[:layout["lfanew"]] + bytes(shift) + data[layout["lfanew"]:])
    struct.pack_into("<I", distant, 0x3C, 0x2000)
    for index, offset in enumerate(layout["raw_offsets"]):
        struct.pack_into("<I", distant, layout["table_offset"] + shift + 40 * index + 20, offset + shift)
    return {"elf64le": elf()[0], "elf32be": elf(width=32, order=">", machine=8)[0],
            "pe32plus": data, "pe32plus-distant": bytes(distant)}


def load_yarax_ruleset(lock, path=None):
    try:
        with (YARAX_RULESET_PATH if path is None else Path(path)).open("rb") as stream:
            raw = stream.read(65_537)
    except OSError:
        raise VerificationError("YaraxRulesetUnavailable") from None
    need(len(raw) <= 65_536, "YaraxRulesetTooLarge")
    need(isinstance(lock, dict) and lock.get("ruleset_sha256") == sha256_hex(raw) == YARAX_RULESET_SHA256,
         "YaraxRulesetHash")
    value = decode(raw)
    need(isinstance(value, dict) and value.get("ruleset") == YARAX_RULESET_NAME and
         isinstance(value.get("rules"), list), "YaraxRulesetShape")
    return value


def verify_yarax_lock(lock):
    need(isinstance(lock, dict) and
         set(lock) == {"adapter_version", "base_digest", "image_id", "platform", "ruleset_sha256", "wheel_sha256"},
         "YaraxLockPins")
    need(lock["adapter_version"] == YARAX_ADAPTER_VERSION and lock["platform"] == PLATFORM and
         lock["base_digest"] == YARAX_BASE_DIGEST and lock["wheel_sha256"] == YARAX_WHEEL_SHA256 and
         lock["ruleset_sha256"] == YARAX_RULESET_SHA256 and
         bool(re.fullmatch(r"sha256:[0-9a-f]{64}", str(lock["image_id"]))), "YaraxLockPins")


def verify_ghidra_lock(lock):
    need(isinstance(lock, dict) and set(lock) == {
        "adapter_version", "base_digest", "image_id", "platform", "ghidra_sha256", "jdk_sha256"}, "GhidraLockPins")
    need(lock["adapter_version"] == GHIDRA_ADAPTER_VERSION and lock["platform"] == PLATFORM and
         lock["base_digest"] == GHIDRA_BASE_DIGEST and lock["ghidra_sha256"] == GHIDRA_SHA256 and
         lock["jdk_sha256"] == GHIDRA_JDK_SHA256 and
         isinstance(lock["image_id"], str) and re.fullmatch(r"sha256:[0-9a-f]{64}", lock["image_id"]),
         "GhidraLockPins")


def ghidra_fixtures():
    return dict(zip(GHIDRA_FIXTURE_NAMES, (elf_code()[0], pe_code()[0], elf_data_only()[0])))


def ghidra_args():
    return {"max_functions": 64, "decompile": 8, "max_chars": 1024, "max_calls": 128}


def compare_ghidra_observations(data, observations):
    """Check declared entries/call instructions, without guessing derived names or C."""
    need(type(data) is bytes and isinstance(observations, (list, tuple)), "KnownAnswerShape")
    layout = next((layout for sample, layout in (elf_code(), pe_code(), elf_data_only()) if sample == data), None)
    need(layout is not None, "KnownAnswerFixture")
    groups = {"function": [], "pseudocode": [], "call": []}
    schemas = {"function": {"kind", "index", "name", "entry", "size"},
               "pseudocode": {"kind", "index", "entry", "text", "truncated"},
               "call": {"kind", "from", "to", "to_name"}}
    for item in observations:
        need(isinstance(item, Observation) and item.location.within(len(data)), "KnownAnswerLocation")
        value = item.value
        kind = value.get("kind")
        need(type(kind) is str and kind in groups and set(value) == schemas[kind], "KnownAnswerSchema")
        groups[kind].append(item)
    functions, calls = groups["function"], groups["call"]
    need(len(functions) == len(layout["functions"]) and len(calls) == len(layout["calls"]), "KnownAnswerCount")
    for index, (item, expected) in enumerate(zip(functions, layout["functions"])):
        value = item.value
        remaining = layout.get("text_raw_size", layout["text"]["size"]) - (expected["offset"] - layout["text"]["offset"])
        need(type(value["index"]) is int and value["index"] == index and
             type(value["entry"]) is int and value["entry"] == expected["entry"] and
             type(value["size"]) is int and 1 <= value["size"] and value["entry"] + value["size"] <= 2**64,
             "KnownAnswerFunction")
        need(item.location.offset == expected["offset"] and
             item.location.length == min(value["size"], 4096, remaining), "KnownAnswerFunctionAnchor")
        need(type(value["name"]) is str and 1 <= len(value["name"]) <= 128 and
             value["name"].isprintable(), "KnownAnswerName")
    names = {item.value["entry"]: item.value["name"] for item in functions}
    for item, expected in zip(calls, layout["calls"]):
        value = item.value
        need(type(value["from"]) is int and type(value["to"]) is int and
             (value["from"], value["to"]) == (expected["from"], expected["to"]) and
             (item.location.offset, item.location.length) == (expected["offset"], expected["length"]),
             "KnownAnswerCall")
        need(type(value["to_name"]) is str and value["to_name"] == names[value["to"]], "KnownAnswerName")
    seen = set()
    for item in groups["pseudocode"]:
        value = item.value
        index = value["index"]
        need(type(index) is int and 0 <= index < len(functions) and index not in seen, "KnownAnswerPseudocode")
        function = functions[index]
        need(type(value["entry"]) is int and value["entry"] == function.value["entry"] and
             item.location == function.location and type(value["text"]) is str and len(value["text"]) <= 1024 and
             type(value["truncated"]) is bool, "KnownAnswerPseudocode")
        seen.add(index)


def yarax_fixtures():
    return {
        "upx_markers": b"\x00UPX!----UPX0----UPX1\x00-EncodedCommand\x00FromBase64String\x00sekurlsa::",
        "utf16_markers": b"\x00\x00" + "-EncodedCommand\x00FromBase64String\x00sekurlsa::".encode("utf-16le"),
        "clean": b"deterministic clean fixture\x00",
        "repeated_markers": b"UPX!" * 80 + b"sekurlsa::",
    }


def compare_yarax_observations(data, observations, ruleset, max_matches=64):
    need(isinstance(data, bytes) and isinstance(observations, (list, tuple)) and
         type(max_matches) is int and 1 <= max_matches <= 64, "KnownAnswerShape")
    expected = []
    for rule in ruleset["rules"]:
        for pattern in rule["patterns"]:
            needle, start = bytes.fromhex(pattern["hex"]), 0
            for _ in range(min(YARAX_MATCHES_PER_PATTERN, max_matches)):
                offset = data.find(needle, start)
                if offset < 0:
                    break
                expected.append((offset, len(needle), YARAX_RULESET_NAME, rule["id"], pattern["id"]))
                start = offset + 1
    expected.sort(key=lambda row: (row[0], row[3], row[4]))
    expected = expected[:max_matches]
    actual = []
    for item in observations:
        need(isinstance(item, Observation) and item.location.within(len(data)), "KnownAnswerLocation")
        need(set(item.value) == {"ruleset", "rule", "pattern"} and
             all(type(item.value[key]) is str for key in ("ruleset", "rule", "pattern")), "KnownAnswerMatch")
        actual.append((item.location.offset, item.location.length,
                       item.value["ruleset"], item.value["rule"], item.value["pattern"]))
    need(actual == expected, "KnownAnswerMatches")


def compare_observations(data, operation, observations):
    need(operation in ("lief.headers", "lief.sections") and isinstance(observations, (list, tuple)), "KnownAnswerShape")
    for item in observations:
        need(isinstance(item, Observation) and item.location.within(len(data)), "KnownAnswerLocation")
    headers = structure.headers(data, {})
    expected = headers[0].value
    if operation == "lief.headers":
        kind = expected["format"]
        count = "shnum" if kind == "elf" else "number_of_sections"
        for key in ("format", "machine_name", count):
            values = [item.value[key] for item in observations if key in item.value]
            need(len(values) == 1 and type(values[0]) is type(expected[key]) and values[0] == expected[key],
                 "KnownAnswerHeader")
        if kind == "elf":
            need(len(observations) == 1 and observations[0].location == headers[0].location, "KnownAnswerPhysicalHeader")
        else:
            pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
            optional_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
            records = {item.value.get("structure"): item for item in observations}
            need(len(observations) == 3 and set(records) == {"dos", "coff", "optional"}, "KnownAnswerPEParts")
            need((records["dos"].location.offset, records["dos"].location.length) == (0, 64) and
                 records["dos"].value.get("e_lfanew") == pe_offset, "KnownAnswerDOS")
            need((records["coff"].location.offset, records["coff"].location.length) == (pe_offset, 24) and
                 all(key in records["coff"].value for key in ("format", "machine_name", count)), "KnownAnswerCOFF")
            optional = records["optional"].location
            need(optional.offset == pe_offset + 24 and 20 <= optional.length <= optional_size, "KnownAnswerOptional")
    else:
        expected_sections = structure.sections(data, {"max_sections": 64})
        need(len(observations) == len(expected_sections), "KnownAnswerSectionCount")
        for got, want in zip(observations, expected_sections):
            need(got.location == want.location and all(type(got.value.get(k)) is type(want.value[k]) and
                 got.value[k] == want.value[k] for k in ("index", "offset", "size", "writable", "executable")),
                 "KnownAnswerSection")


def receipt_passes(receipt):
    try:
        tool = receipt.get("tool")
        need(receipt.get("schema") == "reverseai.m2-runtime/1" and receipt.get("platform") == PLATFORM and
             tool in ("lief", "yarax", "ghidra") and receipt.get("profile") == "small" and receipt.get("offline") is True,
             "ReceiptIdentity")
        for key in ("lock_sha256", "verifier_sha256", "executor_sha256"):
            need(bool(re.fullmatch(r"[0-9a-f]{64}", receipt.get(key, ""))), "ReceiptBinding")
        pins = receipt["lock"]
        need(pins["platform"] == PLATFORM and receipt["image_id"] == pins["image_id"] and
             bool(re.fullmatch(r"sha256:[0-9a-f]{64}", pins["image_id"])), "ReceiptImage")
        if tool == "ghidra":
            verify_ghidra_lock(pins)
            need("ruleset_sha256" not in receipt and "wheel_sha256" not in receipt, "ReceiptGhidraPins")
        else:
            need(bool(re.fullmatch(r"sha256:[0-9a-f]{64}", pins["base_digest"])) and
                 bool(re.fullmatch(r"[0-9a-f]{64}", pins["wheel_sha256"])) and
                 pins["adapter_version"] == ("1.0.0-r2" if tool == "lief" else YARAX_ADAPTER_VERSION), "ReceiptLockPins")
            if tool == "yarax":
                verify_yarax_lock(pins)
                need(receipt.get("ruleset_sha256") == YARAX_RULESET_SHA256, "ReceiptYaraxPins")
        required, runs = required_checks(tool), native_runs(tool)
        rows = receipt["checks"]
        need(isinstance(rows, list) and len(rows) == len(required) and
             {r["id"] for r in rows} == set(required) and all(r["status"] == "passed" for r in rows),
             "ReceiptChecks")
        cleanup = receipt["cleanup"]
        need(len(cleanup) == runs and len({r["container_id"] for r in cleanup}) == runs and
             all(re.fullmatch(r"[0-9a-f]{64}", r["container_id"]) and r["verified"] is True and
                 r["staging_removed"] is True for r in cleanup), "ReceiptCleanup")
        return True
    except (VerificationError, KeyError, TypeError, AttributeError):
        return False


def probe_code(name, *, tool="lief"):
    """Fixed trusted probes only; none of this code is supplied by a sample."""
    pids, memory, _, _, wall = limits(tool)
    bodies = {
        "runtime_identity": """
            fields = dict(line.split(':', 1) for line in open('/proc/self/status') if ':' in line)
            r.update(uid=os.getuid(), gid=os.getgid(),
                     cap_eff=int(fields['CapEff'],16), cap_prm=int(fields['CapPrm'],16),
                     cap_inh=int(fields['CapInh'],16), cap_amb=int(fields['CapAmb'],16),
                     no_new_privs=int(fields['NoNewPrivs']), seccomp=int(fields['Seccomp']))
        """,
        "network": """
            try:
                with socket.socket() as connection:
                    connection.settimeout(1)
                    connection.connect(('198.51.100.1',443))
            except OSError as exc:
                r.update(blocked=True,errno=exc.errno)
        """,
        "write_root": """
            try:
                with open('/reverseai-negative-control','xb') as stream:
                    stream.write(b'x')
            except OSError as exc:
                r.update(blocked=True,errno=exc.errno)
        """,
        "write_snapshot": """
            try:
                with open('/snapshot/input','ab') as stream:
                    stream.write(b'x')
            except OSError as exc:
                r.update(blocked=True,errno=exc.errno)
        """,
        "setuid": """
            try:
                os.setuid(0)
            except OSError as exc:
                r.update(blocked=True,errno=exc.errno)
        """,
        "capability": """
            try:
                with socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP):
                    pass
            except OSError as exc:
                r.update(blocked=True,errno=exc.errno)
        """,
        "pids": f"""
            children=[]
            r['limit']=int(open('/sys/fs/cgroup/pids.max').read())
            try:
                for _ in range({pids + 16}):
                    try:
                        child=os.fork()
                    except OSError as exc:
                        r.update(blocked=True,errno=exc.errno)
                        break
                    if child==0:
                        time.sleep(8)
                        os._exit(0)
                    children.append(child)
                r['spawned']=len(children)
            finally:
                for child in children:
                    try:
                        os.kill(child,9)
                    except ProcessLookupError:
                        pass
                for child in children:
                    os.waitpid(child,0)
        """,
        "memory": f"""
            def oom_kills():
                return int(dict(line.split() for line in open('/sys/fs/cgroup/memory.events'))['oom_kill'])
            r['limit']=int(open('/sys/fs/cgroup/memory.max').read())
            before=oom_kills()
            child=subprocess.run([sys.executable,'-I','-B','-c','x=bytearray({memory // 1024**2 + 88}*1024*1024);x[0]=1'],
                                 stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
            r.update(child_returncode=child.returncode,oom_kill_delta=oom_kills()-before,
                     blocked=child.returncode==-9)
        """,
    }
    if name == "wall":
        return f"import time; time.sleep({wall + 15})"
    if name == "stdout":
        return f"import sys; sys.stdout.buffer.write(b'x'*{MAX_WORKER_REPLY_BYTES + 1}); sys.stdout.buffer.flush()"
    need(name in bodies, "UnknownProbe")
    header = ("import json,os,socket,subprocess,sys,time\n"
              + "r=" + repr({"protocol": PROBE_PROTOCOL, "probe": name, "attempted": True, "blocked": False}) + "\n")
    return header + textwrap.dedent(bodies[name]) + "\nprint(json.dumps(r,separators=(',',':')),flush=True)\n"


def derive_control_argv(argv, image_id, code=None):
    """Change only the lifecycle and, for controls, the fixed entrypoint/tail."""
    need(isinstance(argv, list) and all(isinstance(v, str) for v in argv) and
         argv[:2] == ["docker", "run"] and argv.count(image_id) == 1, "BuilderArgv")
    need(code is None or isinstance(code, str), "ControlCodeType")
    at = argv.index(image_id)
    options = argv[2:at]
    pulls = [index for index, value in enumerate(options) if value == "--pull"]
    need(len(pulls) == 1 and pulls[0] + 1 < len(options) and options[pulls[0] + 1] == "never" and
         not any(value.startswith("--pull=") for value in options), "BuilderPullPolicy")
    result = list(argv)
    result[1] = "create"
    if code is not None:
        result = result[:at] + ["--entrypoint", "python3", image_id, "-I", "-B", "-c", code]
    # Flags are copied verbatim; exact-output tests cover both transformations.
    return result


class NativeVerifier:
    """A native controller; constructors and all unit validators are Docker-free."""

    def __init__(self, boundary, lock, receipt, *, tool="lief", ruleset=None):
        need(tool in ("lief", "yarax", "ghidra"), "VerifierTool")
        need(tool != "yarax" or isinstance(ruleset, dict), "YaraxRulesetShape")
        if tool == "yarax":
            verify_yarax_lock(lock)
        if tool == "ghidra":
            verify_ghidra_lock(lock)
            verify_ghidra_executor_profile(boundary)
        self.boundary, self.lock, self.receipt = boundary, lock, receipt
        self.tool, self.ruleset = tool, ruleset
        self.native_runs = native_runs(tool)
        self.wall = limits(tool)[4]
        self.image = None
        self.active = None
        self.inspected = 0
        self.last = None

    def docker(self, args, *, cap=1_048_576):
        return self.boundary.run_bounded(["docker", *args], timeout=5, max_output=cap)

    def run_bounded(self, argv, *, timeout, max_output):
        options = {"profile": "ghidra"} if self.tool == "ghidra" else {}
        return self.boundary.run_bounded(argv, timeout=timeout, max_output=max_output, **options)

    def one_inspect(self, args):
        value = decode(self.docker(args))
        need(isinstance(value, list) and len(value) == 1 and isinstance(value[0], dict), "InspectShape")
        return value[0]

    def local_daemon(self):
        need(not os.environ.get("DOCKER_HOST") and not os.environ.get("DOCKER_CONTEXT"), "DockerEnvironmentOverride")
        context = self.one_inspect(["context", "inspect"])
        endpoint = context.get("Endpoints", {}).get("docker", {}).get("Host", "")
        need(isinstance(endpoint, str) and endpoint.startswith("unix:///"), "NonlocalDockerDaemon")
        server = decode(self.docker(["version", "--format", "{{json .Server}}"], cap=65_536))
        need(isinstance(server, dict) and server.get("Os") == "linux" and server.get("Arch") == "arm64", "DaemonPlatform")
        return {"os": server["Os"], "arch": server["Arch"], "version": server.get("Version")}

    def image_check(self):
        self.image = self.one_inspect(["image", "inspect", self.lock["image_id"]])
        verify_image(self.image, self.lock)
        self.receipt["image_id"] = self.image["Id"]
        return {"image_id": self.image["Id"], "platform": PLATFORM}

    def absent(self, container_id):
        try:
            output = self.docker(["ps", "--all", "--no-trunc", "--filter", "id=" + container_id,
                                  "--format", "{{.ID}}"], cap=256)
            return output.strip() == b""
        except Exception:
            return False

    def cleanup(self, row):
        try:
            self.docker(["rm", "--force", row["container_id"]], cap=256)
        except Exception:
            pass  # An auto-removed container is proved absent by a successful ps.
        row["verified"] = self.absent(row["container_id"])
        need(row["verified"], "ContainerCleanupUnverified")

    def reconcile_create(self, name, snapshot):
        row = {"container_id": None, "container_name": name, "uncertain_create": True,
               "verified": False, "staging_removed": False}
        self.receipt["cleanup"].append(row)
        self.last = (row, Path(snapshot))
        try:
            raw = self.docker(["ps", "--all", "--no-trunc", "--filter", "name=^/" + name + "$",
                               "--format", "{{.ID}}"], cap=256)
            ids = raw.decode("ascii").strip().splitlines()
            need(len(ids) <= 1 and all(re.fullmatch(r"[0-9a-f]{64}", cid) for cid in ids), "CreateLookupID")
            if ids:
                cid = ids[0]
                data = self.one_inspect(["inspect", cid])
                need(data.get("Id") == cid and data.get("Name") == "/" + name and
                     data.get("Image") == self.lock["image_id"], "CreateLookupOwnership")
                verify_snapshot_mount(data, snapshot)
                row["container_id"] = cid
                self.cleanup(row)
            else:
                row["verified"] = True  # Observed absent at this lookup; a late daemon create remains possible.
        except Exception:
            raise VerificationError("CreateCleanupUnverified") from None

    def runner(self, argv, *, timeout, max_output):
        if argv[:2] != ["docker", "run"]:
            return self.run_bounded(argv, timeout=timeout, max_output=max_output)
        need(type(timeout) is int and timeout == self.wall and max_output == MAX_WORKER_REPLY_BYTES,
             "ExecutorLimitsChanged")
        name = argv[argv.index("--name") + 1]
        need(bool(re.fullmatch(r"reverseai-[a-z0-9-]{1,64}", name)), "BuilderContainerName")
        mount = next(csv.reader(io.StringIO(argv[argv.index("--mount") + 1])))
        sources = [item.removeprefix("source=") for item in mount if item.startswith("source=")]
        need(len(sources) == 1, "BuilderSnapshot")
        snapshot = sources[0]
        at = argv.index(self.lock["image_id"])
        operation, args = argv[at + 1], decode(argv[at + 2])
        if self.tool == "ghidra":
            need(operation == "ghidra.analyze" and args == ghidra_args(), "GhidraRequestChanged")
        need(argv == self.boundary.build_argv(self.lock["image_id"], name, snapshot, operation, args), "BuilderMismatch")
        code = probe_code(self.active, tool=self.tool) if self.active is not None else None
        created = derive_control_argv(argv, self.lock["image_id"], code)
        try:
            raw = self.boundary.run_bounded(created, timeout=5, max_output=128)
            need(isinstance(raw, bytes), "CreatedContainerID")
            cid = raw.decode("ascii", errors="replace").strip()
            need(bool(re.fullmatch(r"[0-9a-f]{64}", cid)), "CreatedContainerID")
        except BaseException:
            self.reconcile_create(name, snapshot)
            raise
        row = {"container_id": cid, "verified": False, "staging_removed": False}
        self.receipt["cleanup"].append(row)
        self.last = (row, Path(snapshot))
        stop, running = threading.Event(), threading.Event()
        watcher = None
        try:
            data = self.one_inspect(["inspect", cid])
            need(data.get("Id") == cid, "InspectContainerID")
            command = argv[at + 1:] if code is None else ["-I", "-B", "-c", code]
            entrypoint = ENTRYPOINT if code is None else ["python3"]
            verify_container(data, self.image, self.lock, snapshot, entrypoint=entrypoint, command=command,
                             tool=self.tool)
            self.inspected += 1
            if self.active == "wall":
                def observe_running():
                    while not stop.is_set():
                        try:
                            raw = self.boundary.run_bounded(["docker", "inspect", "--format", "{{.State.Running}}", cid],
                                                            timeout=2, max_output=16)
                            if raw.strip() == b"true":
                                running.set()
                                return
                        except Exception:
                            pass
                        stop.wait(0.1)
                watcher = threading.Thread(target=observe_running, daemon=True)
                watcher.start()
            started = time.monotonic()
            try:
                return self.run_bounded(["docker", "start", "--attach", cid],
                                        timeout=timeout, max_output=max_output)
            except self.boundary.ContainedTimeout as exc:
                need(self.active == "wall" and str(exc) == "WorkerTimeout", "UnexpectedTimeout")
                result = {"protocol": PROBE_PROTOCOL, "probe": "wall", "attempted": True, "blocked": True,
                          "error": "WorkerTimeout", "running_observed": running.is_set(),
                          "elapsed": time.monotonic() - started, "timeout": timeout}
                return json.dumps(result).encode()
            except self.boundary.ContainedError as exc:
                need(self.active == "stdout" and str(exc) == "WorkerOutputLimit", "UnexpectedWorkerFailure")
                return json.dumps({"protocol": PROBE_PROTOCOL, "probe": "stdout", "attempted": True, "blocked": True,
                                   "error": "WorkerOutputLimit", "max_output": max_output}).encode()
        finally:
            stop.set()
            try:
                self.cleanup(row)
            finally:
                if watcher is not None:
                    watcher.join(timeout=2.5)
                    need(not watcher.is_alive(), "MonitorCleanupUnverified")

    def invoke(self, data, operation, args, *, probe=None):
        self.active, self.last = probe, None
        executor = self.boundary.DockerExecutor(self.lock, runner=self.runner, **lock_options(self.tool))
        try:
            return executor.run(operation, args, data, sha256_hex(data))
        finally:
            if self.last is not None:
                row, snapshot = self.last
                row["staging_removed"] = not snapshot.exists()
                need(row["staging_removed"], "SnapshotCleanupUnverified")
            self.active = None

    def record(self, name, check):
        try:
            evidence = check()
            row = {"id": name, "status": "passed", "evidence": evidence}
        except Exception as exc:
            reason = str(exc) if isinstance(exc, VerificationError) else type(exc).__name__
            row = {"id": name, "status": "failed", "reason": reason}
        self.receipt["checks"].append(row)
        return row["status"] == "passed"

    def control(self, name, data):
        operation = "lief.headers" if self.tool == "lief" else "yarax.matches"
        args = {} if self.tool == "lief" else {"ruleset": YARAX_RULESET_NAME, "max_matches": 32}
        if self.tool == "ghidra":
            operation, args = "ghidra.analyze", ghidra_args()
        value = decode(self.invoke(data, operation, args, probe=name))
        validate_probe(name, value, tool=self.tool)
        return value

    def known_answer(self, data, operation):
        if self.tool == "ghidra":
            need(operation == "ghidra.analyze", "KnownAnswerShape")
            raw = self.invoke(data, operation, ghidra_args())
            observations = parse_worker_reply(raw, input_sha256=sha256_hex(data), max_observations=400)
            ghidra_verify.verify(data, observations, ghidra_args())
            compare_ghidra_observations(data, observations)
            return {"input_sha256": sha256_hex(data), "input_bytes": len(data), "observations": len(observations)}
        if self.tool == "yarax":
            need(operation == "yarax.matches", "KnownAnswerShape")
            raw = self.invoke(data, operation, {"ruleset": YARAX_RULESET_NAME, "max_matches": 64})
            observations = parse_worker_reply(raw, input_sha256=sha256_hex(data), max_observations=64)
            compare_yarax_observations(data, observations, self.ruleset, max_matches=64)
            return {"input_sha256": sha256_hex(data), "input_bytes": len(data), "observations": len(observations)}
        raw = self.invoke(data, operation, {} if operation == "lief.headers" else {"max_sections": 64})
        observations = parse_worker_reply(raw, input_sha256=sha256_hex(data),
                                          max_observations=3 if operation == "lief.headers" else 64)
        compare_observations(data, operation, observations)
        return {"input_sha256": sha256_hex(data), "input_bytes": len(data), "observations": len(observations)}

    def run(self):
        if not self.record("local_daemon", self.local_daemon) or not self.record("image", self.image_check):
            return
        values = fixtures() if self.tool == "lief" else yarax_fixtures() if self.tool == "yarax" else ghidra_fixtures()
        control_data = values[{"lief": "elf64le", "yarax": "upx_markers", "ghidra": "elf_code"}[self.tool]]
        for name in CONTROL_NAMES:
            self.record(name, lambda name=name: self.control(name, control_data))
        for name, data in values.items():
            for op in (("headers", "sections") if self.tool == "lief" else
                       ("matches",) if self.tool == "yarax" else ("analyze",)):
                self.record(f"{name}.{op}", lambda data=data, op=op: self.known_answer(data, self.tool + "." + op))
        self.record("container", lambda: need(self.inspected == self.native_runs, "ContainerInspectionMissing"))


def write_receipt(path, receipt):
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(receipt, stream, sort_keys=True, indent=2, allow_nan=False)
        stream.write("\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tool", choices=("lief", "yarax", "ghidra"), required=True)
    parser.add_argument("--profile", choices=("small",), required=True)
    parser.add_argument("--offline", action="store_true", required=True)
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    receipt = {"schema": "reverseai.m2-runtime/1", "tool": args.tool, "profile": args.profile,
               "offline": args.offline, "platform": PLATFORM, "checks": [], "cleanup": []}
    interrupted = False
    try:
        receipt["verifier_sha256"] = sha256_hex(Path(__file__).read_bytes())
        from reverseai import contained
        need(contained.WALL_SECONDS == WALL_SECONDS, "ExecutorWallLimit")
        with args.lock.open("rb") as stream:
            raw = stream.read(16_385)
        need(len(raw) <= 16_384, "LockTooLarge")
        receipt["lock_sha256"] = sha256_hex(raw)
        candidate_lock = decode(raw)
        if args.tool == "yarax":
            verify_yarax_lock(candidate_lock)
        if args.tool == "ghidra":
            verify_ghidra_lock(candidate_lock)
            verify_ghidra_executor_profile(contained)
        receipt["lock"] = contained.load_lock(candidate_lock, **lock_options(args.tool))
        ruleset = None
        if args.tool == "yarax":
            ruleset = load_yarax_ruleset(receipt["lock"])
            receipt["ruleset_sha256"] = receipt["lock"]["ruleset_sha256"]
        executor_source = Path(contained.__file__)
        receipt["executor_sha256"] = sha256_hex(executor_source.read_bytes())
        if args.tool == "lief":
            NativeVerifier(contained, receipt["lock"], receipt).run()
        elif args.tool == "yarax":
            NativeVerifier(contained, receipt["lock"], receipt, tool="yarax", ruleset=ruleset).run()
            load_yarax_ruleset(receipt["lock"])
        else:
            NativeVerifier(contained, receipt["lock"], receipt, tool="ghidra").run()
        need(receipt["verifier_sha256"] == sha256_hex(Path(__file__).read_bytes()) and
             receipt["executor_sha256"] == sha256_hex(executor_source.read_bytes()), "SourceChangedDuringVerification")
    except KeyboardInterrupt:
        interrupted = True
        receipt["checks"].append({"id": "interrupted", "status": "failed"})
    except Exception as exc:
        receipt["checks"].append({"id": "controller", "status": "failed",
                                  "reason": str(exc) if isinstance(exc, VerificationError) else type(exc).__name__})
    recorded = {row["id"] for row in receipt["checks"]}
    required = required_checks(args.tool)
    receipt["checks"].extend({"id": name, "status": "not_run"} for name in required if name not in recorded)
    receipt["passed"] = receipt_passes(receipt)
    try:
        write_receipt(args.receipt, receipt)
    except (OSError, ValueError):
        print("Native verification receipt refused", file=sys.stderr)
        return 1
    print("Native containment " + ("passed" if receipt["passed"] else "failed"), file=sys.stderr)
    return 130 if interrupted else 0 if receipt["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
