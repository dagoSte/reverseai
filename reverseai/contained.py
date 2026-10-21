"""Fixed Docker boundary for contained tools; no native tool runs on the host."""

from collections.abc import Mapping
from functools import partial
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import stat
import subprocess
import sys
import tempfile
import time
from types import MappingProxyType
import uuid

from reverseai.contract import MAX_WORKER_REPLY_BYTES, canonical_json, sha256_hex

STAGING_ROOT = Path("/Users/Shared/rea-safe-staging-501")
WALL_SECONDS = 45
GHIDRA_WALL_SECONDS = 240
PLATFORM = "linux/arm64"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
GHIDRA_VERSION = "12.1.4-r5"
GHIDRA_PINS = MappingProxyType({
    "base_digest": "sha256:16bf2b5c59a08523519d3c8589deca849285dee1d62a3653e124c3dba340f15e",
    "ghidra_sha256": "ddac49f903da9d5bac833e5cc79395098b9c33cfd3279be5f31bd00387d2d4db",
    "jdk_sha256": "23e37e026f12f3e706f18938ff611db3032d075b09d0879a25d06718c773e223",
})
_LEGACY_PROFILE = MappingProxyType({"pids": 64, "memory": "512m", "cpus": 1,
    "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=64m", "wall_seconds": WALL_SECONDS})
_GHIDRA_PROFILE = MappingProxyType({"pids": 256, "memory": "2g", "cpus": 2,
    "tmpfs": "/tmp:rw,noexec,nosuid,nodev,size=512m", "wall_seconds": GHIDRA_WALL_SECONDS})


def resource_profile(operation):
    """Only the validated operation selects resources; requests cannot override them."""
    if operation == "ghidra.analyze":
        return _GHIDRA_PROFILE
    if operation in ("lief.headers", "lief.sections", "yarax.matches"):
        return _LEGACY_PROFILE
    raise ContainedError("InvalidWorkerArguments")


class ContainedError(RuntimeError):
    """A short controller-side error that never contains command output or paths."""


class ContainedTimeout(ContainedError, TimeoutError):
    pass


def load_lock(lock, *, adapter_version="1.0.0-r2", extra_keys=()):
    """Validate tool-provided pins; the default version preserves legacy M2a callers."""
    try:
        if isinstance(lock, Mapping):
            value = dict(lock)
        else:
            with Path(lock).open("rb") as stream:
                raw = stream.read(16_385)
            if len(raw) > 16_384:
                raise ValueError
            value = json.loads(raw)
        if not isinstance(value, dict) or not _DIGEST.fullmatch(value.get("image_id", "")):
            raise ValueError
        if value.get("platform") != PLATFORM or value.get("adapter_version") != adapter_version:
            raise ValueError
        if not _DIGEST.fullmatch(value.get("base_digest", "")):
            raise ValueError
        if adapter_version == GHIDRA_VERSION:
            keys = ("image_id", "platform", "adapter_version", *GHIDRA_PINS)
            if extra_keys or set(value) != set(keys) or any(value[key] != pin for key, pin in GHIDRA_PINS.items()):
                raise ValueError
        else:
            if not re.fullmatch(r"[0-9a-f]{64}", value.get("wheel_sha256", "")):
                raise ValueError
            keys = ("image_id", "platform", "base_digest", "wheel_sha256", "adapter_version") + tuple(extra_keys)
        if extra_keys and (set(value) != set(keys) or any(
                not re.fullmatch(r"[0-9a-f]{64}", value.get(key, "")) for key in extra_keys)):
            raise ValueError
        return {key: value[key] for key in keys}
    except (OSError, ValueError, TypeError):
        raise ContainedError("InvalidImageLock") from None


def _validated_args(operation, args):
    # Validate here as well as at the gateway: this is the last boundary before argv.
    if not isinstance(args, Mapping):
        raise ContainedError("InvalidWorkerArguments")
    if operation == "lief.headers" and not args:
        return {}
    if operation == "lief.sections" and not set(args) - {"max_sections"}:
        count = args.get("max_sections", 32)
        if type(count) is int and 1 <= count <= 64:
            return {"max_sections": count}
    if operation == "yarax.matches" and not set(args) - {"ruleset", "max_matches"}:
        count = args.get("max_matches", 32)
        if args.get("ruleset", "m2_fixture_v1") == "m2_fixture_v1" and type(count) is int and 1 <= count <= 64:
            return {"ruleset": "m2_fixture_v1", "max_matches": count}
    if operation == "ghidra.analyze" and not set(args) - {"max_functions", "decompile", "max_chars", "max_calls",
                                                       "assembly", "max_instructions", "max_refs", "max_strings"}:
        bounds = {"max_functions": (1, 128, 64), "decompile": (0, 16, 8),
                  "max_chars": (64, 2048, 1024), "max_calls": (0, 256, 128),
                  "assembly": (0, 8, 4), "max_instructions": (1, 64, 32),
                  "max_refs": (0, 128, 64), "max_strings": (0, 64, 32)}
        checked = {key: args.get(key, default) for key, (_, _, default) in bounds.items()}
        if all(type(checked[key]) is int and low <= checked[key] <= high for key, (low, high, _) in bounds.items()):
            return checked
    raise ContainedError("InvalidWorkerArguments")


def build_argv(image_id, name, staging_folder, operation, args):
    """The single contract argv builder, also used by the native verifier."""
    args = _validated_args(operation, args)
    profile = resource_profile(operation)
    folder = os.fspath(staging_folder)
    if not isinstance(image_id, str) or not _DIGEST.fullmatch(image_id):
        raise ContainedError("InvalidImageLock")
    if not re.fullmatch(r"reverseai-[a-z0-9]{1,64}", name):
        raise ContainedError("InvalidContainerName")
    if not isinstance(folder, str) or not os.path.isabs(folder) or any(c in folder for c in ",\r\n\x00"):
        raise ContainedError("InvalidStagingFolder")
    return [
        "docker", "run", "--rm", "--init", "--pull", "never", "--name", name, "--platform", PLATFORM,
        "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--user", "65534:65534", "--pids-limit", str(profile["pids"]), "--memory", profile["memory"],
        "--memory-swap", profile["memory"], "--cpus", str(profile["cpus"]), "--tmpfs", profile["tmpfs"], "--log-driver", "none",
        "--mount", f"type=bind,source={folder},target=/snapshot,readonly", image_id, operation, canonical_json(args),
    ]


def run_bounded(argv, *, timeout=WALL_SECONDS, max_output=MAX_WORKER_REPLY_BYTES, profile="default"):
    """Drain at most cap+1 bytes; communicate()/capture_output would be unbounded."""
    # Trusted controllers select a fixed profile; calls may only tighten its limits.
    if profile not in ("default", "ghidra"):
        raise ContainedError("InvalidWorkerArguments")
    timeout = min(timeout, GHIDRA_WALL_SECONDS if profile == "ghidra" else WALL_SECONDS)
    max_output = min(max_output, MAX_WORKER_REPLY_BYTES)
    process = None
    try:
        deadline = time.monotonic() + timeout
        process = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.DEVNULL, shell=False)
        output = bytearray()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = deadline - time.monotonic()
                if remaining <= 0 or not selector.select(remaining):
                    raise ContainedTimeout("WorkerTimeout")
                chunk = os.read(process.stdout.fileno(), min(65_536, max_output + 1 - len(output)))
                if not chunk:
                    selector.unregister(process.stdout)
                    break
                output.extend(chunk)
                if len(output) > max_output:
                    raise ContainedError("WorkerOutputLimit")
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ContainedTimeout("WorkerTimeout")
        if process.wait(timeout=remaining) != 0:
            raise ContainedError("WorkerProcessError")
        return bytes(output)
    except ContainedError:
        raise
    except subprocess.TimeoutExpired:
        raise ContainedTimeout("WorkerTimeout") from None
    except OSError:
        raise ContainedError("WorkerProcessError") from None
    finally:
        if process is not None:
            if process.poll() is None:
                process.kill()
                process.wait()
            process.stdout.close()


def inspect_image(image_id):
    raw = run_bounded(["docker", "image", "inspect", "--format", "{{.Id}}", image_id], timeout=5, max_output=128)
    try:
        return raw.decode("ascii").strip()
    except UnicodeError:
        raise ContainedError("ImageUnavailable") from None


class DockerExecutor:
    """runner(argv, *, timeout, max_output) -> bytes; inspect(image_id) -> local ID.

    Injections allow unit tests without Docker or the shared staging directory.
    The lock is frozen at construction so the reported identity matches every run.
    """

    def __init__(self, lock, runner=None, *, adapter_version="1.0.0-r2", extra_keys=(),
                 inspect=inspect_image, staging_root=STAGING_ROOT):
        self.lock = MappingProxyType(load_lock(lock, adapter_version=adapter_version, extra_keys=extra_keys))
        self.runner = runner if runner is not None else (
            partial(run_bounded, profile="ghidra") if adapter_version == GHIDRA_VERSION else run_bounded)
        self.inspect = inspect
        self.staging_root = Path(staging_root)

    def available(self):
        try:
            return self.inspect(self.lock["image_id"]) == self.lock["image_id"]
        except Exception:
            return False

    def run(self, operation, args, data, input_sha256):
        args = _validated_args(operation, args)
        if (operation == "ghidra.analyze") != (self.lock["adapter_version"] == GHIDRA_VERSION):
            raise ContainedError("InvalidWorkerArguments")
        if not isinstance(data, bytes) or sha256_hex(data) != input_sha256:
            raise ContainedError("SnapshotMismatch")
        if not self.available():
            raise ContainedError("ImageUnavailable")
        folder, started, succeeded = None, False, False
        name = "reverseai-" + uuid.uuid4().hex
        try:
            # Caller-owned private root (0700); same-user lstat/mkdtemp swaps are out of scope.
            root = self.staging_root.lstat()
            if not stat.S_ISDIR(root.st_mode) or root.st_uid != os.geteuid() or root.st_mode & 0o077:
                raise ContainedError("UnsafeStagingFolder")
            folder = Path(tempfile.mkdtemp(prefix="reverseai-", dir=self.staging_root))
            os.chmod(folder, 0o700)
            with (folder / "input").open("xb") as stream:
                stream.write(data)
                os.fchmod(stream.fileno(), 0o444)
            os.chmod(folder, 0o555)
            argv = build_argv(self.lock["image_id"], name, folder, operation, args)
            started = True
            raw = self.runner(argv, timeout=resource_profile(operation)["wall_seconds"], max_output=MAX_WORKER_REPLY_BYTES)
            if not isinstance(raw, bytes) or len(raw) > MAX_WORKER_REPLY_BYTES:
                raise ContainedError("WorkerOutputLimit")
            started = False  # --rm has removed the successfully completed container.
            succeeded = True
            return raw
        except (ContainedError, KeyboardInterrupt, SystemExit):
            raise
        except (TimeoutError, subprocess.TimeoutExpired):
            raise ContainedTimeout("WorkerTimeout") from None
        except Exception:
            raise ContainedError("WorkerProcessError") from None
        finally:
            failure = None if succeeded else sys.exception()
            if started:
                try:
                    self.runner(["docker", "kill", name], timeout=5, max_output=256)
                except Exception:
                    pass  # Preserve the original failure; Docker may already have removed it.
            if folder is not None:
                try:
                    os.chmod(folder, 0o700)
                    shutil.rmtree(folder)
                except OSError:
                    if failure is None:
                        raise ContainedError("StagingCleanupError") from None
                    failure.add_note("StagingCleanupError")
