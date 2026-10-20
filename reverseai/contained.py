"""Fixed Docker boundary for the LIEF worker; no native parser runs on the host."""

from collections.abc import Mapping
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
DEFAULT_LOCK = Path(__file__).resolve().parents[1] / "containers/lief/image.lock.json"
WALL_SECONDS = 45
PLATFORM = "linux/arm64"
ADAPTER_VERSION = "1.0.0-r2"
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")


class ContainedError(RuntimeError):
    """A short controller-side error that never contains command output or paths."""


class ContainedTimeout(ContainedError, TimeoutError):
    pass


def load_lock(lock):
    """Copy a lock mapping, or read a small local lock file, and validate its pins."""
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
        if value.get("platform") != PLATFORM or value.get("adapter_version") != ADAPTER_VERSION:
            raise ValueError
        if not _DIGEST.fullmatch(value.get("base_digest", "")):
            raise ValueError
        if not re.fullmatch(r"[0-9a-f]{64}", value.get("wheel_sha256", "")):
            raise ValueError
        return {key: value[key] for key in ("image_id", "platform", "base_digest", "wheel_sha256", "adapter_version")}
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
    raise ContainedError("InvalidWorkerArguments")


def build_argv(image_id, name, staging_folder, operation, args):
    """The single contract argv builder, also used by the native verifier."""
    args = _validated_args(operation, args)
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
        "--user", "65534:65534", "--pids-limit", "64", "--memory", "512m", "--memory-swap", "512m",
        "--cpus", "1", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m", "--log-driver", "none",
        "--mount", f"type=bind,source={folder},target=/snapshot,readonly", image_id, operation, canonical_json(args),
    ]


def run_bounded(argv, *, timeout=WALL_SECONDS, max_output=MAX_WORKER_REPLY_BYTES):
    """Drain at most cap+1 bytes; communicate()/capture_output would be unbounded."""
    # Trusted inspect/kill/probe calls may tighten limits; callers cannot widen them.
    timeout = min(timeout, WALL_SECONDS)
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

    def __init__(self, lock=DEFAULT_LOCK, runner=run_bounded, *, inspect=inspect_image, staging_root=STAGING_ROOT):
        self.lock = MappingProxyType(load_lock(lock))
        self.runner = runner
        self.inspect = inspect
        self.staging_root = Path(staging_root)

    def available(self):
        try:
            return self.inspect(self.lock["image_id"]) == self.lock["image_id"]
        except Exception:
            return False

    def run(self, operation, args, data, input_sha256):
        args = _validated_args(operation, args)
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
            raw = self.runner(argv, timeout=WALL_SECONDS, max_output=MAX_WORKER_REPLY_BYTES)
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
