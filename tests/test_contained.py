"""Controller tests use inert bytes and fake Docker; process probes run Python only."""

import json
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from reverseai.contained import (
    DockerExecutor, ContainedError, ContainedTimeout, MAX_WORKER_REPLY_BYTES,
    build_argv, load_lock, run_bounded,
)
from reverseai.contract import sha256_hex


def lock():
    return {"image_id": "sha256:" + "a" * 64, "platform": "linux/arm64",
            "base_digest": "sha256:" + "b" * 64, "wheel_sha256": "c" * 64, "adapter_version": "1.0.0-r1"}


class ExecutorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.calls = []
        self.data = b"inert snapshot, never executed"

    def executor(self, runner=None, inspect=None):
        return DockerExecutor(lock(), runner=runner or self.runner,
                              inspect=inspect or (lambda image: image), staging_root=self.root)

    def runner(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        if argv[1] == "kill":
            return b""
        mount = argv[argv.index("--mount") + 1]
        folder = Path(mount.split("source=", 1)[1].split(",target=", 1)[0])
        self.assertEqual(folder.parent, self.root)
        self.assertEqual(stat.S_IMODE(folder.stat().st_mode), 0o555)
        self.assertEqual(stat.S_IMODE((folder / "input").stat().st_mode), 0o444)
        self.assertEqual((folder / "input").read_bytes(), self.data)
        self.assertEqual(list(folder.iterdir()), [folder / "input"])
        return b'{"synthetic":true}'

    def run_executor(self, executor):
        return executor.run("lief.sections", {"max_sections": 17}, self.data, sha256_hex(self.data))

    def test_success_uses_the_exact_contract_argv_and_removes_snapshot(self):
        self.assertEqual(self.run_executor(self.executor()), b'{"synthetic":true}')
        argv, kwargs = self.calls[0]
        name, mount = argv[argv.index("--name") + 1], argv[argv.index("--mount") + 1]
        self.assertRegex(name, r"^reverseai-[a-f0-9]{32}$")
        self.assertEqual(argv, [
            "docker", "run", "--rm", "--init", "--pull", "never", "--name", name, "--platform", "linux/arm64",
            "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--user", "65534:65534", "--pids-limit", "64", "--memory", "512m", "--memory-swap", "512m",
            "--cpus", "1", "--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=64m", "--log-driver", "none",
            "--mount", mount, lock()["image_id"], "lief.sections", '{"max_sections":17}',
        ])
        self.assertEqual(kwargs, {"timeout": 45, "max_output": MAX_WORKER_REPLY_BYTES})
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertEqual(len(self.calls), 1)

    def test_failure_kills_only_its_named_container_and_cleans_up(self):
        for failure in (OSError("secret /host/path"), subprocess.TimeoutExpired(["private"], 45),
                        TimeoutError("private"), ContainedError("WorkerOutputLimit")):
            with self.subTest(failure=type(failure).__name__):
                self.calls.clear()

                def fail(argv, **kwargs):
                    self.runner(argv, **kwargs)
                    if argv[1] == "run":
                        raise failure
                    return b""

                expected = ContainedTimeout if isinstance(failure, (TimeoutError, subprocess.TimeoutExpired)) else ContainedError
                with self.assertRaises(expected) as caught:
                    self.run_executor(self.executor(runner=fail))
                self.assertNotIn("private", str(caught.exception))
                self.assertNotIn("/", str(caught.exception))
                self.assertEqual(list(self.root.iterdir()), [])
                argv = self.calls[0][0]
                self.assertEqual(self.calls[-1][0], ["docker", "kill", argv[argv.index("--name") + 1]])

    def test_failure_still_removes_snapshot_if_kill_fails(self):
        def fail(argv, **kwargs):
            self.runner(argv, **kwargs)
            raise OSError("hidden host path")

        with self.assertRaisesRegex(ContainedError, "^WorkerProcessError$"):
            self.run_executor(self.executor(runner=fail))
        self.assertEqual(list(self.root.iterdir()), [])

    def _run_with_failed_cleanup(self, failure=None, *, kill_fails=False):
        def runner(argv, **kwargs):
            result = self.runner(argv, **kwargs)
            if argv[1] == "run" and failure is not None:
                raise failure
            if argv[1] == "kill" and kill_fails:
                raise OSError("/private/kill-failure")
            return result

        with patch("reverseai.contained.shutil.rmtree", side_effect=OSError("/private/cleanup-failure")):
            return self.run_executor(self.executor(runner=runner))

    def test_cleanup_failure_preserves_each_primary_exception_and_adds_only_a_safe_note(self):
        class OtherFailure(BaseException):
            pass

        for failure in (ContainedTimeout("WorkerTimeout"), ContainedError("WorkerOutputLimit"),
                        KeyboardInterrupt(), SystemExit(17), OtherFailure("Stopped")):
            with self.subTest(failure=type(failure).__name__):
                failure.add_note("ExistingNotice")
                with self.assertRaises(BaseException) as caught:
                    self._run_with_failed_cleanup(failure)
                self.assertIs(caught.exception, failure)
                self.assertEqual(caught.exception.__notes__, ["ExistingNotice", "StagingCleanupError"])
                self.assertNotIn("/", str(caught.exception))
                self.assertNotIn("/", " ".join(caught.exception.__notes__))

    def test_cleanup_failure_keeps_plain_runner_errors_sanitized(self):
        with self.assertRaisesRegex(ContainedError, "^WorkerProcessError$") as caught:
            self._run_with_failed_cleanup(OSError("/private/runner-failure"))
        self.assertIs(type(caught.exception), ContainedError)
        self.assertEqual(caught.exception.__notes__, ["StagingCleanupError"])

    def test_cleanup_and_kill_failures_keep_the_original_timeout_retriable(self):
        failure = ContainedTimeout("WorkerTimeout")
        with self.assertRaises(BaseException) as caught:
            self._run_with_failed_cleanup(failure, kill_fails=True)
        self.assertIs(caught.exception, failure)
        self.assertIsInstance(caught.exception, TimeoutError)
        self.assertEqual(caught.exception.__notes__, ["StagingCleanupError"])
        self.assertEqual([argv[1] for argv, _ in self.calls], ["run", "kill"])

    def test_cleanup_failure_preserves_a_staging_error_before_the_runner_starts(self):
        with patch("reverseai.contained.build_argv", side_effect=OSError("/private/staging-failure")):
            with self.assertRaisesRegex(ContainedError, "^WorkerProcessError$") as caught:
                self._run_with_failed_cleanup()
        self.assertEqual(caught.exception.__notes__, ["StagingCleanupError"])
        self.assertEqual(self.calls, [])

    def test_successful_run_fails_closed_on_cleanup_error_even_inside_an_outer_handler(self):
        with self.assertRaisesRegex(ContainedError, "^StagingCleanupError$") as caught:
            self._run_with_failed_cleanup()
        self.assertFalse(getattr(caught.exception, "__notes__", []))
        try:
            raise ValueError("/private/caller-failure")
        except ValueError:
            with self.assertRaisesRegex(ContainedError, "^StagingCleanupError$") as caught:
                self._run_with_failed_cleanup()
            self.assertFalse(getattr(caught.exception, "__notes__", []))

    def test_stdout_cap_is_also_checked_for_an_injected_runner(self):
        def oversized(argv, **kwargs):
            self.runner(argv, **kwargs)
            return b"x" * (MAX_WORKER_REPLY_BYTES + 1)

        with self.assertRaisesRegex(ContainedError, "^WorkerOutputLimit$"):
            self.run_executor(self.executor(runner=oversized))
        self.assertEqual(self.calls[-1][0][1], "kill")
        self.assertEqual(list(self.root.iterdir()), [])

    def test_image_mismatch_or_inspect_failure_never_stages_or_runs(self):
        def unavailable(image):
            raise OSError("/hidden/docker/socket")

        for inspect in (lambda image: "sha256:" + "d" * 64, unavailable):
            with self.subTest(inspect=inspect):
                executor = self.executor(inspect=inspect)
                self.assertFalse(executor.available())
                with self.assertRaisesRegex(ContainedError, "^ImageUnavailable$"):
                    self.run_executor(executor)
                self.assertEqual(self.calls, [])
                self.assertEqual(list(self.root.iterdir()), [])

    def test_wrong_digest_and_unvalidated_operations_never_reach_runner(self):
        executor = self.executor()
        with self.assertRaisesRegex(ContainedError, "SnapshotMismatch"):
            executor.run("lief.headers", {}, self.data, "0" * 64)
        for operation, args in (("sh", {}), ("lief.headers", {"path": "/etc/passwd"}),
                                ("lief.sections", {"max_sections": True}), ("lief.sections", {"max_sections": 65}),
                                ("lief.sections", {"max_sections": "--privileged"})):
            with self.subTest(operation=operation, args=args), self.assertRaises(ContainedError):
                executor.run(operation, args, self.data, sha256_hex(self.data))
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.root.iterdir()), [])

    def test_staging_root_must_be_private_and_not_a_symlink(self):
        for mode in (0o777, 0o755):
            os.chmod(self.root, mode)
            with self.assertRaisesRegex(ContainedError, "^UnsafeStagingFolder$"):
                self.run_executor(self.executor())
        os.chmod(self.root, 0o700)
        alias = self.root / "alias"
        alias.symlink_to(self.root, target_is_directory=True)
        executor = self.executor()
        executor.staging_root = alias
        with self.assertRaisesRegex(ContainedError, "^UnsafeStagingFolder$"):
            self.run_executor(executor)
        alias.unlink()
        self.assertEqual(self.calls, [])

    def test_staging_io_failure_is_short_and_cleans_the_created_folder(self):
        with patch("reverseai.contained.build_argv", side_effect=OSError("private /path")):
            with self.assertRaisesRegex(ContainedError, "^WorkerProcessError$"):
                self.run_executor(self.executor())
        self.assertEqual(self.calls, [])
        self.assertEqual(list(self.root.iterdir()), [])


class LockAndArgvTests(unittest.TestCase):
    def test_lock_file_pins_are_validated_and_copied(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "lock.json"
            path.write_text(json.dumps(lock()))
            self.assertEqual(load_lock(path), lock())
            original = lock()
            executor = DockerExecutor(original, inspect=lambda image: image)
            original["image_id"] = "changed"
            self.assertEqual(executor.lock["image_id"], lock()["image_id"])
            with self.assertRaises(TypeError):
                executor.lock["image_id"] = "changed"
            for key, bad in (("image_id", "latest"), ("platform", "linux/amd64"), ("base_digest", "unpinned"),
                             ("wheel_sha256", "short"), ("adapter_version", "other")):
                with self.subTest(key=key), self.assertRaisesRegex(ContainedError, "^InvalidImageLock$"):
                    load_lock(dict(lock(), **{key: bad}))
            for raw in (b"\xff", b"[1]", b"x" * 16_385):
                path.write_bytes(raw)
                with self.assertRaisesRegex(ContainedError, "^InvalidImageLock$"):
                    load_lock(path)
            with self.assertRaisesRegex(ContainedError, "^InvalidImageLock$"):
                load_lock(path.with_name("absent"))

    def test_builder_rejects_mount_option_injection_and_sets_defaults(self):
        argv = build_argv(lock()["image_id"], "reverseai-abc", "/private/staging", "lief.sections", {})
        self.assertEqual(argv[-1], '{"max_sections":32}')
        for folder in ("relative", "/tmp/staging,target=/host", "/tmp/line\n"):
            with self.subTest(folder=folder), self.assertRaises(ContainedError):
                build_argv(lock()["image_id"], "reverseai-abc", folder, "lief.headers", {})
        with self.assertRaises(ContainedError):
            build_argv("latest", "reverseai-abc", "/tmp/staging", "lief.headers", {})
        with self.assertRaises(ContainedError):
            build_argv(lock()["image_id"], "--privileged", "/tmp/staging", "lief.headers", {})


class ProcessRunnerTests(unittest.TestCase):
    def run_python(self, source, **kwargs):
        return run_bounded([sys.executable, "-I", "-B", "-c", source], **kwargs)

    def test_stdout_is_bytes_stderr_is_discarded_and_exact_cap_is_allowed(self):
        self.assertEqual(self.run_python("import os; os.write(2, b'private'); os.write(1, b'abcd')",
                                         timeout=5, max_output=4), b"abcd")

    def test_large_and_endless_outputs_are_stopped_at_the_byte_cap(self):
        with self.assertRaisesRegex(ContainedError, "^WorkerOutputLimit$"):
            self.run_python("import os\nwhile True: os.write(1, b'x' * 8192)", timeout=5, max_output=1024)

    def test_timeout_kills_and_reaps_the_cli_process(self):
        popen, processes = subprocess.Popen, []

        def record(*args, **kwargs):
            process = popen(*args, **kwargs)
            processes.append(process)
            self.assertIs(kwargs["shell"], False)
            self.assertEqual(kwargs["stdin"], subprocess.DEVNULL)
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            return process

        with patch("reverseai.contained.subprocess.Popen", side_effect=record):
            with self.assertRaisesRegex(ContainedTimeout, "^WorkerTimeout$"):
                self.run_python("import time; time.sleep(60)", timeout=0.1, max_output=1024)
        self.assertIsNotNone(processes[0].poll())

    def test_nonzero_exit_is_a_short_error(self):
        with self.assertRaisesRegex(ContainedError, "^WorkerProcessError$"):
            self.run_python("import sys; sys.stderr.write('/private/path'); sys.exit(17)", timeout=5, max_output=1024)

    def test_closed_stdout_does_not_bypass_the_wall_limit(self):
        with self.assertRaisesRegex(ContainedTimeout, "^WorkerTimeout$"):
            self.run_python("import os, time; os.close(1); time.sleep(60)", timeout=0.1, max_output=1024)

    def test_runner_callers_cannot_widen_the_production_limits(self):
        with patch("reverseai.contained.WALL_SECONDS", 0.1):
            with self.assertRaises(ContainedTimeout):
                self.run_python("import time; time.sleep(60)", timeout=60, max_output=1024)
        with self.assertRaisesRegex(ContainedError, "^WorkerOutputLimit$"):
            self.run_python(f"import os; os.write(1, b'x' * {MAX_WORKER_REPLY_BYTES + 1})",
                            timeout=5, max_output=MAX_WORKER_REPLY_BYTES * 2)
