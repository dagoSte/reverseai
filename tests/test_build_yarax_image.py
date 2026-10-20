"""tools/build_yarax_image.py without Docker or the internet: offline pins, Dockerfile checks, the ruleset hash in the
lock, the download's host, redirect, size and hash checks, and the exact docker calls."""

import contextlib
import hashlib
import http.server
import importlib.util
import io
import json
from pathlib import Path
import shutil
import tempfile
import threading
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("build_yarax_image", ROOT / "tools" / "build_yarax_image.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)
WHEEL_BYTES = b"stand-in wheel, never installed"


class FakeDocker:
    def __init__(self):
        self.calls = []
        self.context = None
        self.ruleset = None

    def __call__(self, *args, capture=False):
        self.calls.append(args)
        if args[0] == "build":
            context = Path(args[-1])
            self.context = sorted(str(path.relative_to(context)) for path in context.rglob("*"))
            self.ruleset = (context / build.RULESET).read_bytes()
            Path(args[args.index("--iidfile") + 1]).write_text("sha256:" + "e" * 64 + "\n")


class BuildTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.wheels = self.root / "wheels"
        self.wheels.mkdir()
        (self.wheels / build.WHEEL).write_bytes(WHEEL_BYTES)
        self.lock = self.root / "image.lock.json"
        self.docker = FakeDocker()

    def build(self, *extra, source=None):
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(build, "docker", self.docker))
            stack.enter_context(patch.object(build, "wheel_sha256", return_value=hashlib.sha256(WHEEL_BYTES).hexdigest()))
            if source:
                stack.enter_context(patch.object(build, "SOURCE", source))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            return build.main(["--wheel-dir", str(self.wheels), "--lock", str(self.lock), *extra])

    def copy(self, label):
        source = self.root / label.replace(" ", "-")
        shutil.copytree(build.SOURCE, source, ignore=shutil.ignore_patterns("image.lock.json"))
        return source

    def test_the_base_is_pulled_by_digest_the_build_is_offline_and_the_lock_has_the_ruleset_hash(self):
        self.assertEqual(self.build(), 0)
        pull, built = self.docker.calls
        self.assertEqual(pull, ("pull", "--platform", "linux/arm64", build.BASE))
        self.assertEqual(built[:6], ("build", "--platform", "linux/arm64", "--network", "none", "--pull=false"))
        self.assertEqual(built[6:8], ("--iidfile", built[7]))
        self.assertEqual(built[8:10], ("--tag", "reverseai-yarax:1.21.0-r1"))
        self.assertEqual(len(built), 11)
        self.assertEqual(self.docker.context, ["Dockerfile", "m2_fixture_v1.json", "requirements.txt", "wheels",
                                               "wheels/" + build.WHEEL, "worker.py"])
        self.assertEqual(json.loads(self.lock.read_text()), {
            "image_id": "sha256:" + "e" * 64, "platform": "linux/arm64", "base_digest": build.BASE_DIGEST,
            "wheel_sha256": hashlib.sha256(WHEEL_BYTES).hexdigest(), "adapter_version": "1.21.0-r1",
            "ruleset_sha256": hashlib.sha256((build.SOURCE / build.RULESET).read_bytes()).hexdigest()})

    def test_the_lock_records_the_hash_of_the_ruleset_copied_into_the_build(self):
        source = self.copy("other ruleset")
        (source / build.RULESET).write_bytes(b'{"rules": [], "ruleset": "m2_fixture_v1"}\n')
        self.assertEqual(self.build(source=source), 0)
        self.assertEqual(self.docker.ruleset, b'{"rules": [], "ruleset": "m2_fixture_v1"}\n')
        self.assertEqual(json.loads(self.lock.read_text())["ruleset_sha256"], hashlib.sha256(self.docker.ruleset).hexdigest())

    def test_the_dockerfile_installs_only_the_hashed_local_wheel_and_compiles_the_ruleset(self):
        text = (build.SOURCE / "Dockerfile").read_text()
        install = text[text.index("RUN python3 -m pip install"):text.index("rm -rf /tmp/wheels")]
        for flag in ("--no-index", "--find-links /tmp/wheels", "--only-binary=:all:", "--require-hashes", "--no-deps",
                     "-r /opt/reverseai/requirements.txt"):
            self.assertIn(flag, install)
        self.assertIn("s.loader.exec_module(w); w.compiled('m2_fixture_v1')", text)
        self.assertEqual(build.BASE_DIGEST, json.loads((ROOT / "containers" / "lief" / "image.lock.json").read_text())["base_digest"])

    def test_a_dockerfile_from_line_other_than_the_pinned_base_is_refused_before_docker(self):
        for label, lines in (("tag only", ["FROM python:3.12-slim"]), ("other digest", ["FROM python:3.12-slim@sha256:" + "0" * 64]),
                             ("named stage", ["FROM " + build.BASE + " AS worker"]), ("second stage", ["FROM " + build.BASE, "FROM busybox"]),
                             ("lower case", ["from " + build.BASE]), ("lower-case second stage", ["FROM " + build.BASE, "from busybox"]),
                             ("no FROM", ["RUN true"])):
            with self.subTest(label):
                source = self.copy(label)
                (source / "Dockerfile").write_text("# ReverseAI worker\n" + "\n".join(lines) + "\n")
                with self.assertRaisesRegex(SystemExit, "Dockerfile FROM differs"):
                    self.build(source=source)
                self.assertEqual(self.docker.calls, [])

    def test_another_image_or_stage_and_parser_directives_are_refused_before_docker(self):
        base = "FROM " + build.BASE
        for label, lines, reason in (
                ("COPY --from an image", [base, "COPY --from=busybox /bin/sh /bin/sh"], "another image or stage"),
                ("COPY --FROM upper case", [base, "COPY --FROM=busybox /bin/sh /bin/sh"], "another image or stage"),
                ("RUN --mount from", [base, "RUN --mount=type=bind,from=busybox,target=/x true"], "another image or stage"),
                ("RUN --mount on a continuation line", [base, "RUN \\", "    --mount=type=bind,from=busybox,target=/x true"],
                 "another image or stage"),
                ("syntax directive", ["# syntax=docker/dockerfile:1", base], "parser directives"),
                ("escape directive", ["#escape=`", base], "parser directives"),
                ("check directive with spaces", ["#  check = skip=all", base], "parser directives")):
            with self.subTest(label):
                source = self.copy(label)
                (source / "Dockerfile").write_text("\n".join(lines) + "\n")
                with self.assertRaisesRegex(SystemExit, reason):
                    self.build(source=source)
                self.assertEqual(self.docker.calls, [])
        allowed = self.copy("cache mount")
        (allowed / "Dockerfile").write_text("# a comment = not a directive here\n" + base + "\nRUN --mount=type=tmpfs,target=/x true\n")
        self.assertEqual(self.build(source=allowed), 0)

    def test_a_wheel_with_another_hash_is_refused_before_docker(self):
        (self.wheels / build.WHEEL).write_bytes(WHEEL_BYTES + b"!")
        with self.assertRaisesRegex(SystemExit, "pinned SHA-256"):
            self.build()
        self.assertEqual(self.docker.calls, [])

    def test_requirements_pin_exactly_the_contract_wheel(self):
        self.assertEqual(build.wheel_sha256(), "9bd9961b44b47dd747d526e61c703a2a8170426d003e789e7724bc7862de6d56")
        self.assertTrue(build.WHEEL_URL.startswith("https://files.pythonhosted.org/packages/"))
        self.assertTrue(build.WHEEL_URL.endswith("/yara_x-1.21.0-cp38-abi3-manylinux_2_28_aarch64.whl"))


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    requested = []

    def do_GET(self):
        RedirectHandler.requested.append(self.path)
        self.send_response(302)
        self.send_header("Location", "/elsewhere.whl")
        self.end_headers()

    def log_message(self, *args):
        pass


class Opener:
    def __init__(self, body):
        self.body, self.urls = body, []

    def open(self, url, timeout):
        self.urls.append(url)
        return io.BytesIO(self.body)


class DownloadTests(unittest.TestCase):
    def test_a_redirect_is_refused_and_never_followed(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        RedirectHandler.requested.clear()
        host = f"http://127.0.0.1:{server.server_port}/"
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary, build.WHEEL)
            with patch.object(build, "WHEEL_HOST", host), patch.object(build, "WHEEL_URL", host + build.WHEEL), \
                    self.assertRaisesRegex(SystemExit, "redirected"):
                build.fetch_wheel(target, hashlib.sha256(WHEEL_BYTES).hexdigest())
            self.assertFalse(target.exists())
        self.assertEqual(RedirectHandler.requested, ["/" + build.WHEEL])

    def test_a_url_off_the_pinned_host_or_file_is_refused_before_any_request(self):
        for url in ("https://example.invalid/packages/" + build.WHEEL, "http://files.pythonhosted.org/packages/" + build.WHEEL,
                    build.WHEEL_HOST + "x/" + build.WHEEL + ".exe", build.WHEEL_HOST.rstrip("/") + ".evil.invalid/" + build.WHEEL):
            with self.subTest(url), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(build, "WHEEL_URL", url), \
                    patch.object(build.urllib.request, "build_opener", side_effect=AssertionError("request made")):
                with self.assertRaisesRegex(SystemExit, "not the pinned PyPI file"):
                    build.fetch_wheel(Path(temporary, build.WHEEL), hashlib.sha256(WHEEL_BYTES).hexdigest())

    def test_the_download_is_size_and_hash_checked_before_it_is_written(self):
        pinned = hashlib.sha256(WHEEL_BYTES).hexdigest()
        for label, body, limit, refused in (("pinned bytes", WHEEL_BYTES, build.WHEEL_BYTES_LIMIT, False),
                                            ("other bytes", WHEEL_BYTES + b"!", build.WHEEL_BYTES_LIMIT, True),
                                            ("over the size limit", WHEEL_BYTES, len(WHEEL_BYTES) - 1, True)):
            opener = Opener(body)
            with self.subTest(label), tempfile.TemporaryDirectory() as temporary, \
                    patch.object(build.urllib.request, "build_opener", return_value=opener) as factory, \
                    patch.object(build, "WHEEL_BYTES_LIMIT", limit):
                target = Path(temporary, build.WHEEL)
                if refused:
                    with self.assertRaisesRegex(SystemExit, "does not match the pinned SHA-256"):
                        build.fetch_wheel(target, pinned)
                    self.assertFalse(target.exists())
                else:
                    build.fetch_wheel(target, pinned)
                    self.assertEqual(target.read_bytes(), WHEEL_BYTES)
                factory.assert_called_once_with(build.RefuseRedirects)
                self.assertEqual(opener.urls, [build.WHEEL_URL])
        self.assertEqual(build.WHEEL_BYTES_LIMIT, 16 * 1024 * 1024)


if __name__ == "__main__":
    unittest.main()
