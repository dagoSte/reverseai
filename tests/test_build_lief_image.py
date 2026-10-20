"""tools/build_lief_image.py without Docker or the internet: offline pins, the FROM check, redirects and the exact docker calls."""

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
SPEC = importlib.util.spec_from_file_location("build_lief_image", ROOT / "tools" / "build_lief_image.py")
build = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(build)
WHEEL_BYTES = b"stand-in wheel, never installed"


class FakeDocker:
    def __init__(self):
        self.calls = []
        self.context = None

    def __call__(self, *args, capture=False):
        self.calls.append(args)
        if args[0] == "build":
            context = Path(args[-1])
            self.context = sorted(str(path.relative_to(context)) for path in context.rglob("*"))
            Path(args[args.index("--iidfile") + 1]).write_text("sha256:" + "d" * 64 + "\n")


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

    def test_the_base_is_pulled_by_digest_and_the_build_is_offline(self):
        self.assertEqual(self.build(), 0)
        pull, built = self.docker.calls
        self.assertEqual(pull, ("pull", "--platform", "linux/arm64", build.BASE))
        self.assertEqual(built[:6], ("build", "--platform", "linux/arm64", "--network", "none", "--pull=false"))
        self.assertEqual(built[6:8], ("--iidfile", built[7]))
        self.assertEqual(built[8:10], ("--tag", "reverseai-lief:1.0.0-r2"))
        self.assertEqual(len(built), 11)
        self.assertEqual(self.docker.context, ["Dockerfile", "requirements.txt", "wheels",
                                               "wheels/" + build.WHEEL, "worker.py"])
        self.assertEqual(json.loads(self.lock.read_text()), {
            "image_id": "sha256:" + "d" * 64, "platform": "linux/arm64", "base_digest": build.BASE_DIGEST,
            "wheel_sha256": hashlib.sha256(WHEEL_BYTES).hexdigest(), "adapter_version": "1.0.0-r2"})

    def test_the_dockerfile_installs_only_the_hashed_local_wheel(self):
        text = (build.SOURCE / "Dockerfile").read_text()
        install = text[text.index("RUN python3 -m pip install"):text.index("rm -rf /tmp/wheels")]
        for flag in ("--no-index", "--find-links /tmp/wheels", "--only-binary=:all:", "--require-hashes", "--no-deps",
                     "-r /opt/reverseai/requirements.txt"):
            self.assertIn(flag, install)
        self.assertIn("worker.py'); w = u.module_from_spec(s); s.loader.exec_module(w); w.parser_configs()", text)

    def test_a_dockerfile_from_line_other_than_the_pinned_base_is_refused_before_docker(self):
        for label, lines in (("tag only", ["FROM python:3.12-slim"]), ("other digest", ["FROM python:3.12-slim@sha256:" + "0" * 64]),
                             ("named stage", ["FROM " + build.BASE + " AS worker"]), ("second stage", ["FROM " + build.BASE, "FROM busybox"]),
                             ("lower case", ["from " + build.BASE]), ("lower-case second stage", ["FROM " + build.BASE, "from busybox"]),
                             ("no FROM", ["RUN true"])):
            with self.subTest(label):
                source = self.root / label.replace(" ", "-")
                shutil.copytree(build.SOURCE, source, ignore=shutil.ignore_patterns("image.lock.json"))
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
                source = self.root / label.replace(" ", "-")
                shutil.copytree(build.SOURCE, source, ignore=shutil.ignore_patterns("image.lock.json"))
                (source / "Dockerfile").write_text("\n".join(lines) + "\n")
                with self.assertRaisesRegex(SystemExit, reason):
                    self.build(source=source)
                self.assertEqual(self.docker.calls, [])
        mount = self.root / "cache-mount"
        shutil.copytree(build.SOURCE, mount, ignore=shutil.ignore_patterns("image.lock.json"))
        (mount / "Dockerfile").write_text("# a comment = not a directive here\n" + base + "\nRUN --mount=type=tmpfs,target=/x true\nUSER 65534:65534\n")
        self.assertEqual(self.build(source=mount), 0)

    def test_add_and_any_non_ascii_byte_are_refused_before_docker(self):
        base = ("FROM " + build.BASE).encode()
        for label, content, reason in (
                ("ADD of a URL", base + b"\nADD https://example.invalid/x.tar /x\n", "ADD is refused"),
                ("ADD of a Git repository", base + b"\nADD https://example.invalid/r.git /r\n", "ADD is refused"),
                ("local ADD", base + b"\nADD wheels/ /tmp/wheels/\n", "ADD is refused"),
                ("lower-case add", base + b"\nadd wheels/ /tmp/wheels/\n", "ADD is refused"),
                ("BOM before a syntax directive", b"\xef\xbb\xbf# syntax=docker/dockerfile:1\n" + base + b"\n", "must be ASCII"),
                ("non-ASCII in a comment", b"# caf\xc3\xa9\n" + base + b"\n", "must be ASCII")):
            with self.subTest(label):
                source = self.root / label.replace(" ", "-")
                shutil.copytree(build.SOURCE, source, ignore=shutil.ignore_patterns("image.lock.json"))
                (source / "Dockerfile").write_bytes(content)
                with self.assertRaisesRegex(SystemExit, reason):
                    self.build(source=source)
                self.assertEqual(self.docker.calls, [])

    def copy(self, label):
        source = self.root / label.replace(" ", "-")
        shutil.copytree(build.SOURCE, source, ignore=shutil.ignore_patterns("image.lock.json"))
        return source

    def test_continued_lines_are_joined_before_any_check(self):
        """BuildKit joins a line ending in a backslash with the next one, skipping comment and empty lines in between."""
        base, user = "FROM " + build.BASE, "USER 65534:65534"
        for label, lines, reason in (
                ("ADD split inside its name", [base, "A\\", "DD https://example.invalid/x.bin /x.bin", user], "ADD is refused"),
                ("ADD split before its last letter", [base, "AD\\", "D https://example.invalid/r.git /r", user], "ADD is refused"),
                ("ADD split with a comment and an empty line", [base, "A\\", "# kept out of the join", "", "DD x /x", user],
                 "ADD is refused"),
                ("ADD split with spaces after the backslash", [base, "A\\  ", "DD x /x", user], "ADD is refused"),
                ("ADD continued to the end of the file", [base, user, "ADD x /x \\"], "ADD is refused"),
                ("second FROM split", [base, "FR\\", "OM busybox", user], "FROM differs"),
                ("--from split", [base, "COPY --fr\\", "om=busybox /bin/sh /bin/sh", user], "another image or stage"),
                ("mount from= split", [base, "RUN --mount=type=bind,fr\\", "om=busybox,target=/x true", user], "another image or stage")):
            with self.subTest(label):
                source = self.copy(label)
                (source / "Dockerfile").write_text("\n".join(lines) + "\n")
                with self.assertRaisesRegex(SystemExit, reason):
                    self.build(source=source)
                self.assertEqual(self.docker.calls, [])

    def test_exactly_one_user_65534_in_any_case(self):
        base = "FROM " + build.BASE
        for label, lines in (("lower-case extra user", [base, "USER 65534:65534", "user root"]),
                             ("root instead", [base, "USER root"]), ("no USER", [base]),
                             ("USER twice", [base, "USER 65534:65534", "USER 65534:65534"]),
                             ("USER split by a continuation", [base, "USER 65534:65534", "US\\", "ER root"]),
                             ("lower-case USER keyword, written unlike the pinned line", [base, "user 65534:65534"])):
            with self.subTest(label):
                source = self.copy(label)
                (source / "Dockerfile").write_text("\n".join(lines) + "\n")
                with self.assertRaisesRegex(SystemExit, "exactly one USER 65534:65534"):
                    self.build(source=source)
                self.assertEqual(self.docker.calls, [])

    def test_a_wheel_with_another_hash_is_refused_before_docker(self):
        (self.wheels / build.WHEEL).write_bytes(WHEEL_BYTES + b"!")
        with self.assertRaisesRegex(SystemExit, "pinned SHA-256"):
            self.build()
        self.assertEqual(self.docker.calls, [])


class RedirectHandler(http.server.BaseHTTPRequestHandler):
    requested = []

    def do_GET(self):
        RedirectHandler.requested.append(self.path)
        self.send_response(302)
        self.send_header("Location", "/elsewhere.whl")
        self.end_headers()

    def log_message(self, *args):
        pass


class DownloadTests(unittest.TestCase):
    def test_a_redirect_is_refused_and_never_followed(self):
        server = http.server.HTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        RedirectHandler.requested.clear()
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary, build.WHEEL)
            with patch.object(build, "WHEEL_URL", f"http://127.0.0.1:{server.server_port}/" + build.WHEEL), \
                    self.assertRaisesRegex(SystemExit, "redirected"):
                build.fetch_wheel(target, hashlib.sha256(WHEEL_BYTES).hexdigest())
            self.assertFalse(target.exists())
        self.assertEqual(RedirectHandler.requested, ["/" + build.WHEEL])

    def test_the_download_is_size_and_hash_checked_before_it_is_written(self):
        class Opener:
            def __init__(self, body):
                self.body, self.urls = body, []

            def open(self, url, timeout):
                self.urls.append(url)
                return io.BytesIO(self.body)

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


if __name__ == "__main__":
    unittest.main()
